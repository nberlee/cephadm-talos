//go:build live

package orch

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

// TestLiveJobs runs `never` jobs on a real cluster of the current state
// (CEPHADM_TALOS_HOME): a zap of a free device and an image probe.
//
//	CEPHADM_TALOS_LIVE_HOST=<host> CEPHADM_TALOS_LIVE_DEVICE=/dev/sdb go test -tags live -run TestLiveJobs ./internal/orch/
func TestLiveJobs(t *testing.T) {
	o := liveOrch(t)
	st := o.St

	h, ok := st.Host(os.Getenv("CEPHADM_TALOS_LIVE_HOST"))
	if !ok {
		t.Fatal("set CEPHADM_TALOS_LIVE_HOST to a host of the cluster")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	start := time.Now()
	if err := o.zap(ctx, h, os.Getenv("CEPHADM_TALOS_LIVE_DEVICE")); err != nil {
		t.Fatalf("zap: %v", err)
	}

	t.Logf("zap took %s", time.Since(start).Round(time.Millisecond))

	start = time.Now()

	info, err := o.resolveImage(ctx, h.Addr, st.Image, false)
	if err != nil || !strings.HasPrefix(info.Version, "20.") {
		t.Fatalf("probe: %+v %v", info, err)
	}

	t.Logf("probe: Ceph %s %s, took %s", info.Version, info.Arch, time.Since(start).Round(time.Millisecond))
}

// TestLiveStore publishes and reads back records through config-key on the
// mon host of the current state, then removes them again.
//
//	go test -tags live -run TestLiveStore ./internal/orch/
func TestLiveStore(t *testing.T) {
	o := liveOrch(t)

	adm, err := o.adminHost()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	prefix := store.Prefix + "inc/live-test/"

	start := time.Now()

	b, err := o.configKeys(ctx, adm.Addr, prefix)
	if err != nil {
		t.Fatal(err)
	}

	s := store.Store{B: b, Incarnation: "live-test"}
	big := strings.Repeat("0123456789", 20000) // 200 KB: several chunks

	var m store.Manifest

	for i := range 3 {
		if m, err = s.Publish(ctx, map[string][]byte{"big": []byte(big), "n": []byte{byte('0' + i)}}); err != nil {
			t.Fatal(err)
		}
	}

	t.Logf("3 publications in %s", time.Since(start).Round(time.Millisecond))

	// a fresh snapshot, as the next command would read it
	b2, err := o.configKeys(ctx, adm.Addr, prefix)
	if err != nil {
		t.Fatal(err)
	}

	s2 := store.Store{B: b2, Incarnation: "live-test"}

	latest, err := s2.Latest(ctx)
	if err != nil || latest.Seq != m.Seq {
		t.Fatalf("latest %+v %v", latest, err)
	}

	if v, err := s2.Read(ctx, latest, "big"); err != nil || string(v) != big {
		t.Fatalf("big: %d bytes %v", len(v), err)
	}

	keys, _ := b2.List(ctx, prefix)
	t.Logf("%d keys after compaction", len(keys))

	if err := b2.Remove(ctx, keys); err != nil {
		t.Fatal(err)
	}
}

// TestLiveAgentStatus fetches every agent's status record with a mgr's client
// certificate, as the module polls it.
//
//	go test -tags live -run TestLiveAgentStatus -v ./internal/orch/
func TestLiveAgentStatus(t *testing.T) {
	o := liveOrch(t)

	mgrs := o.St.DaemonsOf(state.TypeMgr, "")
	if len(mgrs) == 0 {
		t.Fatal("no mgr")
	}

	mgr, _ := o.St.Host(mgrs[0].Host)

	cfg, err := agent.ClientTLSConfig([]byte(o.St.Agent.CACert), []byte(mgr.MgrClientCert), []byte(mgr.MgrClientKey))
	if err != nil {
		t.Fatal(err)
	}

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 30 * time.Second}

	for _, h := range o.St.Hosts {
		resp, err := cl.Get("https://" + net.JoinHostPort(h.Addr, strconv.Itoa(agent.Port)) + "/status?refresh=1")
		if err != nil {
			t.Fatal(err)
		}

		b, _ := io.ReadAll(io.LimitReader(resp.Body, agent.MaxRecord))
		resp.Body.Close() //nolint:errcheck

		var rec agent.Record
		if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &rec) != nil || rec.Records != "ok" || rec.Node == nil {
			t.Errorf("%s: %d %s", h.Name, resp.StatusCode, b)

			continue
		}

		t.Logf("%s: records %s, node %+v, %d containers", h.Name, rec.Records, *rec.Node, len(rec.Containers))
	}
}

// liveOrch opens the current cluster as a command does: the workstation's
// state, then the cluster's state from its mons.
func liveOrch(t *testing.T) *Orch {
	t.Helper()

	st, err := state.Load("")
	if err != nil {
		t.Fatal(err)
	}

	tc := &talos.Client{Default: talos.Conn{Talosconfig: st.Talosconfig, Context: st.Context}, Hosts: map[string]talos.Conn{}}
	t.Cleanup(func() { tc.Close() }) //nolint:errcheck

	for _, h := range st.Hosts {
		tc.Hosts[h.Addr] = talos.Conn{Talosconfig: h.Talosconfig, Context: h.Context}
	}

	o := &Orch{Talos: tc, St: st, Out: os.Stdout}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := o.Open(ctx); err != nil {
		t.Fatal(err)
	}

	return o
}
