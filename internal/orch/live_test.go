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

	"gopkg.in/yaml.v3"

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

	serial, link, err := o.diskIdentity(ctx, h.Addr, os.Getenv("CEPHADM_TALOS_LIVE_DEVICE"))
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := o.zap(ctx, h, link, serial, randHex(3)); err != nil {
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

		t.Logf("%s: records %s, node %+v, %d containers, observed %s", h.Name, rec.Records, *rec.Node, len(rec.Containers), rec.ObservedAt.Format(time.RFC3339))

		for name, c := range rec.Containers {
			if c.Version != "" {
				t.Logf("%s: %s reports Ceph %s", h.Name, name, c.Version)
			}
		}
	}
}

// TestLivePolicyAdmitsTheCluster runs the agents' admission policy over the
// documents deployed on every node, with the node's disks: everything a grant
// could carry must pass. The CLI's own documents are skipped, and the first
// mon's bootstrap document is expected to be refused.
//
//	go test -tags live -run TestLivePolicyAdmitsTheCluster -v ./internal/orch/
func TestLivePolicyAdmitsTheCluster(t *testing.T) {
	o := liveOrch(t)
	ctx := context.Background()

	for _, h := range o.St.Hosts {
		cfg, err := o.Talos.MachineConfig(ctx, h.Addr)
		if err != nil {
			t.Fatal(err)
		}

		disks, err := o.Talos.Disks(ctx, h.Addr)
		if err != nil {
			t.Fatal(err)
		}

		var ds []agent.Disk
		for _, d := range disks {
			ds = append(ds, agent.Disk{Serial: d.TypedSpec().Serial, Symlinks: d.TypedSpec().Symlinks})
		}

		var docs []agent.Doc

		var names []string

		dec := yaml.NewDecoder(strings.NewReader(cfg))

		for {
			var m map[string]any
			if err := dec.Decode(&m); err != nil {
				break
			}

			kind, _ := m["kind"].(string)
			name, _ := m["name"].(string)

			if kind == "ContainerConfig" {
				names = append(names, name)
			}

			cluster := strings.HasPrefix(name, "ceph-"+o.St.Short()+"-") || strings.HasPrefix(name, "ceph/") || name == "ceph"
			if !cluster || name == o.agentDocName(h) || name == o.recordsInitDocName(h) {
				continue
			}

			b, _ := yaml.Marshal(m)
			docs = append(docs, agent.Doc{Kind: kind, Name: name, YAML: b})
		}

		pol := &agent.Policy{FSID: o.St.FSID, Host: h.Name, Repos: o.imageRepos(), CACert: o.St.Agent.CACert}

		// the operator's last approval, as the agents have it (none before the handoff)
		appr, _, err := o.lastApproval()
		if err != nil {
			t.Fatal(err)
		}

		for _, d := range docs {
			err := pol.Check([]agent.Doc{d}, ds, names, appr)

			bootstrap := strings.Contains(string(d.YAML), "MODE=bootstrap")

			switch {
			case err != nil && !bootstrap:
				t.Errorf("%s: %s: %v", h.Name, d.Key(), err)
			case err == nil && bootstrap:
				t.Errorf("%s: %s: the bootstrap mon was admitted", h.Name, d.Key())
			default:
				t.Logf("%s: %s: %v", h.Name, d.Key(), err)
			}
		}
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

	// the tests act as a mgr or an agent: they need its keys
	if err := o.LoadSecrets(ctx); err != nil {
		t.Fatal(err)
	}

	return o
}
