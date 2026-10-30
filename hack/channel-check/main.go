// channel-check exercises the agent channel of a running cluster from the
// workstation (plan 03, step 1): it asks the active mgr's module for a
// confirmation with a host's agent client certificate, and calls the bridge
// with the mgr host's agent certificate: a call, a store publication read back
// and removed (step 4), and an auth get. It reads the CLI state, so it is a
// test tool only.
//
// usage: go run ./hack/channel-check <mgr host> <agent host>
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/orch"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

func main() {
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(mgrHost, agentHost string) error {
	st, err := state.Load("") // the current cluster
	if err != nil {
		return err
	}

	tc := &talos.Client{Default: talos.Conn{Talosconfig: st.Talosconfig, Context: st.Context}}
	defer tc.Close() //nolint:errcheck

	// the certificates are in the cluster's state, in its mons
	if err := (&orch.Orch{Talos: tc, St: st, Out: os.Stderr}).Open(context.Background()); err != nil {
		return err
	}

	mgr, ok := st.Host(mgrHost)
	if !ok {
		return fmt.Errorf("no host %s", mgrHost)
	}

	ag, ok := st.Host(agentHost)
	if !ok {
		return fmt.Errorf("no host %s", agentHost)
	}

	cfg, err := agent.ClientTLSConfig([]byte(st.Agent.CACert), []byte(ag.AgentClientCert), []byte(ag.AgentClientKey))
	if err != nil {
		return err
	}

	ch, err := agent.NewChannel(pki.Identity{FSID: st.FSID, Role: pki.RoleAgent, Name: ag.Name})
	if err != nil {
		return err
	}

	start := time.Now()
	conf, until, err := ch.Confirm(context.Background(), cfg, agent.ConfirmTarget{Addr: mgr.Addr, Mgr: mgr.Name}, 1, "channel-check", strings.Repeat("00", 32))
	fmt.Printf("confirm as agent.%s: gid=%d mgr=%s valid for %s, took %s, err=%v\n", ag.Name, conf.GID, conf.Mgr, time.Until(until).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), err)

	// the bridge: only the mgr host's own agent
	for _, who := range []state.Host{mgr, ag} {
		cfg, err := agent.ClientTLSConfig([]byte(st.Agent.CACert), []byte(who.AgentClientCert), []byte(who.AgentClientKey))
		if err != nil {
			return err
		}

		id := make([]byte, 16)
		_, _ = rand.Read(id)

		body, _ := json.Marshal(wire.BridgeRequest{Version: wire.Version, Call: "health", Args: map[string]any{}, Deadline: 5, DispatchID: hex.EncodeToString(id)})
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}

		start = time.Now()

		resp, err := cl.Post("https://"+net.JoinHostPort(mgr.Addr, strconv.Itoa(wire.ModulePort))+"/v1/bridge", "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("bridge as agent.%s: %v\n", who.Name, err)

			continue
		}

		out, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close() //nolint:errcheck

		fmt.Printf("bridge as agent.%s: %d %s (%s)\n", who.Name, resp.StatusCode, bytes.TrimSpace(out), time.Since(start).Round(time.Millisecond))
	}

	return storeCheck(st, mgr)
}

// storeCheck publishes, reads back and removes records through the bridge, as
// the leader will, and reads a daemon key.
func storeCheck(st *state.State, mgr state.Host) error {
	cfg, err := agent.ClientTLSConfig([]byte(st.Agent.CACert), []byte(mgr.AgentClientCert), []byte(mgr.AgentClientKey))
	if err != nil {
		return err
	}

	ctx := context.Background()
	b := &agent.Bridge{TLS: cfg, Addr: mgr.Addr, Mgr: mgr.Name, FSID: st.FSID}
	prefix := store.Prefix + "inc/channel-check/"

	start := time.Now()

	snap, err := b.Store(ctx, prefix)
	if err != nil {
		return err
	}

	s := store.Store{B: snap, Incarnation: "channel-check"}
	big := strings.Repeat("0123456789", 20000) // 200 KB: several chunks

	for i := range 3 {
		if _, err := s.Publish(ctx, map[string][]byte{"big": []byte(big), "n": {byte('0' + i)}}); err != nil {
			return err
		}
	}

	fmt.Printf("store: 3 publications through the bridge in %s (entry limit %d)\n", time.Since(start).Round(time.Millisecond), snap.EntryLimit())

	snap2, err := b.Store(ctx, prefix)
	if err != nil {
		return err
	}

	s2 := store.Store{B: snap2, Incarnation: "channel-check"}

	m, err := s2.Latest(ctx)
	if err != nil {
		return err
	}

	v, err := s2.Read(ctx, m, "big")
	if err != nil || string(v) != big {
		return fmt.Errorf("read back %d bytes: %w", len(v), err)
	}

	keys, err := snap2.List(ctx, prefix)
	if err != nil {
		return err
	}

	fmt.Printf("store: read back seq %d, %d keys\n", m.Seq, len(keys))

	if err := snap2.Remove(ctx, keys); err != nil {
		return err
	}

	if left, err := snap2.List(ctx, prefix); err != nil || len(left) != 0 {
		return fmt.Errorf("store: %d keys left after removal: %w", len(left), err)
	}

	if _, found, err := b.AuthGet(ctx, "mgr."+mgr.Name); err != nil || !found {
		return fmt.Errorf("auth get mgr.%s through the bridge: found=%v: %w", mgr.Name, found, err)
	}

	fmt.Printf("auth get mgr.%s through the bridge: found\n", mgr.Name)

	// refused by the module's allowlist, not lost on the way
	_, _, err = b.AuthGet(ctx, "client.admin")
	if err == nil || errors.Is(err, agent.ErrOutcomeUnknown) || !strings.Contains(err.Error(), "entity not allowed") {
		return fmt.Errorf("auth get client.admin through the bridge was not refused: %w", err)
	}

	fmt.Println("auth get client.admin through the bridge: refused")

	return nil
}
