// channel-check exercises the agent channel of a running cluster from the
// workstation (plan 03, step 1): it asks the active mgr's module for a
// confirmation with a host's agent client certificate, and checks that the
// bridge, on the mgr host's loopback, cannot be reached from the network. It
// reads the CLI state, so it is a test tool only.
//
// usage: go run ./hack/channel-check <mgr host> <agent host>
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	// the certificates are in the cluster's state, in its mons, their keys
	// in its secrets
	o := &orch.Orch{Talos: tc, St: st, Out: os.Stderr}
	if err := o.Open(context.Background()); err != nil {
		return err
	}

	if err := o.LoadSecrets(context.Background()); err != nil {
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

	// the bridge is on the mgr host's loopback only: from here neither port serves it
	return bridgeUnreachable(st, mgr)
}

// bridgeUnreachable checks that the module's public port does not serve the
// bridge, even to the mgr host's own agent certificate, and that the bridge
// port does not answer from the network. The real leader's revisions exercise
// the bridge itself.
func bridgeUnreachable(st *state.State, mgr state.Host) error {
	cfg, err := agent.ClientTLSConfig([]byte(st.Agent.CACert), []byte(mgr.AgentClientCert), []byte(mgr.AgentClientKey))
	if err != nil {
		return err
	}

	id := make([]byte, 16)
	_, _ = rand.Read(id)

	body, _ := json.Marshal(wire.BridgeRequest{Version: wire.Version, Call: "health", Args: map[string]any{}, Deadline: 5, DispatchID: hex.EncodeToString(id)})
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}

	resp, err := cl.Post("https://"+net.JoinHostPort(mgr.Addr, strconv.Itoa(wire.ModulePort))+"/v1/bridge", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("the module's public port: %w", err)
	}

	resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("the module's public port answered the bridge with %d", resp.StatusCode)
	}

	fmt.Printf("bridge on port %d as agent.%s: %d\n", wire.ModulePort, mgr.Name, resp.StatusCode)

	addr := net.JoinHostPort(mgr.Addr, strconv.Itoa(wire.BridgePort))

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		c.Close() //nolint:errcheck

		return fmt.Errorf("the bridge port %s accepts connections from the network", addr)
	}

	fmt.Printf("bridge port %s from the network: %v\n", addr, err)

	return nil
}
