// channel-check exercises the agent channel of a running cluster from the
// workstation (plan 03, step 1): it asks the active mgr's module for a
// confirmation with a host's agent client certificate, and calls the bridge
// with the mgr host's agent certificate. It reads the CLI state, so it is a
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
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
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

	return nil
}
