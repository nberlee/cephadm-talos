// grant-check exercises grants on a running cluster from the workstation
// (plan 03, step 4): it hands a node to its agent with the operator
// certificate, then acts as the leader with the mgr host's agent certificate:
// it reads the active mgr's gid through the bridge and grants the node an
// image probe and then its removal, each confirmed by the module. It reads
// the CLI state, so it is a test tool only. The node stays handed over.
//
// usage: go run ./hack/grant-check <mgr host> <target host>
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/orch"
	"github.com/nberlee/cephadm-talos/internal/spec"
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

func post(cl *http.Client, url string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}

	resp, err := cl.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}

	defer resp.Body.Close() //nolint:errcheck

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %d %s", url, resp.StatusCode, bytes.TrimSpace(raw))
	}

	return json.Unmarshal(raw, out)
}

func run(mgrHost, target string) error {
	st, err := state.Load("")
	if err != nil {
		return err
	}

	tc := &talos.Client{Default: talos.Conn{Talosconfig: st.Talosconfig, Context: st.Context}}
	defer tc.Close() //nolint:errcheck

	if err := (&orch.Orch{Talos: tc, St: st, Out: os.Stderr}).Open(context.Background()); err != nil {
		return err
	}

	mgr, ok := st.Host(mgrHost)
	if !ok {
		return fmt.Errorf("no host %s", mgrHost)
	}

	h, ok := st.Host(target)
	if !ok {
		return fmt.Errorf("no host %s", target)
	}

	agentURL := "https://" + net.JoinHostPort(h.Addr, strconv.Itoa(agent.Port))
	client := func(certPEM, keyPEM string) (*http.Client, error) {
		cfg, err := agent.ClientTLSConfig([]byte(st.Agent.CACert), []byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, err
		}

		return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 3 * time.Minute}, nil
	}

	// the handoff, as the CLI
	op, err := client(st.Agent.OperatorCert, st.Agent.OperatorKey)
	if err != nil {
		return err
	}

	var ho wire.HandoffReply

	err = post(op, agentURL+"/v1/handoff", wire.Handoff{Version: wire.Version, FSID: st.FSID, Host: h.Name, Revision: 1}, &ho)
	fmt.Printf("handoff of %s: %+v %v\n", h.Name, ho, err)

	// the leader: the agent on the active mgr's host
	leader, err := client(mgr.AgentClientCert, mgr.AgentClientKey)
	if err != nil {
		return err
	}

	cfg, err := agent.ClientTLSConfig([]byte(st.Agent.CACert), []byte(mgr.AgentClientCert), []byte(mgr.AgentClientKey))
	if err != nil {
		return err
	}

	b := &agent.Bridge{TLS: cfg, Addr: mgr.Addr, Mgr: mgr.Name, FSID: st.FSID}

	id, _ := agent.NewDispatchID()

	res, err := b.Call(context.Background(), id, "mgr dump", nil, 5*time.Second)
	if err != nil {
		return err
	}

	var dump struct {
		ActiveGID  int64  `json:"active_gid"`
		ActiveName string `json:"active_name"`
	}

	if err := json.Unmarshal([]byte(res.Out), &dump); err != nil || dump.ActiveName != mgr.Name {
		return fmt.Errorf("mgr dump: active %q: %v", dump.ActiveName, err)
	}

	name := st.DocName(state.Daemon{Type: "probe", ID: "c0ffee"})

	probe, err := spec.Render(daemons.Probe(name, st.Image))
	if err != nil {
		return err
	}

	y := string(probe)
	now := time.Now().Unix()

	for i, docs := range [][]wire.GrantDoc{
		{{Kind: "ContainerConfig", Name: name, YAML: &y}},
		{{Kind: "ContainerConfig", Name: name}},
	} {
		g := wire.Grant{
			Version: wire.Version, FSID: st.FSID, Host: h.Name, Mgr: mgr.Name, MgrAddr: mgr.Addr, GID: dump.ActiveGID,
			Revision: now + int64(i), Operation: fmt.Sprintf("grant-check-%d-%d", now, i), Docs: docs,
		}

		start := time.Now()

		var res wire.Operation
		if err := post(leader, agentURL+"/v1/grant", g, &res); err != nil {
			return err
		}

		fmt.Printf("grant %s (revision %d, gid %d): %s %s (%s)\n", g.Operation, g.Revision, g.GID, res.State, res.Error, time.Since(start).Round(time.Millisecond))

		if res.State != wire.OpCompleted {
			return errors.New("the grant did not complete")
		}
	}

	// a grant of a stale incarnation is refused by the confirmation
	g := wire.Grant{
		Version: wire.Version, FSID: st.FSID, Host: h.Name, Mgr: mgr.Name, MgrAddr: mgr.Addr, GID: dump.ActiveGID - 1,
		Revision: now + 2, Operation: fmt.Sprintf("grant-check-%d-stale", now), Docs: []wire.GrantDoc{{Kind: "ContainerConfig", Name: name, YAML: &y}},
	}

	var stale wire.Operation
	if err := post(leader, agentURL+"/v1/grant", g, &stale); err != nil {
		return err
	}

	fmt.Printf("grant of gid %d: %s %s\n", g.GID, stale.State, stale.Error)

	if stale.State != wire.OpRefused {
		return errors.New("a stale incarnation's grant was not refused")
	}

	return nil
}
