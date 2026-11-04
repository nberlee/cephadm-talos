package orch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

// The CLI's operator calls, its handoff and restore's check verify an agent
// by its chain and identity, not by the address it is dialled at (plan 04,
// step 5): a host that moved answers at an address its certificate does not
// name.
func TestTheOperatorsCallsVerifyIdentityNotAddress(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)

	if err := o.setupAgent(context.Background(), "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	// its certificate names 10.9.9.9; it is dialled at 127.0.0.1
	h := state.Host{Name: "h1", Addr: "10.9.9.9"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	pair, err := tls.X509KeyPair([]byte(h.AgentCert), []byte(h.AgentKey))
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(o.St.Agent.CACert))

	a := &fakeAgent{revision: 7, node: f}
	srv := httptest.NewUnstartedServer(a)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	old := agentAddr
	agentAddr = func(state.Host) string { return srv.Listener.Addr().String() }

	t.Cleanup(func() { agentAddr = old })

	get := func(host state.Host) error {
		cl, err := o.operatorClient(host)
		if err != nil {
			return err
		}

		resp, err := cl.Get(agentURL(host, "/v1/suspend"))
		if err == nil {
			resp.Body.Close() //nolint:errcheck
		}

		return err
	}

	if err := get(h); err != nil {
		t.Fatalf("a moved agent: %v", err)
	}

	if err := get(state.Host{Name: "h2", Addr: "10.9.9.9"}); err == nil {
		t.Fatal("another agent's identity accepted")
	}

	if ok, err := o.agentServes(h, h.AgentCert); err != nil || !ok {
		t.Fatalf("restore's check of a moved agent: %v %v", ok, err)
	}

	if _, err := o.agentServes(state.Host{Name: "h2"}, h.AgentCert); err == nil {
		t.Fatal("restore's check accepted another identity")
	}
}
