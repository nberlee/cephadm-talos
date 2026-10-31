package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// testGranter is a handed-over node with a fake module that confirms gid 42
// for mgr h0, unless told otherwise.
type testGranter struct {
	*Granter
	patches *countingPatch
	gid     int64
	refuse  error
	expired bool
	calls   int
}

func newTestGranter(t *testing.T) *testGranter {
	t.Helper()

	n, tc := testNode(t)

	_, err := n.Adopt(context.Background(), 1)
	must(t, err)

	cp := &countingPatch{Client: tc}
	n.Talos = cp

	ch, err := NewChannel(pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h1"})
	must(t, err)

	tg := &testGranter{Granter: NewGranter(n, ch, nil, n.Records), patches: cp, gid: 42}
	tg.confirm = func(_ context.Context, target ConfirmTarget, revision int64, operation, hash string) (wire.Confirmation, time.Time, error) {
		tg.calls++

		// the reservation is durable before the confirmation is asked
		op, found, err := tg.readOp(operation)
		if err != nil || !found || op.State != wire.OpReserved || op.InputsHash != hash {
			t.Errorf("no reservation before the confirmation: %+v %v %v", op, found, err)
		}

		if tg.refuse != nil {
			return wire.Confirmation{}, time.Time{}, tg.refuse
		}

		until := time.Now().Add(ConfirmValidity)
		if tg.expired {
			until = time.Now().Add(-time.Second)
		}

		return wire.Confirmation{Mgr: target.Mgr, GID: tg.gid, Revision: revision, Operation: operation, InputsHash: hash}, until, nil
	}

	return tg
}

func probeGrant(rev int64, op, id string) wire.Grant {
	name := "ceph-" + testFSID[:8] + "-probe-" + id
	y := string(mustRender(daemons.Probe(name, testImage)))

	return wire.Grant{
		Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42,
		Revision: rev, Operation: op, Docs: []wire.GrantDoc{{Kind: "ContainerConfig", Name: name, YAML: &y}},
	}
}

func mustRender(d any) []byte {
	b, err := spec.Render(d)
	if err != nil {
		panic(err)
	}

	return b
}

func TestGrantApplies(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	op, err := g.Grant(ctx, probeGrant(2, "op-1", "aaaaaa"))
	if err != nil || op.State != wire.OpCompleted || g.patches.n != 1 {
		t.Fatalf("grant: %+v %v, %d patches", op, err, g.patches.n)
	}

	// a retry returns the record, nothing is applied again
	op, err = g.Grant(ctx, probeGrant(2, "op-1", "aaaaaa"))
	if err != nil || op.State != wire.OpCompleted || g.patches.n != 1 || g.calls != 1 {
		t.Fatalf("retry: %+v %v, %d patches, %d confirmations", op, err, g.patches.n, g.calls)
	}

	// the same id with other inputs
	if _, err := g.Grant(ctx, probeGrant(3, "op-1", "bbbbbb")); err == nil {
		t.Fatal("an operation id reused with other inputs")
	}

	if st := g.Node.Status(ctx); st.State != "owned" || st.Revision != 2 {
		t.Fatalf("status %+v", st)
	}
}

func TestGrantNeedsAConfirmationOfItsIncarnation(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	for name, set := range map[string]func(){
		"no answer":           func() { g.refuse = errors.New("connection refused") },
		"another incarnation": func() { g.gid = 43 },
		"an expired answer":   func() { g.expired = true },
	} {
		g.refuse, g.gid, g.expired = nil, 42, false
		set()

		op, err := g.Grant(ctx, probeGrant(2, "op-2", "aaaaaa"))
		if err != nil || op.State != wire.OpRefused || g.patches.n != 0 {
			t.Errorf("%s: %+v %v, %d patches", name, op, err, g.patches.n)
		}
	}

	// nothing changed: the same operation may be granted again once confirmed
	g.refuse, g.gid, g.expired = nil, 42, false

	op, err := g.Grant(ctx, probeGrant(2, "op-2", "aaaaaa"))
	if err != nil || op.State != wire.OpCompleted {
		t.Fatalf("after confirmation: %+v %v", op, err)
	}
}

func TestGrantRefusedOrUncertain(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	// refused by the policy: a tagged image
	gr := probeGrant(2, "op-3", "aaaaaa")
	y := strings.Replace(*gr.Docs[0].YAML, testImage, "quay.io/ceph/ceph:v20.2.4", 1)
	gr.Docs[0].YAML = &y

	op, err := g.Grant(ctx, gr)
	if err != nil || op.State != wire.OpRefused || g.patches.n != 0 {
		t.Fatalf("policy refusal: %+v %v", op, err)
	}

	// Talos may or may not have taken the config
	g.Node.Talos = failingPatch{g.patches.Client}

	op, err = g.Grant(ctx, probeGrant(3, "op-4", "bbbbbb"))
	if err != nil || op.State != wire.OpUncertain {
		t.Fatalf("failed patch: %+v %v", op, err)
	}

	// a retry does not apply again, and nothing else is applied
	g.Node.Talos = g.patches

	if op, _ = g.Grant(ctx, probeGrant(3, "op-4", "bbbbbb")); op.State != wire.OpUncertain {
		t.Fatalf("retry of an uncertain grant: %+v", op)
	}

	if _, err := g.Grant(ctx, probeGrant(4, "op-5", "cccccc")); err == nil || !strings.Contains(err.Error(), "unresolved") || g.patches.n != 0 {
		t.Fatalf("grant after an uncertain one: %v, %d patches", err, g.patches.n)
	}
}

// slowConfig makes every config read take a while.
type slowConfig struct {
	*countingPatch
	d time.Duration
}

func (s slowConfig) MachineConfig(ctx context.Context, node string) (string, error) {
	time.Sleep(s.d)

	return s.countingPatch.MachineConfig(ctx, node)
}

func TestGrantSafetyBounds(t *testing.T) {
	ctx := context.Background()

	// the confirmation runs out while the node is read and admitted
	g := newTestGranter(t)
	g.Node.Talos = slowConfig{g.patches, 150 * time.Millisecond}

	confirm := g.confirm
	g.confirm = func(ctx context.Context, target ConfirmTarget, revision int64, operation, hash string) (wire.Confirmation, time.Time, error) {
		c, _, err := confirm(ctx, target, revision, operation, hash)

		return c, time.Now().Add(100 * time.Millisecond), err
	}

	op, err := g.Grant(ctx, probeGrant(2, "op-7", "aaaaaa"))
	if err != nil || op.State != wire.OpRefused || g.patches.n != 0 {
		t.Fatalf("expired during the apply: %+v %v, %d patches", op, err, g.patches.n)
	}

	// an operation that started before a crash, without an outcome: nothing else runs
	g = newTestGranter(t)
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-crashed", Revision: 2, InputsHash: "x", GID: 42, State: wire.OpStarted}))

	if _, err := g.Grant(ctx, probeGrant(3, "op-8", "aaaaaa")); err == nil || !strings.Contains(err.Error(), "op-crashed") {
		t.Fatalf("grant after a crash: %v", err)
	}

	// damaged records block too, without applying
	for name, rec := range map[string]string{
		"an unknown state": `{"version":1,"operation":"op-bad","revision":2,"inputs_hash":"x","gid":42,"state":"done"}`,
		"no operation id":  `{"version":1,"revision":2,"inputs_hash":"x","gid":42,"state":"started"}`,
		"another id":       `{"version":1,"operation":"op-other","revision":2,"inputs_hash":"x","gid":42,"state":"started"}`,
		"not JSON":         `{"version":1,`,
		"another version":  `{"version":2,"operation":"op-bad","revision":2,"inputs_hash":"x","gid":42,"state":"completed"}`,
		"no inputs hash":   `{"version":1,"operation":"op-bad","revision":2,"gid":42,"state":"completed"}`,
	} {
		g = newTestGranter(t)
		must(t, g.Records.Write("op-op-bad", []byte(rec)))

		if _, err := g.Grant(ctx, probeGrant(3, "op-8", "aaaaaa")); err == nil || g.patches.n != 0 {
			t.Errorf("grant next to a record with %s: %v, %d patches", name, err, g.patches.n)
		}
	}

	// refusals without a confirmation leave no records; finished ones are pruned
	g = newTestGranter(t)
	g.refuse = errors.New("not the active mgr")

	for i := range 20 {
		if op, err := g.Grant(ctx, probeGrant(2, "op-x"+strings.Repeat("y", i), "aaaaaa")); err != nil || op.State != wire.OpRefused {
			t.Fatalf("%+v %v", op, err)
		}
	}

	if names, _ := g.Records.List("op-"); len(names) != 0 {
		t.Fatalf("%d records left by unconfirmed grants", len(names))
	}

	old := maxOperations
	maxOperations = 3

	t.Cleanup(func() { maxOperations = old })

	g.refuse = nil

	for i := range 5 {
		if op, err := g.Grant(ctx, probeGrant(int64(2+i), "op-p"+string(rune('a'+i)), strings.Repeat(string(rune('a'+i)), 6))); err != nil || op.State != wire.OpCompleted {
			t.Fatalf("%+v %v", op, err)
		}
	}

	if names, _ := g.Records.List("op-"); len(names) != 3 || names[0] != "op-op-pc" {
		t.Fatalf("records after pruning: %v", names)
	}
}

func TestGrantServerBounds(t *testing.T) {
	g := newTestGranter(t)
	ca := newTestCA(t)
	leader := certOf(t, ca, pki.RoleAgent, "h0")

	// a busy agent answers at once
	g.mu <- struct{}{}

	w := httptest.NewRecorder()
	g.HandleGrant(w, request(t, http.MethodPost, "/v1/grant", probeGrant(2, "op-9", "aaaaaa"), leader))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("busy agent: %d", w.Code)
	}

	<-g.mu

	// a grant slower than the server's write timeout still gets its answer
	srvCert, srvKey := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	cfg, err := TLSConfig([]byte(ca.cert), []byte(srvCert), []byte(srvKey))
	must(t, err)

	confirm := g.confirm
	g.confirm = func(ctx context.Context, target ConfirmTarget, revision int64, operation, hash string) (wire.Confirmation, time.Time, error) {
		time.Sleep(300 * time.Millisecond)

		return confirm(ctx, target, revision, operation, hash)
	}

	srv := httptest.NewUnstartedServer((&Agent{Granter: g.Granter}).Handler())
	srv.TLS = cfg
	srv.Config.WriteTimeout = 100 * time.Millisecond
	srv.StartTLS()
	t.Cleanup(srv.Close)

	c, k := ca.pair(pki.RoleAgent, "h0", x509.ExtKeyUsageClientAuth, testFSID)
	cl := ca.client(c, k)

	body, _ := json.Marshal(probeGrant(2, "op-10", "aaaaaa"))

	resp, err := cl.Post(srv.URL+"/v1/grant", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("slow grant: %v", err)
	}

	defer resp.Body.Close() //nolint:errcheck

	var op wire.Operation
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&op) != nil || op.State != wire.OpCompleted {
		t.Fatalf("slow grant: %d %+v", resp.StatusCode, op)
	}
}

// request builds a request as the TLS server would hand it over.
func request(t *testing.T, method, path string, body any, cert *x509.Certificate) *http.Request {
	t.Helper()

	var b []byte
	if body != nil {
		var err error

		b, err = json.Marshal(body)
		must(t, err)
	}

	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}

	return r
}

func certOf(t *testing.T, ca testCA, role pki.Role, name string) *x509.Certificate {
	t.Helper()

	usage := x509.ExtKeyUsageClientAuth
	c, _ := ca.pair(role, name, usage, testFSID)

	block, _ := pem.Decode([]byte(c))

	cert, err := x509.ParseCertificate(block.Bytes)
	must(t, err)

	return cert
}

func TestGrantEndpoints(t *testing.T) {
	g := newTestGranter(t)
	ca := newTestCA(t)

	leader, other, mgr, operator := certOf(t, ca, pki.RoleAgent, "h0"), certOf(t, ca, pki.RoleAgent, "h2"), certOf(t, ca, pki.RoleMgr, "h0"), certOf(t, ca, pki.RoleOperator, "cli")

	serve := func(r *http.Request, h http.HandlerFunc) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h(w, r)

		return w
	}

	// only the agent beside the grant's mgr, with a well-formed grant for this host
	for name, c := range map[string]struct {
		cert *x509.Certificate
		gr   wire.Grant
	}{
		"a mgr":           {mgr, probeGrant(2, "op-6", "aaaaaa")},
		"another agent":   {other, probeGrant(2, "op-6", "aaaaaa")},
		"another host":    {leader, func() wire.Grant { g := probeGrant(2, "op-6", "aaaaaa"); g.Host = "h3"; return g }()},
		"a bad op id":     {leader, func() wire.Grant { g := probeGrant(2, "op-6", "aaaaaa"); g.Operation = "../x"; return g }()},
		"no documents":    {leader, func() wire.Grant { g := probeGrant(2, "op-6", "aaaaaa"); g.Docs = nil; return g }()},
		"a bad mgr addr":  {leader, func() wire.Grant { g := probeGrant(2, "op-6", "aaaaaa"); g.MgrAddr = "h0"; return g }()},
		"revision 0":      {leader, func() wire.Grant { g := probeGrant(0, "op-6", "aaaaaa"); return g }()},
		"an operator":     {operator, probeGrant(2, "op-6", "aaaaaa")},
		"another version": {leader, func() wire.Grant { g := probeGrant(2, "op-6", "aaaaaa"); g.Version = 2; return g }()},
	} {
		if w := serve(request(t, http.MethodPost, "/v1/grant", c.gr, c.cert), g.HandleGrant); w.Code == http.StatusOK {
			t.Errorf("%s: granted", name)
		}
	}

	if g.patches.n != 0 {
		t.Fatalf("%d patches from refused grants", g.patches.n)
	}

	w := serve(request(t, http.MethodPost, "/v1/grant", probeGrant(2, "op-6", "aaaaaa"), leader), g.HandleGrant)

	var op wire.Operation
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &op) != nil || op.State != wire.OpCompleted {
		t.Fatalf("grant: %d %s", w.Code, w.Body)
	}

	// the record by operation id, for the leader only
	r := request(t, http.MethodGet, "/v1/operations/op-6", nil, leader)
	r.SetPathValue("id", "op-6")

	if w := serve(r, g.HandleOperation); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"completed"`) {
		t.Fatalf("operation: %d %s", w.Code, w.Body)
	}

	r = request(t, http.MethodGet, "/v1/operations/op-6", nil, mgr)
	r.SetPathValue("id", "op-6")

	if w := serve(r, g.HandleOperation); w.Code != http.StatusForbidden {
		t.Fatalf("operation for a mgr: %d", w.Code)
	}

	// the handoff: operator only, refused once owned
	h := wire.Handoff{Version: wire.Version, FSID: testFSID, Host: "h1", Revision: 1}
	if w := serve(request(t, http.MethodPost, "/v1/handoff", h, leader), g.HandleHandoff); w.Code != http.StatusForbidden {
		t.Fatalf("handoff by an agent: %d", w.Code)
	}

	if w := serve(request(t, http.MethodPost, "/v1/handoff", h, operator), g.HandleHandoff); w.Code != http.StatusConflict {
		t.Fatalf("handoff of an owned node: %d %s", w.Code, w.Body)
	}
}
