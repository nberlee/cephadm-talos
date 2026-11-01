package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// testGranter is a handed-over node with a fake module that confirms gid 42
// for mgr h0, unless told otherwise.
type testGranter struct {
	*Granter
	patches *countingPatch
	fake    *talostest.Node
	gid     int64
	epoch   int64
	refuse  error
	expired bool
	calls   int
}

func newTestGranter(t *testing.T) *testGranter {
	t.Helper()

	n, tc, f := testNodeFake(t)

	_, err := n.Adopt(context.Background(), 1)
	must(t, err)

	cp := &countingPatch{Client: tc}
	n.Talos = cp

	ch, err := NewChannel(pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h1"})
	must(t, err)

	tg := &testGranter{Granter: NewGranter(n, ch, nil, n.Records), patches: cp, fake: f, gid: 42, epoch: 5}
	tg.confirm = func(_ context.Context, target ConfirmTarget, revision int64, operation, hash string) (wire.Confirmation, time.Time, error) {
		tg.calls++

		// the reservation is durable before a grant's confirmation is asked (an
		// abandon or a close has none)
		abandon := hash == wire.AbandonInputs(wire.Abandon{FSID: testFSID, Host: "h1", Revision: revision, Operation: operation}) ||
			strings.HasPrefix(operation, "close-")

		op, found, err := tg.readOp(operation)
		if !abandon && (err != nil || !found || op.State != wire.OpReserved || op.InputsHash != hash) {
			t.Errorf("no reservation before the confirmation: %+v %v %v", op, found, err)
		}

		if tg.refuse != nil {
			return wire.Confirmation{}, time.Time{}, tg.refuse
		}

		until := time.Now().Add(ConfirmValidity)
		if tg.expired {
			until = time.Now().Add(-time.Second)
		}

		return wire.Confirmation{Mgr: target.Mgr, GID: tg.gid, Epoch: tg.epoch, Revision: revision, Operation: operation, InputsHash: hash}, until, nil
	}

	return tg
}

func probeGrant(rev int64, op, id string) wire.Grant {
	name := "ceph-" + testFSID[:8] + "-probe-" + id
	y := string(mustRender(daemons.Probe(name, testImage)))

	return wire.Grant{
		Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5,
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

	// not visible on the node proves nothing while Talos may still handle the
	// apply: a retry does not run it again, nothing else runs
	g.Node.Talos = g.patches

	if op, _ = g.Grant(ctx, probeGrant(3, "op-4", "bbbbbb")); op.State != wire.OpUncertain || g.patches.n != 0 {
		t.Fatalf("retry right after the failed patch: %+v, %d patches", op, g.patches.n)
	}

	// once the apply cannot be in progress anymore, its absence decides: refused,
	// and the same grant may run
	var intent applyIntent

	if _, err := g.Node.readJSON(applyRecord, &intent); err != nil {
		t.Fatal(err)
	}

	intent.At = intent.At.Add(-ApplySettle)
	must(t, g.Node.writeJSON(applyRecord, intent))

	if op, _ = g.Grant(ctx, probeGrant(3, "op-4", "bbbbbb")); op.State != wire.OpCompleted || g.patches.n != 1 {
		t.Fatalf("retry after the apply settled: %+v, %d patches", op, g.patches.n)
	}

	// a patch the node cannot tell about (neither before nor after): it stays
	// uncertain and blocks
	g.Node.Talos = otherWriterPatch{g.patches.Client, t}

	if op, _ = g.Grant(ctx, probeGrant(4, "op-5", "cccccc")); op.State != wire.OpUncertain {
		t.Fatalf("overtaken patch: %+v", op)
	}

	g.Node.Talos = g.patches

	if _, err := g.Grant(ctx, probeGrant(5, "op-6", "dddddd")); err == nil || !strings.Contains(err.Error(), "unresolved") {
		t.Fatalf("grant after an undecidable one: %v", err)
	}
}

// otherWriterPatch fails after another writer changed ceph.conf: the node
// shows neither the state before nor the one after the apply.
type otherWriterPatch struct {
	*talos.Client
	t *testing.T
}

func (o otherWriterPatch) Patch(ctx context.Context, node string, _ ...[]byte) error {
	if err := o.Client.Patch(ctx, node, yamlOf(o.t, conf("10.5.0.7"))); err != nil {
		return err
	}

	return errors.New("connection reset")
}

func TestReconcileFromTheNode(t *testing.T) {
	ctx := context.Background()

	// an operation started before a crash, its ownership written: completed
	g := newTestGranter(t)
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-a", Revision: 1, InputsHash: "x", GID: 42, State: wire.OpStarted}))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-a"); op.State != wire.OpCompleted {
		t.Fatalf("started at the owned revision: %+v", op)
	}

	// started, but the ownership is older: it did not get to its intent
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-b", Revision: 7, InputsHash: "x", GID: 42, State: wire.OpStarted}))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-b"); op.State != wire.OpRefused {
		t.Fatalf("started above the owned revision: %+v", op)
	}

	// an apply that reached Talos but not its ownership record: completed
	own, _, err := g.Node.ownership()
	must(t, err)

	must(t, g.Node.writeJSON(applyRecord, applyIntent{Schema: ownershipSchema, Revision: 9, Before: own.Docs, Sent: map[string]string{}}))
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-c", Revision: 9, InputsHash: "x", GID: 42, State: wire.OpUncertain}))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-c"); op.State != wire.OpCompleted {
		t.Fatalf("apply with its effect on the node: %+v", op)
	}

	if own, _, _ := g.Node.ownership(); own.Revision != 9 {
		t.Fatalf("ownership after reconciling: %d", own.Revision)
	}

	if st := g.Node.Status(ctx); st.State != "owned" {
		t.Fatalf("status %+v", st)
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

	// an operation that started, the node newer than it: the node cannot tell,
	// nothing else runs
	g = newTestGranter(t)
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-crashed", Revision: 1, InputsHash: "x", GID: 42, State: wire.OpStarted}))
	must(t, g.Node.writeJSON(ownershipRecord, Ownership{Schema: ownershipSchema, Revision: 5, Docs: map[string]string{}}))

	if _, err := g.Grant(ctx, probeGrant(6, "op-8", "aaaaaa")); err == nil || !strings.Contains(err.Error(), "op-crashed") {
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

func TestCloseRaisesTheSessionFloor(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	c := wire.Close{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 50, Epoch: 9}

	// unconfirmed: nothing changes
	g.refuse = errors.New("not the active mgr")
	if _, err := g.Close(ctx, c); err == nil {
		t.Fatal("an unconfirmed close")
	}

	g.refuse, g.gid, g.epoch = nil, 50, 9

	if f, err := g.Close(ctx, c); err != nil || f != 9 {
		t.Fatalf("close: %d %v", f, err)
	}

	// the older incarnation can no longer grant, abandon or lower the floor
	g.gid, g.epoch = 42, 5

	if _, err := g.Grant(ctx, probeGrant(2, "old", "aaaaaa")); err == nil || !strings.Contains(err.Error(), "closed") || g.patches.n != 0 {
		t.Fatalf("grant of a closed incarnation: %v", err)
	}

	if _, found, _ := g.readOp("old"); found {
		t.Fatal("a closed incarnation left a record")
	}

	if _, err := g.Close(ctx, wire.Close{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5}); err == nil {
		t.Fatal("the floor was lowered")
	}

	// the floor survives a restart: it is a record
	g2 := NewGranter(g.Node, g.Channel, nil, g.Records)
	if f, err := g2.floor(); err != nil || f != 9 {
		t.Fatalf("floor after a restart: %d %v", f, err)
	}

	// the new incarnation grants
	g.gid, g.epoch = 50, 9

	gr := probeGrant(3, "new", "bbbbbb")
	gr.GID, gr.Epoch = 50, 9

	if op, err := g.Grant(ctx, gr); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("grant of the new incarnation: %+v %v", op, err)
	}
}

func TestReconcileWaitsForAnApplyInProgress(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	own, _, err := g.Node.ownership()
	must(t, err)

	boot, err := g.Node.Talos.BootID(ctx, "")
	must(t, err)

	// an apply sent just now, not visible yet: Talos may still commit it
	must(t, g.Node.writeJSON(applyRecord, applyIntent{Schema: ownershipSchema, Revision: 9, Before: own.Docs, Sent: map[string]string{"EtcFileConfig/ceph/x": "h"}, BootID: boot, At: time.Now()}))

	if outcome, _, _, err := g.Node.Reconcile(ctx); err != nil || outcome != "uncertain" {
		t.Fatalf("fresh apply: %s %v", outcome, err)
	}

	// sent on an earlier boot: it either committed before the reboot or never will
	must(t, g.Node.writeJSON(applyRecord, applyIntent{Schema: ownershipSchema, Revision: 9, Before: own.Docs, Sent: map[string]string{"EtcFileConfig/ceph/x": "h"}, BootID: "boot-0", At: time.Now()}))

	if outcome, _, _, err := g.Node.Reconcile(ctx); err != nil || outcome != "refused" {
		t.Fatalf("apply of an earlier boot: %s %v", outcome, err)
	}

	// a reservation left by a stop before the grant started is refused
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-r", Revision: 3, InputsHash: "x", GID: 42, State: wire.OpReserved}))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-r"); op.State != wire.OpRefused {
		t.Fatalf("left reservation: %+v", op)
	}
}

// monGrant grants h1 a joining mon, a daemon the agent may restart.
func monGrant(t *testing.T, rev int64, op string) (wire.Grant, string, string) {
	t.Helper()

	st := state.New(testFSID)
	st.Image = testImage
	st.AddHost(state.Host{Name: "h1", Addr: "10.5.0.3"})
	st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1", DeployID: "0123456789abcdef"})
	h, _ := st.Host("h1")
	d, _ := st.Find("mon.h1")

	c, err := render.Daemon(st, h, d, testImage, func(string) (string, error) { return fakeKey, nil }, func(string) (string, error) { return "", errors.New("no secret") })
	must(t, err)

	y := string(mustRender(c))
	g := probeGrant(rev, op, "aaaaaa")
	g.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: c.MetaName, YAML: &y}}

	td, err := checkDoc(Doc{Kind: "ContainerConfig", Name: c.MetaName, YAML: []byte(y)})
	must(t, err)

	return g, c.MetaName, td.hash
}

func addInstance(t *testing.T, f *talostest.Node, name string, gen uint64) {
	t.Helper()

	inst := containers.NewContainerInstanceSpec(containers.NamespaceName, fmt.Sprintf("%s-%d", name, gen))
	inst.TypedSpec().ContainerID, inst.TypedSpec().Generation = name, gen
	must(t, f.St.Create(context.Background(), inst))
}

func TestGrantRestartsADaemon(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	gr, name, hash := monGrant(t, 2, "op-m1")
	if op, err := g.Grant(ctx, gr); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("mon: %+v %v", op, err)
	}

	addInstance(t, g.fake, name, 1)
	addInstance(t, g.fake, name, 2)

	restart := func(rev int64, id string, r wire.GrantRestart) wire.Grant {
		gr := probeGrant(rev, id, "aaaaaa")
		gr.Docs, gr.Restart = nil, &r

		return gr
	}

	// the current instance is restarted, after the record names it; it is
	// started until the next instance exists
	g.fake.HoldRestarts = true

	op, err := g.Grant(ctx, restart(3, "op-r1", wire.GrantRestart{Kind: "ContainerConfig", Name: name, Hash: hash}))
	if err != nil || op.State != wire.OpStarted || op.Instance != name+"-2" || op.BootID == "" || len(g.fake.Restarted) != 1 || g.fake.Restarted[0] != name+"-2" {
		t.Fatalf("restart: %+v %v %v", op, err, g.fake.Restarted)
	}

	// still stopping: a retry returns the record and restarts nothing, and no
	// other grant runs beside it
	if op, err = g.Grant(ctx, restart(3, "op-r1", wire.GrantRestart{Kind: "ContainerConfig", Name: name, Hash: hash})); err != nil || op.State != wire.OpStarted || len(g.fake.Restarted) != 1 {
		t.Fatalf("retry: %+v %v", op, err)
	}

	if _, err := g.Grant(ctx, probeGrant(4, "op-p0", "eeeeee")); err == nil || !strings.Contains(err.Error(), "op-r1") {
		t.Fatalf("a grant beside a restart in progress: %v", err)
	}

	// the next instance runs: completed
	addInstance(t, g.fake, name, 3)
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-r1"); op.State != wire.OpCompleted {
		t.Fatalf("after the next instance: %+v", op)
	}

	// the revision is fenced: the same grant under a new id cannot run again
	if op, err := g.Grant(ctx, restart(3, "op-r2", wire.GrantRestart{Kind: "ContainerConfig", Name: name, Hash: hash})); err != nil || op.State != wire.OpRefused || len(g.fake.Restarted) != 1 {
		t.Fatalf("a restart at a fenced revision: %+v %v", op, err)
	}

	g.fake.HoldRestarts = false

	// not with another hash, not a document it does not own, not a job or probe
	pg := probeGrant(4, "op-p1", "bbbbbb")
	if op, err := g.Grant(ctx, pg); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("probe: %+v %v", op, err)
	}

	probeDoc := pg.Docs[0]
	probeTD, err := checkDoc(Doc{Kind: probeDoc.Kind, Name: probeDoc.Name, YAML: []byte(*probeDoc.YAML)})
	must(t, err)

	for i, r := range []wire.GrantRestart{
		{Kind: "ContainerConfig", Name: name, Hash: "00"},
		{Kind: "ContainerConfig", Name: "ceph-" + testFSID[:8] + "-mon-h2", Hash: hash},
		{Kind: "ContainerConfig", Name: probeDoc.Name, Hash: probeTD.hash},
		{Kind: "ContainerConfig", Name: n2(g).docName("agent"), Hash: hash},
	} {
		op, err := g.Grant(ctx, restart(int64(10+i), fmt.Sprintf("op-x%d", i), r))
		if err != nil || op.State != wire.OpRefused || len(g.fake.Restarted) != 1 {
			t.Errorf("%d: %+v %v %v", i, op, err, g.fake.Restarted)
		}
	}
}

func n2(g *testGranter) *Node { return g.Node }

func TestARestartWithoutOutcomeIsReconciledFromItsInstance(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	gr, name, _ := monGrant(t, 2, "op-m1")
	if op, err := g.Grant(ctx, gr); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("mon: %+v %v", op, err)
	}

	addInstance(t, g.fake, name, 1)

	boot, err := g.Node.Talos.BootID(ctx, "")
	must(t, err)

	// a restart that stopped after its record: the same instance still runs
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-lost", Revision: 3, InputsHash: "00", GID: 42, State: wire.OpStarted, Instance: name + "-1", BootID: boot, At: time.Now().UnixNano()}))

	// one sent longer ago than ApplySettle, its instance still current: it did not happen
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-old", Revision: 3, InputsHash: "00", GID: 42, State: wire.OpUncertain, Instance: name + "-1", BootID: boot, At: time.Now().Add(-ApplySettle - time.Minute).UnixNano()}))

	if _, err := g.Grant(ctx, probeGrant(4, "op-p2", "cccccc")); err == nil || !strings.Contains(err.Error(), "op-lost") {
		t.Fatalf("a grant beside an undecided restart: %v", err)
	}

	if op, _, _ := g.readOp("op-old"); op.State != wire.OpRefused {
		t.Fatalf("old restart: %+v", op)
	}

	// a newer instance runs: it happened
	addInstance(t, g.fake, name, 2)

	if op, err := g.Grant(ctx, probeGrant(4, "op-p2", "cccccc")); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("after the new instance: %+v %v", op, err)
	}

	if op, _, _ := g.readOp("op-lost"); op.State != wire.OpCompleted {
		t.Fatalf("lost restart: %+v", op)
	}
}
