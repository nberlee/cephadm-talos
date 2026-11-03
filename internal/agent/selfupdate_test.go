package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/siderolabs/talos/pkg/machinery/resources/network"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// Agent images of the tests: the one the agents run, a newer one, both
// approved, and one of another repository the operator approved too.
var (
	agentImage   = "registry.example/cephadm-talos@sha256:" + strings.Repeat("11", 32)
	agentImage2  = "registry.example/cephadm-talos@sha256:" + strings.Repeat("22", 32)
	foreignImage = "registry.example/other@sha256:" + strings.Repeat("33", 32)
)

// agentApproval is an approval of the test image and the agent images.
func agentApproval(t *testing.T, serial int64) approval.Signed {
	t.Helper()

	s, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: testFSID, Serial: serial, Images: []string{testImage, agentImage, agentImage2, foreignImage}})
	must(t, err)

	return s
}

// withAgentDocs puts the agent's own documents on a node as the CLI renders
// them (agent CA ca, image agentImage), and the address its certificates
// name; it returns the agent's server certificate.
func withAgentDocs(t *testing.T, n *Node, f *talostest.Node, ca testCA) string {
	t.Helper()

	ctx := context.Background()

	addr := network.NewAddressStatus(network.NamespaceName, "lo/127.0.0.1/8")
	addr.TypedSpec().Address = netip.MustParsePrefix("127.0.0.1/8")
	must(t, f.St.Create(ctx, addr))

	sc, sk := ca.pair(pki.RoleAgent, n.Host, x509.ExtKeyUsageServerAuth, testFSID)
	cc, ck := ca.pair(pki.RoleAgent, n.Host, x509.ExtKeyUsageClientAuth, testFSID)

	init := n.docName("records-init")
	agent := daemons.Agent(n.docName("agent"), init, agentImage, []string{"quay.io/ceph/ceph"}, testApprovalPub, ca.cert, sc, sk, cc, ck)

	tc, ok := n.Talos.(*countingPatch)
	if !ok {
		t.Fatal("not a counting node")
	}

	must(t, tc.Client.Patch(ctx, "", mustRender(daemons.RecordsInit(init, agentImage)), mustRender(agent)))

	return sc
}

// selfSetup is a granter of h1 whose node holds its agent's documents, with
// the agent images approved.
func selfSetup(t *testing.T) (*testGranter, testCA, *talostest.ImageService) {
	t.Helper()

	img := &talostest.ImageService{Cache: map[string]string{}, Remote: map[string]string{}}
	g := newTestGranter(t, img)
	ca := newTestCA(t)

	withAgentDocs(t, g.Node, g.fake, ca)
	must(t, g.Node.RecordApproval(context.Background(), agentApproval(t, 2)))

	return g, ca, img
}

func selfGrant(rev int64, op string, su wire.SelfUpdate) wire.Grant {
	return wire.Grant{
		Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5,
		Revision: rev, Operation: op, SelfUpdate: &su,
	}
}

// ownOnNode is the agent's own document as the node holds it.
func ownOnNode(t *testing.T, n *Node) ownDoc {
	t.Helper()

	cfg, err := n.Talos.MachineConfig(context.Background(), "")
	must(t, err)

	typed, err := typedDocs([]byte(cfg))
	must(t, err)

	d, err := n.ownDoc(typed)
	must(t, err)

	return d
}

func TestASelfUpdateRenewsTheAgentsCertificates(t *testing.T) {
	g, ca, _ := selfSetup(t)
	ctx := context.Background()

	sc, sk := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	cc, ck := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageClientAuth, testFSID)
	gr := selfGrant(2, "op-s1", wire.SelfUpdate{Cert: sc, Key: sk, ClientCert: cc, ClientKey: ck})

	op, err := g.Grant(ctx, gr)
	if err != nil || op.State != wire.OpCompleted || !op.Self || g.patches.n != 1 {
		t.Fatalf("self-update: %+v %v, %d patches", op, err, g.patches.n)
	}

	// the new certificates and keys, the image as it was; records-init not sent
	d := ownOnNode(t, g.Node)
	if cert, _ := d.pemOf(daemons.EnvCert); cert != sc || d.image != agentImage {
		t.Fatalf("the agent's document: %s", d.image)
	}

	if key, _ := d.pemOf(daemons.EnvClientKey); key != ck {
		t.Fatal("the client key is not the granted one")
	}

	rec, found, err := g.Node.selfDecided()
	agentKey, _ := g.Node.selfKeys()

	if err != nil || !found || rec.Operation != "op-s1" || rec.Outcome != wire.OpCompleted || len(rec.Sent) != 1 || rec.Sent[agentKey] == "" {
		t.Fatalf("self-update record %+v %v %v", rec, found, err)
	}

	// the ownership is untouched and has no drift; the revision is fenced
	if st := g.Node.Status(ctx); st.State != "owned" || st.Revision != 1 {
		t.Fatalf("status %+v", st)
	}

	if f, _ := g.Node.fence(); f != 2 {
		t.Fatalf("fence %d", f)
	}

	// a retry returns the record
	if op, err := g.Grant(ctx, gr); err != nil || op.State != wire.OpCompleted || g.patches.n != 1 {
		t.Fatalf("retry: %+v %v", op, err)
	}

	// a cluster grant still applies
	if op, err := g.Grant(ctx, probeGrant(3, "op-s2", "aaaaaa")); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("a grant after the self-update: %+v %v", op, err)
	}
}

func TestASelfUpdateChangesTheImageOfBothDocuments(t *testing.T) {
	g, _, _ := selfSetup(t)
	ctx := context.Background()

	// the image it runs needs nothing: nothing changes
	op, err := g.Grant(ctx, selfGrant(2, "op-i1", wire.SelfUpdate{Image: agentImage}))
	if err != nil || op.State != wire.OpCompleted || g.patches.n != 0 {
		t.Fatalf("the same image: %+v %v, %d patches", op, err, g.patches.n)
	}

	op, err = g.Grant(ctx, selfGrant(3, "op-i2", wire.SelfUpdate{Image: agentImage2}))
	if err != nil || op.State != wire.OpCompleted || g.patches.n != 1 {
		t.Fatalf("a new image: %+v %v, %d patches", op, err, g.patches.n)
	}

	cfg, err := g.Node.Talos.MachineConfig(ctx, "")
	must(t, err)

	if d := ownOnNode(t, g.Node); d.image != agentImage2 || strings.Contains(cfg, agentImage) {
		t.Fatalf("after the update: %s\n%s", d.image, cfg)
	}
}

func TestASelfUpdateChecksItsFields(t *testing.T) {
	g, ca, _ := selfSetup(t)
	ctx := context.Background()

	sc, sk := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	cc, ck := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageClientAuth, testFSID)
	other, ok := ca.pair(pki.RoleAgent, "h2", x509.ExtKeyUsageServerAuth, testFSID)
	alien := newTestCA(t)
	ac, ak := alien.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	elsewhere, ek, err := pki.Issue(ca.cert, ca.key, pki.Leaf{
		CommonName: "agent", IPs: []string{"10.9.9.9"}, Names: []string{"h1"}, Usage: x509.ExtKeyUsageServerAuth, Years: 1,
		Identity: &pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h1"},
	})
	must(t, err)

	for i, su := range []wire.SelfUpdate{
		{Image: "registry.example/cephadm-talos@sha256:" + strings.Repeat("44", 32)}, // not approved
		{Image: foreignImage},                                     // another repository
		{Image: "registry.example/cephadm-talos:v2"},              // a tag
		{Cert: sc, Key: sk},                                       // half of them
		{Cert: other, Key: ok, ClientCert: cc, ClientKey: ck},     // another host's
		{Cert: cc, Key: ck, ClientCert: sc, ClientKey: sk},        // the uses swapped
		{Cert: sc, Key: ck, ClientCert: cc, ClientKey: sk},        // the keys swapped
		{Cert: ac, Key: ak, ClientCert: cc, ClientKey: ck},        // another CA
		{Cert: elsewhere, Key: ek, ClientCert: cc, ClientKey: ck}, // not the node's address
	} {
		op, err := g.Grant(ctx, selfGrant(int64(2+i), "op-c"+string(rune('a'+i)), su))
		if err != nil || op.State != wire.OpRefused || g.patches.n != 0 {
			t.Errorf("%d: %+v %v, %d patches", i, op, err, g.patches.n)
		}
	}

	// a self-update and documents together are malformed
	gr := selfGrant(20, "op-cx", wire.SelfUpdate{Image: agentImage2})
	gr.Docs = probeGrant(20, "op-cx", "aaaaaa").Docs

	if err := g.checkGrant(gr, "h0"); err == nil {
		t.Fatal("a self-update with documents")
	}

	// suspended, it refuses before anything is recorded
	must(t, g.Suspend(ctx, testSession))

	if _, err := g.Grant(ctx, selfGrant(30, "op-cy", wire.SelfUpdate{Image: agentImage2})); err == nil {
		t.Fatal("a self-update while suspended")
	}

	if _, err := g.Grant(ctx, wire.Grant{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5, Revision: 31, Operation: "op-cz", Pull: agentImage2}); err == nil {
		t.Fatal("a pull while suspended")
	}
}

func TestAnInterruptedSelfUpdateIsDecidedFromTheNode(t *testing.T) {
	g, _, _ := selfSetup(t)
	ctx := context.Background()

	// the instance is replaced while it patches: Talos took the config
	g.fake.FailAfterApply = errors.New("connection reset")

	op, err := g.Grant(ctx, selfGrant(2, "op-u1", wire.SelfUpdate{Image: agentImage2}))
	if err != nil || op.State != wire.OpUncertain {
		t.Fatalf("interrupted: %+v %v", op, err)
	}

	// undecided, it blocks every later apply, a cluster grant's too: Talos
	// patches the whole config
	if snap, _ := g.Node.Snapshot(ctx); !snap.Intent {
		t.Fatal("no apply intent")
	}

	if _, err := g.Node.Apply(ctx, 3, nil); err == nil {
		t.Fatal("an apply beside an undecided self-update")
	}

	// the next instance decides it from the node's config
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-u1"); op.State != wire.OpCompleted {
		t.Fatalf("reconciled: %+v", op)
	}

	if snap, _ := g.Node.Snapshot(ctx); snap.Intent {
		t.Fatal("the intent stayed")
	}

	// lost before Talos had it: refused once the apply settled
	g.fake.FailBeforeApply = errors.New("connection reset")

	op, err = g.Grant(ctx, selfGrant(4, "op-u2", wire.SelfUpdate{Image: agentImage}))
	if err != nil || op.State != wire.OpUncertain {
		t.Fatalf("lost: %+v %v", op, err)
	}

	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-u2"); op.State != wire.OpUncertain {
		t.Fatalf("decided before the apply settled: %+v", op)
	}

	var intent applyIntent

	_, err = g.Node.readJSON(applyRecord, &intent)
	must(t, err)

	intent.At = intent.At.Add(-ApplySettle)
	must(t, g.Node.writeJSON(applyRecord, intent))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-u2"); op.State != wire.OpRefused {
		t.Fatalf("after it settled: %+v", op)
	}

	// a stop after the decision's record and before the operation's: the
	// operation follows the record; one stopped before its intent is refused
	for id, want := range map[string]string{"op-u3": wire.OpCompleted, "op-u4": wire.OpRefused} {
		must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: id, Revision: 9, InputsHash: "h", GID: 42, State: wire.OpStarted, Self: true}))

		if id == "op-u3" {
			must(t, g.Node.writeJSON(selfRecord, selfUpdateRecord{Schema: ownershipSchema, Operation: id, Revision: 9, Outcome: wire.OpCompleted}))
		}

		must(t, g.Reconcile(ctx))

		if op, _, _ := g.readOp(id); op.State != want {
			t.Errorf("%s: %+v, want %s", id, op, want)
		}
	}
}

func TestARestoreSettlesOnlyASelfUpdatesIntent(t *testing.T) {
	g, _, _ := selfSetup(t)
	ctx := context.Background()

	// a cluster apply's intent is never settled so
	g.Node.Talos = failingPatch{g.patches.Client}

	if op, _ := g.Grant(ctx, probeGrant(2, "op-r1", "aaaaaa")); op.State != wire.OpUncertain {
		t.Fatalf("failed patch: %+v", op)
	}

	if op, err := SettleSelfUpdate(g.Records); err != nil || op != "" {
		t.Fatalf("settled a cluster apply: %q %v", op, err)
	}

	if snap, _ := g.Node.Snapshot(ctx); !snap.Intent {
		t.Fatal("a cluster apply's intent removed")
	}

	// a self-update's: failed, superseded by the restore, its revision fenced
	must(t, g.Node.Records.Remove(applyRecord))
	must(t, g.Records.Remove(opRecord("op-r1")))

	g.Node.Talos = g.patches
	g.fake.FailAfterApply = errors.New("connection reset")

	if op, _ := g.Grant(ctx, selfGrant(5, "op-r2", wire.SelfUpdate{Image: agentImage2})); op.State != wire.OpUncertain {
		t.Fatalf("interrupted: %+v", op)
	}

	rep, err := InspectRecords(g.Records, "")
	if err != nil || rep.ApplySelf != "op-r2" {
		t.Fatalf("inspection %+v %v", rep, err)
	}

	if op, err := SettleSelfUpdate(g.Records); err != nil || op != "op-r2" {
		t.Fatalf("settled %q %v", op, err)
	}

	if op, _, _ := g.readOp("op-r2"); op.State != wire.OpFailed {
		t.Fatalf("its operation: %+v", op)
	}

	if snap, _ := g.Node.Snapshot(ctx); snap.Intent || snap.Fence < 5 {
		t.Fatalf("after the settlement: %+v", snap)
	}

	if op, err := SettleSelfUpdate(g.Records); err != nil || op != "" {
		t.Fatalf("settled twice: %q %v", op, err)
	}
}

func TestAPullGrant(t *testing.T) {
	g, _, img := selfSetup(t)
	ctx := context.Background()

	pull := func(rev int64, op, ref string) wire.Operation {
		t.Helper()

		res, err := g.Grant(ctx, wire.Grant{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5, Revision: rev, Operation: op, Pull: ref})
		must(t, err)

		return res
	}

	if op := pull(2, "op-p1", agentImage2); op.State != wire.OpCompleted || !op.Pull || g.patches.n != 0 {
		t.Fatalf("pull: %+v", op)
	}

	if _, ok := img.Cache[agentImage2]; !ok {
		t.Fatalf("not pulled: %v", img.Cache)
	}

	for i, ref := range []string{foreignImage, "registry.example/cephadm-talos@sha256:" + strings.Repeat("55", 32)} {
		if op := pull(int64(3+i), "op-p"+string(rune('2'+i)), ref); op.State != wire.OpRefused {
			t.Errorf("%s: %+v", ref, op)
		}
	}

	// one a stop interrupted did not finish
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-p9", Revision: 9, InputsHash: "h", GID: 42, State: wire.OpStarted, Pull: true}))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-p9"); op.State != wire.OpRefused {
		t.Fatalf("an interrupted pull: %+v", op)
	}
}
