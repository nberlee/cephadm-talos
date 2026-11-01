package agent

import (
	"context"
	"crypto/x509"
	"fmt"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"os"
	"strings"
	"testing"

	"github.com/siderolabs/talos/pkg/machinery/resources/block"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

func TestApprovalsOnlyGoUp(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	must(t, n.RecordApproval(ctx, testApproval(t, 3)))

	if err := n.RecordApproval(ctx, testApproval(t, 2)); err == nil {
		t.Fatal("an older approval was recorded")
	}

	must(t, n.RecordApproval(ctx, testApproval(t, 3))) // the same one again

	other, _, _ := approval.NewKey()

	s, err := approval.Sign(other, approval.Approval{Version: approval.Version, FSID: testFSID, Serial: 9})
	must(t, err)

	if err := n.RecordApproval(ctx, s); err == nil {
		t.Fatal("an approval of another key was recorded")
	}

	if a, err := n.Approval(ctx); err != nil || a.Serial != 3 {
		t.Fatalf("approval %+v %v", a, err)
	}
}

// grantOf grants one document.
func grantOf(t *testing.T, rev int64, op string, c any) wire.Grant {
	t.Helper()

	g := probeGrant(rev, op, "aaaaaa")
	y := string(mustRender(c))
	name := c.(interface{ Name() string }).Name()
	g.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: name, YAML: &y}}

	return g
}

func TestUnapprovedImagesAndDisksAreRefused(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	// an image the operator did not approve, until an approval names it
	other := "quay.io/ceph/ceph@sha256:" + strings.Repeat("cd", 32)
	probe := daemons.Probe("ceph-"+testFSID[:8]+"-probe-bbbbbb", other)

	if op, err := g.Grant(ctx, grantOf(t, 2, "op-i1", probe)); err != nil || op.State != wire.OpRefused || !strings.Contains(op.Error, "approved") {
		t.Fatalf("unapproved image: %+v %v", op, err)
	}

	newer, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: testFSID, Serial: 2, Images: []string{testImage, other}})
	must(t, err)

	gr := grantOf(t, 3, "op-i2", probe)
	gr.Approval = &newer

	if op, err := g.Grant(ctx, gr); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("approved image: %+v %v", op, err)
	}

	// a disk: prepared only with an entry, once
	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, g.fake.St.Create(ctx, disk))

	st := state.New(testFSID)
	st.Image = testImage
	st.AddHost(state.Host{Name: "h1", Addr: "10.5.0.3"})
	h, _ := st.Host("h1")

	prep := func(deploy string) any {
		d := state.Daemon{Type: state.TypeOSD, ID: "h1-sdb", Host: "h1", DeployID: deploy, DiskSerial: "QM00003", DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}

		c, err := render.OSDPrepare(st, h, d, func(string) (string, error) { return fakeKey, nil })
		must(t, err)

		return c
	}

	first := grantOf(t, 4, "op-p1", prep("0123456789abcdef"))
	if op, err := g.Grant(ctx, first); err != nil || op.State != wire.OpRefused || !strings.Contains(op.Error, "prepare") {
		t.Fatalf("prepare without an entry: %+v %v", op, err)
	}

	entry := approval.Disk{Host: "h1", Serial: "QM00003", Action: approval.Prepare, Since: 3}
	withEntry, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: testFSID, Serial: 3, Images: []string{testImage}, Disks: []approval.Disk{entry}})
	must(t, err)

	first = grantOf(t, 5, "op-p2", prep("0123456789abcdef"))
	first.Approval = &withEntry

	if op, err := g.Grant(ctx, first); err != nil || op.State != wire.OpStarted || op.Job == nil {
		t.Fatalf("approved prepare: %+v %v", op, err)
	}

	finishJob(t, g, "op-p2", 0, "osd_id 3")

	// the entry belongs to that job now: another deployment on the disk is refused
	second := grantOf(t, 6, "op-p3", prep("fedcba9876543210"))
	if op, err := g.Grant(ctx, second); err != nil || op.State != wire.OpRefused || !strings.Contains(op.Error, "used by another job") {
		t.Fatalf("a second prepare on the entry: %+v %v", op, err)
	}

	// a zap that skips the label check needs a zap entry; one that checks does not
	dev := "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"
	zapWith := func(id string, unlabelled bool, inputs string) any {
		return daemons.Zap(daemons.Params{
			Name: st.DocName(state.Daemon{Type: "job", ID: id}), Image: testImage, FSID: testFSID, ID: "job",
			Device: dev, DiskSerial: "QM00003", ZapUnlabelled: unlabelled,
		}, id, inputs)
	}
	zap := func(id string, unlabelled bool) any {
		return zapWith(id, unlabelled, daemons.ZapInputs("h1", dev, "QM00003", unlabelled, ""))
	}

	// the agent computes a job's inputs: other ones in the grant are refused
	if op, err := g.Grant(ctx, grantOf(t, 7, "op-z0", zapWith("aaaaa0", false, render.JobInputs("zap", "h1", dev, "QM00003")))); err != nil || op.State != wire.OpRefused {
		t.Fatalf("a zap with inputs of its own: %+v %v", op, err)
	}

	if op, err := g.Grant(ctx, grantOf(t, 8, "op-z1", zap("aaaaa1", true))); err != nil || op.State != wire.OpRefused || !strings.Contains(op.Error, "zap") {
		t.Fatalf("an unlabelled zap without an entry: %+v %v", op, err)
	}

	if op, err := g.Grant(ctx, grantOf(t, 9, "op-z2", zap("aaaaa2", false))); err != nil || op.State != wire.OpStarted {
		t.Fatalf("a zap with its label check: %+v %v", op, err)
	}
}

func TestMgrPairsAsTheNodeHoldsThem(t *testing.T) {
	ca := newTestCA(t)
	c1, k1 := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, testFSID)
	c2, _ := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, testFSID)

	file := func(name, contents string) (string, typedDoc) {
		td, err := checkDoc(Doc{Kind: "EtcFileConfig", Name: name, YAML: mustRender(spec.EtcFile(name, 0o600, contents))})
		must(t, err)

		return "EtcFileConfig/" + name, td
	}

	cert, key := daemons.MgrCertFile, daemons.MgrKeyFile
	cur := map[string]typedDoc{}
	kc, tc := file(cert, c1)
	kk, tk := file(key, k1)
	cur[kc], cur[kk] = tc, tk

	_, tc2 := file(cert, c2)

	for name, c := range map[string]struct {
		typed map[string]typedDoc
		sent  map[string]string
		ok    bool
	}{
		"nothing of the pair":           {nil, map[string]string{}, true},
		"a certificate without its key": {map[string]typedDoc{kc: tc2}, map[string]string{kc: tc2.hash}, false},
		"the key removed alone":         {nil, map[string]string{kk: ""}, false},
		"both removed":                  {nil, map[string]string{kc: "", kk: ""}, true},
		"the same pair again":           {map[string]typedDoc{kc: tc, kk: tk}, map[string]string{kc: tc.hash, kk: tk.hash}, true},
	} {
		if err := mgrPairs(cur, c.typed, c.sent); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDiskEntriesAreUsedOnceAndKept(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, g.fake.St.Create(ctx, disk))

	st := state.New(testFSID)
	st.Image = testImage
	st.AddHost(state.Host{Name: "h1", Addr: "10.5.0.3"})
	h, _ := st.Host("h1")

	prep := func(deploy string) (string, string) {
		d := state.Daemon{Type: state.TypeOSD, ID: "h1-sdb", Host: "h1", DeployID: deploy, DiskSerial: "QM00003", DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}

		c, err := render.OSDPrepare(st, h, d, func(string) (string, error) { return fakeKey, nil })
		must(t, err)

		return c.MetaName, string(mustRender(c))
	}

	sign := func(serial int64, since ...int64) *approval.Signed {
		a := approval.Approval{Version: approval.Version, FSID: testFSID, Serial: serial, Images: []string{testImage}}
		for _, s := range since {
			a.Disks = append(a.Disks, approval.Disk{Host: "h1", Serial: "QM00003", Action: approval.Prepare, Since: s})
		}

		s, err := approval.Sign(testApprovalPriv, a)
		must(t, err)

		return &s
	}

	// two jobs of one grant on one entry: refused, and nothing is reserved
	n1, y1 := prep("0123456789abcdef")
	n2, y2 := prep("fedcba9876543210")
	both := probeGrant(2, "op-b1", "aaaaaa")
	both.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: n1, YAML: &y1}, {Kind: "ContainerConfig", Name: n2, YAML: &y2}}
	both.Approval = sign(2, 2)

	if op, err := g.Grant(ctx, both); err != nil || op.State != wire.OpRefused {
		t.Fatalf("two jobs on one entry: %+v %v", op, err)
	}

	one := probeGrant(3, "op-b2", "aaaaaa")
	one.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: n1, YAML: &y1}}
	one.Approval = both.Approval

	if op, err := g.Grant(ctx, one); err != nil || op.State != wire.OpStarted {
		t.Fatalf("the entry was reserved by the refused grant: %+v %v", op, err)
	}

	finishJob(t, g, "op-b2", 0, "")

	// approving the disk again is a new entry: another job may use it
	two := probeGrant(4, "op-b3", "aaaaaa")
	two.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: n2, YAML: &y2}}
	two.Approval = sign(3, 2, 3)

	if op, err := g.Grant(ctx, two); err != nil || op.State != wire.OpStarted {
		t.Fatalf("a job on a new entry: %+v %v", op, err)
	}

	// the ownership kept the serial through the grants
	if own, _, err := g.Node.ownership(); err != nil || own.ApprovalSerial != 3 {
		t.Fatalf("ownership %+v %v", own, err)
	}

	// a lost approval record does not reset anything: admission stops
	must(t, g.Node.Records.Remove(approvalRecord))

	if _, err := g.Node.Approval(ctx); err == nil {
		t.Fatal("a missing approval record went unnoticed")
	}

	if err := g.Node.RecordApproval(ctx, testApproval(t, 1)); err == nil {
		t.Fatal("an older approval was recorded after the record was lost")
	}
}

func TestAnApprovalBeforeTheHandoffIsKept(t *testing.T) {
	n, _ := testNode(t) // records approval 1 before it is handed over
	ctx := context.Background()

	own, err := n.Adopt(ctx, 1)
	if err != nil || own.ApprovalSerial != 1 {
		t.Fatalf("adopt %+v %v", own, err)
	}

	must(t, n.Records.Remove(approvalRecord))

	if _, err := n.Approval(ctx); err == nil {
		t.Fatal("a missing approval record went unnoticed")
	}
}

// finishJob ends the job of an operation as job.sh does: its result file, then
// a reconcile reads it.
func finishJob(t *testing.T, g *testGranter, opID string, rc int, out string) wire.Operation {
	t.Helper()

	op, found, err := g.readOp(opID)
	if err != nil || !found || op.Job == nil {
		t.Fatalf("no job operation %s: %v", opID, err)
	}

	must(t, os.WriteFile(g.Node.jobFile(op.Job.ID, "result"), []byte(fmt.Sprintf("rc %d\ninputs %s\n%s", rc, op.Job.Inputs, out)), 0o644))

	// and its container ended
	cs := containers.NewContainerStatus(containers.NamespaceName, op.Job.Doc)
	cs.TypedSpec().State = containers.ContainerStateCompleted
	if rc != 0 {
		cs.TypedSpec().State = containers.ContainerStateFailed
	}

	must(t, g.fake.St.Create(context.Background(), cs))
	must(t, g.Reconcile(context.Background()))

	op, _, err = g.readOp(opID)
	must(t, err)

	return op
}

func TestAJobFromGrantToTombstone(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, g.fake.St.Create(ctx, disk))

	st := state.New(testFSID)
	st.Image = testImage
	dev := "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"

	zap := func(id string) (string, string) {
		c := daemons.Zap(daemons.Params{Name: st.DocName(state.Daemon{Type: "job", ID: id}), Image: testImage, FSID: testFSID, ID: "job", Device: dev, DiskSerial: "QM00003"},
			id, daemons.ZapInputs("h1", dev, "QM00003", false, ""))

		return c.MetaName, string(mustRender(c))
	}

	name, y := zap("aaaaa1")
	gr := probeGrant(2, "op-j1", "aaaaaa")
	gr.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: name, YAML: &y}}

	if op, err := g.Grant(ctx, gr); err != nil || op.State != wire.OpStarted || op.Job.ID != "aaaaa1" {
		t.Fatalf("job: %+v %v", op, err)
	}

	// still running: nothing decided
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-j1"); op.State != wire.OpStarted {
		t.Fatalf("decided while running: %+v", op)
	}

	op := finishJob(t, g, "op-j1", 0, "zapped")
	if op.State != wire.OpCompleted || op.Result == nil || op.Result.RC != 0 || op.Result.Output != "zapped" {
		t.Fatalf("result: %+v", op)
	}

	// its document goes only with an acknowledgement of exactly that outcome
	remove := func(rev int64, id string, ack *wire.JobAck) (wire.Operation, error) {
		gr := probeGrant(rev, id, "aaaaaa")
		gr.Docs, gr.Ack = []wire.GrantDoc{{Kind: "ContainerConfig", Name: name}}, ack

		return g.Grant(ctx, gr)
	}

	for i, ack := range []*wire.JobAck{nil, {Job: "aaaaa1", Inputs: op.Job.Inputs, RC: 1}, {Job: "aaaaa1", Inputs: "00", RC: 0}} {
		if res, err := remove(int64(3+i), fmt.Sprintf("op-r%d", i), ack); err != nil || res.State != wire.OpRefused {
			t.Errorf("removal %d: %+v %v", i, res, err)
		}
	}

	if res, err := remove(6, "op-r9", &wire.JobAck{Job: "aaaaa1", Inputs: op.Job.Inputs, RC: 0}); err != nil || res.State != wire.OpCompleted {
		t.Fatalf("acknowledged removal: %+v %v", res, err)
	}

	if op, _, _ := g.readOp("op-j1"); !op.Acked {
		t.Fatalf("not acknowledged: %+v", op)
	}

	if _, err := os.Stat(g.Node.jobFile("aaaaa1", "tombstone")); err != nil {
		t.Fatalf("no tombstone for the job script: %v", err)
	}

	// the result goes once the document and instance are gone; the tombstone stays
	must(t, g.Reconcile(ctx))

	if _, err := os.Stat(g.Node.jobFile("aaaaa1", "result")); !os.IsNotExist(err) {
		t.Fatalf("result kept: %v", err)
	}

	// the job never runs again, under any operation id
	gr = probeGrant(7, "op-j2", "aaaaaa")
	gr.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: name, YAML: &y}}

	if res, err := g.Grant(ctx, gr); err != nil || res.State != wire.OpRefused || !strings.Contains(res.Error, "acknowledged") {
		t.Fatalf("a tombstoned job: %+v %v", res, err)
	}

	// a job that started and left no result is uncertain: it holds back other
	// jobs on the node, not documents
	name2, y2 := zap("aaaaa2")
	gr = probeGrant(8, "op-j3", "aaaaaa")
	gr.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: name2, YAML: &y2}}

	if res, err := g.Grant(ctx, gr); err != nil || res.State != wire.OpStarted {
		t.Fatalf("second job: %+v %v", res, err)
	}

	must(t, os.WriteFile(g.Node.jobFile("aaaaa2", "started"), []byte("started\n"), 0o644))

	cs := containers.NewContainerStatus(containers.NamespaceName, name2)
	cs.TypedSpec().State = containers.ContainerStateFailed
	must(t, g.fake.St.Create(ctx, cs))
	must(t, g.Reconcile(ctx))

	if res, _, _ := g.readOp("op-j3"); res.State != wire.OpUncertain {
		t.Fatalf("job without a result: %+v", res)
	}

	name3, y3 := zap("aaaaa3")
	gr = probeGrant(9, "op-j4", "aaaaaa")
	gr.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: name3, YAML: &y3}}

	if _, err := g.Grant(ctx, gr); err == nil || !strings.Contains(err.Error(), "op-j3") {
		t.Fatalf("a job beside an uncertain one: %v", err)
	}

	if res, err := g.Grant(ctx, probeGrant(10, "op-d1", "bbbbbb")); err != nil || res.State != wire.OpCompleted {
		t.Fatalf("a document beside an uncertain job: %+v %v", res, err)
	}
}

func TestJobOutcomeEdges(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, g.fake.St.Create(ctx, disk))

	st := state.New(testFSID)
	dev := "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"
	zap := func(id string) (string, string) {
		c := daemons.Zap(daemons.Params{Name: st.DocName(state.Daemon{Type: "job", ID: id}), Image: testImage, FSID: testFSID, ID: "job", Device: dev, DiskSerial: "QM00003"},
			id, daemons.ZapInputs("h1", dev, "QM00003", false, ""))

		return c.MetaName, string(mustRender(c))
	}

	name, y := zap("bbbbb1")
	gr := probeGrant(2, "op-e1", "aaaaaa")
	gr.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: name, YAML: &y}}

	op, err := g.Grant(ctx, gr)
	must(t, err)

	// a result while the container still runs decides nothing
	must(t, os.WriteFile(g.Node.jobFile("bbbbb1", "result"), []byte("rc 0\ninputs "+op.Job.Inputs+"\nok"), 0o644))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-e1"); op.State != wire.OpStarted {
		t.Fatalf("decided while running: %+v", op)
	}

	// a damaged result is no evidence: uncertain
	must(t, os.WriteFile(g.Node.jobFile("bbbbb1", "result"), []byte("rc 0 trailing\ninputs "+op.Job.Inputs+"\nok"), 0o644))

	cs := containers.NewContainerStatus(containers.NamespaceName, name)
	cs.TypedSpec().State = containers.ContainerStateCompleted
	must(t, g.fake.St.Create(ctx, cs))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-e1"); op.State != wire.OpUncertain {
		t.Fatalf("a damaged result: %+v", op)
	}

	// replacing the job's document by another document needs the acknowledgement too
	probe := daemons.Probe(name, testImage)
	y2 := string(mustRender(probe))
	gr = probeGrant(3, "op-e2", "aaaaaa")
	gr.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: name, YAML: &y2}}

	if res, err := g.Grant(ctx, gr); err != nil || res.State != wire.OpRefused || !strings.Contains(res.Error, "acknowledgement") {
		t.Fatalf("a replacement without an acknowledgement: %+v %v", res, err)
	}

	// an acknowledgement whose grant completed while the agent was down is finished
	rec, _, _ := g.readOp("op-e1")
	rec.AckBy = "op-e3"
	must(t, g.writeOp(rec))
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-e3", Revision: 4, InputsHash: "00", GID: 42, State: wire.OpCompleted}))
	must(t, g.Reconcile(ctx))

	if rec, _, _ := g.readOp("op-e1"); !rec.Acked {
		t.Fatalf("the acknowledgement was not finished: %+v", rec)
	}

	if _, err := os.Stat(g.Node.jobFile("bbbbb1", "tombstone")); err != nil {
		t.Fatal("no tombstone")
	}
}

func TestARefusedJobIsAcknowledgedWithoutDocuments(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, g.fake.St.Create(ctx, disk))

	st := state.New(testFSID)
	st.Image = testImage
	st.AddHost(state.Host{Name: "h1", Addr: "10.5.0.3"})
	h, _ := st.Host("h1")
	d := state.Daemon{Type: state.TypeOSD, ID: "h1-sdb", Host: "h1", DeployID: "0123456789abcdef", DiskSerial: "QM00003", DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}

	c, err := render.OSDPrepare(st, h, d, func(string) (string, error) { return fakeKey, nil })
	must(t, err)

	// no approval of the disk: refused at admission, its record kept for the leader
	op, err := g.Grant(ctx, grantOf(t, 2, "op-a1", c))
	if err != nil || op.State != wire.OpRefused || op.Job == nil {
		t.Fatalf("prepare: %+v %v", op, err)
	}

	gr := probeGrant(3, "op-a2", "aaaaaa")
	gr.Docs, gr.Ack = nil, &wire.JobAck{Job: op.Job.ID, Inputs: op.Job.Inputs, RC: -1}

	if res, err := g.Grant(ctx, gr); err != nil || res.State != wire.OpCompleted {
		t.Fatalf("acknowledgement alone: %+v %v", res, err)
	}

	if rec, _, _ := g.readOp("op-a1"); !rec.Acked {
		t.Fatalf("not acknowledged: %+v", rec)
	}
}

func TestAcknowledgementsAreIdempotentAndFenced(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	st := state.New(testFSID)
	st.Image = testImage
	st.AddHost(state.Host{Name: "h1", Addr: "10.5.0.3"})
	h, _ := st.Host("h1")
	d := state.Daemon{Type: state.TypeOSD, ID: "h1-sdb", Host: "h1", DeployID: "0123456789abcdef", DiskSerial: "QM00003", DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}

	c, err := render.OSDPrepare(st, h, d, func(string) (string, error) { return fakeKey, nil })
	must(t, err)

	op, err := g.Grant(ctx, grantOf(t, 2, "op-f1", c))
	if err != nil || op.State != wire.OpRefused {
		t.Fatalf("prepare: %+v %v", op, err)
	}

	ack := func(rev int64, id string) wire.Operation {
		gr := probeGrant(rev, id, "aaaaaa")
		gr.Docs, gr.Ack = nil, &wire.JobAck{Job: op.Job.ID, Inputs: op.Job.Inputs, RC: -1}

		res, err := g.Grant(ctx, gr)
		must(t, err)

		return res
	}

	if res := ack(5, "op-f2"); res.State != wire.OpCompleted {
		t.Fatalf("first acknowledgement: %+v", res)
	}

	// the same acknowledgement again changes nothing and is no error
	if res := ack(6, "op-f3"); res.State != wire.OpCompleted {
		t.Fatalf("repeated acknowledgement: %+v", res)
	}

	// a revision at or below the fence is refused
	if res := ack(4, "op-f4"); res.State != wire.OpRefused {
		t.Fatalf("an acknowledgement below the fence: %+v", res)
	}
}
