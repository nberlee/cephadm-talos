package agent

import (
	"context"
	"crypto/x509"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
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

	if op, err := g.Grant(ctx, first); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("approved prepare: %+v %v", op, err)
	}

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

	if op, err := g.Grant(ctx, grantOf(t, 9, "op-z2", zap("aaaaa2", false))); err != nil || op.State != wire.OpCompleted {
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

	if op, err := g.Grant(ctx, one); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("the entry was reserved by the refused grant: %+v %v", op, err)
	}

	// approving the disk again is a new entry: another job may use it
	two := probeGrant(4, "op-b3", "aaaaaa")
	two.Docs = []wire.GrantDoc{{Kind: "ContainerConfig", Name: n2, YAML: &y2}}
	two.Approval = sign(3, 2, 3)

	if op, err := g.Grant(ctx, two); err != nil || op.State != wire.OpCompleted {
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
