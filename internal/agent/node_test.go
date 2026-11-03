package agent

import (
	"context"
	"errors"
	"github.com/nberlee/cephadm-talos/internal/approval"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/config/types/runtime"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

const testFSID = "eb8dac3e-0ba7-4795-8feb-a80e8593331f"

// failingPatch fails every Patch, after which Talos may or may not have the config.
type failingPatch struct{ *talos.Client }

func (failingPatch) Patch(context.Context, string, ...[]byte) error {
	return errors.New("connection reset")
}

func testNode(t *testing.T) (*Node, *talos.Client) {
	t.Helper()

	n, tc, _ := testNodeFake(t)

	return n, tc
}

// testNodeFake is testNode with the fake Talos node behind it, and its image
// service if one is given.
func testNodeFake(t *testing.T, images ...machine.ImageServiceServer) (*Node, *talos.Client, *talostest.Node) {
	t.Helper()

	f := talostest.New(t, images...)
	tc := &talos.Client{Dial: func(ctx context.Context, _ talos.Conn) (*client.Client, error) { return f.Dial(ctx) }}
	t.Cleanup(func() { tc.Close() }) //nolint:errcheck

	pol := &Policy{FSID: testFSID, Host: "h1", Repos: []string{"quay.io/ceph/ceph"}, ApprovalKey: testApprovalPub}

	n := &Node{Talos: tc, Records: &records.Store{Dir: t.TempDir()}, JobsDir: t.TempDir(), FSID: testFSID, Host: "h1", Policy: pol}

	// the operator approved the test image
	must(t, n.RecordApproval(context.Background(), testApproval(t, 1)))

	return n, tc, f
}

// the test approval key, and approvals signed with it
var testApprovalPriv, testApprovalPub = func() (string, string) {
	priv, pub, err := approval.NewKey()
	if err != nil {
		panic(err)
	}

	return priv, pub
}()

func testApproval(t *testing.T, serial int64, disks ...approval.Disk) approval.Signed {
	t.Helper()

	s, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: testFSID, Serial: serial, Images: []string{testImage}, Disks: disks})
	must(t, err)

	return s
}

func yamlOf(t *testing.T, d any) []byte {
	t.Helper()

	b, err := spec.Render(d)
	must(t, err)

	return b
}

func TestNodeOwnership(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	if st := n.Status(ctx); st.State != "unowned" {
		t.Fatalf("before the handoff: %+v", st)
	}

	if _, err := n.Apply(ctx, 2, nil); err == nil {
		t.Fatal("apply before the handoff")
	}

	// the handoff: ceph.conf is the cluster's, the app container is not, the agent's own document stays the CLI's
	agentDoc := n.docName("agent")
	must(t, tc.Patch(ctx, "", yamlOf(t, container(agentDoc, "registry/agent:1"))))

	own, err := n.Adopt(ctx, 1)
	must(t, err)

	if want := []string{"EtcFileConfig/ceph/ceph.conf"}; !slices.Equal(keys(own.Docs), want) {
		t.Fatalf("adopted %v, want %v", keys(own.Docs), want)
	}

	if _, err := n.Adopt(ctx, 1); err == nil {
		t.Fatal("adopted twice")
	}

	probe := n.prefix() + "probe-aaaaaa"
	docs := []Doc{
		{Kind: "ContainerConfig", Name: probe, YAML: yamlOf(t, daemons.Probe(probe, testImage))},
		{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: yamlOf(t, conf("10.5.0.3"))},
	}

	if own, err = n.Apply(ctx, 2, docs); err != nil {
		t.Fatal(err)
	}

	if len(own.Docs) != 2 || own.Revision != 2 {
		t.Fatalf("after revision 2: %+v", own)
	}

	cfg, err := tc.MachineConfig(ctx, "")
	must(t, err)

	if !strings.Contains(cfg, "fsid = "+testFSID) || !strings.Contains(cfg, "name: app") || !strings.Contains(cfg, agentDoc) {
		t.Fatalf("config after the apply:\n%s", cfg)
	}

	if st := n.Status(ctx); st.State != "owned" || st.Owned != 2 || st.Revision != 2 {
		t.Fatalf("status %+v", st)
	}

	// an old or repeated revision, the CLI's documents and other documents are refused
	for _, bad := range []struct {
		rev  int64
		docs []Doc
	}{
		{2, docs},
		{3, []Doc{{Kind: "ContainerConfig", Name: agentDoc, YAML: yamlOf(t, container(agentDoc, "registry/agent:2"))}}},
		{3, []Doc{{Kind: "ContainerConfig", Name: "app"}}},
		{3, []Doc{{Kind: "UserVolumeConfig", Name: "cephadm-talos"}}},
		{3, []Doc{docs[1], docs[1]}},
	} {
		if _, err := n.Apply(ctx, bad.rev, bad.docs); err == nil {
			t.Errorf("revision %d with %v applied", bad.rev, bad.docs)
		}
	}

	// a removal
	if own, err = n.Apply(ctx, 3, []Doc{{Kind: "ContainerConfig", Name: probe}}); err != nil {
		t.Fatal(err)
	}

	if cfg, _ = tc.MachineConfig(ctx, ""); strings.Contains(cfg, probe) || len(own.Docs) != 1 {
		t.Fatalf("after the removal: %v\n%s", own.Docs, cfg)
	}
}

func TestNodeDrift(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	_, err := n.Adopt(ctx, 1)
	must(t, err)

	conf := []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: yamlOf(t, conf("10.5.0.4"))}}

	// someone else changes an owned document
	must(t, tc.Patch(ctx, "", yamlOf(t, spec.CephConf("[global]\nedited = 1\n"))))

	if st := n.Status(ctx); st.State != "drift" || !slices.Equal(st.Drift, []string{"changed EtcFileConfig/ceph/ceph.conf"}) {
		t.Fatalf("status %+v", st)
	}

	if _, err := n.Apply(ctx, 2, conf); !errors.Is(err, ErrDrift) {
		t.Fatalf("apply on drift: %v", err)
	}

	// a cluster document the agent did not write
	foreign := n.prefix() + "osd-x"
	must(t, tc.Patch(ctx, "", yamlOf(t, container(foreign, "quay.io/ceph/ceph:v20.2.4"))))

	st := n.Status(ctx)
	if !slices.Contains(st.Drift, "foreign ContainerConfig/"+foreign) {
		t.Fatalf("foreign document not reported: %+v", st)
	}
}

func TestNodeUncertainApply(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	_, err := n.Adopt(ctx, 1)
	must(t, err)

	n.Talos = failingPatch{tc}

	conf := []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: yamlOf(t, conf("10.5.0.4"))}}
	if _, err := n.Apply(ctx, 2, conf); err == nil {
		t.Fatal("failed patch reported as applied")
	}

	n.Talos = tc

	if st := n.Status(ctx); st.State != "uncertain" || st.Revision != 2 {
		t.Fatalf("status %+v", st)
	}

	if _, err := n.Apply(ctx, 3, conf); err == nil || !strings.Contains(err.Error(), "uncertain") {
		t.Fatalf("apply after an uncertain one: %v", err)
	}
}

// countingPatch counts the patches that reach Talos.
type countingPatch struct {
	*talos.Client
	n int
}

func (c *countingPatch) Patch(ctx context.Context, node string, patches ...[]byte) error {
	c.n++

	return c.Client.Patch(ctx, node, patches...)
}

func TestNodeChecksTheDocumentsYAML(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	_, err := n.Adopt(ctx, 1)
	must(t, err)

	cp := &countingPatch{Client: tc}
	n.Talos = cp

	probe := n.prefix() + "probe-aaaaaa"
	ok := yamlOf(t, daemons.Probe(probe, testImage))
	app := yamlOf(t, container("app", "docker.io/library/alpine:3"))

	for name, yamlDoc := range map[string][]byte{
		"a second document":       append(append([]byte{}, ok...), app...),
		"another document's name": app,
		"a patch directive":       []byte("apiVersion: v1alpha1\nkind: ContainerConfig\nname: " + probe + "\n$patch: delete\n"),
		"an unknown field":        append(append([]byte{}, ok...), []byte("bogus: 1\n")...),
		"no document":             []byte("---\n"),
	} {
		if _, err := n.Apply(ctx, 2, []Doc{{Kind: "ContainerConfig", Name: probe, YAML: yamlDoc}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if cp.n != 0 {
		t.Fatalf("%d patches for refused documents", cp.n)
	}

	if _, err := n.Apply(ctx, 2, []Doc{{Kind: "ContainerConfig", Name: probe, YAML: ok}}); err != nil {
		t.Fatal(err)
	}

	cfg, _ := tc.MachineConfig(ctx, "")
	if !strings.Contains(cfg, "image: docker.io/library/alpine:3") {
		t.Errorf("the app container changed:\n%s", cfg)
	}
}

// racingPatch applies the patch, then another writer changes ceph.conf before
// the agent reads the config back.
type racingPatch struct {
	*talos.Client
	t *testing.T
}

func (r racingPatch) Patch(ctx context.Context, node string, patches ...[]byte) error {
	if err := r.Client.Patch(ctx, node, patches...); err != nil {
		return err
	}

	return r.Client.Patch(ctx, node, yamlOf(r.t, spec.CephConf("[global]\nother = writer\n")))
}

func TestAnotherWriterBetweenPatchAndReadBack(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	_, err := n.Adopt(ctx, 1)
	must(t, err)

	n.Talos = racingPatch{Client: tc, t: t}

	conf := []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: yamlOf(t, conf("10.5.0.3"))}}
	if _, err := n.Apply(ctx, 2, conf); !errors.Is(err, ErrDrift) {
		t.Fatalf("apply overtaken by another writer: %v", err)
	}

	n.Talos = tc

	if st := n.Status(ctx); st.State != "uncertain" || st.Revision != 2 {
		t.Fatalf("status %+v", st)
	}
}

func TestUntouchedDocumentsKeepTheirHash(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	// the fixture's ceph.conf has no mode: Talos re-encodes it on every patch
	_, err := n.Adopt(ctx, 1)
	must(t, err)

	probe := n.prefix() + "probe-aaaaaa"
	if _, err := n.Apply(ctx, 2, []Doc{{Kind: "ContainerConfig", Name: probe, YAML: yamlOf(t, daemons.Probe(probe, testImage))}}); err != nil {
		t.Fatal(err)
	}

	if st := n.Status(ctx); st.State != "owned" {
		t.Fatalf("after applying another document: %+v", st)
	}
}

func TestConcurrentApplies(t *testing.T) {
	n, _ := testNode(t)
	ctx := context.Background()

	_, err := n.Adopt(ctx, 1)
	must(t, err)

	var wg sync.WaitGroup

	errs := make([]error, 3)

	for i := range 3 {
		wg.Go(func() {
			name := n.prefix() + "probe-" + strings.Repeat(string(rune('a'+i)), 6)
			_, errs[i] = n.Apply(ctx, int64(2+i), []Doc{{Kind: "ContainerConfig", Name: name, YAML: yamlOf(t, daemons.Probe(name, testImage))}})
		})
	}

	wg.Wait()

	own, found, err := n.ownership()
	if err != nil || !found {
		t.Fatal(err)
	}

	applied := 0
	for _, err := range errs {
		if err == nil {
			applied++
		}
	}

	// an older revision after a newer one is refused, never applied over it
	if own.Revision != 4 || len(own.Docs) != 1+applied {
		t.Fatalf("revision %d with %d documents after %d applies (%v)", own.Revision, len(own.Docs), applied, errs)
	}

	if st := n.Status(ctx); st.State != "owned" {
		t.Fatalf("status %+v", st)
	}
}

// testImage is a cluster image the test policy admits.
var testImage = "quay.io/ceph/ceph@sha256:" + strings.Repeat("ab", 32)

// conf is the cluster's ceph.conf with the given mons.
func conf(mons ...string) *runtime.EtcFileConfigV1Alpha1 {
	return spec.CephConf(daemons.CephConf(testFSID, mons))
}

func container(name, image string) *spec.ContainerConfig {
	c := spec.Container(name, image)
	c.ContainerEntrypoint = []string{"/bin/true"}

	return c
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	slices.Sort(out)

	return out
}

func TestApplyRunsThePolicy(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	_, err := n.Adopt(ctx, 1)
	must(t, err)

	cp := &countingPatch{Client: tc}
	n.Talos = cp

	// an IPv6 zone smuggling options into ceph.conf through carriage returns
	evil := conf("::1%x\rmon_host = 10.5.0.3\rdebug_ms = 20\r#")
	if _, err := n.Apply(ctx, 2, []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: yamlOf(t, evil)}}); err == nil {
		t.Fatal("ceph.conf with a zone admitted")
	}

	n.Policy = nil
	if _, err := n.Apply(ctx, 2, []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: yamlOf(t, conf("10.5.0.3"))}}); err == nil {
		t.Fatal("applied without a policy")
	}

	if cp.n != 0 {
		t.Fatalf("%d patches reached Talos", cp.n)
	}
}

// delayedPatch stalls inside Patch, as a slow config read there would.
type delayedPatch struct {
	*talos.Client
	d time.Duration
}

func (p delayedPatch) Patch(ctx context.Context, node string, patches ...[]byte) error {
	time.Sleep(p.d)

	return p.Client.Patch(ctx, node, patches...)
}

func TestApplyDeadlineInsidePatch(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	_, err := n.Adopt(ctx, 1)
	must(t, err)

	n.Talos = delayedPatch{tc, 150 * time.Millisecond}

	before, _ := tc.MachineConfig(ctx, "")

	_, err = n.ApplyBefore(ctx, time.Now().Add(100*time.Millisecond), 2, []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: yamlOf(t, conf("10.5.0.3"))}})
	if !errors.Is(err, ErrNotApplied) || !errors.Is(err, talos.ErrApplyDeadline) {
		t.Fatalf("apply past its deadline: %v", err)
	}

	if after, _ := tc.MachineConfig(ctx, ""); after != before {
		t.Fatal("the config changed")
	}

	// nothing was sent: no uncertain outcome
	if st := n.Status(ctx); st.State != "owned" || st.Revision != 1 {
		t.Fatalf("status %+v", st)
	}
}
