package agent

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/siderolabs/talos/pkg/machinery/client"

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

	f := talostest.New(t)
	tc := &talos.Client{Dial: func(ctx context.Context, _ talos.Conn) (*client.Client, error) { return f.Dial(ctx) }}
	t.Cleanup(func() { tc.Close() }) //nolint:errcheck

	return &Node{Talos: tc, Records: &records.Store{Dir: t.TempDir()}, FSID: testFSID, Host: "h1"}, tc
}

func render(t *testing.T, d any) []byte {
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
	must(t, tc.Patch(ctx, "", render(t, container(agentDoc, "registry/agent:1"))))

	own, err := n.Adopt(ctx, 1)
	must(t, err)

	if want := []string{"EtcFileConfig/ceph/ceph.conf"}; !slices.Equal(keys(own.Docs), want) {
		t.Fatalf("adopted %v, want %v", keys(own.Docs), want)
	}

	if _, err := n.Adopt(ctx, 1); err == nil {
		t.Fatal("adopted twice")
	}

	probe := n.prefix() + "probe-a"
	docs := []Doc{
		{Kind: "ContainerConfig", Name: probe, YAML: render(t, container(probe, "quay.io/ceph/ceph:v20.2.4"))},
		{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: render(t, spec.CephConf("[global]\nfsid = x\n"))},
	}

	if own, err = n.Apply(ctx, 2, docs); err != nil {
		t.Fatal(err)
	}

	if len(own.Docs) != 2 || own.Revision != 2 {
		t.Fatalf("after revision 2: %+v", own)
	}

	cfg, err := tc.MachineConfig(ctx, "")
	must(t, err)

	if !strings.Contains(cfg, "fsid = x") || !strings.Contains(cfg, "name: app") || !strings.Contains(cfg, agentDoc) {
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
		{3, []Doc{{Kind: "ContainerConfig", Name: agentDoc, YAML: render(t, container(agentDoc, "registry/agent:2"))}}},
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

	conf := []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: render(t, spec.CephConf("[global]\n"))}}

	// someone else changes an owned document
	must(t, tc.Patch(ctx, "", render(t, spec.CephConf("[global]\nedited = 1\n"))))

	if st := n.Status(ctx); st.State != "drift" || !slices.Equal(st.Drift, []string{"changed EtcFileConfig/ceph/ceph.conf"}) {
		t.Fatalf("status %+v", st)
	}

	if _, err := n.Apply(ctx, 2, conf); !errors.Is(err, ErrDrift) {
		t.Fatalf("apply on drift: %v", err)
	}

	// a cluster document the agent did not write
	foreign := n.prefix() + "osd-x"
	must(t, tc.Patch(ctx, "", render(t, container(foreign, "quay.io/ceph/ceph:v20.2.4"))))

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

	conf := []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: render(t, spec.CephConf("[global]\n"))}}
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

	probe := n.prefix() + "probe-a"
	ok := render(t, container(probe, "quay.io/ceph/ceph:v20.2.4"))
	app := render(t, container("app", "docker.io/library/alpine:3"))

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

	return r.Client.Patch(ctx, node, render(r.t, spec.CephConf("[global]\nother = writer\n")))
}

func TestAnotherWriterBetweenPatchAndReadBack(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	_, err := n.Adopt(ctx, 1)
	must(t, err)

	n.Talos = racingPatch{Client: tc, t: t}

	conf := []Doc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf", YAML: render(t, spec.CephConf("[global]\nmine = 1\n"))}}
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

	probe := n.prefix() + "probe-a"
	if _, err := n.Apply(ctx, 2, []Doc{{Kind: "ContainerConfig", Name: probe, YAML: render(t, container(probe, "quay.io/ceph/ceph:v20.2.4"))}}); err != nil {
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
			name := n.prefix() + "probe-" + string(rune('a'+i))
			_, errs[i] = n.Apply(ctx, int64(2+i), []Doc{{Kind: "ContainerConfig", Name: name, YAML: render(t, container(name, "quay.io/ceph/ceph:v20.2.4"))}})
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
