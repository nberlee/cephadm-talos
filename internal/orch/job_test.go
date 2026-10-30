package orch

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

// An apply that fails after the node accepted the config (a lost connection)
// must still remove the job document, and report the apply error, not a
// cleanup error.
func TestRunJobCleansUpAfterAFailedApply(t *testing.T) {
	f := talostest.New(t)
	f.FailAfterApply = status.Error(codes.Unavailable, "connection lost")

	o := fakeOrch(t, f)
	tc := o.Talos
	doc := daemons.Probe("ceph-eb8dac3e-probe-abc", "quay.io/ceph/ceph:v20.2.4")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	_, err := o.runJob(ctx, "node", doc, "abc", 30*time.Second)
	if err == nil || !strings.Contains(err.Error(), "connection lost") {
		t.Fatalf("want the apply error, got %v", err)
	}

	var cleanup *JobCleanupError
	if errors.As(err, &cleanup) {
		t.Fatalf("cleanup failed: %v", err)
	}

	cfg, err := tc.MachineConfig(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(cfg, doc.MetaName) {
		t.Errorf("job document left in the config:\n%s", cfg)
	}
}

// fakeOrch returns an Orch whose Talos client talks to the fake node.
func fakeOrch(t *testing.T, f *talostest.Node) *Orch {
	t.Helper()
	t.Setenv("CEPHADM_TALOS_HOME", t.TempDir())

	tc := &talos.Client{Dial: func(ctx context.Context, _ talos.Conn) (*client.Client, error) { return f.Dial(ctx) }}
	t.Cleanup(func() { tc.Close() }) //nolint:errcheck

	st := state.New("eb8dac3e-0ba7-4795-8feb-a80e8593331f")
	st.Image, st.CephVersion, st.Arch = "quay.io/ceph/ceph@sha256:abc", SupportedCeph, SupportedArch

	o := &Orch{Talos: tc, St: st, Out: io.Discard, StoreBackend: &store.Memory{}, AuthGet: noAuth}
	if err := o.openStore(context.Background(), ""); err != nil {
		t.Fatal(err)
	}

	return o
}

// noAuth is mon auth without entities: every key is new.
func noAuth(string) (string, bool, error) { return "", false, nil }

// reload reads the state back as the next command would: the workstation's
// part from disk, the cluster's part from the (memory) store.
func reload(t *testing.T, o *Orch) *state.State {
	t.Helper()

	st, err := state.Load(o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	next := &Orch{Talos: o.Talos, St: st, Out: io.Discard, StoreBackend: o.StoreBackend, AuthGet: noAuth}
	if len(st.Hosts) == 0 {
		st.Hosts = []state.Host{{Name: "contact"}} // Open needs a node to go through
	}

	if err := next.Open(context.Background()); err != nil {
		t.Fatal(err)
	}

	return st
}

func TestGatesAtOperationBoundaries(t *testing.T) {
	f := talostest.New(t)
	f.VersionTag = "v1.14.5"

	o := fakeOrch(t, f)
	o.St.AddHost(state.Host{Name: "h1", Addr: "node"})
	o.St.AddHost(state.Host{Name: "h2", Addr: "node", Maintenance: true})
	o.St.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1"})

	ctx := context.Background()

	// deploying onto a registered host checks its Talos version
	if err := o.Deploy(ctx, state.TypeMgr, "h1", ""); err == nil || !strings.Contains(err.Error(), "needs v1.15.0") {
		t.Errorf("deploy on Talos 1.14: got %v", err)
	}

	// recovery and removal are not gated
	if err := o.MaintenanceExit(ctx, "h2"); err != nil {
		t.Errorf("maintenance exit on Talos 1.14: %v", err)
	}

	if err := o.RemoveHost(ctx, "h2"); err != nil {
		t.Errorf("host rm on Talos 1.14: %v", err)
	}

	// an unsupported cluster image refuses deploys before touching a node
	o.St.CephVersion = "20.2.3"

	if err := o.Deploy(ctx, state.TypeMgr, "h1", ""); err == nil || !strings.Contains(err.Error(), "supports only Ceph") {
		t.Errorf("deploy on an old cluster image: got %v", err)
	}
}

func TestWaitGoneWaitsForTheInstance(t *testing.T) {
	f := talostest.New(t)
	o := fakeOrch(t, f)
	ctx := context.Background()

	// the status is gone already, the instance (its process) only later
	inst := containers.NewContainerInstanceSpec(containers.NamespaceName, "job-1")
	inst.TypedSpec().ContainerID = "job"

	if err := f.St.Create(ctx, inst); err != nil {
		t.Fatal(err)
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		_ = f.St.Destroy(ctx, inst.Metadata())
	}()

	start := time.Now()

	if err := o.waitGone(ctx, "node", "job", 10*time.Second); err != nil {
		t.Fatal(err)
	}

	if time.Since(start) < 400*time.Millisecond {
		t.Errorf("waitGone returned while the instance was still there")
	}
}

func TestParseJobResult(t *testing.T) {
	res, in, err := parseJobResult([]byte("rc 3\ninputs abc\nline 1\nline 2"))
	if err != nil || res.RC != 3 || in != "abc" || res.Output != "line 1\nline 2" {
		t.Fatalf("%+v %q %v", res, in, err)
	}

	for _, bad := range []string{"", "rc x\ninputs a\n", "rc 0\n", "rc 0\nnot inputs\n", "rc 0\ninputs \n"} {
		if _, _, err := parseJobResult([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
