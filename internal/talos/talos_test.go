package talos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cosi-project/runtime/pkg/state"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/resources/block"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// connect returns a Client that talks to the fake node.
func connect(t *testing.T, f *talostest.Node) *Client {
	t.Helper()

	c := &Client{Dial: func(ctx context.Context, _ Conn) (*client.Client, error) { return f.Dial(ctx) }}
	t.Cleanup(func() { c.Close() }) //nolint:errcheck

	return c
}

func TestPatchKeepsOtherDocuments(t *testing.T) {
	f := talostest.New(t)
	c := connect(t, f)

	del := []byte("apiVersion: v1alpha1\nkind: ContainerConfig\nname: app\n$patch: delete\n---\napiVersion: v1alpha1\nkind: ContainerConfig\nname: gone\n$patch: delete\n")
	add := []byte("apiVersion: v1alpha1\nkind: ContainerConfig\nname: app\nimage: docker.io/library/alpine:3\nenvironment:\n  - B=2\n---\napiVersion: v1alpha1\nkind: ContainerConfig\nname: new\nimage: docker.io/library/alpine:3\n")

	must(t, c.Patch(context.Background(), "node", del, add))

	if len(f.Applied) != 1 {
		t.Fatalf("want one apply, got %d", len(f.Applied))
	}

	got := string(f.Applied[0])
	for _, want := range []string{"kind: EtcFileConfig", "name: new", "B=2", "type: controlplane"} {
		if !strings.Contains(got, want) {
			t.Errorf("applied config misses %q:\n%s", want, got)
		}
	}

	// delete-then-add replaces the list instead of appending to it
	if strings.Contains(got, "A=1") {
		t.Errorf("old environment survived:\n%s", got)
	}

	cfg, err := c.MachineConfig(context.Background(), "node")
	must(t, err)

	if !strings.Contains(cfg, "B=2") {
		t.Errorf("MachineConfig does not show the applied config:\n%s", cfg)
	}
}

func TestPatchDryRunHasNoNodeAccess(t *testing.T) {
	var out bytes.Buffer

	c := &Client{DryRun: true, Out: &out, Dial: func(context.Context, Conn) (*client.Client, error) {
		t.Fatal("dry-run dialed a node")

		return nil, nil
	}}

	must(t, c.Patch(context.Background(), "node", []byte("kind: X\n")))

	if !strings.Contains(out.String(), "kind: X") {
		t.Errorf("dry-run did not print the patch: %q", out.String())
	}
}

func TestReads(t *testing.T) {
	f := talostest.New(t)
	c := connect(t, f)
	ctx := context.Background()

	cs := containers.NewContainerStatus(containers.NamespaceName, "app")
	cs.TypedSpec().State = containers.ContainerStateRunning
	cs.TypedSpec().Image = "sha256:abc"
	must(t, f.St.Create(ctx, cs))

	is := containers.NewContainerImageStatus(containers.NamespaceName, "app")
	is.TypedSpec().Phase = containers.ContainerImagePhaseReady
	is.TypedSpec().Digest = "sha256:abc"
	must(t, f.St.Create(ctx, is))

	for i, gen := range []uint64{3, 7} {
		inst := containers.NewContainerInstanceStatus(containers.NamespaceName, "app-"+string(rune('a'+i)))
		inst.TypedSpec().ContainerID = "app"
		inst.TypedSpec().Generation = gen
		must(t, f.St.Create(ctx, inst))
	}

	hn := network.NewHostnameStatus(network.NamespaceName, network.HostnameID)
	hn.TypedSpec().Hostname = "talos-1"
	must(t, f.St.Create(ctx, hn))

	for _, id := range []string{"sdb", "sda"} {
		must(t, f.St.Create(ctx, block.NewDisk(block.NamespaceName, id)))
	}

	st, err := c.ContainerStatuses(ctx, "node")
	must(t, err)

	if s := st["app"]; s.State != containers.ContainerStateRunning || s.Image != "sha256:abc" {
		t.Errorf("status %+v", s)
	}

	img, err := c.ImageStatus(ctx, "node", "app")
	must(t, err)

	if img.Phase != containers.ContainerImagePhaseReady || img.Digest != "sha256:abc" {
		t.Errorf("image status %+v", img)
	}

	if _, err := c.ImageStatus(ctx, "node", "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing image status: want ErrNotFound, got %v", err)
	}

	if g, err := c.InstanceGeneration(ctx, "node", "app"); err != nil || g != 7 {
		t.Errorf("generation %d, %v", g, err)
	}

	if left, err := c.HasInstances(ctx, "node", "other"); err != nil || left {
		t.Errorf("instances of other: %t, %v", left, err)
	}

	if h, err := c.Hostname(ctx, "node"); err != nil || h != "talos-1" {
		t.Errorf("hostname %q, %v", h, err)
	}

	if v, err := c.Version(ctx, "node"); err != nil || v != "v1.15.0-alpha.2" {
		t.Errorf("version %q, %v", v, err)
	}

	disks, err := c.Disks(ctx, "node")
	must(t, err)

	if len(disks) != 2 || disks[0].Metadata().ID() != "sda" {
		t.Errorf("disks not sorted: %v", disks)
	}

	logs, err := c.Logs(ctx, "node", "app")
	if err != nil || logs != "line 1\nline 2\n" {
		t.Errorf("logs %q, %v", logs, err)
	}
}

func setState(t *testing.T, st state.State, id string, s containers.ContainerState) {
	t.Helper()

	ctx := context.Background()
	cs := containers.NewContainerStatus(containers.NamespaceName, id)
	cs.TypedSpec().State = s

	cur, err := st.Get(ctx, cs.Metadata())
	if err != nil {
		must(t, st.Create(ctx, cs))

		return
	}

	cs.Metadata().SetVersion(cur.Metadata().Version())
	must(t, st.Update(ctx, cs))
}

func running(c *Client, id string) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		st, err := c.ContainerStatuses(ctx, "node")

		return err == nil && st[id].State == containers.ContainerStateRunning, nil
	}
}

func TestWaitForSeedsAndWatches(t *testing.T) {
	f := talostest.New(t)
	c := connect(t, f)
	ctx := context.Background()

	// already true: returns from the seed check
	setState(t, f.St, "a", containers.ContainerStateRunning)
	must(t, c.WaitFor(ctx, "node", StatusTypes, 5*time.Second, running(c, "a")))

	// becomes true later: woken up by the watch
	setState(t, f.St, "b", containers.ContainerStatePending)

	go func() {
		time.Sleep(300 * time.Millisecond)
		setState(t, f.St, "b", containers.ContainerStateRunning)
	}()

	must(t, c.WaitFor(ctx, "node", StatusTypes, 5*time.Second, running(c, "b")))

	// never true: times out
	if err := c.WaitFor(ctx, "node", StatusTypes, 500*time.Millisecond, running(c, "never")); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want a deadline error, got %v", err)
	}
}

func TestWaitForSurvivesAServerRestart(t *testing.T) {
	f := talostest.New(t)
	c := connect(t, f)
	ctx := context.Background()

	setState(t, f.St, "b", containers.ContainerStatePending)

	go func() {
		time.Sleep(300 * time.Millisecond)
		f.Srv.Stop() // breaks the watch
		setState(t, f.St, "b", containers.ContainerStateRunning)
		time.Sleep(300 * time.Millisecond)
		f.Serve(t)
	}()

	must(t, c.WaitFor(ctx, "node", StatusTypes, 20*time.Second, running(c, "b")))
}

func TestRebootWaitsForReady(t *testing.T) {
	old := rebootPoll
	rebootPoll = 50 * time.Millisecond

	t.Cleanup(func() { rebootPoll = old })

	f := talostest.New(t)
	c := connect(t, f)

	var readyAt time.Time

	f.OnBoot = func() {
		// a new boot id with ready=false must not end the wait
		time.Sleep(500 * time.Millisecond)

		ctx := context.Background()
		ms := runtime.NewMachineStatus()
		cur, _ := f.St.Get(ctx, ms.Metadata())
		ms.Metadata().SetVersion(cur.Metadata().Version())
		ms.TypedSpec().Stage = runtime.MachineStageRunning
		ms.TypedSpec().Status.Ready = true

		f.Mu.Lock()
		readyAt = time.Now()
		f.Mu.Unlock()

		must(t, f.St.Update(ctx, ms))
	}

	must(t, c.Reboot(context.Background(), "node"))

	returned := time.Now()

	f.Mu.Lock()
	defer f.Mu.Unlock()

	if f.Reboots != 1 || readyAt.IsZero() || returned.Before(readyAt) {
		t.Fatalf("reboots %d, ready at %v, returned at %v", f.Reboots, readyAt, returned)
	}
}

func TestPullImageRefreshNormalizes(t *testing.T) {
	imgs := &talostest.ImageService{
		Cache:  map[string]string{"docker.io/ceph/ceph:v20": "sha256:old"},
		Remote: map[string]string{"docker.io/ceph/ceph:v20": "sha256:new"},
	}
	f := talostest.New(t, imgs)

	c := connect(t, f)
	ctx := context.Background()

	got, err := c.PullImage(ctx, "node", "ceph/ceph:v20", false)
	if err != nil || got != "docker.io/ceph/ceph@sha256:old" {
		t.Fatalf("cached pull: %q, %v", got, err)
	}

	got, err = c.PullImage(ctx, "node", "ceph/ceph:v20", true)
	if err != nil || got != "docker.io/ceph/ceph@sha256:new" {
		t.Fatalf("refresh: %q, %v (removed %v)", got, err, imgs.Removed)
	}
}

func TestPatchApplyError(t *testing.T) {
	f := talostest.New(t)
	c := connect(t, f)

	// a patch that does not parse never reaches the node
	if err := c.Patch(context.Background(), "node", []byte("apiVersion: v1alpha1\nkind: ContainerConfig\nname: broken\nimage: [\n")); err == nil {
		t.Error("unparsable patch accepted")
	}

	// a config the node rejects is an error, and nothing is applied
	err := c.Patch(context.Background(), "node", []byte("apiVersion: v1alpha1\nkind: ContainerConfig\nname: rejected\nimage: docker.io/library/alpine:3\n"))
	if err == nil || !strings.Contains(err.Error(), "config validation failed") {
		t.Errorf("node rejection: got %v", err)
	}

	if len(f.Applied) != 0 {
		t.Errorf("applied %d configs", len(f.Applied))
	}
}

func TestPermanent(t *testing.T) {
	denied := fmt.Errorf("list: %w", status.Error(codes.PermissionDenied, "no"))
	if Permanent(denied) == nil {
		t.Error("permission denied is not permanent")
	}

	if Permanent(fmt.Errorf("list: %w", status.Error(codes.Unavailable, "down"))) != nil {
		t.Error("unavailable is permanent")
	}

	if Permanent(wrap("get", status.Error(codes.NotFound, "gone"))) != nil {
		t.Error("not found is permanent")
	}
}

func TestRebootCancelled(t *testing.T) {
	f := talostest.New(t)
	c := connect(t, f)

	// the node never becomes ready again
	f.OnBoot = func() {}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := c.Reboot(ctx, "node"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want the context error, got %v", err)
	}
}

func TestFollowLogsDryRunHasNoNodeAccess(t *testing.T) {
	var out bytes.Buffer

	c := &Client{DryRun: true, Out: &out, Dial: func(context.Context, Conn) (*client.Client, error) {
		t.Fatal("dry-run dialed a node")

		return nil, nil
	}}

	if err := c.FollowLogs(context.Background(), "node", "app", &out); err != nil {
		t.Fatal(err)
	}
}
