package orch

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

// An apply that fails after the node accepted the config (a lost connection)
// must still remove the job document, and report the apply error, not a
// cleanup error.
func TestRunJobCleansUpAfterAFailedApply(t *testing.T) {
	f := talostest.New(t)
	f.FailAfterApply = status.Error(codes.Unavailable, "connection lost")

	tc := &talos.Client{Dial: func(ctx context.Context, _ talos.Conn) (*client.Client, error) { return f.Dial(ctx) }}
	t.Cleanup(func() { tc.Close() }) //nolint:errcheck

	o := &Orch{Talos: tc, St: state.New("eb8dac3e-0ba7-4795-8feb-a80e8593331f"), Out: io.Discard}
	doc := daemons.Probe("ceph-eb8dac3e-probe-abc", "quay.io/ceph/ceph:v20.2.4", "abc")

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

	if strings.Contains(cfg, doc.Name) {
		t.Errorf("job document left in the config:\n%s", cfg)
	}
}
