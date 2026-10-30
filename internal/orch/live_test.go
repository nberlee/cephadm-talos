//go:build live

package orch

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

// TestLiveJobs runs `never` jobs on a real cluster of the current state
// (CEPHADM_TALOS_HOME): a zap of a free device and an image probe.
//
//	CEPHADM_TALOS_LIVE_HOST=<host> CEPHADM_TALOS_LIVE_DEVICE=/dev/sdb go test -tags live -run TestLiveJobs ./internal/orch/
func TestLiveJobs(t *testing.T) {
	st, err := state.Load("")
	if err != nil {
		t.Fatal(err)
	}

	tc := &talos.Client{Default: talos.Conn{Talosconfig: st.Talosconfig, Context: st.Context}}
	defer tc.Close() //nolint:errcheck

	o := &Orch{Talos: tc, St: st, Out: os.Stdout}

	h, ok := st.Host(os.Getenv("CEPHADM_TALOS_LIVE_HOST"))
	if !ok {
		t.Fatal("set CEPHADM_TALOS_LIVE_HOST to a host of the cluster")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	start := time.Now()
	if err := o.zap(ctx, h, os.Getenv("CEPHADM_TALOS_LIVE_DEVICE")); err != nil {
		t.Fatalf("zap: %v", err)
	}

	t.Logf("zap took %s", time.Since(start).Round(time.Millisecond))

	start = time.Now()

	info, err := o.resolveImage(ctx, h.Addr, st.Image, false)
	if err != nil || !strings.HasPrefix(info.Version, "20.") {
		t.Fatalf("probe: %+v %v", info, err)
	}

	t.Logf("probe: Ceph %s %s, took %s", info.Version, info.Arch, time.Since(start).Round(time.Millisecond))
}
