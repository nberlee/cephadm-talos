package orch

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

func TestParseProbe(t *testing.T) {
	info, err := parseProbe("ceph version 20.2.4 (abc123) tentacle (stable)\narch x86_64\n")
	if err != nil || info.Version != "20.2.4" || info.Arch != "x86_64" {
		t.Fatalf("got %+v, %v", info, err)
	}

	if _, err := parseProbe("bash: ceph: command not found\narch x86_64\n"); err == nil {
		t.Fatal("want an error for output without a version")
	}
}

func TestGates(t *testing.T) {
	o := &Orch{Talos: &talos.Client{}, St: state.New("eb8dac3e-0ba7-4795-8feb-a80e8593331f")}

	for _, tc := range []struct {
		info imageInfo
		want string
	}{
		{imageInfo{Ref: "a", Version: SupportedCeph, Arch: SupportedArch}, ""},
		{imageInfo{Ref: "b", Version: "20.2.3", Arch: SupportedArch}, "supports only Ceph"},
		{imageInfo{Ref: "c", Version: "", Arch: ""}, "supports only Ceph"},
		{imageInfo{Ref: "d", Version: SupportedCeph, Arch: "aarch64"}, "supports only x86_64"},
	} {
		err := o.gateImage(tc.info)
		if (tc.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: got %v, want %q", tc.info.Ref, err, tc.want)
		}
	}

	// a cluster without a verified version is refused, unless skipped
	if err := o.gateCluster(); err == nil {
		t.Error("unverified cluster image accepted")
	}

	o.SkipVersionCheck = true

	if err := o.gateImage(imageInfo{Ref: "b", Version: "20.2.3"}); err != nil {
		t.Errorf("skip-version-check: %v", err)
	}
}

func TestReAddingAHostKeepsItsConnection(t *testing.T) {
	o := &Orch{Talos: &talos.Client{DryRun: true}, St: state.New("eb8dac3e-0ba7-4795-8feb-a80e8593331f"), Out: io.Discard}
	o.St.AddHost(state.Host{Name: "dry-run-10-5-0-9", Addr: "10.5.0.9", Talosconfig: "/x/talosconfig", Context: "other", Maintenance: true})

	h, err := o.addHost(context.Background(), "10.5.0.9", false)
	if err != nil {
		t.Fatal(err)
	}

	if h.Talosconfig != "/x/talosconfig" || h.Context != "other" || !h.Maintenance {
		t.Errorf("host fields lost: %+v", h)
	}
}

func TestANodeNeedsAnX8664V3CPU(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)

	if err := o.checkTalos(context.Background(), "node"); err != nil {
		t.Fatalf("an x86-64-v3 CPU: %v", err)
	}

	// an x86-64-v2 CPU (no AVX2, BMI, FMA)
	f.Files = map[string]string{"/proc/cpuinfo": "processor\t: 0\nflags\t\t: fpu sse sse2 ssse3 cx16 sse4_1 sse4_2 popcnt lahf_lm\n"}

	if err := o.checkTalos(context.Background(), "node"); err == nil || !strings.Contains(err.Error(), "avx2") {
		t.Fatalf("an x86-64-v2 CPU: %v", err)
	}
}

func TestHostNamesAreLowercase(t *testing.T) {
	for name, ok := range map[string]bool{"cephadm-talos-controlplane-1": true, "Node4": false, "a_b.c": true, "-x": false} {
		if err := hostName(name); (err == nil) != ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
