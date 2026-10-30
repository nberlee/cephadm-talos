package daemons

import (
	"os"
	"strings"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/spec"
)

func params() Params {
	return Params{
		Name: "ceph-0123abcd-osd-cephadm-talos-worker-1-vdb", Image: "quay.io/ceph/ceph:v20",
		FSID: "0123abcd-0000-4000-8000-000000000000", ID: "cephadm-talos-worker-1-vdb", Addr: "10.5.0.3",
		Keyring: Keyring("client.bootstrap-osd", "AQAAAA=="), Device: "/dev/vdb", Mode: "join",
	}
}

// TestRenderAll renders one of every document. Set CEPHADM_TALOS_DUMP=file to write
// them out, e.g. to check them with `talosctl validate`.
func TestRenderAll(t *testing.T) {
	p := params()
	mgr, mon := p, p
	mgr.Name, mon.Name = "ceph-0123abcd-mgr-cephadm-talos-worker-1", "ceph-0123abcd-mon-cephadm-talos-worker-1"

	out, err := spec.Render(
		spec.CephVolume(), spec.CephConf("[global]\nfsid = x\n"),
		Mon(mon), Mgr(mgr), OSD(p), Job(Params{Name: "ceph-0123abcd-job-abc123", Image: p.Image, FSID: p.FSID, Keyring: "k"}, "abc123", "inputs", "ceph -s"),
		RecordsInit("ceph-0123abcd-records-init-h1", p.Image), spec.RecordsVolume(),
		spec.Delete("ContainerConfig", "ceph-0123abcd-job-abc123"),
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"profile: privileged", "source: /dev", "volumeType: directory", "$patch: delete", "mode: host", "name: ceph/ceph.conf", "mode: 0o644", "policy: never", "policy: on-failure", "name: cephadm-talos"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rendered docs miss %q", want)
		}
	}

	if f := os.Getenv("CEPHADM_TALOS_DUMP"); f != "" {
		if err := os.WriteFile(f, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEntrypointHasCommonPrelude(t *testing.T) {
	c := OSD(params())
	if !strings.Contains(c.ContainerEntrypoint[2], "set -euo pipefail") || !strings.Contains(c.ContainerEntrypoint[2], "ceph-volume raw prepare") {
		t.Fatal("osd entrypoint not assembled")
	}
}

func TestKeyring(t *testing.T) {
	got := Keyring("mgr.a", "KEY", "mon", "profile mgr")
	want := "[mgr.a]\n\tkey = KEY\n\tcaps mon = \"profile mgr\"\n"

	if got != want {
		t.Fatalf("got %q", got)
	}
}
