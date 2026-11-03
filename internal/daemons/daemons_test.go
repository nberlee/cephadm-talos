package daemons

import (
	"os"
	"slices"
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
	if !strings.Contains(c.ContainerEntrypoint[2], "set -euo pipefail") || !strings.Contains(c.ContainerEntrypoint[2], "ceph-volume raw activate") {
		t.Fatal("osd entrypoint not assembled")
	}

	// the OSD daemon only activates; preparing is the prepare job's
	if strings.Contains(c.ContainerEntrypoint[2], "raw prepare") {
		t.Fatal("the osd daemon prepares devices")
	}
}

func TestOSDPrepareJob(t *testing.T) {
	p := params()
	p.Keyring, p.DiskSerial = "[client.bootstrap-osd]\n\tkey = K\n", "QM00001"
	c := OSDPrepare(p, "j1", "inputs")

	env := strings.Join(c.ContainerEnvironment, "\n")
	for _, want := range []string{"JOB_IGNORE_TERM=1", "DISK_SERIAL=QM00001", "DEVICE=" + p.Device, "JOB=j1", "JOB_INPUTS=inputs"} {
		if !strings.Contains(env, want) {
			t.Errorf("environment misses %s", want)
		}
	}

	if n := strings.Count(env, "CEPHADM_TALOS_KEYRING="); n != 1 {
		t.Errorf("%d keyring variables", n)
	}

	if c.RestartConfig == nil || c.RestartConfig.RestartPolicy != "never" || c.ContainerStopTimeout != MaxStopTimeout {
		t.Errorf("restart %+v, stop timeout %s", c.RestartConfig, c.ContainerStopTimeout)
	}

	cmd := ""
	for _, e := range c.ContainerEnvironment {
		if v, ok := strings.CutPrefix(e, "CMD="); ok {
			cmd = v
		}
	}

	if !strings.Contains(cmd, "ceph-volume raw prepare") || !strings.Contains(cmd, "DISK_SERIAL") {
		t.Error("the job's command is not the prepare script")
	}
}

func TestKeyring(t *testing.T) {
	got := Keyring("mgr.a", "KEY", "mon", "profile mgr")
	want := "[mgr.a]\n\tkey = KEY\n\tcaps mon = \"profile mgr\"\n"

	if got != want {
		t.Fatalf("got %q", got)
	}
}

func TestZapJob(t *testing.T) {
	p := params()
	p.Device, p.DiskSerial = "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00001", "QM00001"
	c := Zap(p, "j2", "inputs")

	env := strings.Join(c.ContainerEnvironment, "\n")
	for _, want := range []string{"DISK_SERIAL=QM00001", "DEVICE=" + p.Device, "JOB=j2", "CEPHADM_TALOS_KEYRING=\n"} {
		if !strings.Contains(env+"\n", want) {
			t.Errorf("environment misses %q", want)
		}
	}

	if !strings.Contains(env, "ceph-volume lvm zap") || c.SecurityConfig.SecurityProfile != "privileged" {
		t.Error("not the privileged zap script")
	}
}

func TestJoiningMonHasTheMonKeyOnly(t *testing.T) {
	k := MonKeyring("AQBkey==")
	if strings.Count(k, "[") != 1 || !strings.HasPrefix(k, "[mon.]\n") || !strings.Contains(k, `caps mon = "allow *"`) {
		t.Errorf("mon keyring %q", k)
	}
}

func TestCephConfAndImageRepository(t *testing.T) {
	conf := CephConf("f1", []string{"10.5.0.3", "fd00::1"})
	for _, want := range []string{"fsid = f1\n", "mon_host = [v2:10.5.0.3:3300,v1:10.5.0.3:6789],[v2:[fd00::1]:3300,v1:[fd00::1]:6789]\n", "ms_bind_ipv4 = true\n", "ms_bind_ipv6 = true\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("ceph.conf misses %q:\n%s", want, conf)
		}
	}

	for ref, want := range map[string]string{
		"quay.io/ceph/ceph@sha256:" + strings.Repeat("a", 64): "quay.io/ceph/ceph",
		"10.5.0.1:5000/cephadm-talos-agent:dev":               "10.5.0.1:5000/cephadm-talos-agent",
		"alpine:3":                                            "docker.io/library/alpine",
	} {
		if got, err := ImageRepository(ref); err != nil || got != want {
			t.Errorf("%s: %q %v", ref, got, err)
		}
	}

	a := Agent("ceph-0123abcd-agent-h1", "ceph-0123abcd-records-init-h1", "registry/agent:1", []string{"quay.io/ceph/ceph", "quay.io/ceph/keepalived"}, "approval-key", false, "ca", "c", "k", "cc", "ck")
	if !strings.Contains(strings.Join(a.ContainerEnvironment, "\n"), EnvImageRepos+"=quay.io/ceph/ceph quay.io/ceph/keepalived") {
		t.Error("the agent document misses its image repositories")
	}

	// the fail-closed revocation list policy, only when set (plan 04, step 3)
	if strings.Contains(strings.Join(a.ContainerEnvironment, "\n"), EnvCRLFailClosed) {
		t.Error("fail closed without the setting")
	}

	closed := Agent("ceph-0123abcd-agent-h1", "ceph-0123abcd-records-init-h1", "registry/agent:1", nil, "approval-key", true, "ca", "c", "k", "cc", "ck")
	if !slices.Contains(closed.ContainerEnvironment, EnvCRLFailClosed+"=1") {
		t.Error("the setting is not in the document")
	}
}
