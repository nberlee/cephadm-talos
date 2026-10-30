package orch

import (
	"strings"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

func TestVersionAtLeast(t *testing.T) {
	for v, ok := range map[string]bool{
		"v1.15.0-alpha.1": true,
		"v1.15.2":         true,
		"v1.16.0":         true,
		"v2.0.0":          true,
		"v1.14.2":         false,
		"":                false,
	} {
		if got := versionAtLeast(v, MinTalos); got != ok {
			t.Errorf("versionAtLeast(%q) = %v", v, got)
		}
	}
}

func TestShellJoin(t *testing.T) {
	if got := shellJoin([]string{"ceph -s; ceph df"}); got != "ceph -s; ceph df" {
		t.Fatal(got)
	}

	if got := shellJoin([]string{"ceph", "config", "set", "global", "x", "it's"}); got != `'ceph' 'config' 'set' 'global' 'x' 'it'\''s'` {
		t.Fatal(got)
	}
}

func TestParsePrepared(t *testing.T) {
	id, uuid, err := parsePrepared("cephadm-talos: preparing\nRunning command: ...\nosd_id 4\nosd_uuid 9b1c\n")
	if err != nil || id != 4 || uuid != "9b1c" {
		t.Fatalf("got %d %q %v", id, uuid, err)
	}

	for _, bad := range []string{"", "osd_id 4\n", "osd_uuid x\n", "osd_id -1\nosd_uuid x\n", "osd_id x\nosd_uuid x\n"} {
		if _, _, err := parsePrepared(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// valid reports whether Talos accepts a container name.
func valid(name string) error {
	_, err := spec.Render(spec.Container(name, "docker.io/library/alpine:3"))

	return err
}

func TestDocNameBounded(t *testing.T) {
	st := state.New("0123abcd-0000-4000-8000-000000000000")
	long := strings.Repeat("h", 63)

	a := st.DocName(state.Daemon{Type: state.TypeOSD, ID: long + "-vdb"})
	b := st.DocName(state.Daemon{Type: state.TypeOSD, ID: long + "-vdc"})

	if len(a) > 63 || a == b || valid(a) != nil {
		t.Fatalf("bad names %q %q", a, b)
	}

	if n := st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-"}); valid(n) != nil {
		t.Fatalf("trailing dash name %q", n)
	}

	up := st.DocName(state.Daemon{Type: state.TypeMon, ID: "Node-1"})
	if valid(up) != nil || up == st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-1"}) {
		t.Fatalf("uppercase name %q", up)
	}

	if got := st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-1"}); got != "ceph-0123abcd-mon-node-1" {
		t.Fatalf("short name changed: %q", got)
	}
}

func TestCertCovers(t *testing.T) {
	ca, caKey, err := newCA("0123abcd-0000-4000-8000-000000000000")
	if err != nil {
		t.Fatal(err)
	}

	cert, _, err := newServerCert(ca, caKey, []string{"10.5.0.200", "10.5.0.2"}, []string{"node-1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}

	if !certCovers(cert, []string{"10.5.0.2", "10.5.0.200"}, []string{"localhost", "node-1"}) {
		t.Fatal("same SANs in another order must be covered")
	}

	if certCovers(cert, []string{"10.5.0.2", "10.5.0.200", "10.5.0.3"}, []string{"localhost", "node-1"}) {
		t.Fatal("a new host must trigger a reissue")
	}
}

func TestLastVIPStart(t *testing.T) {
	logs := "CEPHADM-TALOS-VIP-START 1-1\nEntering BACKUP STATE\nCEPHADM-TALOS-VIP-START 2-7\nStartup complete\n"

	if m, ok := lastVIPStart(logs); m != "2-7" || ok {
		t.Fatalf("got %q %v, the latest start is not ready yet", m, ok)
	}

	if m, ok := lastVIPStart(logs + "(rgw) Entering MASTER STATE\n"); m != "2-7" || !ok {
		t.Fatalf("got %q %v", m, ok)
	}
}
