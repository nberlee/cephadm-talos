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

func TestParseOSDMarker(t *testing.T) {
	logs := "CEPHADM-TALOS-OSD-ID=old 1 uuid-old\nnoise\nCEPHADM-TALOS-OSD-ID=new 4 uuid-a\nCEPHADM-TALOS-OSD-ID=new 4 uuid-b\n"

	id, uuid, ok := parseOSDMarker(logs, "new")
	if !ok || id != 4 || uuid != "uuid-b" {
		t.Fatalf("got %d %q %v", id, uuid, ok)
	}

	if _, _, ok := parseOSDMarker(logs, "other"); ok {
		t.Fatal("matched a foreign deploy id")
	}
}

func TestDocNameBounded(t *testing.T) {
	st := state.New("0123abcd-0000-4000-8000-000000000000")
	long := strings.Repeat("h", 63)

	a := st.DocName(state.Daemon{Type: state.TypeOSD, ID: long + "-vdb"})
	b := st.DocName(state.Daemon{Type: state.TypeOSD, ID: long + "-vdc"})

	if len(a) > 63 || a == b || spec.ValidateName(a) != nil {
		t.Fatalf("bad names %q %q", a, b)
	}

	if n := st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-"}); spec.ValidateName(n) != nil {
		t.Fatalf("trailing dash name %q", n)
	}

	up := st.DocName(state.Daemon{Type: state.TypeMon, ID: "Node-1"})
	if spec.ValidateName(up) != nil || up == st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-1"}) {
		t.Fatalf("uppercase name %q", up)
	}

	if got := st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-1"}); got != "ceph-0123abcd-mon-node-1" {
		t.Fatalf("short name changed: %q", got)
	}
}
