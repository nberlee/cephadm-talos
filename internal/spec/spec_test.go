package spec

import (
	"strings"
	"testing"
)

// Container names are validated by the machinery document, not by us.
func TestRenderValidatesNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"ceph-0123abcd-mon-node-1":   true,
		"ceph-0123abcd-mon-10.5.0.3": false,
		"Ceph":                       false,
		strings.Repeat("a", 63):      true,
		strings.Repeat("a", 64):      false,
	} {
		_, err := Render(Container(name, "docker.io/library/alpine:3"))
		if (err == nil) != ok {
			t.Errorf("Render(%q) = %v, want ok=%v", name, err, ok)
		}
	}
}

func TestRenderDelete(t *testing.T) {
	out, err := Render(Delete("ContainerConfig", "app"))
	if err != nil || !strings.Contains(string(out), "$patch: delete") {
		t.Fatalf("%v\n%s", err, out)
	}
}
