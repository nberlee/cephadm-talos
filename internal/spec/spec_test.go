package spec

import (
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	for name, ok := range map[string]bool{
		"ceph-0123abcd-mon-node-1":   true,
		"ceph-0123abcd-mon-10.5.0.3": false,
		"Ceph":                       false,
		"-ceph":                      false,
		strings.Repeat("a", 63):      true,
		strings.Repeat("a", 64):      false,
	} {
		if err := ValidateName(name); (err == nil) != ok {
			t.Errorf("ValidateName(%q) = %v, want ok=%v", name, err, ok)
		}
	}
}

func TestRenderRejectsBadName(t *testing.T) {
	if _, err := Render(ContainerConfig{Header: Header{Name: "Bad_Name"}}); err == nil {
		t.Fatal("expected error")
	}
}
