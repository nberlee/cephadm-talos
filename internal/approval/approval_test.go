package approval

import (
	"encoding/base64"
	"strings"
	"testing"
)

const fsid = "eb8dac3e-0ba7-4795-8feb-a80e8593331f"

func TestSignAndVerify(t *testing.T) {
	priv, pub, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}

	img := "quay.io/ceph/ceph@sha256:" + strings.Repeat("ab", 32)
	a := Approval{Version: Version, FSID: fsid, Serial: 2, Images: []string{img}, Disks: []Disk{{Host: "h1", Serial: "QM00003", Action: Prepare, Since: 2}}}

	s, err := Sign(priv, a)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Verify(pub, s, fsid)
	if err != nil || !got.Image(img) || got.Image("quay.io/ceph/ceph:v20") {
		t.Fatalf("%+v %v", got, err)
	}

	if d, ok := got.Entry("h1", "QM00003", Prepare); !ok || d.Key() != "h1/QM00003/prepare/2" {
		t.Fatalf("entry %+v", d)
	}

	if _, ok := got.Entry("h1", "QM00003", Zap); ok {
		t.Fatal("zap approved")
	}

	// another key, another cluster, a changed payload: refused
	_, other, _ := NewKey()
	if _, err := Verify(other, s, fsid); err == nil {
		t.Error("verified with another key")
	}

	if _, err := Verify(pub, s, "other"); err == nil {
		t.Error("verified for another cluster")
	}

	b, _ := base64.StdEncoding.DecodeString(s.Payload)
	s.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(b), `"serial":2`, `"serial":9`, 1)))

	if _, err := Verify(pub, s, fsid); err == nil {
		t.Error("verified a changed payload")
	}
}

func TestShapes(t *testing.T) {
	ok := Approval{Version: Version, FSID: fsid, Serial: 3}
	if err := ok.Check(fsid); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []Approval{
		{Version: 2, FSID: fsid, Serial: 3},
		{Version: Version, FSID: fsid, Serial: 0},
		{Version: Version, FSID: fsid, Serial: 3, Images: []string{"quay.io/ceph/ceph:v20"}},
		{Version: Version, FSID: fsid, Serial: 3, Disks: []Disk{{Host: "h1", Serial: "x", Action: "wipe", Since: 3}}},
		{Version: Version, FSID: fsid, Serial: 3, Disks: []Disk{{Host: "h1", Serial: "x", Action: Zap, Since: 4}}},
		{Version: Version, FSID: fsid, Serial: 3, Disks: []Disk{{Host: "../h", Serial: "x", Action: Zap, Since: 3}}},
		{Version: Version, FSID: fsid, Serial: 3, Disks: []Disk{{Host: "h1", Serial: "x", Action: Zap, Since: 3}, {Host: "h1", Serial: "x", Action: Zap, Since: 3}}},
	} {
		if bad.Check(fsid) == nil {
			t.Errorf("%+v passed", bad)
		}
	}
}
