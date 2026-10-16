package cephx

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"
)

func TestEncodeLayout(t *testing.T) {
	secret := []byte("0123456789abcdef")
	created := time.Unix(1700000000, 42)

	raw, err := base64.StdEncoding.DecodeString(encode(cryptoAES, secret, created))
	if err != nil {
		t.Fatal(err)
	}

	if len(raw) != 28 {
		t.Fatalf("expected 28 bytes, got %d", len(raw))
	}

	if typ := binary.LittleEndian.Uint16(raw[0:]); typ != cryptoAES {
		t.Fatalf("type = %d", typ)
	}

	if sec := binary.LittleEndian.Uint32(raw[2:]); sec != 1700000000 {
		t.Fatalf("sec = %d", sec)
	}

	if n := binary.LittleEndian.Uint16(raw[10:]); n != 16 {
		t.Fatalf("len = %d", n)
	}

	if string(raw[12:]) != string(secret) {
		t.Fatal("secret mismatch")
	}
}

func TestNewKeyUnique(t *testing.T) {
	a, _ := NewKey(KeyAES256K)
	b, _ := NewKey(KeyAES256K)

	raw, _ := base64.StdEncoding.DecodeString(a)
	if binary.LittleEndian.Uint16(raw) != cryptoAES256KRB5 || len(raw) != 12+32 {
		t.Fatalf("bad key layout %x", raw)
	}

	if a == b {
		t.Fatalf("bad keys %q %q", a, b)
	}
}

func TestKeyTypeFor(t *testing.T) {
	for img, want := range map[string]string{
		"quay.io/ceph/ceph:v20.2.3":     KeyAES,
		"quay.io/ceph/ceph:v20.2.4":     KeyAES256K,
		"quay.io/ceph/ceph:v20":         KeyAES256K,
		"quay.io/ceph/ceph:v19.2.3":     KeyAES,
		"quay.io/ceph/ceph:v19":         KeyAES,
		"quay.io/ceph/ceph:v20.1":       KeyAES,
		"quay.io/ceph/ceph@sha256:abcd": KeyAES256K,
		"localhost:5000/ceph:v20.2.3":   KeyAES,
		"quay.io/ceph/ceph:latest":      KeyAES256K,
	} {
		if got := KeyTypeFor(img); got != want {
			t.Errorf("KeyTypeFor(%q) = %s, want %s", img, got, want)
		}
	}

	if raw, _ := NewKey(KeyAES); len(raw) != 40 {
		t.Errorf("aes key %q", raw)
	}
}
