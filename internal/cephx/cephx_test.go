package cephx

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"
)

func TestEncodeLayout(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	created := time.Unix(1700000000, 42)

	raw, err := base64.StdEncoding.DecodeString(encode(cryptoAES256KRB5, secret, created))
	if err != nil {
		t.Fatal(err)
	}

	if len(raw) != 44 {
		t.Fatalf("expected 44 bytes, got %d", len(raw))
	}

	if typ := binary.LittleEndian.Uint16(raw[0:]); typ != cryptoAES256KRB5 {
		t.Fatalf("type = %d", typ)
	}

	if sec := binary.LittleEndian.Uint32(raw[2:]); sec != 1700000000 {
		t.Fatalf("sec = %d", sec)
	}

	if n := binary.LittleEndian.Uint16(raw[10:]); n != 32 {
		t.Fatalf("len = %d", n)
	}

	if string(raw[12:]) != string(secret) {
		t.Fatal("secret mismatch")
	}
}

func TestNewKeyUnique(t *testing.T) {
	a, _ := NewKey()
	b, _ := NewKey()

	raw, _ := base64.StdEncoding.DecodeString(a)
	if binary.LittleEndian.Uint16(raw) != cryptoAES256KRB5 || len(raw) != 12+32 {
		t.Fatalf("bad key layout %x", raw)
	}

	if a == b {
		t.Fatalf("bad keys %q %q", a, b)
	}
}
