package crl

import (
	"crypto/x509"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
)

func newCA(t *testing.T) (string, string) {
	t.Helper()

	c, k, err := pki.NewCA("test agent CA", 1)
	if err != nil {
		t.Fatal(err)
	}

	return c, k
}

func leaf(t *testing.T, caCert, caKey string) *x509.Certificate {
	t.Helper()

	id := pki.Identity{FSID: "eb8dac3e-0ba7-4795-8feb-a80e8593331f", Role: pki.RoleAgent, Name: "h1"}

	c, _, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "agent h1", Usage: x509.ExtKeyUsageClientAuth, Years: 1, Identity: &id})
	if err != nil {
		t.Fatal(err)
	}

	cert, err := pki.Parse(c)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func TestAcceptance(t *testing.T) {
	caCert, caKey := newCA(t)
	otherCert, otherKey := newCA(t)
	now := time.Now()

	good, err := Issue(caCert, caKey, big.NewInt(5), nil, now, MaxValidity)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Parse(good, caCert, now); err != nil {
		t.Fatalf("a good list: %v", err)
	}

	for name, der := range map[string][]byte{
		"another CA":   must(Issue(otherCert, otherKey, big.NewInt(5), nil, now, time.Hour)),
		"future":       must(Issue(caCert, caKey, big.NewInt(5), nil, now.Add(10*time.Minute), time.Hour)),
		"too long":     must(Issue(caCert, caKey, big.NewInt(5), nil, now, MaxValidity+time.Second)),
		"no number":    must(Issue(caCert, caKey, big.NewInt(0), nil, now, time.Hour)),
		"not a list":   []byte("garbage"),
		"empty":        nil,
		"tampered DER": tamper(good),
	} {
		if _, err := Parse(der, caCert, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// a list another CA signed under this CA's name is refused by its signature
	if _, err := Parse(must(Issue(otherCert, otherKey, big.NewInt(5), nil, now, time.Hour)), otherCert, now); err != nil {
		t.Fatalf("the other CA's own list: %v", err)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}

	return b
}

func tamper(der []byte) []byte {
	b := append([]byte(nil), der...)
	b[len(b)-3] ^= 0xff

	return b
}

func TestHolder(t *testing.T) {
	caCert, caKey := newCA(t)
	now := time.Now()
	peer := leaf(t, caCert, caKey)
	path := File(filepath.Join(t.TempDir(), "crl.der"))
	h := &Holder{CA: caCert, Persist: path, Now: func() time.Time { return now }}

	if h.Check(peer) != nil || !h.Current().Stale(now) {
		t.Fatal("no list: the peer is valid, the state stale")
	}

	l7, err := h.Install(must(Issue(caCert, caKey, big.NewInt(7), []*big.Int{peer.SerialNumber}, now, time.Hour)))
	if err != nil || l7.Len() != 1 {
		t.Fatal(err)
	}

	if err := h.Check(peer); err == nil {
		t.Fatal("a revoked peer passed")
	}

	// an older or equal number changes nothing
	if _, err := h.Install(must(Issue(caCert, caKey, big.NewInt(7), nil, now, time.Hour))); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("an equal number: %v", err)
	}

	if _, err := h.Install(must(Issue(caCert, caKey, big.NewInt(6), nil, now, time.Hour))); !errors.Is(err, ErrNotNewer) {
		t.Fatalf("a lower number: %v", err)
	}

	if h.Check(peer) == nil {
		t.Fatal("an older list replaced the newer")
	}

	// persisted: a new holder loads it
	h2 := &Holder{CA: caCert, Persist: path, Now: func() time.Time { return now }}
	if err := h2.Load(); err != nil || h2.Current() == nil || h2.Current().Number.Int64() != 7 || h2.Check(peer) == nil {
		t.Fatalf("after a restart: %v", err)
	}

	// stale past nextUpdate
	if h2.Current().Stale(now) || !h2.Current().Stale(now.Add(2*time.Hour)) {
		t.Fatal("staleness")
	}

	// an expired peer certificate is refused whatever the list
	later := &Holder{CA: caCert, Now: func() time.Time { return peer.NotAfter.Add(time.Second) }}
	if later.Check(peer) == nil {
		t.Fatal("an expired peer passed")
	}
}
