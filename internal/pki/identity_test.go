package pki

import (
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
)

func issueWith(t *testing.T, id *Identity, extra ...*url.URL) *x509.Certificate {
	t.Helper()

	caCert, caKey, err := NewCA("test CA", 1)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, _, err := Issue(caCert, caKey, Leaf{CommonName: "x", Usage: x509.ExtKeyUsageClientAuth, Years: 1, Identity: id})
	if err != nil {
		t.Fatal(err)
	}

	c, err := Parse(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	c.URIs = append(c.URIs, extra...)

	return c
}

func TestIdentityRoundTrip(t *testing.T) {
	id := Identity{FSID: "510c917f-1234", Role: RoleAgent, Name: "host-1"}
	c := issueWith(t, &id)

	got, err := CertIdentity(c)
	if err != nil || got != id {
		t.Fatalf("got %+v, %v; want %+v", got, err, id)
	}

	if _, err := Require(c, id); err != nil {
		t.Fatal(err)
	}

	if _, err := Require(c, Identity{FSID: id.FSID, Role: RoleAgent}); err != nil {
		t.Fatalf("any name of the role: %v", err)
	}
}

func TestRequireRefuses(t *testing.T) {
	id := Identity{FSID: "fsid-a", Role: RoleAgent, Name: "host-1"}
	c := issueWith(t, &id)

	for _, want := range []Identity{
		{FSID: "fsid-b", Role: RoleAgent, Name: "host-1"},
		{FSID: "fsid-a", Role: RoleMgr, Name: "host-1"},
		{FSID: "fsid-a", Role: RoleAgent, Name: "host-2"},
	} {
		if _, err := Require(c, want); err == nil {
			t.Errorf("accepted %s for %s", id, want)
		}
	}
}

func TestCertIdentityRefuses(t *testing.T) {
	if _, err := CertIdentity(issueWith(t, nil)); err == nil || !strings.Contains(err.Error(), "no cephadm-talos identity") {
		t.Errorf("no identity: %v", err)
	}

	two := issueWith(t, &Identity{FSID: "f", Role: RoleMgr, Name: "a"}, &url.URL{Scheme: identityScheme, Host: "f", Path: "/mgr/b"})
	if _, err := CertIdentity(two); err == nil {
		t.Error("accepted two identities")
	}

	for _, bad := range []*url.URL{
		{Scheme: identityScheme, Host: "f", Path: "/mgr"},
		{Scheme: identityScheme, Host: "", Path: "/mgr/a"},
		{Scheme: identityScheme, Host: "f", Path: "/mgr/a/b"},
		{Scheme: identityScheme, Host: "f", Path: "/mgr/a", RawQuery: "x=1"},
	} {
		c := issueWith(t, nil, bad)
		if _, err := CertIdentity(c); err == nil {
			t.Errorf("accepted malformed %s", bad)
		}
	}

	// a foreign URI SAN is ignored
	other := issueWith(t, &Identity{FSID: "f", Role: RoleOperator, Name: "admin"}, &url.URL{Scheme: "spiffe", Host: "x", Path: "/y"})
	if got, err := CertIdentity(other); err != nil || got.Role != RoleOperator {
		t.Errorf("foreign SAN: %+v %v", got, err)
	}
}
