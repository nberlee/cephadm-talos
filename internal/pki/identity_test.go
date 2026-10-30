package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
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
		{Scheme: identityScheme, Host: "f", Path: "/mgr/a", ForceQuery: true},
		{Scheme: identityScheme, Host: "f", Path: "/mgr/a/"},
		{Scheme: identityScheme, Host: "f:1", Path: "/mgr/a"},
		{Scheme: identityScheme, Host: "f", Path: "/mgr/h%31", RawPath: "/mgr/h%31"},
		{Scheme: identityScheme, Host: "f", Path: "/mgr/h 1"},
	} {
		c := issueWith(t, nil, bad)
		if _, err := CertIdentity(c); err == nil {
			t.Errorf("accepted malformed %s", bad)
		}
	}

	// an identity in another case of the scheme still counts, so two are refused
	upper := issueWith(t, &Identity{FSID: "f", Role: RoleAgent, Name: "h1"}, &url.URL{Scheme: "CEPHADM-TALOS", Host: "f", Path: "/mgr/h2"})
	if _, err := CertIdentity(upper); err == nil {
		t.Error("accepted an identity next to a case variant")
	}

	// a foreign URI SAN is ignored
	other := issueWith(t, &Identity{FSID: "f", Role: RoleOperator, Name: "admin"}, &url.URL{Scheme: "spiffe", Host: "x", Path: "/y"})
	if got, err := CertIdentity(other); err != nil || got.Role != RoleOperator {
		t.Errorf("foreign SAN: %+v %v", got, err)
	}
}

// TestIdentityFromDER parses SANs from the raw bytes of a certificate's SAN
// extension, as they arrive, with the same cases as the mgr module's IdentityTest.
func TestIdentityFromDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	certWith := func(raw ...string) *x509.Certificate {
		// GeneralNames with uniformResourceIdentifier [6] IA5String, written verbatim
		var names []asn1.RawValue
		for _, r := range raw {
			names = append(names, asn1.RawValue{Tag: 6, Class: asn1.ClassContextSpecific, Bytes: []byte(r)})
		}

		val, err := asn1.Marshal(names)
		if err != nil {
			t.Fatal(err)
		}

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: val}},
		}

		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}

		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("%v: %v", raw, err)
		}

		return c
	}

	// url.Parse lowercases the scheme and drops an empty fragment; the module does the same
	for _, ok := range []string{"CEPHADM-TALOS://f1/agent/h1", "cephadm-talos://f1/agent/h1#"} {
		if id, err := CertIdentity(certWith(ok)); err != nil || id != (Identity{FSID: "f1", Role: RoleAgent, Name: "h1"}) {
			t.Errorf("%s: %+v %v", ok, id, err)
		}
	}

	for _, bad := range [][]string{
		{"cephadm-talos://f1/agent/%68%31"},
		{"cephadm-talos://f1/agent/h1?"},
		{"cephadm-talos://f1/agent/h1#x"},
		{"cephadm-talos://f1:1/agent/h1"},
		{"cephadm-talos://f1/agent/h1/"},
		{"cephadm-talos://f1/agent/_node"},
		{"cephadm-talos://f1/agent/h1", "CEPHADM-TALOS://f1/mgr/h2"},
		{"cephadm-talos://f1/agent/h1", "cephadm-talos:f1/mgr/h2"},
		{"cephadm-talos://f1/agent/h1", "cephadm-talos:/f1/mgr/h2"},
		{"cephadm-talos://f1/agent/h1", "cephadm-talos:"},
	} {
		if id, err := CertIdentity(certWith(bad...)); err == nil {
			t.Errorf("%v accepted as %+v", bad, id)
		}
	}
}

func TestIssueRefusesAnInvalidIdentity(t *testing.T) {
	caCert, caKey, err := NewCA("test CA", 1)
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range []Identity{
		{FSID: "f1", Role: RoleAgent, Name: "_node"},
		{FSID: "f1", Role: RoleAgent, Name: ""},
		{FSID: "f/1", Role: RoleAgent, Name: "h1"},
	} {
		if _, _, err := Issue(caCert, caKey, Leaf{CommonName: "x", Usage: x509.ExtKeyUsageClientAuth, Years: 1, Identity: &id}); err == nil {
			t.Errorf("issued %+v", id)
		}
	}

	if err := ValidName("_node"); err == nil {
		t.Error("_node accepted as a host name")
	}
}
