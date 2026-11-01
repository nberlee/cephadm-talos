package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// servingPEM is a self-signed serving certificate with its key, for IP and DNS names.
func servingPEM(t *testing.T, from, to time.Time, names ...string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)

	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rgw"}, NotBefore: from, NotAfter: to}

	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(t, err)

	kb, err := x509.MarshalECPrivateKey(key)
	must(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func TestRGWCertificatesAreForTheirNode(t *testing.T) {
	pol := &Policy{FSID: testFSID, Host: "h1"}
	now := time.Now()
	node := func() (NodeIdentity, error) {
		return NodeIdentity{Hostname: "h1", Addrs: []string{"10.5.0.3", "fe80::1"}}, nil
	}

	rgwDoc := func(pemS string, user bool, addr string) (string, typedDoc) {
		p := daemons.Params{Name: "ceph-" + testFSID[:8] + "-rgw-h1", Image: testImage, FSID: testFSID, ID: "h1", Addr: addr, Port: 443, TLSPEM: pemS, TLSUser: user, Keyring: "[client.rgw.h1]\n\tkey = x\n"}
		td, err := checkDoc(Doc{Kind: "ContainerConfig", Name: p.Name, YAML: mustRender(daemons.RGW(p))})
		must(t, err)

		return "ContainerConfig/" + p.Name, td
	}

	vipDoc := func(vip string) (string, typedDoc) {
		p := daemons.Params{Name: "ceph-" + testFSID[:8] + "-vip-h1", Image: testImage, FSID: testFSID, ID: "h1", Addr: "10.5.0.3", Port: 443, VIP: vip, VRID: 50, Priority: 150, VRRPPass: "abc"}
		td, err := checkDoc(Doc{Kind: "ContainerConfig", Name: p.Name, YAML: mustRender(daemons.VIP(p, testImage))})
		must(t, err)

		return "ContainerConfig/" + p.Name, td
	}

	valid := func(names ...string) string { return servingPEM(t, now.Add(-time.Hour), now.Add(time.Hour), names...) }

	check := func(rgwPEM string, user bool, addr, vip string) error {
		typed, sent := map[string]typedDoc{}, map[string]string{}

		k, td := rgwDoc(rgwPEM, user, addr)
		typed[k], sent[k] = td, "h"

		if vip != "" {
			k, td := vipDoc(vip)
			typed[k], sent[k] = td, "h"
		}

		return pol.rgwCerts(map[string]typedDoc{}, typed, sent, node, now)
	}

	for name, c := range map[string]struct {
		pem      string
		user     bool
		addr     string
		vip      string
		refusing string
	}{
		"generated, for its node and VIP":  {pem: valid("10.5.0.3", "h1", "10.5.0.200"), addr: "10.5.0.3", vip: "10.5.0.200/24"},
		"without the VIP":                  {pem: valid("10.5.0.3", "h1"), addr: "10.5.0.3", vip: "10.5.0.200/24", refusing: "10.5.0.200"},
		"without the hostname":             {pem: valid("10.5.0.3"), addr: "10.5.0.3", refusing: "h1"},
		"an ADDR not of this node":         {pem: valid("10.9.9.9", "h1"), addr: "10.9.9.9", refusing: "not an address of this node"},
		"expired":                          {pem: servingPEM(t, now.Add(-2*time.Hour), now.Add(-time.Hour), "10.5.0.3", "h1"), addr: "10.5.0.3", refusing: "not valid now"},
		"the operator's, for its DNS name": {pem: valid("s3.example.com"), user: true, addr: "10.5.0.3", vip: "10.5.0.200/24"},
		"the operator's, not yet valid":    {pem: servingPEM(t, now.Add(time.Hour), now.Add(2*time.Hour), "s3.example.com"), user: true, addr: "10.5.0.3", refusing: "not valid now"},
	} {
		err := check(c.pem, c.user, c.addr, c.vip)
		if c.refusing == "" && err != nil || c.refusing != "" && (err == nil || !strings.Contains(err.Error(), c.refusing)) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// the identity is read only for a generated certificate's names: removing
	// the last RGW, or the operator's certificate, does not need it
	broken := func() (NodeIdentity, error) { return NodeIdentity{}, errors.New("no talos") }
	k, td := rgwDoc(valid("10.5.0.3", "h1"), false, "10.5.0.3")

	if err := pol.rgwCerts(map[string]typedDoc{k: td}, map[string]typedDoc{}, map[string]string{k: ""}, broken, now); err != nil {
		t.Fatalf("removing the RGW: %v", err)
	}

	ku, tu := rgwDoc(valid("s3.example.com"), true, "10.5.0.3")
	if err := pol.rgwCerts(map[string]typedDoc{}, map[string]typedDoc{ku: tu}, map[string]string{ku: "h"}, broken, now); err != nil {
		t.Fatalf("the operator's certificate: %v", err)
	}

	// a revision that changes no RGW or keepalived checks nothing
	if err := pol.rgwCerts(map[string]typedDoc{}, map[string]typedDoc{}, map[string]string{"ContainerConfig/ceph-" + testFSID[:8] + "-mon-h1": "h"}, node, now); err != nil {
		t.Fatal(err)
	}
}

func TestVRRPStateSinceTheLastStart(t *testing.T) {
	for logs, want := range map[string]wire.VRRP{
		"":                        {},
		"Entering MASTER STATE\n": {},
		"CEPHADM-TALOS-VIP-START 1\nEntering BACKUP STATE\n":                            {Start: "1", State: "BACKUP"},
		"CEPHADM-TALOS-VIP-START 1\nEntering BACKUP STATE\nEntering MASTER STATE\n":     {Start: "1", State: "MASTER"},
		"CEPHADM-TALOS-VIP-START 1\nEntering MASTER STATE\nCEPHADM-TALOS-VIP-START 2\n": {Start: "2"},
		"CEPHADM-TALOS-VIP-START 2\nEntering MASTER STATE\nEntering FAULT STATE\n":      {Start: "2", State: "FAULT"},
	} {
		if got := vrrpState(logs); got != want {
			t.Errorf("%q: %+v, want %+v", logs, got, want)
		}
	}
}
