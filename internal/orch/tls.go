package orch

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
)

// newCA creates a self-signed CA for the cluster's RGW endpoints.
func newCA(fsid string) (certPEM, keyPEM string, err error) {
	return pki.NewCA("cephadm-talos CA "+fsid[:8], 10)
}

// rgwCertLifetime is a generated RGW certificate's lifetime: at most a year,
// as browsers may reach the RGWs (plan 04, A1).
const rgwCertLifetime = 365 * 24 * time.Hour

// newServerCert issues an RGW server certificate for the given IPs and DNS names.
func newServerCert(caCertPEM, caKeyPEM string, ips []string, names []string) (certPEM, keyPEM string, err error) {
	return pki.Issue(caCertPEM, caKeyPEM, pki.Leaf{CommonName: "rgw", IPs: ips, Names: names, Usage: x509.ExtKeyUsageServerAuth, Lifetime: rgwCertLifetime})
}

// certCovers reports whether a PEM certificate has exactly these SANs.
func certCovers(certPEM string, ips, names []string) bool {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	have := map[string]bool{}
	for _, ip := range cert.IPAddresses {
		have[ip.String()] = true
	}

	for _, n := range cert.DNSNames {
		have[n] = true
	}

	want := map[string]bool{}
	for _, v := range append(append([]string{}, ips...), names...) {
		if ip := net.ParseIP(v); ip != nil {
			v = ip.String()
		}

		want[v] = true
	}

	if len(have) != len(want) {
		return false
	}

	for v := range want {
		if !have[v] {
			return false
		}
	}

	return true
}

// certFingerprint is the SHA-256 fingerprint of the first certificate in a PEM
// bundle, formatted like `openssl x509 -fingerprint -sha256` (AA:BB:...).
func certFingerprint(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("no certificate in PEM")
	}

	sum := sha256.Sum256(block.Bytes)
	parts := make([]string, len(sum))

	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}

	return strings.Join(parts, ":"), nil
}

// rgwCertSANs are the names a client may use to reach RGW: the VIP and every host.
func (o *Orch) rgwCertSANs() (ips, names []string) {
	if o.St.RGW != nil && o.St.RGW.VIP != "" {
		if ip, _, err := net.ParseCIDR(o.St.RGW.VIP); err == nil {
			ips = append(ips, ip.String())
		}
	}

	for _, h := range o.St.Hosts {
		ips = append(ips, h.Addr)
		names = append(names, h.Name)
	}

	return ips, append(names, "localhost")
}

// ensureRGWCert creates or reissues the generated RGW certificate so it covers
// the current VIP and hosts. User-supplied certificates are left alone.
func (o *Orch) ensureRGWCert() error {
	r := o.St.RGW
	if r.UserCert {
		return nil
	}

	if r.CACert == "" {
		c, k, err := newCA(o.St.FSID)
		if err != nil {
			return err
		}

		r.CACert, r.CAKey = c, k
	}

	ips, names := o.rgwCertSANs()

	// a new certificate restarts every rgw: only reissue when the names changed
	if _, err := tls.X509KeyPair([]byte(r.Cert), []byte(r.Key)); err == nil && certCovers(r.Cert, ips, names) {
		return nil
	}

	c, k, err := newServerCert(r.CACert, r.CAKey, ips, names)
	if err != nil {
		return err
	}

	r.Cert, r.Key = c, k

	if o.Talos.DryRun {
		return nil
	}

	// clients need the CA, e.g. curl --cacert ~/.cephadm-talos/<fsid>/rgw-ca.crt
	if err := os.MkdirAll(o.St.Dir(), 0o700); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(o.St.Dir(), "rgw-ca.crt"), []byte(r.CACert), 0o644)
}
