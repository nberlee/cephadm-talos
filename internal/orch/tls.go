package orch

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// newCA creates a self-signed CA for the cluster's RGW endpoints.
func newCA(fsid string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "cephadm-talos CA " + fsid[:8]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	k, err := encodeKey(key)

	return encodeCert(der), k, err
}

// newServerCert issues a server certificate for the given IPs and DNS names.
func newServerCert(caCertPEM, caKeyPEM string, ips []string, names []string) (certPEM, keyPEM string, err error) {
	ca, err := tls.X509KeyPair([]byte(caCertPEM), []byte(caKeyPEM))
	if err != nil {
		return "", "", fmt.Errorf("load CA: %w", err)
	}

	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return "", "", err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "rgw"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}

	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, p)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return "", "", err
	}

	k, err := encodeKey(key)

	return encodeCert(der), k, err
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

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))

	return n
}

func encodeCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func encodeKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
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
	if r.Cert != "" && certCovers(r.Cert, ips, names) {
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
