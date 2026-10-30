// Package pki issues the cluster's own certificates: the RGW CA and server
// certificates, and the agent CA with its server and client certificates.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

// NewCA creates a self-signed CA valid for the given number of years.
func NewCA(commonName string, years int) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(years, 0, 0),
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

// Leaf describes a certificate issued by a CA.
type Leaf struct {
	CommonName string
	IPs        []string
	Names      []string
	// Usage is x509.ExtKeyUsageServerAuth or x509.ExtKeyUsageClientAuth; a
	// certificate gets exactly one, so a server certificate cannot act as a client
	Usage x509.ExtKeyUsage
	Years int
	// Lifetime, if set, replaces Years
	Lifetime time.Duration
	// Identity, if set, is carried as a URI SAN (see Identity)
	Identity *Identity
}

// Issue signs a leaf certificate with the CA.
func Issue(caCertPEM, caKeyPEM string, l Leaf) (certPEM, keyPEM string, err error) {
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
		Subject:      pkix.Name{CommonName: l.CommonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter(l),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{l.Usage},
		DNSNames:     l.Names,
	}

	if l.Identity != nil {
		if err := l.Identity.Valid(); err != nil {
			return "", "", err
		}

		tmpl.URIs = []*url.URL{l.Identity.URI()}
	}

	for _, ip := range l.IPs {
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

func notAfter(l Leaf) time.Time {
	if l.Lifetime > 0 {
		return time.Now().Add(l.Lifetime)
	}

	return time.Now().AddDate(l.Years, 0, 0)
}

// Parse returns the first certificate of a PEM bundle.
func Parse(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("no certificate in PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

// NotAfter returns the expiry of the first certificate of a PEM bundle.
func NotAfter(certPEM string) (time.Time, error) {
	c, err := Parse(certPEM)
	if err != nil {
		return time.Time{}, err
	}

	return c.NotAfter, nil
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
