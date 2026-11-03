package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"time"
)

// Issue signs a list with the agent CA as the module issues one (bridge.py
// issue_crl); for tests of the verifiers.
func Issue(caCertPEM, caKeyPEM string, number *big.Int, serials []*big.Int, thisUpdate time.Time, validity time.Duration) ([]byte, error) {
	pair, err := tls.X509KeyPair([]byte(caCertPEM), []byte(caKeyPEM))
	if err != nil {
		return nil, err
	}

	c, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}

	tmpl := &x509.RevocationList{Number: number, ThisUpdate: thisUpdate, NextUpdate: thisUpdate.Add(validity)}
	for _, s := range serials {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: thisUpdate})
	}

	return x509.CreateRevocationList(rand.Reader, tmpl, c, pair.PrivateKey.(crypto.Signer))
}
