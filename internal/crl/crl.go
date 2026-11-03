// Package crl is the agent CA's certificate revocation list on its verifiers
// (plan 04, step 3): the acceptance rules every Go verifier applies to a list
// (the agents, the CLI), and the installed list each checks peer
// certificates against. The mgr module issues the list; it is public and
// authenticates itself by the agent CA's signature.
package crl

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Limits fixed in the verifiers, not set by the module.
const (
	// MaxValidity is the longest validity (nextUpdate minus thisUpdate) a list may have
	MaxValidity = 7 * 24 * time.Hour
	// MaxFuture is how far in the future a list's thisUpdate may be
	MaxFuture = 5 * time.Minute
	// MaxSize bounds a list's DER encoding
	MaxSize = 4 << 20
)

// List is a checked revocation list of the agent CA.
type List struct {
	DER        []byte
	Number     *big.Int
	ThisUpdate time.Time
	NextUpdate time.Time
	revoked    map[string]bool // serials, decimal
}

// Stale reports whether the list is past its nextUpdate.
func (l *List) Stale(now time.Time) bool { return l == nil || now.After(l.NextUpdate) }

// Names reports whether the list names a certificate's serial.
func (l *List) Names(c *x509.Certificate) bool {
	return l != nil && c != nil && c.SerialNumber != nil && l.revoked[c.SerialNumber.String()]
}

// Len is the number of serials the list names.
func (l *List) Len() int { return len(l.revoked) }

// ca parses the agent CA certificate (PEM).
func ca(caPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(caPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("crl: no agent CA certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}

// Parse checks a list as every verifier accepts one: signed by the agent CA,
// naming it as issuer, with a CRL number, a thisUpdate not more than
// MaxFuture ahead of now and a validity of at most MaxValidity. The number
// is compared by the caller (Holder.Install).
func Parse(der []byte, caPEM string, now time.Time) (*List, error) {
	if len(der) == 0 || len(der) > MaxSize {
		return nil, errors.New("crl: empty or too large")
	}

	c, err := ca(caPEM)
	if err != nil {
		return nil, err
	}

	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("crl: %w", err)
	}

	if !bytes.Equal(rl.RawIssuer, c.RawSubject) {
		return nil, errors.New("crl: not issued by the agent CA")
	}

	if err := rl.CheckSignatureFrom(c); err != nil {
		return nil, fmt.Errorf("crl: the signature does not verify: %w", err)
	}

	switch {
	case rl.Number == nil || rl.Number.Sign() <= 0:
		return nil, errors.New("crl: no CRL number")
	case rl.ThisUpdate.After(now.Add(MaxFuture)):
		return nil, errors.New("crl: thisUpdate is in the future")
	case rl.NextUpdate.IsZero() || !rl.NextUpdate.After(rl.ThisUpdate) || rl.NextUpdate.Sub(rl.ThisUpdate) > MaxValidity:
		return nil, fmt.Errorf("crl: a validity of more than %s", MaxValidity)
	}

	l := &List{DER: bytes.Clone(der), Number: rl.Number, ThisUpdate: rl.ThisUpdate, NextUpdate: rl.NextUpdate, revoked: map[string]bool{}}
	for _, e := range rl.RevokedCertificateEntries {
		if e.SerialNumber != nil {
			l.revoked[e.SerialNumber.String()] = true
		}
	}

	return l, nil
}

// Persist keeps the installed list (the agent's records, the CLI's cluster
// directory); written atomically before a list is installed.
type Persist interface {
	Write(der []byte) error
	Read() ([]byte, error) // nil without one
}

// Holder is a verifier's installed list: only a list with a higher number
// than the one it holds replaces it, persisted first.
type Holder struct {
	CA      string // the agent CA certificate, PEM
	Persist Persist
	Now     func() time.Time

	mu  sync.Mutex // serializes Install
	cur atomic.Pointer[List]
}

func (h *Holder) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}

	return time.Now()
}

// Current returns the installed list, nil before any.
func (h *Holder) Current() *List {
	if h == nil {
		return nil
	}

	return h.cur.Load()
}

// Load installs the persisted list, if there is one that still checks; a
// damaged one is reported and nothing is installed.
func (h *Holder) Load() error {
	if h.Persist == nil {
		return nil
	}

	der, err := h.Persist.Read()
	if err != nil || der == nil {
		return err
	}

	// its thisUpdate may be far in the past now: only the future bound is checked against now
	l, err := Parse(der, h.CA, h.now())
	if err != nil {
		return err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if c := h.cur.Load(); c == nil || l.Number.Cmp(c.Number) > 0 {
		h.cur.Store(l)
	}

	return nil
}

// ErrNotNewer is returned for a list whose number is not above the installed one's.
var ErrNotNewer = errors.New("crl: not newer than the installed list")

// Install checks a list, persists it and installs it; it returns
// ErrNotNewer for a list that is not newer, which changes nothing.
func (h *Holder) Install(der []byte) (*List, error) {
	l, err := Parse(der, h.CA, h.now())
	if err != nil {
		return nil, err
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if c := h.cur.Load(); c != nil && l.Number.Cmp(c.Number) <= 0 {
		return c, ErrNotNewer
	}

	if h.Persist != nil {
		if err := h.Persist.Write(l.DER); err != nil {
			return nil, err
		}
	}

	h.cur.Store(l)

	return l, nil
}

// Check refuses a peer certificate the installed list names, or one outside
// its validity (a kept-alive connection outlives its handshake, and an
// expired revocation is pruned from the list). A nil holder checks the
// validity only.
func (h *Holder) Check(c *x509.Certificate) error {
	if c == nil {
		return errors.New("no peer certificate")
	}

	now := time.Now()
	if h != nil {
		now = h.now()
	}

	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return errors.New("the peer certificate is not valid now")
	}

	if h.Current().Names(c) {
		return fmt.Errorf("the peer certificate (serial %s) is revoked", c.SerialNumber)
	}

	return nil
}

// File persists a list in one file, written atomically (the CLI's crl.der).
type File string

func (f File) Read() ([]byte, error) {
	b, err := os.ReadFile(string(f))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	return b, err
}

func (f File) Write(der []byte) error {
	if err := os.MkdirAll(filepath.Dir(string(f)), 0o700); err != nil {
		return err
	}

	tmp := string(f) + ".tmp"
	if err := os.WriteFile(tmp, der, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, string(f))
}
