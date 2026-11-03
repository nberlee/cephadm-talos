package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// ConfirmValidity is how long a confirmation counts, from sending the challenge.
const ConfirmValidity = 10 * time.Second

// dialPort is the module's confirmation port and bridgePort its bridge port
// on loopback; tests point them elsewhere.
var (
	dialPort   = func() string { return strconv.Itoa(wire.ModulePort) }
	bridgePort = func() string { return strconv.Itoa(wire.BridgePort) }
)

// Leader is the incarnation that last heartbeated this agent (plan 03, item 1).
type Leader struct {
	Mgr   string
	GID   int64
	Epoch int64
	At    time.Time
}

// Channel is the agent's side of the agent channel: its session, the leader it
// heard from, and the client for the module's confirmation endpoint.
type Channel struct {
	Self    pki.Identity // the agent's own identity: cluster and host
	Session string       // new on every start
	// CRL refuses a module whose server certificate the agent's list names
	// (plan 04, step 3); nil checks its validity only
	CRL *crl.Holder

	mu     sync.Mutex
	leader *Leader

	now func() time.Time
}

// NewChannel starts a session for the agent with the given identity.
func NewChannel(self pki.Identity) (*Channel, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return &Channel{Self: self, Session: hex.EncodeToString(b), now: time.Now}, nil
}

// Leader returns the last heartbeat's incarnation, or nil.
func (c *Channel) Leader() *Leader {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.leader == nil {
		return nil
	}

	l := *c.leader

	return &l
}

// HandleHeartbeat accepts heartbeats from the mgr on the agent's own host only.
func (c *Channel) HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "no client certificate", http.StatusForbidden)

		return
	}

	if _, err := pki.Require(r.TLS.PeerCertificates[0], pki.Identity{FSID: c.Self.FSID, Role: pki.RoleMgr, Name: c.Self.Name}); err != nil {
		http.Error(w, "heartbeats come from this host's mgr only: "+err.Error(), http.StatusForbidden)

		return
	}

	var hb wire.Heartbeat

	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&hb); err != nil || hb.Version != wire.Version || hb.FSID != c.Self.FSID || hb.Mgr != c.Self.Name || hb.GID <= 0 {
		http.Error(w, "malformed heartbeat", http.StatusBadRequest)

		return
	}

	c.mu.Lock()
	changed := c.leader == nil || c.leader.GID != hb.GID
	c.leader = &Leader{Mgr: hb.Mgr, GID: hb.GID, Epoch: hb.Epoch, At: c.now()}
	c.mu.Unlock()

	if changed {
		log.Printf("leader is mgr.%s, gid %d (mgrmap epoch %d)", hb.Mgr, hb.GID, hb.Epoch)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wire.HeartbeatReply{Version: wire.Version, Session: c.Session})
}

// ConfirmTarget is where and to whom a confirmation is asked: the active mgr.
type ConfirmTarget struct {
	Addr string // the mgr host's address
	Mgr  string // the mgr's name, its certificate's identity
}

// Confirm asks the module in the active mgr for a fresh confirmation of an
// operation. It returns the confirmation and the time until which it counts,
// measured from sending the challenge; any error means no confirmation.
func (c *Channel) Confirm(ctx context.Context, tlsCfg *tls.Config, t ConfirmTarget, revision int64, operation, inputsHash string) (wire.Confirmation, time.Time, error) {
	chal := make([]byte, 16)
	if _, err := rand.Read(chal); err != nil {
		return wire.Confirmation{}, time.Time{}, err
	}

	req := wire.ConfirmRequest{
		Version: wire.Version, FSID: c.Self.FSID, Session: c.Session, Host: c.Self.Name,
		Revision: revision, Operation: operation, InputsHash: inputsHash, Challenge: hex.EncodeToString(chal),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return wire.Confirmation{}, time.Time{}, err
	}

	// the module must be the named mgr of this cluster; its key signs the answer
	var peer *x509.Certificate

	cfg := tlsCfg.Clone()
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no server certificate")
		}

		if _, err := pki.Require(cs.PeerCertificates[0], pki.Identity{FSID: c.Self.FSID, Role: pki.RoleMgr, Name: t.Mgr}); err != nil {
			return err
		}

		if err := c.CRL.Check(cs.PeerCertificates[0]); err != nil {
			return err
		}

		peer = cs.PeerCertificates[0]

		return nil
	}

	sent := c.now()
	until := sent.Add(ConfirmValidity)

	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+net.JoinHostPort(t.Addr, dialPort())+"/v1/confirm", bytes.NewReader(body))
	if err != nil {
		return wire.Confirmation{}, time.Time{}, err
	}

	hreq.Header.Set("Content-Type", "application/json")

	resp, err := cl.Do(hreq)
	if err != nil {
		return wire.Confirmation{}, time.Time{}, fmt.Errorf("no confirmation: %w", err)
	}

	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return wire.Confirmation{}, time.Time{}, err
	}

	if resp.StatusCode != http.StatusOK {
		return wire.Confirmation{}, time.Time{}, fmt.Errorf("no confirmation: module answered %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}

	conf, err := verifyConfirmation(raw, peer, t.Mgr, req)
	if err != nil {
		return wire.Confirmation{}, time.Time{}, err
	}

	if !c.now().Before(until) {
		return wire.Confirmation{}, time.Time{}, errors.New("confirmation arrived after its validity")
	}

	return conf, until, nil
}

// verifyConfirmation checks the signature over the exact payload bytes with the
// mgr's server key, then that the payload confirms exactly this challenge.
func verifyConfirmation(raw []byte, peer *x509.Certificate, mgr string, req wire.ConfirmRequest) (wire.Confirmation, error) {
	if peer == nil {
		return wire.Confirmation{}, errors.New("no verified mgr certificate")
	}

	var reply wire.ConfirmReply
	if err := json.Unmarshal(raw, &reply); err != nil {
		return wire.Confirmation{}, fmt.Errorf("malformed confirmation: %w", err)
	}

	payload, err := base64.StdEncoding.DecodeString(reply.Payload)
	if err != nil {
		return wire.Confirmation{}, fmt.Errorf("malformed confirmation payload: %w", err)
	}

	sig, err := base64.StdEncoding.DecodeString(reply.Signature)
	if err != nil {
		return wire.Confirmation{}, fmt.Errorf("malformed confirmation signature: %w", err)
	}

	pub, ok := peer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return wire.Confirmation{}, errors.New("the mgr's key is not ECDSA")
	}

	sum := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return wire.Confirmation{}, errors.New("confirmation signature does not verify")
	}

	var conf wire.Confirmation

	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&conf); err != nil {
		return wire.Confirmation{}, fmt.Errorf("malformed confirmation: %w", err)
	}

	if conf.Version != wire.Version || conf.FSID != req.FSID || conf.Session != req.Session || conf.Host != req.Host ||
		conf.Revision != req.Revision || conf.Operation != req.Operation || conf.InputsHash != req.InputsHash ||
		conf.Challenge != req.Challenge || conf.Mgr != mgr || conf.GID <= 0 || conf.Epoch <= 0 {
		return wire.Confirmation{}, errors.New("confirmation does not match the challenge")
	}

	return conf, nil
}

// ClientTLSConfig is the agent's client side of the agent channel: its client
// certificate, and only servers issued by the agent CA.
func ClientTLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("agent client certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("agent CA: no certificate found")
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}
