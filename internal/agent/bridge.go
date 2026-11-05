package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nberlee/cephadm-talos/internal/approval"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// MaxBridgeDeadline is the longest a bridge call waits for its answer; the
// module refuses longer ones (bridge.py MAX_BRIDGE_DEADLINE).
const MaxBridgeDeadline = 10 * time.Second

// BridgeMaxValue is the largest config-key value one bridge call carries
// (bridge.py MAX_VALUE).
const BridgeMaxValue = 48 << 10

// maxBridgeReply bounds a bridge answer: the module keeps at most 256 KiB of
// output, which JSON escaping can grow.
const maxBridgeReply = 2 << 20

// ErrOutcomeUnknown means a bridge call may or may not have run: its deadline
// passed, or the connection failed after the request may have been sent. Its
// outcome can be fetched by dispatch id while the module keeps it.
var ErrOutcomeUnknown = errors.New("bridge: outcome unknown")

// ErrDispatchUnknown means the module has no record of a dispatch id: never
// received, expired, or lost with a restart of the mgr.
var ErrDispatchUnknown = errors.New("bridge: dispatch id unknown to the module")

// errOutcomePending marks an unknown outcome the module itself reported: the
// call is still running there.
var errOutcomePending = errors.New("still running")

// errBridgeRan marks a call that ran (its commands were sent) but has no
// output to give: an outcome all the same.
var errBridgeRan = errors.New("bridge")

// errBridgeBad marks a call the module refused with 400: not allowed for what
// its ledger shows, as distinct from one to ask again (409, 429, 503).
var errBridgeBad = errors.New("bridge")

// BridgeResult is a mon command's result through the bridge.
type BridgeResult struct {
	R    int
	Out  string
	Outs string
}

// Bridge is the leader's client for the module's bridge in the active mgr on
// its own host (plan 03, item 2): allowlisted mon commands with the mgr's
// credentials.
type Bridge struct {
	TLS  *tls.Config // the agent's client certificate and the agent CA
	Addr string      // the mgr host's address: the agent's own host, or 127.0.0.1
	Mgr  string      // the mgr's name, its certificate's identity
	FSID string
	// CRL refuses a module whose server certificate the agent's list names
	// (plan 04, step 3); nil checks its validity only
	CRL *crl.Holder

	// Intents keeps a record of every mutating call before it is made, until
	// its outcome is known (plan 03, step 7 slice D); nil keeps none (tests).
	// GID and Epoch are the leader's incarnation, which the records name.
	Intents    *records.Store
	GID, Epoch int64
	// ops are the daemon and host of each executable operation the ledger
	// returned, for the intents
	ops map[string][2]string
	// snapshot is the key of the ledger snapshot the last page followed, ""
	// without one: every operation at or below it is finished (plan 04, step 4)
	snapshot string
}

// intentRecord prefixes the bridge intents in the agent's records.
const intentRecord = "bridge-"

// intentCalls are the calls that change the cluster outside the leader's own
// journal: each gets an intent. The journal writes (config-key set and rm
// below the incarnation) do not: a takeover freezes that namespace.
var intentCalls = map[string]bool{
	"auth get-or-create": true, "mgr cert": true, "retire": true, "retire host": true, "bind disk": true,
	"confirm osd": true, "close create": true, "osd out": true, "drain": true, "mon rm": true,
	"noout set": true, "noout unset": true, "maintained": true, "mgr fail": true, "upgrade done": true,
	"upgrade refused": true, "rgw cert": true, "rgw cert done": true, "retire keepalived": true, "mgr cert done": true,
	"agent cert": true, "agent cert done": true, "drain done": true, "retire start": true, "retire done": true,
}

// intend records a call's intent before it is made.
func (b *Bridge) intend(dispatch, call string, args map[string]any) error {
	if b.Intents == nil || !intentCalls[call] {
		return nil
	}

	in := wire.BridgeIntent{Version: wire.Version, Dispatch: dispatch, Call: call, GID: b.GID, Epoch: b.Epoch, At: time.Now().UnixNano()}
	if op, ok := args["operation"].(string); ok {
		in.Operation = op
		in.Daemon, in.Host = b.ops[op][0], b.ops[op][1]
	}

	if d, ok := args["daemon"].(string); ok && d != "" {
		in.Daemon = d
	}

	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}

	return b.Intents.Write(intentRecord+dispatch, raw)
}

// reserve names what the next calls of an operation change, for their intents.
func (b *Bridge) reserve(op, daemon, host string) {
	if b.ops == nil {
		b.ops = map[string][2]string{}
	}

	b.ops[op] = [2]string{daemon, host}
}

// settled removes a call's intent once its outcome is known: an answer, or a
// refusal before anything was sent. An unknown outcome keeps it.
func (b *Bridge) settled(dispatch string, err error) {
	if b.Intents == nil || errors.Is(err, ErrOutcomeUnknown) || errors.Is(err, ErrDispatchUnknown) {
		return
	}

	if rmErr := b.Intents.Remove(intentRecord + dispatch); rmErr != nil && !errors.Is(rmErr, records.ErrNotFound) {
		log.Printf("bridge: intent %s: %v", dispatch, rmErr)
	}
}

// OpenIntents returns the intents whose outcome is not known yet.
func OpenIntents(recs *records.Store) ([]wire.BridgeIntent, error) {
	names, err := recs.List(intentRecord)
	if err != nil {
		return nil, err
	}

	out := []wire.BridgeIntent{}

	for _, n := range names {
		raw, err := recs.Read(n)
		if errors.Is(err, records.ErrNotFound) {
			continue
		}

		if err != nil {
			return nil, err
		}

		var in wire.BridgeIntent
		if err := json.Unmarshal(raw, &in); err != nil || in.Dispatch != strings.TrimPrefix(n, intentRecord) {
			return nil, fmt.Errorf("record %s: damaged", n)
		}

		out = append(out, in)
	}

	return out, nil
}

// NewDispatchID returns a fresh dispatch id for a bridge call.
func NewDispatchID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func (b *Bridge) client() *http.Client {
	// the mgr's server certificate names its host: the leader dials its own
	// host's loopback address and checks that name besides the identity
	cfg := WithPeer(b.TLS, func(c *x509.Certificate) error {
		if err := c.VerifyHostname(b.Mgr); err != nil {
			return err
		}

		if _, err := pki.Require(c, pki.Identity{FSID: b.FSID, Role: pki.RoleMgr, Name: b.Mgr}); err != nil {
			return err
		}

		return b.CRL.Check(c)
	})
	cfg.ServerName = b.Mgr

	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}
}

func (b *Bridge) url(path string) string {
	return "https://" + net.JoinHostPort(b.Addr, bridgePort()) + path
}

// Call runs one allowlisted call under dispatch, a fresh id the caller may
// have persisted first. A call that does not complete within deadline returns
// ErrOutcomeUnknown; Outcome fetches it later.
func (b *Bridge) Call(ctx context.Context, dispatch, call string, args map[string]any, deadline time.Duration) (BridgeResult, error) {
	if deadline <= 0 || deadline > MaxBridgeDeadline {
		return BridgeResult{}, fmt.Errorf("bridge: deadline %s outside (0, %s]", deadline, MaxBridgeDeadline)
	}

	if args == nil {
		args = map[string]any{}
	}

	body, err := json.Marshal(wire.BridgeRequest{Version: wire.Version, Call: call, Args: args, Deadline: deadline.Seconds(), DispatchID: dispatch})
	if err != nil {
		return BridgeResult{}, err
	}

	if err := b.intend(dispatch, call, args); err != nil {
		return BridgeResult{}, fmt.Errorf("bridge: %s: recording its intent: %w", call, err)
	}

	// the module answers within its deadline; the connection gets a margin for the handshake
	ctx, cancel := context.WithTimeout(ctx, deadline+5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url("/v1/bridge"), bytes.NewReader(body))
	if err != nil {
		return BridgeResult{}, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client().Do(req)
	if err != nil {
		// the request may have reached the module before the connection failed
		return BridgeResult{}, fmt.Errorf("%w: %s %s: %w", ErrOutcomeUnknown, call, dispatch, err)
	}

	res, err := b.reply(resp, call, dispatch)
	b.settled(dispatch, err)

	return res, err
}

// Outcome fetches the outcome of an earlier call by its dispatch id.
func (b *Bridge) Outcome(ctx context.Context, dispatch string) (BridgeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, MaxBridgeDeadline)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url("/v1/bridge/"+dispatch), nil)
	if err != nil {
		return BridgeResult{}, err
	}

	resp, err := b.client().Do(req)
	if err != nil {
		return BridgeResult{}, fmt.Errorf("%w: %s: %w", ErrOutcomeUnknown, dispatch, err)
	}

	res, err := b.reply(resp, "outcome", dispatch)
	// only an outcome settles: another refusal of the fetch says nothing about the call
	if err == nil || errors.Is(err, errBridgeRan) {
		b.settled(dispatch, nil)
	}

	return res, err
}

func (b *Bridge) reply(resp *http.Response, call, dispatch string) (BridgeResult, error) {
	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBridgeReply+1))
	if err != nil {
		return BridgeResult{}, fmt.Errorf("%w: %s %s: %w", ErrOutcomeUnknown, call, dispatch, err)
	}

	if len(raw) > maxBridgeReply {
		return BridgeResult{}, fmt.Errorf("%w: %s %s: answer larger than %d bytes", ErrOutcomeUnknown, call, dispatch, maxBridgeReply)
	}

	switch {
	case resp.StatusCode == http.StatusNotFound && call == "outcome":
		return BridgeResult{}, fmt.Errorf("%w: %s", ErrDispatchUnknown, dispatch)
	case resp.StatusCode != http.StatusOK:
		// refused before anything was sent to the mons
		if resp.StatusCode == http.StatusBadRequest {
			return BridgeResult{}, fmt.Errorf("%w: %s refused: %d %s", errBridgeBad, call, resp.StatusCode, bytes.TrimSpace(raw))
		}

		return BridgeResult{}, fmt.Errorf("bridge: %s refused: %d %s", call, resp.StatusCode, bytes.TrimSpace(raw))
	}

	var r struct {
		Outcome string `json:"outcome"`
		R       int    `json:"r"`
		Out     string `json:"out"`
		Outs    string `json:"outs"`
		Error   string `json:"error"`
	}

	if err := json.Unmarshal(raw, &r); err != nil {
		return BridgeResult{}, fmt.Errorf("%w: %s %s: %w", ErrOutcomeUnknown, call, dispatch, err)
	}

	switch r.Outcome {
	case "done":
		if r.Error != "" { // ran, but its output was not kept, or failed after sending
			return BridgeResult{R: r.R}, fmt.Errorf("%w: %s: %s", errBridgeRan, call, r.Error)
		}

		return BridgeResult{R: r.R, Out: r.Out, Outs: r.Outs}, nil
	case "unknown":
		return BridgeResult{}, fmt.Errorf("%w: %w: %s %s", ErrOutcomeUnknown, errOutcomePending, call, dispatch)
	default:
		return BridgeResult{}, fmt.Errorf("%w: %s %s: outcome %q", ErrOutcomeUnknown, call, dispatch, r.Outcome)
	}
}

// do runs one call with a fresh dispatch id and requires success.
func (b *Bridge) do(ctx context.Context, call string, args map[string]any) (string, error) {
	id, err := NewDispatchID()
	if err != nil {
		return "", err
	}

	res, err := b.Call(ctx, id, call, args, MaxBridgeDeadline)
	if err != nil {
		return "", err
	}

	if res.R != 0 {
		return "", fmt.Errorf("bridge: %s: %s (%d)", call, strings.TrimSpace(res.Outs), res.R)
	}

	return res.Out, nil
}

// BridgeStore is the leader's store backend through the bridge. It reads
// without a snapshot (the module returns at most 256 KiB per call, too little
// for a dump of two publications), which is safe for the readers it has: the
// leader reads its own incarnation, of which it is the only writer, and a
// predecessor's incarnation after that one is frozen (store.Backend).
type BridgeStore struct {
	b      *Bridge
	prefix string
	limit  int
}

// Store returns the bridge backend for keys below prefix.
func (b *Bridge) Store(ctx context.Context, prefix string) (*BridgeStore, error) {
	out, err := b.do(ctx, "entry limit", nil)
	if err != nil {
		return nil, err
	}

	n, err := parseLimit(out)
	if err != nil {
		return nil, err
	}

	return &BridgeStore{b: b, prefix: prefix, limit: n}, nil
}

func (s *BridgeStore) inside(key string) error {
	if !strings.HasPrefix(key, s.prefix) {
		return fmt.Errorf("config-key %s is outside %s", key, s.prefix)
	}

	return nil
}

// EntryLimit is the mons' entry limit, capped by what one bridge call carries.
func (s *BridgeStore) EntryLimit() int { return min(s.limit, BridgeMaxValue) }

func (s *BridgeStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err := s.inside(key); err != nil {
		return nil, err
	}

	id, err := NewDispatchID()
	if err != nil {
		return nil, err
	}

	res, err := s.b.Call(ctx, id, "config-key get", map[string]any{"key": key}, MaxBridgeDeadline)
	if err != nil {
		return nil, err
	}

	switch res.R {
	case 0:
		return []byte(res.Out), nil
	case -2: // ENOENT
		return nil, store.ErrNotFound
	}

	return nil, fmt.Errorf("bridge: config-key get %s: %s (%d)", key, strings.TrimSpace(res.Outs), res.R)
}

func (s *BridgeStore) List(ctx context.Context, prefix string) ([]string, error) {
	if err := s.inside(prefix); err != nil {
		return nil, err
	}

	// in pages, each below the module's output limit
	var keys []string

	for after := ""; ; {
		out, err := s.b.do(ctx, "config-key keys", map[string]any{"prefix": prefix, "after": after})
		if err != nil {
			return nil, err
		}

		var page struct {
			Keys []string `json:"keys"`
			More bool     `json:"more"`
		}

		if err := json.Unmarshal([]byte(out), &page); err != nil {
			return nil, fmt.Errorf("bridge: config-key keys %s: %w", prefix, err)
		}

		for _, k := range page.Keys {
			if !strings.HasPrefix(k, prefix) || k <= after {
				return nil, fmt.Errorf("bridge: config-key keys %s returned %s after %s", prefix, k, after)
			}

			after = k
		}

		keys = append(keys, page.Keys...)

		if !page.More {
			return keys, nil
		}

		if len(page.Keys) == 0 {
			return nil, fmt.Errorf("bridge: config-key keys %s: an empty page with more to come", prefix)
		}
	}
}

// SetMany writes one entry per call, in order. Each write is idempotent (the
// same value under the same key), so a publication may be repeated after an
// unknown outcome.
func (s *BridgeStore) SetMany(ctx context.Context, kvs []store.KV) error {
	for _, kv := range kvs {
		if err := s.inside(kv.Key); err != nil {
			return err
		}
	}

	for _, kv := range kvs {
		if _, err := s.b.do(ctx, "config-key set", map[string]any{"key": kv.Key, "value": string(kv.Value)}); err != nil {
			return err
		}
	}

	return nil
}

func (s *BridgeStore) Remove(ctx context.Context, keys []string) error {
	for _, k := range keys {
		if err := s.inside(k); err != nil {
			return err
		}
	}

	for _, k := range keys {
		if _, err := s.b.do(ctx, "config-key rm", map[string]any{"key": k}); err != nil {
			return err
		}
	}

	return nil
}

// AuthGet returns an entity's secret from mon auth, found false if it has none.
// Only the daemon identities the leader renders are allowed (no client.admin).
func (b *Bridge) AuthGet(ctx context.Context, entity string) (string, bool, error) {
	id, err := NewDispatchID()
	if err != nil {
		return "", false, err
	}

	res, err := b.Call(ctx, id, "auth get", map[string]any{"entity": entity}, MaxBridgeDeadline)
	if err != nil {
		return "", false, err
	}

	if res.R == -2 { // ENOENT
		return "", false, nil
	}

	if res.R != 0 {
		return "", false, fmt.Errorf("bridge: auth get %s: %s (%d)", entity, strings.TrimSpace(res.Outs), res.R)
	}

	k, err := parseAuth(res.Out, entity)

	return k, err == nil, err
}

// Secret returns one of the cluster's secrets the leader renders into a
// document (a mgr host's TLS keys, the RGW serving key, the VRRP password),
// or an agent's keys for the renewal of its certificates it carries out; the
// module releases no other, never the CA keys.
func (b *Bridge) Secret(ctx context.Context, name string) (string, error) {
	id, err := NewDispatchID()
	if err != nil {
		return "", err
	}

	res, err := b.Call(ctx, id, "secret get", map[string]any{"name": name}, MaxBridgeDeadline)
	if err != nil {
		return "", err
	}

	if res.R != 0 || res.Out == "" {
		// never the module's message: it might quote a value
		return "", fmt.Errorf("bridge: secret %s not available (%d)", name, res.R)
	}

	return res.Out, nil
}

// LedgerEntry is one operation the module accepted (internal/mgrmodule ledger.py).
type LedgerEntry struct {
	Key string
	Op  LedgerOp
}

// LedgerOp is an operation entry of the ledger.
type LedgerOp struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Daemon  string `json:"daemon"`
	Host    string `json:"host"`
	GID     int64  `json:"gid"`
	Epoch   int64  `json:"epoch"`
	Seq     int64  `json:"seq"`
	Request string `json:"request,omitempty"`
	Device  string `json:"device,omitempty"` // create_osd: the disk as the operator named it
	// remove_osd: the OSD's uuid, and whether to zap and to skip the safety check
	UUID  string `json:"uuid,omitempty"`
	Zap   bool   `json:"zap,omitempty"`
	Force bool   `json:"force,omitempty"`
	// upgrade_start: the target image; the controls: the start they control
	Image   string `json:"image,omitempty"`
	Upgrade string `json:"upgrade,omitempty"`
	// add_daemon of an RGW: its port, and the operator's certificate chain
	Port int    `json:"port,omitempty"`
	Cert string `json:"cert,omitempty"`
	// apply_ingress: the VIP, router id, hosts in order, whether it set a new
	// password (the secret ingress/<op>/vrrp); its image in Image
	// add_host: the enrolled node's address, agent certificates and labels
	Addr            string   `json:"addr,omitempty"`
	AgentCert       string   `json:"agent_cert,omitempty"`
	AgentClientCert string   `json:"agent_client_cert,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	VIP             string   `json:"vip,omitempty"`
	VRID            int      `json:"vrid,omitempty"`
	Hosts           []string `json:"hosts,omitempty"`
	NewPassword     bool     `json:"new_password,omitempty"`
	// drain_stop, drain_resume: the drain they control (plan 04, step 5);
	// drain_host's --zap-osd-devices is Zap
	Drain string `json:"drain,omitempty"`
	// move_resume: the move it resumes (plan 04, step 5); set_host_addr's
	// new address is Addr
	Move string `json:"move,omitempty"`
}

// Ledger returns the executable operations after a ledger key, in the order
// they run, a page at a time; more reports whether a later page exists.
func (b *Bridge) Ledger(ctx context.Context, after string) (entries []LedgerEntry, more bool, err error) {
	out, err := b.do(ctx, "ledger", map[string]any{"after": after})
	if err != nil {
		return nil, false, err
	}

	var page struct {
		Entries  [][2]json.RawMessage `json:"entries"`
		More     bool                 `json:"more"`
		Snapshot string               `json:"snapshot"`
	}

	if err := json.Unmarshal([]byte(out), &page); err != nil {
		return nil, false, fmt.Errorf("bridge: ledger: %w", err)
	}

	b.snapshot = page.Snapshot

	prev := after

	for _, raw := range page.Entries {
		var e LedgerEntry
		if err := json.Unmarshal(raw[0], &e.Key); err != nil || e.Key <= prev {
			return nil, false, fmt.Errorf("bridge: ledger: keys out of order")
		}

		if err := json.Unmarshal(raw[1], &e.Op); err != nil {
			return nil, false, fmt.Errorf("bridge: ledger entry %s: %w", e.Key, err)
		}

		entries, prev = append(entries, e), e.Key

		if b.ops == nil {
			b.ops = map[string][2]string{}
		}

		b.ops[e.Op.ID] = [2]string{e.Op.Daemon, e.Op.Host}
	}

	return entries, page.More, nil
}

// LedgerAbove returns the snapshot key and the ids of every executable
// operation above it (plan 04, step 4): an operation id of the ledger that is
// not among them is at or below the snapshot, so finished. "" without a
// snapshot.
func (b *Bridge) LedgerAbove(ctx context.Context) (string, map[string]bool, error) {
	ids := map[string]bool{}
	after, snap := "", ""

	for first := true; ; first = false {
		entries, more, err := b.Ledger(ctx, after)
		if err != nil {
			return "", nil, err
		}

		if first {
			snap = b.snapshot
		} else if b.snapshot != snap {
			return "", nil, fmt.Errorf("%w: the ledger was compacted while it was read", errRetry)
		}

		for _, e := range entries {
			ids[e.Op.ID] = true
			after = e.Key
		}

		if !more || len(entries) == 0 {
			return snap, ids, nil
		}
	}
}

// MgrCerts are certificates the module issued for a mgr (bridge.py
// issue_mgr_certs); their keys are secrets of the attempt.
type MgrCerts struct {
	Attempt    string `json:"attempt"`
	ServerCert string `json:"server_cert"`
	ClientCert string `json:"client_cert"`
}

// MgrCert asks the module for the certificates of a mgr an accepted add
// deploys, or a renewal renews (asked again, a renewal returns the same ones).
func (b *Bridge) MgrCert(ctx context.Context, op string) (MgrCerts, error) {
	out, err := b.do(ctx, "mgr cert", map[string]any{"operation": op})
	if err != nil {
		return MgrCerts{}, err
	}

	var c MgrCerts
	if err := json.Unmarshal([]byte(out), &c); err != nil || c.Attempt == "" || c.ServerCert == "" || c.ClientCert == "" {
		return MgrCerts{}, errors.New("bridge: mgr cert: malformed answer")
	}

	return c, nil
}

// MgrCertDone tells the module that a renewal's mgr certificates are the
// ones in use: that mgr's other certificates are revoked, with certs, the
// ones before the renewal the leader journaled (plan 04, step 3), and their
// keys removed.
func (b *Bridge) MgrCertDone(ctx context.Context, op string, certs []string) error {
	_, err := b.do(ctx, "mgr cert done", withCerts(map[string]any{"operation": op}, certs))

	return err
}

// withCerts adds the certificates to revoke to a call's arguments.
func withCerts(args map[string]any, certs []string) map[string]any {
	var list []string

	for _, c := range certs {
		if c != "" {
			list = append(list, c)
		}
	}

	if len(list) > 0 {
		args["certs"] = list
	}

	return args
}

// AgentCerts are an agent's certificates the module issued for its renewal
// (plan 04, step 2); their keys are secrets of the attempt.
type AgentCerts struct {
	Attempt    string `json:"attempt"`
	ServerCert string `json:"server_cert"`
	ClientCert string `json:"client_cert"`
}

// AgentCert asks the module for the certificates of an agent its renewal
// renews; asked again, it returns the same ones.
func (b *Bridge) AgentCert(ctx context.Context, op string) (AgentCerts, error) {
	out, err := b.do(ctx, "agent cert", map[string]any{"operation": op})
	if err != nil {
		return AgentCerts{}, err
	}

	var c AgentCerts
	if err := json.Unmarshal([]byte(out), &c); err != nil || c.Attempt == "" || c.ServerCert == "" || c.ClientCert == "" {
		return AgentCerts{}, errors.New("bridge: agent cert: malformed answer")
	}

	return c, nil
}

// AgentCertDone tells the module that a renewal's agent certificates are the
// ones in use: that agent's other certificates are revoked, with certs, the
// ones before the renewal, and their keys removed.
func (b *Bridge) AgentCertDone(ctx context.Context, op string, certs []string) error {
	_, err := b.do(ctx, "agent cert done", withCerts(map[string]any{"operation": op}, certs))

	return err
}

// RGWCert is a generated RGW serving certificate the module issued for an
// operation: its attempt and the certificate chain.
type RGWCert struct {
	Attempt string `json:"attempt"`
	Cert    string `json:"cert"`
}

// RGWCert asks the module for a generated RGW serving certificate for an RGW
// add, an ingress apply or a renewal; asked again, it returns the same one.
func (b *Bridge) RGWCert(ctx context.Context, op string) (RGWCert, error) {
	out, err := b.do(ctx, "rgw cert", map[string]any{"operation": op})
	if err != nil {
		return RGWCert{}, err
	}

	var c RGWCert
	if err := json.Unmarshal([]byte(out), &c); err != nil || c.Attempt == "" || c.Cert == "" {
		return RGWCert{}, errors.New("bridge: rgw cert: malformed answer")
	}

	return c, nil
}

// RGWCertDone tells the module which certificate every RGW renders after an
// operation's roll: the ones before it are retired and their keys removed.
func (b *Bridge) RGWCertDone(ctx context.Context, op, keep string) error {
	_, err := b.do(ctx, "rgw cert done", map[string]any{"operation": op, "keep": keep})

	return err
}

// RetireKeepalived asks the module to retire a keepalived an ingress apply
// left out, once its document and instance are gone.
func (b *Bridge) RetireKeepalived(ctx context.Context, op, daemon string) error {
	_, err := b.do(ctx, "retire keepalived", map[string]any{"operation": op, "daemon": daemon})

	return err
}

// Retire asks the module to retire what an accepted removal removed: call
// "retire" for a daemon (auth rm, its keys), "retire host" for a host.
func (b *Bridge) Retire(ctx context.Context, call, op string) error {
	_, err := b.do(ctx, call, map[string]any{"operation": op})

	return err
}

// EnrollCerts are the certificates a host's enrollment record carries
// (cephadm-talos/enroll/<host>), "" without one.
type EnrollCerts struct {
	AgentCert       string `json:"agent_cert"`
	AgentClientCert string `json:"agent_client_cert"`
}

// RetireStart tells the module that an accepted host removal begins its
// retirement (plan 04, step 6): the module marks the host retiring in its
// fold, with the certificates its enrollment record carries now, and returns
// them. Asked again, it returns the ones it recorded.
func (b *Bridge) RetireStart(ctx context.Context, op string) (EnrollCerts, error) {
	out, err := b.do(ctx, "retire start", map[string]any{"operation": op})
	if err != nil {
		return EnrollCerts{}, err
	}

	var c EnrollCerts
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		return EnrollCerts{}, errors.New("bridge: retire start: malformed answer")
	}

	return c, nil
}

// RetireDone ends a host's retirement (plan 04, step 6): the module revokes
// certs (the agent certificates the removal journaled), its enrollment
// record's and every issuance of the host's agent before it deletes their
// keys (the CLI's only if they match certs or the enrollment record's), the
// enrollment record if it still carries the certificates recorded at the
// start, then retires the host. Idempotent.
func (b *Bridge) RetireDone(ctx context.Context, op string, certs []string) error {
	_, err := b.do(ctx, "retire done", withCerts(map[string]any{"operation": op}, certs))

	return err
}

// RetireWith is Retire of a daemon with the certificates the leader
// journaled before it cleared them from the state, which the module revokes
// (a mgr's, plan 04 step 3).
func (b *Bridge) RetireWith(ctx context.Context, op string, certs []string) error {
	_, err := b.do(ctx, "retire", withCerts(map[string]any{"operation": op}, certs))

	return err
}

// RetireDaemon is Retire of one daemon of a drain's step (plan 04, step 5):
// call is "osd out", "drain", "retire" or "mon rm"; daemon "" for the drain's
// first step, every OSD of its host out at once.
func (b *Bridge) RetireDaemon(ctx context.Context, call, op, daemon string, certs []string) error {
	args := map[string]any{"operation": op}
	if daemon != "" {
		args["daemon"] = daemon
	}

	if call == "retire" {
		args = withCerts(args, certs)
	}

	_, err := b.do(ctx, call, args)

	return err
}

// Approval returns the newest approval of the operator in config-key, nil if
// there is none (the module reads it; the agents verify it).
func (b *Bridge) Approval(ctx context.Context) (*approval.Signed, error) {
	out, err := b.do(ctx, "approval", map[string]any{})
	if err != nil {
		return nil, err
	}

	if out == "" {
		return nil, nil
	}

	var s approval.Signed
	if err := json.Unmarshal([]byte(out), &s); err != nil || s.Payload == "" {
		return nil, errors.New("bridge: approval: malformed")
	}

	return &s, nil
}

// BindDisk asks the module to bind an accepted OSD creation to its disk and
// preparation job (once; the same binding again is no change).
func (b *Bridge) BindDisk(ctx context.Context, op, serial, link, job string) error {
	_, err := b.do(ctx, "bind disk", map[string]any{"operation": op, "serial": serial, "link": link, "job": job})

	return err
}

// OSD is an OSD of the OSD map, with the IPs it advertises.
type OSD struct {
	ID          int    `json:"osd"`
	UUID        string `json:"uuid"`
	Up          bool   `json:"up"`
	PublicAddr  string `json:"public_addr,omitempty"`
	ClusterAddr string `json:"cluster_addr,omitempty"`
}

// MoveAddr asks the module to set a moved mgr's or OSD's address settings
// (public_addr, an OSD's cluster_addr too) to its host's new address in the
// monitors' configuration database, for a move's step (plan 04, step 5).
func (b *Bridge) MoveAddr(ctx context.Context, op, daemon string) error {
	_, err := b.do(ctx, "move addr", map[string]any{"operation": op, "daemon": daemon})

	return err
}

// OSDs returns the OSD map's OSDs.
func (b *Bridge) OSDs(ctx context.Context) ([]OSD, error) {
	out, err := b.do(ctx, "osd dump", map[string]any{})
	if err != nil {
		return nil, err
	}

	var osds []OSD
	if err := json.Unmarshal([]byte(out), &osds); err != nil {
		return nil, fmt.Errorf("bridge: osd dump: %w", err)
	}

	return osds, nil
}

// AuthGetFor returns a key an accepted operation needs (client.bootstrap-osd
// for an OSD creation).
func (b *Bridge) AuthGetFor(ctx context.Context, entity, op string) (string, error) {
	out, err := b.do(ctx, "auth get", map[string]any{"entity": entity, "operation": op})
	if err != nil {
		return "", err
	}

	return parseAuth(out, entity)
}

// Quorum returns the names of the mons in quorum.
func (b *Bridge) Quorum(ctx context.Context) ([]string, error) {
	out, err := b.do(ctx, "status", map[string]any{})
	if err != nil {
		return nil, err
	}

	var st struct {
		Quorum []string `json:"quorum_names"`
	}

	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return nil, fmt.Errorf("bridge: status: %w", err)
	}

	return st.Quorum, nil
}

// ActiveMgr returns the name of the active mgr.
func (b *Bridge) ActiveMgr(ctx context.Context) (string, error) {
	name, _, err := b.ActiveMgrGID(ctx)

	return name, err
}

// ActiveMgrGID returns the active mgr's name and gid.
func (b *Bridge) ActiveMgrGID(ctx context.Context) (string, int64, error) {
	name, gid, _, err := b.MgrMap(ctx)

	return name, gid, err
}

// MgrMap returns the active mgr's name and gid, and the standbys' names.
func (b *Bridge) MgrMap(ctx context.Context) (string, int64, []string, error) {
	active, gid, standbys, err := b.mgrDump(ctx)

	var names []string
	for _, s := range standbys {
		names = append(names, s.Name)
	}

	return active, gid, names, err
}

// MgrGIDs returns the active mgr's name and gid, and each standby's gid by name.
func (b *Bridge) MgrGIDs(ctx context.Context) (string, int64, map[string]int64, error) {
	active, gid, standbys, err := b.mgrDump(ctx)

	gids := map[string]int64{}
	for _, s := range standbys {
		gids[s.Name] = s.GID
	}

	return active, gid, gids, err
}

type standby struct {
	Name string `json:"name"`
	GID  int64  `json:"gid"`
}

type mgrMap struct {
	ActiveName string    `json:"active_name"`
	ActiveGID  int64     `json:"active_gid"`
	ActiveAddr string    `json:"active_addr"`
	Standbys   []standby `json:"standbys"`
}

func (b *Bridge) mgrDump(ctx context.Context) (string, int64, []standby, error) {
	m, err := b.mgrMap(ctx)

	return m.ActiveName, m.ActiveGID, m.Standbys, err
}

func (b *Bridge) mgrMap(ctx context.Context) (mgrMap, error) {
	out, err := b.do(ctx, "mgr dump", map[string]any{})
	if err != nil {
		return mgrMap{}, err
	}

	var m mgrMap
	if err := json.Unmarshal([]byte(out), &m); err != nil || m.ActiveName == "" {
		return mgrMap{}, errors.New("bridge: mgr dump: no active mgr")
	}

	return m, nil
}

// ActiveMgrAddr returns the active mgr's name, gid and the IP it advertises
// (the mgr map shows an address for the active mgr only).
func (b *Bridge) ActiveMgrAddr(ctx context.Context) (string, int64, string, error) {
	m, err := b.mgrMap(ctx)
	if err != nil {
		return "", 0, "", err
	}

	// "<ip>:<port>/<nonce>", an IPv6 address in brackets
	addr, _, _ := strings.Cut(m.ActiveAddr, "/")
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		addr = addr[:i]
	}

	return m.ActiveName, m.ActiveGID, strings.Trim(addr, "[]"), nil
}

// OKToStop asks the module for Ceph's check that one daemon of an upgrade's
// step can stop (osd and mon ok-to-stop; nothing to check for the others).
func (b *Bridge) OKToStop(ctx context.Context, op, daemon string) error {
	_, err := b.do(ctx, "ok to stop daemon", map[string]any{"operation": op, "daemon": daemon})

	return err
}

// MgrFail asks the module to fail the active mgr over (by its gid) for an
// operation that must stop it; the active mgr respawns, so the answer may
// never come.
func (b *Bridge) MgrFail(ctx context.Context, op string, gid int64, mgr, host string) error {
	// the intent names the mgr it fails over: the operation (an upgrade's
	// start, a maintenance) may name another daemon or none
	b.reserve(op, "mgr."+mgr, host)

	_, err := b.do(ctx, "mgr fail", map[string]any{"operation": op, "gid": gid})

	return err
}

// AuthGetOrCreate returns the secret of a mgr or RGW identity, created with
// the caps the module fixes for its type if mon auth has none; op is the
// accepted add whose daemon it is.
func (b *Bridge) AuthGetOrCreate(ctx context.Context, entity, op string) (string, error) {
	out, err := b.do(ctx, "auth get-or-create", map[string]any{"entity": entity, "operation": op})
	if err != nil {
		return "", err
	}

	return parseAuth(out, entity)
}

// parseLimit reads `config get` of the entry limit, a JSON number or string.
func parseLimit(out string) (int, error) {
	var v any

	dec := json.NewDecoder(strings.NewReader(out))
	dec.UseNumber()

	if err := dec.Decode(&v); err != nil {
		return 0, fmt.Errorf("bridge: entry limit %q: %w", out, err)
	}

	var s string

	switch x := v.(type) {
	case json.Number:
		s = x.String()
	case string:
		s = x
	}

	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bridge: entry limit %q is not a positive integer", out)
	}

	return n, nil
}

func parseAuth(out, entity string) (string, error) {
	var ents []struct {
		Entity string `json:"entity"`
		Key    string `json:"key"`
	}

	if err := json.Unmarshal([]byte(out), &ents); err != nil || len(ents) != 1 || ents[0].Entity != entity || ents[0].Key == "" {
		return "", fmt.Errorf("bridge: auth %s: unexpected answer", entity)
	}

	return ents[0].Key, nil
}
