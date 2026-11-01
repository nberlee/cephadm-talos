package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
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
	cfg := b.TLS.Clone()
	// the mgr's server certificate names its host: the leader dials its own
	// host's loopback address
	cfg.ServerName = b.Mgr
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no server certificate")
		}

		_, err := pki.Require(cs.PeerCertificates[0], pki.Identity{FSID: b.FSID, Role: pki.RoleMgr, Name: b.Mgr})

		return err
	}

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

	return b.reply(resp, call, dispatch)
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

	return b.reply(resp, "outcome", dispatch)
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
		if r.Error != "" { // ran, but its output was not kept
			return BridgeResult{R: r.R}, fmt.Errorf("bridge: %s: %s", call, r.Error)
		}

		return BridgeResult{R: r.R, Out: r.Out, Outs: r.Outs}, nil
	case "unknown":
		return BridgeResult{}, fmt.Errorf("%w: %s %s", ErrOutcomeUnknown, call, dispatch)
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
// document (a mgr host's TLS keys, the RGW serving key, the VRRP password);
// the module releases no other, never the CA keys or agent keys.
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
}

// Ledger returns the executable operations after a ledger key, in the order
// they run, a page at a time; more reports whether a later page exists.
func (b *Bridge) Ledger(ctx context.Context, after string) (entries []LedgerEntry, more bool, err error) {
	out, err := b.do(ctx, "ledger", map[string]any{"after": after})
	if err != nil {
		return nil, false, err
	}

	var page struct {
		Entries [][2]json.RawMessage `json:"entries"`
		More    bool                 `json:"more"`
	}

	if err := json.Unmarshal([]byte(out), &page); err != nil {
		return nil, false, fmt.Errorf("bridge: ledger: %w", err)
	}

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
	}

	return entries, page.More, nil
}

// AuthGetOrCreate returns the secret of a mgr or RGW identity, created with
// the caps the module fixes for its type if mon auth has none.
func (b *Bridge) AuthGetOrCreate(ctx context.Context, entity string) (string, error) {
	out, err := b.do(ctx, "auth get-or-create", map[string]any{"entity": entity})
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
