package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nberlee/cephadm-talos/internal/approval"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/config/config"

	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// The leader (plan 03, items 1, 5 and 6) runs in the agent beside the active
// mgr, while that mgr's module heartbeats it. It keeps a journal under its
// incarnation (the mgr's gid) in the module's config-key namespace, reached
// through the bridge: requests under req/<id>, which the module writes, and
// the leader's operations under op/<id>. In this step the leader carries out
// one kind of request, a host revision: it renders the host's documents from
// the cluster state the CLI publishes (incarnation "cli", read only), grants
// what the host does not have yet, and records the outcome. Rendered documents
// carry keys and are never written to the journal, only their hashes.

// Journal record versions and kinds.
const (
	journalVersion = 1
	// KindRevision is a request to make a host's documents match the cluster state
	KindRevision = "revision"
)

// leaderFresh is how long a heartbeat keeps the agent the leader.
const leaderFresh = 15 * time.Second

// Journal operation states, besides the agent's (wire.Op*).
const (
	// JournalGranting: the grant is being sent; its outcome is not recorded yet
	JournalGranting = "granting"
	// JournalNoChange: the host already has the rendered documents
	JournalNoChange = "nochange"
	// JournalFailed: nothing was sent (render, pre-check or state error)
	JournalFailed = "failed"
)

// Request is a journal request (req/<id>).
type Request struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Host    string `json:"host"`
}

// JournalOp is the leader's record of a request (op/<id>).
type JournalOp struct {
	Version  int    `json:"version"`
	Kind     string `json:"kind"`
	Host     string `json:"host"`
	State    string `json:"state"`
	Revision int64  `json:"revision,omitempty"`
	// Seq is the cluster state publication the revision was rendered from
	Seq int64 `json:"seq,omitempty"`
	// Docs are the granted documents' hashes, "" for a removal
	Docs  map[string]string `json:"docs,omitempty"`
	Error string            `json:"error,omitempty"`
	// a job's grant: the job and its result as the agent read it
	Job    *wire.JobRef    `json:"job,omitempty"`
	Result *wire.JobResult `json:"result,omitempty"`
	// MgrGID is the active mgr a `mgr fail` phase asked the module to fail over
	MgrGID int64 `json:"mgr_gid,omitempty"`
}

// Takeover is a new leader's progress in taking over from earlier
// incarnations (plan 03, item 6), in its journal under "takeover": the hosts
// whose sessions it closed, and whether it imported its predecessors'
// unresolved operations and undecided requests.
type Takeover struct {
	Version int `json:"version"`
	// Epoch is the incarnation's captured mgrmap epoch: a later takeover
	// imports only from incarnations with a lower one
	Epoch    int64    `json:"epoch"`
	Closed   []string `json:"closed"`
	Imported bool     `json:"imported"`
	// Published: the cluster state is under this incarnation, copied from
	// From's publication FromSeq; from then on this incarnation writes it
	Published bool   `json:"published"`
	From      string `json:"from,omitempty"`
	FromSeq   int64  `json:"from_seq,omitempty"`
}

// JournalPrefix is an incarnation's journal in config-key.
func JournalPrefix(gid int64) string {
	return store.Prefix + "inc/" + strconv.FormatInt(gid, 10) + "/journal/"
}

// LeaderLoop is the leader's loop.
type LeaderLoop struct {
	Self      pki.Identity
	Channel   *Channel
	ClientTLS *tls.Config
	// Policy inputs for the pre-check of a revision: the agents check it again
	Repos  []string
	CACert string
	// CRL is the agent's installed revocation list: the leader refuses a
	// module or agent whose server certificate it names (plan 04, step 3)
	CRL *crl.Holder
	// Every is the tick; 0 is 5 seconds
	Every time.Duration

	// bridgeAddr is where the module listens: this host's loopback
	bridgeAddr string
	// failing: since when a ledger operation keeps failing (ledger.go)
	failing map[string]time.Time
	// ApprovalKey verifies the operator's approvals; approval is the newest
	// one the bridge returned this tick, which every grant carries
	ApprovalKey string
	approval    *approval.Signed
	appr        *approval.Approval
	// closed are the hosts whose earlier sessions this incarnation closed
	closed map[string]bool
	// holding is the host of the ledger operation in progress that orders its
	// host's documents itself (maintenance): its revision requests wait
	holding string
	// serves replaces the TLS handshake with an RGW in tests (servesCert)
	serves func(addr string, port int, chain string) bool
	// stateInc is the incarnation the cluster state is read from: the
	// leader's own once it published its baseline
	stateInc string
	// agentURL returns a host's agent; tests replace it
	agentURL func(h state.Host) string
	now      func() time.Time
	logf     func(format string, args ...any)

	// Records holds the bridge intents (nil: none, in tests); Suspended says
	// whether the agent is suspended, when no tick may run (plan 03, step 7
	// slice D)
	Records   *records.Store
	Suspended func() bool
	// OwnReport is the node report of the leader's own agent, read from its
	// node directly (nil: through the agent, as any other)
	OwnReport func(context.Context) (wire.NodeReport, error)
	// Boundary is the mgr map epoch of the last resumption's boundary: a
	// heartbeat of that epoch or before is from a process the resumption
	// replaced, and makes no tick (plan 03, step 7 slice D, item 10)
	Boundary func() int64
	// tickMu guards cancelTick and ticking: Pause cancels a running tick and
	// waits for it to return
	tickMu     sync.Mutex
	cancelTick context.CancelFunc
	ticking    chan struct{}
}

// paused reports whether the agent is suspended.
func (l *LeaderLoop) paused() bool { return l.Suspended != nil && l.Suspended() }

// replaced reports whether a heartbeat is from a mgr process the last
// resumption replaced: of its boundary's epoch or before.
func (l *LeaderLoop) replaced(lead *Leader) bool {
	return l.Boundary != nil && lead.Epoch <= l.Boundary()
}

// Pause cancels a running tick and waits until it returned; no tick starts
// while Suspended reports true, which the caller made so first.
func (l *LeaderLoop) Pause(ctx context.Context) error {
	l.tickMu.Lock()
	cancel, done := l.cancelTick, l.ticking
	l.tickMu.Unlock()

	if cancel == nil {
		return nil
	}

	cancel()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// tick runs one tick unless the agent is suspended, cancellable by Pause.
func (l *LeaderLoop) tick(ctx context.Context, lead *Leader) {
	l.tickMu.Lock()
	if l.paused() || l.replaced(lead) {
		l.tickMu.Unlock()

		return
	}

	tctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	l.cancelTick, l.ticking = cancel, done
	l.tickMu.Unlock()

	defer func() {
		l.tickMu.Lock()
		l.cancelTick, l.ticking = nil, nil
		l.tickMu.Unlock()
		cancel()
		close(done)
	}()

	if err := l.Tick(tctx, lead.GID, lead.Epoch); err != nil {
		l.log("%v", err)
	}
}

func (l *LeaderLoop) clock() time.Time {
	if l.now != nil {
		return l.now()
	}

	return time.Now()
}

func (l *LeaderLoop) log(format string, args ...any) {
	if l.logf != nil {
		l.logf(format, args...)

		return
	}

	log.Printf("leader: "+format, args...)
}

// Run ticks until ctx is done.
func (l *LeaderLoop) Run(ctx context.Context) {
	every := l.Every
	if every == 0 {
		every = 5 * time.Second
	}

	t := time.NewTicker(every)
	defer t.Stop()

	for {
		if lead := l.active(); lead != nil {
			l.tick(ctx, lead)
		}

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// active returns the heartbeat that makes this agent the leader, or nil.
func (l *LeaderLoop) active() *Leader {
	lead := l.Channel.Leader()
	if lead == nil || lead.Mgr != l.Self.Name || l.clock().Sub(lead.At) > leaderFresh {
		return nil
	}

	return lead
}

// stillLeader reports whether this agent is still the leader of the
// incarnation gid, captured at epoch.
func (l *LeaderLoop) stillLeader(gid, epoch int64) bool {
	lead := l.active()

	return lead != nil && lead.GID == gid && lead.Epoch == epoch
}

// errRetry marks an error the next tick retries: nothing was decided.
var errRetry = errors.New("retried on the next tick")

func (l *LeaderLoop) bridge() *Bridge {
	addr := l.bridgeAddr
	if addr == "" {
		addr = "127.0.0.1"
	}

	return &Bridge{TLS: l.ClientTLS, Addr: addr, Mgr: l.Self.Name, FSID: l.Self.FSID, Intents: l.Records, CRL: l.CRL}
}

// Tick takes over from earlier incarnations as far as it can, then carries
// out the incarnation's pending requests, in id order.
func (l *LeaderLoop) Tick(ctx context.Context, gid, epoch int64) error {
	b := l.bridge()
	b.GID, b.Epoch = gid, epoch
	prefix := JournalPrefix(gid)

	js, err := b.Store(ctx, prefix)
	if err != nil {
		return err
	}

	to, err := l.takeover(ctx, b, js, gid, epoch)
	if err != nil {
		return err
	}

	l.closed = map[string]bool{}
	for _, h := range to.Closed {
		l.closed[h] = true
	}

	// requests are carried out on this incarnation's own state only
	if !to.Published {
		return nil
	}

	// the operator's newest approval, for every grant of this tick
	if err := l.loadApproval(ctx, b); err != nil {
		return err
	}

	// every id with a request or an operation: an imported grant is resolved
	// even without its request
	keys, err := js.List(ctx, prefix)
	if err != nil {
		return err
	}

	seen := map[string]bool{}

	var ids []string

	for _, k := range keys {
		kind, id, ok := strings.Cut(strings.TrimPrefix(k, prefix), "/")
		if ok && (kind == "req" || kind == "op") && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	sort.Strings(ids)

	// the module's accepted operations first, in their own order
	if err := l.ledgerOps(ctx, b, js, gid, epoch); err != nil {
		l.log("ledger: %v", err)
	}

	for _, id := range ids {
		if !l.stillLeader(gid, epoch) {
			return nil // the next leader carries on
		}

		if !operationRe.MatchString(id) {
			l.log("request %q: not an operation id", id)

			continue
		}

		if err := l.request(ctx, b, js, gid, epoch, id); err != nil {
			l.log("request %s: %v", id, err)
		}
	}

	return nil
}

// takeover closes earlier incarnations' sessions on every host it can reach
// and imports its predecessors' journals once. A host whose session is not
// closed yet gets no grant: it is retried on every tick.
func (l *LeaderLoop) takeover(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64) (Takeover, error) {
	key := JournalPrefix(gid) + "takeover"

	to, found, err := readJSONKey[Takeover](ctx, js, key)
	if err != nil {
		return Takeover{}, err
	}

	if !found {
		to = Takeover{Version: journalVersion, Epoch: epoch, Closed: []string{}}
	}

	own := strconv.FormatInt(gid, 10)

	// a publication of this incarnation is its state, whatever the record says
	if !to.Published {
		if _, err := l.latest(ctx, b, own); err == nil {
			to.Published = true
		} else if !errors.Is(err, store.ErrNotFound) {
			return to, err
		}
	}

	src := own
	if !to.Published {
		if src, err = l.stateSource(ctx, b, epoch); err != nil {
			return to, err
		}
	}

	l.stateInc = src

	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return to, err
	}

	me, ok := st.Host(l.Self.Name)
	if !ok {
		return to, fmt.Errorf("the leader's host %s is not in the cluster state", l.Self.Name)
	}

	changed := !found

	for _, h := range st.Hosts {
		if slices.Contains(to.Closed, h.Name) || !l.stillLeader(gid, epoch) {
			continue
		}

		c := wire.Close{Version: wire.Version, FSID: l.Self.FSID, Host: h.Name, Mgr: l.Self.Name, MgrAddr: me.Addr, GID: gid, Epoch: epoch}

		var res wire.CloseReply
		if _, err := l.call(ctx, h, http.MethodPost, "/v1/close", c, &res); err != nil {
			l.log("closing earlier sessions on %s: %v", h.Name, err)

			continue
		}

		to.Closed = append(to.Closed, h.Name)
		changed = true
	}

	if !to.Imported && l.stillLeader(gid, epoch) {
		if err := l.importPredecessors(ctx, b, js, gid, epoch); err != nil {
			return to, err
		}

		to.Imported, changed = true, true
	}

	// the baseline: the state as its source last published it, now this
	// incarnation's to write (plan 03, item 4)
	if !to.Published && to.Imported && l.stillLeader(gid, epoch) {
		// the takeover record, with this incarnation's epoch, is there before
		// its first manifest: whoever finds the manifest can order it
		if err := writeJSONKey(ctx, js, key, to); err != nil {
			return to, err
		}

		recs, seq, err := l.readRecords(ctx, b, src)
		if err != nil {
			return to, err
		}

		bs, err := b.Store(ctx, store.Prefix+"inc/"+own+"/")
		if err != nil {
			return to, err
		}

		if _, err := (store.Store{B: bs, Incarnation: own}).Publish(ctx, recs); err != nil {
			return to, err
		}

		l.log("published the cluster state of %s (publication %d) as incarnation %s", src, seq, own)

		to.Published, to.From, to.FromSeq, changed = true, src, seq, true
		l.stateInc = own
	}

	if changed {
		if err := writeJSONKey(ctx, js, key, to); err != nil {
			return to, err
		}
	}

	return to, nil
}

// importPredecessors carries the earlier incarnations' unresolved grants
// (their outcome is then asked from the agent, or the grant abandoned) and
// undecided requests into this incarnation's journal. Histories are merged
// by id: the newest incarnation that has an operation for an id decides it,
// so a request an intermediate incarnation completed is not run again. The
// grants of an operation the ledger's snapshot covers are not imported.
func (l *LeaderLoop) importPredecessors(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64) error {
	all, err := b.Store(ctx, store.Prefix+"inc/")
	if err != nil {
		return err
	}

	keys, err := all.List(ctx, store.Prefix+"inc/")
	if err != nil {
		return err
	}

	// the predecessors and their epochs: an incarnation that never took over
	// (no takeover record) never acted, and its requests are older than ours
	epochs := map[int64]int64{}

	for _, k := range keys {
		inc, rest, ok := strings.Cut(strings.TrimPrefix(k, store.Prefix+"inc/"), "/journal/")
		if !ok {
			continue
		}

		old, err := strconv.ParseInt(inc, 10, 64)
		if err != nil || old <= 0 || old == gid {
			continue // "cli" has no journal
		}

		if _, ok := epochs[old]; !ok {
			epochs[old] = 0
		}

		if rest == "takeover" {
			to, found, err := readJSONKey[Takeover](ctx, all, k)
			if err != nil {
				return err
			}

			if found {
				epochs[old] = to.Epoch
			}
		}
	}

	// per id: the newest predecessor (by epoch) with an operation, and with a request
	type history struct {
		op, req           int64 // incarnations
		opEpoch, reqEpoch int64
	}

	ids := map[string]*history{}

	for _, k := range keys {
		inc, rest, ok := strings.Cut(strings.TrimPrefix(k, store.Prefix+"inc/"), "/journal/")
		if !ok {
			continue
		}

		old, err := strconv.ParseInt(inc, 10, 64)
		if err != nil {
			continue
		}

		e, known := epochs[old]
		if !known || e >= epoch {
			continue // not a predecessor
		}

		kind, id, _ := strings.Cut(rest, "/")
		if (kind != "op" && kind != "req") || !operationRe.MatchString(id) {
			continue
		}

		h := ids[id]
		if h == nil {
			h = &history{opEpoch: -1, reqEpoch: -1}
			ids[id] = h
		}

		if kind == "op" && e > h.opEpoch {
			h.op, h.opEpoch = old, e
		} else if kind == "req" && e > h.reqEpoch {
			h.req, h.reqEpoch = old, e
		}
	}

	own := JournalPrefix(gid)

	// an operation at or below the ledger's snapshot is finished by definition:
	// a predecessor's record of it, which the module prunes, is never brought
	// back (plan 04, step 4)
	snap, above, err := b.LedgerAbove(ctx)
	if err != nil {
		return err
	}

	for id, h := range ids {
		// what this incarnation already has stays
		if _, err := js.Get(ctx, own+"op/"+id); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}

		if base, _, _ := strings.Cut(id, "."); h.op > 0 && snap != "" && ledgerIDRe.MatchString(base) && !above[base] {
			continue
		}

		if h.op > 0 {
			op, found, err := readJSONKey[JournalOp](ctx, all, JournalPrefix(h.op)+"op/"+id)
			if err != nil || !found {
				return err
			}

			if op.State != JournalGranting && op.State != wire.OpUncertain {
				continue // decided
			}

			l.log("importing grant %s from incarnation %d", id, h.op)

			if err := writeJSONKey(ctx, js, own+"op/"+id, op); err != nil {
				return err
			}

			continue
		}

		if err := l.copyRequest(ctx, all, js, JournalPrefix(h.req)+"req/"+id, own+"req/"+id); err != nil {
			return err
		}
	}

	return nil
}

func (l *LeaderLoop) copyRequest(ctx context.Context, from, to store.Backend, src, dst string) error {
	if _, err := to.Get(ctx, dst); err == nil {
		return nil // never overwritten
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	raw, err := from.Get(ctx, src)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	return to.SetMany(ctx, []store.KV{{Key: dst, Value: raw}})
}

func readJSONKey[T any](ctx context.Context, js store.Backend, key string) (T, bool, error) {
	var v T

	raw, err := js.Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return v, false, nil
	}

	if err != nil {
		return v, false, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&v); err != nil {
		return v, false, fmt.Errorf("%s: %w", key, err)
	}

	return v, true, nil
}

func writeJSONKey(ctx context.Context, js store.Backend, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return js.SetMany(ctx, []store.KV{{Key: key, Value: b}})
}

// request carries out one request, or resolves its grant if its outcome was
// not recorded.
func (l *LeaderLoop) request(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, id string) error {
	prefix := JournalPrefix(gid)
	opKey := prefix + "op/" + id

	op, found, err := readJSONKey[JournalOp](ctx, js, opKey)
	if err != nil {
		return err
	}

	if found {
		// a grant whose outcome is not known yet, or uncertain on the agent,
		// is asked again until the agent decides it
		if op.State != JournalGranting && op.State != wire.OpUncertain {
			return nil // done
		}

		return l.resolve(ctx, b, js, gid, epoch, opKey, op, id)
	}

	raw, err := js.Get(ctx, prefix+"req/"+id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}

	if err != nil {
		return err
	}

	var req Request

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil || req.Version != journalVersion || req.Kind != KindRevision || pki.ValidName(req.Host) != nil {
		return writeJSONKey(ctx, js, opKey, JournalOp{Version: journalVersion, Kind: req.Kind, Host: req.Host, State: JournalFailed, Error: "unknown or malformed request"})
	}

	if req.Host == l.holding || l.holding == holdAll {
		return fmt.Errorf("%w: an operation that orders %s's documents may be in progress", errRetry, req.Host)
	}

	return l.revision(ctx, b, js, gid, epoch, id, req.Host, revisionMode{})
}

// runRevision carries out a revision of a host under id, or resolves its
// grant if its outcome was not recorded.
func (l *LeaderLoop) runRevision(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, id, host string, mode revisionMode) error {
	opKey := JournalPrefix(gid) + "op/" + id

	op, found, err := readJSONKey[JournalOp](ctx, js, opKey)
	if err != nil {
		return err
	}

	if found {
		if op.State != JournalGranting && op.State != wire.OpUncertain {
			return nil
		}

		return l.resolve(ctx, b, js, gid, epoch, opKey, op, id)
	}

	return l.revision(ctx, b, js, gid, epoch, id, host, mode)
}

// stateSource is where a new incarnation takes its baseline from: the
// predecessor with the highest epoch below its own that published a state,
// else the CLI's ("cli").
func (l *LeaderLoop) stateSource(ctx context.Context, b *Bridge, epoch int64) (string, error) {
	all, err := b.Store(ctx, store.Prefix+"inc/")
	if err != nil {
		return "", err
	}

	keys, err := all.List(ctx, store.Prefix+"inc/")
	if err != nil {
		return "", err
	}

	published := map[string]bool{}

	for _, k := range keys {
		inc, rest, ok := strings.Cut(strings.TrimPrefix(k, store.Prefix+"inc/"), "/")
		if ok && strings.HasPrefix(rest, "manifest/") {
			published[inc] = true
		}
	}

	best, bestEpoch := "cli", int64(-1)

	for inc := range published {
		if _, err := strconv.ParseInt(inc, 10, 64); err != nil {
			continue
		}

		to, found, err := readJSONKey[Takeover](ctx, all, store.Prefix+"inc/"+inc+"/journal/takeover")
		if err != nil {
			return "", err
		}

		if found && to.Epoch < epoch && to.Epoch > bestEpoch {
			best, bestEpoch = inc, to.Epoch
		}
	}

	if best == "cli" {
		if !published["cli"] {
			return "", fmt.Errorf("%w: no cluster state has been published", errRetry)
		}

		// the CLI's state is the leader's only once the CLI handed it over:
		// sealed, it is frozen and the CLI writes no more (plan 03, item 11)
		recs, _, err := l.readRecords(ctx, b, "cli")
		if err != nil {
			return "", err
		}

		var c struct {
			Sealed bool `json:"sealed"`
		}

		if err := json.Unmarshal(recs["cluster"], &c); err != nil || !c.Sealed {
			return "", fmt.Errorf("%w: the CLI has not handed the cluster over yet", errRetry)
		}
	}

	return best, nil
}

// latest returns an incarnation's latest manifest.
func (l *LeaderLoop) latest(ctx context.Context, b *Bridge, inc string) (store.Manifest, error) {
	bs, err := b.Store(ctx, store.Prefix+"inc/"+inc+"/")
	if err != nil {
		return store.Manifest{}, err
	}

	return store.Store{B: bs, Incarnation: inc}.Latest(ctx)
}

// readRecords reads an incarnation's latest publication, retrying from a
// fresh manifest: "cli" may still compact while the leader reads it.
func (l *LeaderLoop) readRecords(ctx context.Context, b *Bridge, inc string) (map[string][]byte, int64, error) {
	var lastErr error

	for range 3 {
		bs, err := b.Store(ctx, store.Prefix+"inc/"+inc+"/")
		if err != nil {
			return nil, 0, err
		}

		s := store.Store{B: bs, Incarnation: inc}

		m, err := s.Latest(ctx)
		if err != nil {
			lastErr = err

			continue
		}

		recs := map[string][]byte{}

		for name := range m.Records {
			if recs[name], err = s.Read(ctx, m, name); err != nil {
				break
			}
		}

		if err != nil {
			lastErr = err

			continue
		}

		return recs, m.Seq, nil
	}

	return nil, 0, fmt.Errorf("reading the cluster state of %s: %w", inc, lastErr)
}

// clusterState reads the cluster state: the leader's own once it published
// its baseline, its source before.
func (l *LeaderLoop) clusterState(ctx context.Context, b *Bridge) (*state.State, int64, error) {
	inc := l.stateInc
	if inc == "" {
		return nil, 0, errors.New("no cluster state chosen yet")
	}

	recs, seq, err := l.readRecords(ctx, b, inc)
	if err != nil {
		return nil, 0, err
	}

	st := state.New(l.Self.FSID)
	if err := st.ApplyRecords(recs); err != nil {
		return nil, 0, err
	}

	return st, seq, nil
}

// agentClient talks to a host's agent and requires its certificate.
func (l *LeaderLoop) agentClient(h state.Host) *http.Client {
	cfg := l.ClientTLS.Clone()
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no server certificate")
		}

		if _, err := pki.Require(cs.PeerCertificates[0], pki.Identity{FSID: l.Self.FSID, Role: pki.RoleAgent, Name: h.Name}); err != nil {
			return err
		}

		return l.CRL.Check(cs.PeerCertificates[0])
	}

	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, Timeout: grantTimeout + 30*time.Second}
}

func (l *LeaderLoop) url(h state.Host, path string) string {
	if l.agentURL != nil {
		return l.agentURL(h) + path
	}

	return "https://" + net.JoinHostPort(h.Addr, strconv.Itoa(Port)) + path
}

func (l *LeaderLoop) call(ctx context.Context, h state.Host, method, path string, body, out any) (int, error) {
	var rd io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}

		rd = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, l.url(h, path), rd)
	if err != nil {
		return 0, err
	}

	resp, err := l.agentClient(h).Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxGrant))
	if err != nil {
		return resp.StatusCode, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, bytes.TrimSpace(raw))
	}

	return resp.StatusCode, json.Unmarshal(raw, out)
}

// rendered is a host's rendering: documents to have and removals.
type rendered struct {
	docs   []Doc
	hashes map[string]string
	remove []string // keys
}

// renderHost renders what a host should carry: the ceph volume, ceph.conf,
// the mgr files (or their removal) and its daemons. An OSD that cannot be
// rendered yet (its preparation did not finish) is left out, and its document
// is neither granted nor removed; any other daemon that does not render fails
// the revision, and a bridge error leaves it for the next tick.
func (l *LeaderLoop) renderHost(ctx context.Context, b *Bridge, st *state.State, h state.Host) (rendered, error) {
	// a bridge error is no answer: the request is retried, nothing is decided
	var transient error

	key := func(entity string) (string, error) {
		k, found, err := b.AuthGet(ctx, entity)
		if err != nil {
			transient = err

			return "", err
		}

		if !found {
			return "", fmt.Errorf("%s is not in mon auth", entity)
		}

		return k, nil
	}

	// a daemon stopped without the mons (its cleanup pending) or purged (its
	// disk still to wipe) is on its way out: it is not rendered again
	gone := func(d state.Daemon) bool { return d.LocalOnly || d.Purged || d.Leaving }

	withMgr := false

	for _, d := range st.DaemonsOf(state.TypeMgr, h.Name) {
		withMgr = withMgr || !gone(d) && !h.Maintenance
	}

	// a secret only for the document that carries it, through the bridge
	secret := func(name string) (string, error) {
		v, err := b.Secret(ctx, name)
		if err != nil {
			transient = err
		}

		return v, err
	}

	mgr, err := render.MgrFiles(st, h, withMgr, secret)
	if transient != nil {
		return rendered{}, fmt.Errorf("%w: %w", errRetry, transient)
	}

	if err != nil {
		return rendered{}, err
	}

	objs := append([]any{render.Volume(), spec.CephConf(render.CephConf(st))}, mgr.Upsert...)

	for _, d := range st.Daemons {
		if d.Host != h.Name {
			continue
		}

		// an OSD whose preparation did not finish has no document to grant yet;
		// its document stays as it is, as does a leaving daemon's; a host in
		// maintenance has none
		if gone(d) || h.Maintenance || d.Type == state.TypeOSD && (d.OSDID == nil || d.OSDUUID == "") {
			continue
		}

		c, err := render.Daemon(st, h, d, st.ImageOf(d), key, secret)
		if transient != nil {
			return rendered{}, fmt.Errorf("%w: %w", errRetry, transient)
		}

		if err != nil {
			// nothing partial is granted
			return rendered{}, fmt.Errorf("%s.%s: %w", d.Type, d.ID, err)
		}

		objs = append(objs, c)
	}

	r := rendered{hashes: map[string]string{}}

	for _, o := range objs {
		y, err := spec.Render(o)
		if err != nil {
			return rendered{}, err
		}

		d := Doc{Kind: o.(config.Document).Kind(), Name: o.(config.NamedDocument).Name(), YAML: y}

		td, err := checkDoc(d)
		if err != nil {
			return rendered{}, fmt.Errorf("%s: %w", d.Key(), err)
		}

		r.docs = append(r.docs, d)
		r.hashes[d.Key()] = td.hash
	}

	for _, ref := range mgr.Remove {
		r.remove = append(r.remove, ref.Kind+"/"+ref.Name)
	}

	return r, nil
}

// revisionMode changes what a revision grants: the rendering plus the removal
// of extra owned documents (a removed daemon's), or with strip the removal of
// every document the node owns (a host on its way out).
type revisionMode struct {
	extra []string // keys
	// stop are documents taken off although the rendering has them; hold
	// those not granted yet, leaving them as they are on the node
	stop  []string
	hold  []string
	strip bool
	// only grants nothing but the removal of these documents, without the
	// rendering: what else the node holds stays as it is
	only []string
	// add are documents granted besides the rendering (a job); ack
	// acknowledges a job's result in the same grant
	add []Doc
	ack *wire.JobAck
}

// revision makes a host's documents match the cluster state.
func (l *LeaderLoop) revision(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, id, host string, mode revisionMode) error {
	opKey := JournalPrefix(gid) + "op/" + id
	op := JournalOp{Version: journalVersion, Kind: KindRevision, Host: host}

	fail := func(err error) error {
		op.State, op.Error = JournalFailed, err.Error()

		return writeJSONKey(ctx, js, opKey, op)
	}

	st, seq, err := l.clusterState(ctx, b)
	if err != nil {
		return err // a state read error is retried on the next tick
	}

	op.Seq = seq

	h, ok := st.Host(host)
	if !ok || h.Name != host {
		return fail(fmt.Errorf("no host %s in the cluster state", host))
	}

	// a host whose earlier sessions are not closed yet waits
	if !l.closed[host] {
		return fmt.Errorf("%w: %s's earlier sessions are not closed yet", errRetry, host)
	}

	me, ok := st.Host(l.Self.Name)
	if !ok {
		return fail(fmt.Errorf("the leader's host %s is not in the cluster state", l.Self.Name))
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return err // an unreachable agent is retried on the next tick
	}

	// owned hashes describe what the node should hold: only a node that holds
	// exactly that is compared with the rendering
	switch rep.State {
	case "owned":
	case "error":
		return fmt.Errorf("%s: its agent cannot read its node", h.Name) // retried
	default:
		return fail(fmt.Errorf("%s is %s %v: nothing is granted until that is resolved", h.Name, rep.State, rep.Drift))
	}

	var r rendered

	if mode.strip {
		for k := range rep.Owned {
			r.remove = append(r.remove, k)
		}

		sort.Strings(r.remove)
	} else if len(mode.only) > 0 {
		r.remove = slices.Clone(mode.only)
		sort.Strings(r.remove)
	} else {
		if r, err = l.renderHost(ctx, b, st, h); errors.Is(err, errRetry) {
			return err
		}

		if err != nil {
			return fail(err)
		}

		r.remove = append(r.remove, mode.extra...)

		// a host in maintenance keeps its daemons in the state with their
		// documents removed (renderHost renders none); stop takes documents
		// off before the rest (keepalived before maintenance)
		stop := map[string]bool{}
		for _, k := range mode.stop {
			stop[k] = true
		}

		if h.Maintenance {
			for k := range rep.Owned {
				if strings.HasPrefix(k, "ContainerConfig/") {
					stop[k] = true
				}
			}
		}

		deferred := map[string]bool{}
		for _, k := range mode.hold {
			deferred[k] = true
		}

		if len(stop)+len(deferred) > 0 {
			kept := r.docs[:0]

			for _, d := range r.docs {
				if !stop[d.Key()] && !deferred[d.Key()] {
					kept = append(kept, d)
				}
			}

			r.docs = kept

			for k := range stop {
				r.remove = append(r.remove, k)
			}

			sort.Strings(r.remove)
		}

		for _, d := range mode.add {
			td, err := checkDoc(d)
			if err != nil {
				return fail(err)
			}

			r.docs = append(r.docs, Doc{Kind: d.Kind, Name: d.Name, YAML: td.yaml})
			r.hashes[d.Key()] = td.hash
		}
	}

	// what the host does not have yet
	var grant []wire.GrantDoc

	op.Docs = map[string]string{}

	for _, d := range r.docs {
		if rep.Owned[d.Key()] == r.hashes[d.Key()] {
			continue
		}

		y := string(d.YAML)
		grant = append(grant, wire.GrantDoc{Kind: d.Kind, Name: d.Name, YAML: &y})
		op.Docs[d.Key()] = r.hashes[d.Key()]
	}

	for _, k := range r.remove {
		if _, owned := rep.Owned[k]; owned {
			kind, name, _ := strings.Cut(k, "/")
			grant = append(grant, wire.GrantDoc{Kind: kind, Name: name})
			op.Docs[k] = ""
		}
	}

	// nothing to change, unless an acknowledgement goes along (of a job whose
	// document is gone already, or was never applied)
	if len(grant) == 0 && mode.ack == nil {
		op.State, op.Docs = JournalNoChange, nil

		return writeJSONKey(ctx, js, opKey, op)
	}

	// the agent checks it again; checking first keeps a revision it would
	// refuse from being sent at all
	docs := make([]Doc, 0, len(grant))
	for _, g := range grant {
		d := Doc{Kind: g.Kind, Name: g.Name}
		if g.YAML != nil {
			d.YAML = []byte(*g.YAML)
		}

		docs = append(docs, d)
	}

	disks := make([]Disk, 0, len(rep.Disks))
	for _, d := range rep.Disks {
		disks = append(disks, Disk{Serial: d.Serial, Symlinks: d.Symlinks})
	}

	pol := &Policy{FSID: l.Self.FSID, Host: h.Name, Repos: l.Repos, CACert: l.CACert, CRL: l.CRL}
	if err := pol.Check(docs, disks, rep.Containers, l.appr); err != nil {
		return fail(err)
	}

	op.Revision = max(rep.Revision+1, l.clock().UnixNano())
	op.State = JournalGranting

	if !l.stillLeader(gid, epoch) {
		return nil // nothing written: the next leader decides
	}

	// the intent is in the journal before anything is sent
	if err := writeJSONKey(ctx, js, opKey, op); err != nil {
		return err
	}

	if !l.stillLeader(gid, epoch) {
		return nil // the intent stays: the next leader resolves it
	}

	g := wire.Grant{
		Version: wire.Version, FSID: l.Self.FSID, Host: h.Name, Mgr: l.Self.Name, MgrAddr: me.Addr, GID: gid, Epoch: epoch,
		Revision: op.Revision, Operation: id, Docs: grant, Approval: l.approval, Ack: mode.ack,
	}

	var res wire.Operation
	if _, err := l.call(ctx, h, http.MethodPost, "/v1/grant", g, &res); err != nil {
		// the answer may be lost: the next tick asks the agent
		return fmt.Errorf("grant %s to %s: %w", id, h.Name, err)
	}

	return l.record(ctx, js, opKey, op, res)
}

// record writes a grant's outcome into the journal.
func (l *LeaderLoop) record(ctx context.Context, js store.Backend, opKey string, op JournalOp, res wire.Operation) error {
	if res.State == wire.OpStarted || res.State == wire.OpReserved {
		return nil // not finished: asked again on the next tick
	}

	op.State, op.Error, op.Job, op.Result = res.State, res.Error, res.Job, res.Result
	l.log("%s on %s: %s %s", strings.TrimPrefix(opKey, store.Prefix), op.Host, op.State, op.Error)

	return writeJSONKey(ctx, js, opKey, op)
}

// resolve asks the agent for the outcome of a grant the journal has no outcome
// for. An agent without a record either never received the grant or refused
// it without a confirmation; it records the operation as abandoned.
func (l *LeaderLoop) resolve(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, opKey string, op JournalOp, id string) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	h, ok := st.Host(op.Host)
	if !ok {
		return fmt.Errorf("no host %s in the cluster state", op.Host)
	}

	me, ok := st.Host(l.Self.Name)
	if !ok {
		return fmt.Errorf("the leader's host %s is not in the cluster state", l.Self.Name)
	}

	// the agent confirms the abandon, fences the revision and records the
	// operation as abandoned, under its grant slot: a grant still on its way
	// can then no longer run; an operation it has a record of keeps it
	a := wire.Abandon{
		Version: wire.Version, FSID: l.Self.FSID, Host: h.Name, Mgr: l.Self.Name, MgrAddr: me.Addr,
		GID: gid, Epoch: epoch, Revision: op.Revision, Operation: id,
	}

	var res wire.Operation
	if _, err := l.call(ctx, h, http.MethodPost, "/v1/abandon", a, &res); err != nil {
		return err // retried
	}

	return l.record(ctx, js, opKey, op, res)
}

// loadApproval reads the operator's newest approval and verifies it; an agent
// checks it again. Without one, grants carry none and admit no image.
func (l *LeaderLoop) loadApproval(ctx context.Context, b *Bridge) error {
	s, err := b.Approval(ctx)
	if err != nil {
		return err
	}

	l.approval, l.appr = nil, nil

	if s == nil {
		return nil
	}

	a, err := approval.Verify(l.ApprovalKey, *s, l.Self.FSID)
	if err != nil {
		return fmt.Errorf("the operator's approval: %w", err)
	}

	l.approval, l.appr = s, &a

	return nil
}
