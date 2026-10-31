package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// MaxGrant is the largest grant the agent reads.
const MaxGrant = 4 << 20

// MaxOperations is how many operation records the agent keeps.
const MaxOperations = 1024

// maxOperations is MaxOperations; tests lower it.
var maxOperations = MaxOperations

// reportTimeout bounds one node report; tests lower it.
var reportTimeout = 20 * time.Second

// grantTimeout bounds handling one grant: the confirmation, the apply and its
// read-back.
const grantTimeout = 2 * time.Minute

// operationRe is the grammar of operation ids (bridge.py ID_RE).
var operationRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Granter turns the leader's grants into changes of the agent's node (plan 03,
// items 5 and 7): one at a time, each with a durable operation record, a
// fresh confirmation from the active mgr and the node's admission policy.
type Granter struct {
	Node    *Node
	Channel *Channel
	// ClientTLS is the agent's client side for the module's confirmation endpoint
	ClientTLS *tls.Config
	Records   *records.Store
	// Now is the clock for the confirmation's validity; nil is time.Now
	Now func() time.Time
	// confirm replaces Channel.Confirm in tests
	confirm func(ctx context.Context, t ConfirmTarget, revision int64, operation, inputsHash string) (wire.Confirmation, time.Time, error)

	mu chan struct{} // one grant at a time; a buffered channel so a waiter can give up
	// reports admits one node report at a time
	reports chan struct{}
}

func (g *Granter) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}

	return time.Now()
}

func opRecord(id string) string { return "op-" + id }

func (g *Granter) readOp(id string) (wire.Operation, bool, error) {
	b, err := g.Records.Read(opRecord(id))
	if errors.Is(err, records.ErrNotFound) {
		return wire.Operation{}, false, nil
	}

	if err != nil {
		return wire.Operation{}, false, err
	}

	var op wire.Operation
	if err := json.Unmarshal(b, &op); err != nil {
		return wire.Operation{}, false, fmt.Errorf("record %s: %w", opRecord(id), err)
	}

	// a damaged record is no evidence of anything: it blocks like missing records do
	switch op.State {
	case wire.OpReserved, wire.OpRefused, wire.OpStarted, wire.OpCompleted, wire.OpUncertain, wire.OpAbandoned:
	default:
		return wire.Operation{}, false, fmt.Errorf("record %s: unknown state", opRecord(id))
	}

	if op.Version != wire.Version || op.Operation != id || op.Revision <= 0 || op.InputsHash == "" || op.GID <= 0 {
		return wire.Operation{}, false, fmt.Errorf("record %s: damaged", opRecord(id))
	}

	return op, true, nil
}

func (g *Granter) writeOp(op wire.Operation) error {
	b, err := json.Marshal(op)
	if err != nil {
		return err
	}

	return g.Records.Write(opRecord(op.Operation), b)
}

// checkGrant validates a grant's shape for this agent; leader is the name in
// the sender's certificate.
func (g *Granter) checkGrant(gr wire.Grant, leader string) error {
	self := g.Channel.Self

	switch {
	case gr.Version != wire.Version:
		return errors.New("unknown wire version")
	case gr.FSID != self.FSID || gr.Host != self.Name:
		return errors.New("a grant for another cluster or host")
	case gr.Mgr != leader:
		// the leader is the agent beside the active mgr: same host, same name
		return errors.New("the grant's mgr is not the sender's host")
	case pki.ValidName(gr.Mgr) != nil || gr.GID <= 0 || gr.Revision <= 0 || !operationRe.MatchString(gr.Operation):
		return errors.New("malformed grant")
	case len(gr.Docs) == 0:
		return errors.New("a grant without documents")
	}

	if _, err := netip.ParseAddr(gr.MgrAddr); err != nil {
		return errors.New("mgr_addr: not an IP address")
	}

	for _, d := range gr.Docs {
		if d.Kind == "" || d.Name == "" {
			return errors.New("a document without kind or name")
		}
	}

	return nil
}

// Grant handles one grant and returns the operation's record. The same
// operation id with the same inputs returns the recorded outcome instead of
// applying again, unless nothing changed yet (reserved or refused).
func (g *Granter) Grant(ctx context.Context, gr wire.Grant) (wire.Operation, error) {
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-ctx.Done():
		return wire.Operation{}, ctx.Err()
	}

	return g.grant(ctx, gr)
}

// unresolved returns an operation other than id that started and has no
// recorded outcome, or whose outcome is uncertain: nothing else is applied
// until it is reconciled, also after a restart.
func (g *Granter) unresolved(id string) (string, error) {
	names, err := g.Records.List("op-")
	if err != nil {
		return "", err
	}

	for _, n := range names {
		if n == opRecord(id) {
			continue
		}

		op, found, err := g.readOp(strings.TrimPrefix(n, "op-"))
		if err != nil {
			return "", err
		}

		if found && (op.State == wire.OpStarted || op.State == wire.OpUncertain) {
			return op.Operation, nil
		}
	}

	return "", nil
}

// prune keeps at most MaxOperations records, removing the oldest finished
// ones: a replayed old grant is refused anyway, as its revision is not newer.
func (g *Granter) prune() error {
	names, err := g.Records.List("op-")
	if err != nil || len(names) <= maxOperations {
		return err
	}

	var done []wire.Operation

	for _, n := range names {
		op, found, err := g.readOp(strings.TrimPrefix(n, "op-"))
		if err != nil {
			return err
		}

		if found && (op.State == wire.OpCompleted || op.State == wire.OpRefused || op.State == wire.OpAbandoned) {
			done = append(done, op)
		}
	}

	sort.Slice(done, func(i, j int) bool { return done[i].Revision < done[j].Revision })

	for i := 0; i < len(done) && len(names)-i > maxOperations; i++ {
		if err := g.Records.Remove(opRecord(done[i].Operation)); err != nil {
			return err
		}
	}

	return nil
}

func (g *Granter) grant(ctx context.Context, gr wire.Grant) (wire.Operation, error) {
	hash := wire.GrantInputs(gr)

	prev, found, err := g.readOp(gr.Operation)
	if err != nil {
		return wire.Operation{}, err
	}

	if found {
		if prev.State == wire.OpAbandoned {
			return prev, nil // given up by the leader: never runs
		}

		if prev.InputsHash != hash {
			return wire.Operation{}, errors.New("the operation id was used with other inputs")
		}

		if prev.State != wire.OpReserved && prev.State != wire.OpRefused {
			return prev, nil
		}
	}

	if other, err := g.unresolved(gr.Operation); err != nil || other != "" {
		if err == nil {
			err = fmt.Errorf("operation %s is unresolved: nothing else is applied until it is reconciled", other)
		}

		return wire.Operation{}, err
	}

	op := wire.Operation{Version: wire.Version, Operation: gr.Operation, Revision: gr.Revision, InputsHash: hash, GID: gr.GID, State: wire.OpReserved}

	// the reservation is durable before anything else happens (plan 03, item 5)
	if err := g.writeOp(op); err != nil {
		return wire.Operation{}, err
	}

	// without a confirmation nothing happened, and the reservation is dropped:
	// a sender that cannot be confirmed leaves no record behind
	unconfirmed := func(err error) (wire.Operation, error) {
		op.State, op.Error = wire.OpRefused, err.Error()

		return op, g.Records.Remove(opRecord(op.Operation))
	}

	confirm := g.confirm
	if confirm == nil {
		confirm = func(ctx context.Context, t ConfirmTarget, revision int64, operation, inputsHash string) (wire.Confirmation, time.Time, error) {
			return g.Channel.Confirm(ctx, g.ClientTLS, t, revision, operation, inputsHash)
		}
	}

	conf, until, err := confirm(ctx, ConfirmTarget{Addr: gr.MgrAddr, Mgr: gr.Mgr}, gr.Revision, gr.Operation, hash)
	if err != nil {
		return unconfirmed(err)
	}

	// the confirmation says which incarnation is active: it must be the grant's
	if conf.GID != gr.GID {
		return unconfirmed(fmt.Errorf("the grant is from incarnation %d, mgr.%s is active as %d", gr.GID, conf.Mgr, conf.GID))
	}

	if !g.now().Before(until) {
		return unconfirmed(errors.New("the confirmation expired before the apply"))
	}

	op.State = wire.OpStarted
	if err := g.writeOp(op); err != nil {
		return wire.Operation{}, err
	}

	docs := make([]Doc, 0, len(gr.Docs))
	for _, d := range gr.Docs {
		doc := Doc{Kind: d.Kind, Name: d.Name}
		if d.YAML != nil {
			doc.YAML = []byte(*d.YAML)
		}

		docs = append(docs, doc)
	}

	_, err = g.Node.ApplyBefore(ctx, until, gr.Revision, docs)

	switch {
	case err == nil:
		op.State, op.Error = wire.OpCompleted, ""
	case errors.Is(err, ErrNotApplied):
		op.State, op.Error = wire.OpRefused, err.Error()
	default:
		op.State, op.Error = wire.OpUncertain, err.Error()
	}

	if err := g.writeOp(op); err != nil {
		return op, err
	}

	return op, g.prune()
}

// leaderOf returns the name of the cluster agent that sent a request.
func (g *Granter) leaderOf(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate")
	}

	id, err := pki.CertIdentity(r.TLS.PeerCertificates[0])
	if err != nil {
		return "", err
	}

	if id.FSID != g.Channel.Self.FSID || id.Role != pki.RoleAgent {
		return "", errors.New("grants come from the cluster's agents only")
	}

	return id.Name, nil
}

// HandleGrant serves POST /v1/grant from the leader.
func (g *Granter) HandleGrant(w http.ResponseWriter, r *http.Request) {
	leader, err := g.leaderOf(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	// one grant at a time, taken before the body is read: a busy agent
	// answers at once instead of queueing decoded grants
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	default:
		http.Error(w, "another grant is running", http.StatusTooManyRequests)

		return
	}

	// the answer may come after the server's write timeout for status requests
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(grantTimeout + 10*time.Second))

	var gr wire.Grant

	dec := json.NewDecoder(io.LimitReader(r.Body, MaxGrant))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&gr); err != nil {
		http.Error(w, "malformed grant", http.StatusBadRequest)

		return
	}

	if err := g.checkGrant(gr, leader); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	// the grant runs to its end even if the leader goes away
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), grantTimeout)
	defer cancel()

	op, err := g.grant(ctx, gr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(op)
}

// HandleOperation serves GET /v1/operations/{id}: the record of a grant, for a
// leader whose answer was lost.
func (g *Granter) HandleOperation(w http.ResponseWriter, r *http.Request) {
	if _, err := g.leaderOf(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	id := r.PathValue("id")
	if !operationRe.MatchString(id) {
		http.Error(w, "malformed operation id", http.StatusBadRequest)

		return
	}

	op, found, err := g.readOp(id)

	switch {
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	case !found:
		http.Error(w, "unknown operation", http.StatusNotFound)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(op)
	}
}

// Abandon gives up an operation the agent has no record of (wire.Abandon):
// confirmed like a grant, it fences the operation's revision and records the
// operation as abandoned. An operation the agent has a record of keeps it.
func (g *Granter) Abandon(ctx context.Context, a wire.Abandon) (wire.Operation, error) {
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-ctx.Done():
		return wire.Operation{}, ctx.Err()
	}

	return g.abandon(ctx, a)
}

func (g *Granter) abandon(ctx context.Context, a wire.Abandon) (wire.Operation, error) {
	prev, found, err := g.readOp(a.Operation)
	if err != nil || found {
		return prev, err
	}

	hash := wire.AbandonInputs(a)

	confirm := g.confirm
	if confirm == nil {
		confirm = func(ctx context.Context, t ConfirmTarget, revision int64, operation, inputsHash string) (wire.Confirmation, time.Time, error) {
			return g.Channel.Confirm(ctx, g.ClientTLS, t, revision, operation, inputsHash)
		}
	}

	conf, until, err := confirm(ctx, ConfirmTarget{Addr: a.MgrAddr, Mgr: a.Mgr}, a.Revision, a.Operation, hash)
	if err != nil {
		return wire.Operation{}, err
	}

	if conf.GID != a.GID || !g.now().Before(until) {
		return wire.Operation{}, errors.New("the abandon is not confirmed for this incarnation")
	}

	// the fence first: a late grant of this revision can no longer be applied,
	// also once the record is pruned
	if err := g.Node.FenceBefore(ctx, until, a.Revision); err != nil {
		return wire.Operation{}, err
	}

	op := wire.Operation{Version: wire.Version, Operation: a.Operation, Revision: a.Revision, InputsHash: hash, GID: a.GID, State: wire.OpAbandoned}

	if err := g.writeOp(op); err != nil {
		return op, err
	}

	return op, g.prune()
}

// HandleAbandon serves POST /v1/abandon from the leader.
func (g *Granter) HandleAbandon(w http.ResponseWriter, r *http.Request) {
	leader, err := g.leaderOf(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	default:
		http.Error(w, "a grant is running", http.StatusTooManyRequests)

		return
	}

	var a wire.Abandon

	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&a); err != nil {
		http.Error(w, "malformed abandon", http.StatusBadRequest)

		return
	}

	// the same shape rules as a grant, without documents
	gr := wire.Grant{Version: a.Version, FSID: a.FSID, Host: a.Host, Mgr: a.Mgr, MgrAddr: a.MgrAddr, GID: a.GID, Revision: a.Revision, Operation: a.Operation, Docs: []wire.GrantDoc{{Kind: "-", Name: "-"}}}
	if err := g.checkGrant(gr, leader); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), grantTimeout)
	defer cancel()

	op, err := g.abandon(ctx, a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(op)
}

// HandleNode serves GET /v1/node: the node report, for the leader.
func (g *Granter) HandleNode(w http.ResponseWriter, r *http.Request) {
	if _, err := g.leaderOf(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	// one report at a time, bounded: it holds the node lock while it reads
	select {
	case g.reports <- struct{}{}:
		defer func() { <-g.reports }()
	default:
		http.Error(w, "a report is running", http.StatusTooManyRequests)

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), reportTimeout)
	defer cancel()

	rep, err := g.Node.Report(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}

// HandleHandoff serves POST /v1/handoff from the CLI's operator certificate:
// the agent takes ownership of its node's cluster documents as they are.
func (g *Granter) HandleHandoff(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "no client certificate", http.StatusForbidden)

		return
	}

	id, err := pki.CertIdentity(r.TLS.PeerCertificates[0])
	if err != nil || id.FSID != g.Channel.Self.FSID || id.Role != pki.RoleOperator {
		http.Error(w, "the handoff comes from the operator only", http.StatusForbidden)

		return
	}

	var h wire.Handoff

	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&h); err != nil || h.Version != wire.Version || h.FSID != g.Channel.Self.FSID || h.Host != g.Channel.Self.Name || h.Revision < 0 {
		http.Error(w, "malformed handoff", http.StatusBadRequest)

		return
	}

	own, err := g.Node.Adopt(r.Context(), h.Revision)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wire.HandoffReply{Version: wire.Version, Revision: own.Revision, Owned: len(own.Docs)})
}

// NewGranter returns a Granter; one grant runs at a time.
func NewGranter(n *Node, ch *Channel, clientTLS *tls.Config, recs *records.Store) *Granter {
	return &Granter{Node: n, Channel: ch, ClientTLS: clientTLS, Records: recs, mu: make(chan struct{}, 1), reports: make(chan struct{}, 1)}
}
