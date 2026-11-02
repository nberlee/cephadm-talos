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
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// MaxGrant is the largest grant the agent reads.
const MaxGrant = 4 << 20

// rebootWithin bounds how long a reboot the agent asked Talos for may take to
// come: the node still on the same boot after it did not reboot for it.
const rebootWithin = 20 * time.Minute

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

	// Leader is the agent's leader loop, paused while the agent is suspended
	Leader *LeaderLoop

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
	case wire.OpReserved, wire.OpRefused, wire.OpStarted, wire.OpCompleted, wire.OpUncertain, wire.OpAbandoned, wire.OpFailed:
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
	case pki.ValidName(gr.Mgr) != nil || gr.GID <= 0 || gr.Epoch <= 0 || gr.Revision <= 0 || !operationRe.MatchString(gr.Operation):
		return errors.New("malformed grant")
	case len(gr.Docs) == 0 && gr.Restart == nil && gr.Ack == nil && !gr.Reboot:
		return errors.New("a grant without documents")
	case len(gr.Docs) > 0 && gr.Restart != nil:
		return errors.New("a grant with documents and a restart")
	case gr.Reboot && (len(gr.Docs) > 0 || gr.Restart != nil || gr.Ack != nil):
		return errors.New("a reboot with documents, a restart or an acknowledgement")
	case gr.Restart != nil && (gr.Restart.Kind != "ContainerConfig" || gr.Restart.Name == "" || gr.Restart.Hash == ""):
		return errors.New("a restart without a ContainerConfig, name or hash")
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
func (g *Granter) unresolved(id string, withJob bool) (string, error) {
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

		// an unresolved job holds back other jobs on the node, not documents
		if found && (op.State == wire.OpStarted || op.State == wire.OpUncertain) && (op.Job == nil || withJob) {
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

		// a job's record stays until the leader acknowledged its outcome
		if found && (op.State == wire.OpCompleted || op.State == wire.OpRefused || op.State == wire.OpAbandoned || op.State == wire.OpFailed) &&
			(op.Job == nil || op.Acked) {
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

// sessionRecord holds the session floor: the captured mgrmap epoch of the
// lowest incarnation whose grants, abandons and closes are still admitted
// (plan 03, item 6). Epochs order incarnations; gids do not.
const sessionRecord = "session"

type session struct {
	Schema int   `json:"schema"`
	Floor  int64 `json:"floor"`
}

func (g *Granter) floor() (int64, error) {
	b, err := g.Records.Read(sessionRecord)
	if errors.Is(err, records.ErrNotFound) {
		return 0, nil
	}

	if err != nil {
		return 0, err
	}

	var s session
	if err := json.Unmarshal(b, &s); err != nil || s.Schema != ownershipSchema || s.Floor < 0 {
		return 0, fmt.Errorf("record %s: damaged", sessionRecord)
	}

	return s.Floor, nil
}

// admitted refuses an incarnation captured below the session floor.
func (g *Granter) admitted(epoch int64) error {
	f, err := g.floor()
	if err != nil {
		return err
	}

	if epoch < f {
		return fmt.Errorf("the incarnation of epoch %d is closed: a successor of epoch %d took over", epoch, f)
	}

	return nil
}

// reconcile decides the agent's own unresolved operations where the node
// shows what happened (plan 03, item 6): an apply left with its intent is
// decided by Node.Reconcile; an operation started without an intent either
// completed (the ownership has its revision) or refused before its intent
// (the ownership is older). The barrier guarantees nothing newer ran since.
// What the node cannot tell stays unresolved. Called under the grant slot.
func (g *Granter) reconcile(ctx context.Context) error {
	outcome, rev, owned, err := g.Node.Reconcile(ctx)
	if err != nil {
		return err
	}

	names, err := g.Records.List("op-")
	if err != nil {
		return err
	}

	for _, n := range names {
		op, found, err := g.readOp(strings.TrimPrefix(n, "op-"))
		if err != nil || !found {
			return err
		}

		// a reservation left by a stop between reserving and starting never
		// reached the node: no grant runs while the slot is held
		if op.State == wire.OpReserved {
			op.State, op.Error = wire.OpRefused, "reconciled: the grant stopped before it started"
			if err := g.writeOp(op); err != nil {
				return err
			}

			continue
		}

		// an acknowledgement whose grant was decided later: finished, or dropped
		if op.Job != nil && !op.Acked && op.AckBy != "" {
			by, found, err := g.readOp(op.AckBy)
			if err != nil {
				return err
			}

			switch {
			case found && by.State == wire.OpCompleted:
				if err := g.acknowledge(op); err != nil {
					return err
				}

				op.Acked = true
			case !found || by.State == wire.OpRefused || by.State == wire.OpAbandoned:
				op.AckBy = ""
				if err := g.writeOp(op); err != nil {
					return err
				}
			}
		}

		// an acknowledged job's files go once its document and instance are gone
		if op.Job != nil && op.Acked {
			if err := g.Node.cleanJob(ctx, *op.Job); err != nil {
				return err
			}

			continue
		}

		if op.State != wire.OpStarted && op.State != wire.OpUncertain {
			continue
		}

		// a job: applied first (as for documents), then its result or container
		if op.Job != nil {
			applied, refused := false, false

			switch {
			case outcome == "uncertain" && op.Revision == rev:
				continue
			case outcome != "" && op.Revision == rev:
				applied, refused = outcome == wire.OpCompleted, outcome != wire.OpCompleted
			case outcome == "uncertain":
				continue
			case op.Result == nil && op.State == wire.OpUncertain && owned >= op.Revision:
				applied = true // uncertain from the job: its result may still appear
			case owned >= op.Revision:
				applied = true
			default:
				refused = true
			}

			if refused {
				op.State, op.Error = wire.OpRefused, "reconciled: the job's document was not applied"
			} else if applied {
				st, res, err := g.Node.JobOutcome(ctx, *op.Job)
				if err != nil {
					return err
				}

				if st == "" || (st == wire.OpUncertain && op.State == wire.OpUncertain) {
					continue
				}

				op.State, op.Result, op.Error = st, res, "the job ended"
			}

			if err := g.writeOp(op); err != nil {
				return err
			}

			continue
		}

		// a reboot is done once the node runs another boot; one that did not
		// come within rebootWithin did not happen
		if op.Reboot {
			now, err := g.Node.Talos.BootID(ctx, "")
			if err != nil {
				continue
			}

			switch {
			case now != op.BootID:
				op.State, op.Error = wire.OpCompleted, "reconciled from the boot id"
			case time.Since(time.Unix(0, op.At)) > rebootWithin:
				op.State, op.Error = wire.OpRefused, "the node did not reboot"
			default:
				continue // not yet: it stays unresolved
			}

			if err := g.writeOp(op); err != nil {
				return err
			}

			continue
		}

		// a restart changed no document: its instance tells
		if op.Instance != "" {
			out, err := g.Node.RestartOutcome(ctx, op.Instance, op.BootID, time.Unix(0, op.At))
			if err != nil || out == "" {
				continue // not known yet: it stays unresolved
			}

			op.State, op.Error = out, "reconciled from the daemon's instance"
			if err := g.writeOp(op); err != nil {
				return err
			}

			continue
		}

		switch {
		case outcome == "uncertain" && op.Revision == rev:
			continue // the node cannot tell
		case outcome != "" && op.Revision == rev:
			op.State, op.Error = outcome, "reconciled from the node's config"
		default:
			// an intent still there is someone else's decision
			if outcome == "uncertain" {
				continue
			}

			switch {
			case owned == op.Revision:
				op.State, op.Error = wire.OpCompleted, "reconciled from the node's ownership"
			case owned < op.Revision:
				op.State, op.Error = wire.OpRefused, "reconciled: the apply did not start"
			default:
				continue
			}
		}

		if err := g.writeOp(op); err != nil {
			return err
		}
	}

	return nil
}

func (g *Granter) grant(ctx context.Context, gr wire.Grant) (wire.Operation, error) {
	// checked under the grant slot, which a suspension takes after its record
	if err := g.suspended(); err != nil {
		return wire.Operation{}, err
	}

	if err := g.admitted(gr.Epoch); err != nil {
		return wire.Operation{}, err
	}

	if err := g.reconcile(ctx); err != nil {
		return wire.Operation{}, err
	}

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

	job, ack, err := g.jobOf(gr)
	if err != nil {
		op := wire.Operation{Version: wire.Version, Operation: gr.Operation, Revision: gr.Revision, InputsHash: hash, GID: gr.GID, State: wire.OpRefused, Error: err.Error()}

		return op, nil // refused before anything is recorded
	}

	if other, err := g.unresolved(gr.Operation, job != nil); err != nil || other != "" {
		if err == nil {
			err = fmt.Errorf("operation %s is unresolved: nothing else is applied until it is reconciled", other)
		}

		return wire.Operation{}, err
	}

	op := wire.Operation{Version: wire.Version, Operation: gr.Operation, Revision: gr.Revision, InputsHash: hash, GID: gr.GID, State: wire.OpReserved, Job: job}

	// the reservation is durable before anything else happens (plan 03, item 5)
	if err := g.writeOp(op); err != nil {
		return wire.Operation{}, err
	}

	// the acknowledgement this grant carries is recorded with its job first,
	// so it is finished also after a crash or an apply decided later
	if ack != nil && ack.AckBy != gr.Operation {
		ack.AckBy = gr.Operation
		if err := g.writeOp(*ack); err != nil {
			return wire.Operation{}, err
		}
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
	if conf.GID != gr.GID || conf.Epoch != gr.Epoch {
		return unconfirmed(fmt.Errorf("the grant is from incarnation %d (epoch %d), mgr.%s is active as %d (epoch %d)", gr.GID, gr.Epoch, conf.Mgr, conf.GID, conf.Epoch))
	}

	if !g.now().Before(until) {
		return unconfirmed(errors.New("the confirmation expired before the apply"))
	}

	// the operator's approval the grant carries: verified, and recorded if newer
	if gr.Approval != nil {
		if err := g.Node.RecordApproval(ctx, *gr.Approval); err != nil {
			op.State, op.Error = wire.OpRefused, err.Error()

			return op, g.writeOp(op)
		}
	}

	if gr.Restart != nil {
		return g.restart(ctx, gr, op, until)
	}

	if gr.Reboot {
		return g.reboot(ctx, gr, op, until)
	}

	// an acknowledgement alone changes no document; its revision is fenced like
	// an applied one, so it cannot be replayed once its record is pruned
	if len(gr.Docs) == 0 {
		if err := g.Node.AckBefore(ctx, until, gr.Revision); err != nil {
			op.State, op.Error = wire.OpRefused, err.Error()

			return op, g.writeOp(op)
		}

		op.State, op.Error = wire.OpCompleted, ""
		if err := g.writeOp(op); err != nil {
			return op, err
		}

		if ack != nil {
			if err := g.acknowledge(*ack); err != nil {
				return op, err
			}
		}

		return op, g.prune()
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
	case err == nil && op.Job != nil:
		op.State, op.Error = wire.OpStarted, "" // until the job ended and its result is read
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

	// the acknowledged job is done: a tombstone first, so it never runs again
	if ack != nil && op.State == wire.OpCompleted {
		if err := g.acknowledge(*ack); err != nil {
			return op, err
		}
	}

	return op, g.prune()
}

// restart runs a confirmed restart grant: the operation is recorded as started
// with its instance before Talos is asked. Talos answers once it signalled the
// daemon, before the daemon stopped, so the operation stays started, and an
// error leaves it uncertain: reconcile decides both from the instance, and
// until then the agent runs no other grant.
func (g *Granter) restart(ctx context.Context, gr wire.Grant, op wire.Operation, until time.Time) (wire.Operation, error) {
	started, err := g.Node.RestartBefore(ctx, until, gr.Revision, *gr.Restart, func(instance, boot string) error {
		op.State, op.Instance, op.BootID, op.At = wire.OpStarted, instance, boot, time.Now().UnixNano()

		return g.writeOp(op)
	})

	switch {
	case err == nil:
		op.State, op.Error = wire.OpStarted, "" // until a newer instance exists
	case !started:
		op.State, op.Error = wire.OpRefused, err.Error()
	default:
		op.State, op.Error = wire.OpUncertain, err.Error()
	}

	if err := g.writeOp(op); err != nil {
		return op, err
	}

	return op, g.prune()
}

// reboot runs a confirmed reboot grant: recorded as started with the boot
// before Talos is asked; it completes once the node runs another boot
// (reconcile, after the agent started again). A call never sent, or one
// Talos refused, changed nothing; one without an answer is uncertain, as Talos
// may still reboot.
func (g *Granter) reboot(ctx context.Context, gr wire.Grant, op wire.Operation, until time.Time) (wire.Operation, error) {
	started, err := g.Node.RebootBefore(ctx, until, gr.Revision, func(boot string) error {
		op.State, op.Reboot, op.BootID, op.At = wire.OpStarted, true, boot, time.Now().UnixNano()

		return g.writeOp(op)
	})

	switch {
	case err == nil:
		op.State, op.Error = wire.OpStarted, "" // until the node runs another boot
	case !started:
		op.State, op.Error = wire.OpRefused, err.Error()
	default:
		switch status.Code(err) {
		case codes.Unavailable, codes.DeadlineExceeded, codes.Canceled, codes.Unknown:
			op.State, op.Error = wire.OpUncertain, err.Error()
		default:
			op.State, op.Error = wire.OpRefused, err.Error()
		}
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
	if err := g.suspended(); err != nil {
		return wire.Operation{}, err
	}

	if err := g.admitted(a.Epoch); err != nil {
		return wire.Operation{}, err
	}

	if err := g.reconcile(ctx); err != nil {
		return wire.Operation{}, err
	}

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

	if conf.GID != a.GID || conf.Epoch != a.Epoch || !g.now().Before(until) {
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

// Reconcile decides the agent's unresolved operations the node can decide;
// the agent runs it when it starts.
func (g *Granter) Reconcile(ctx context.Context) error {
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-ctx.Done():
		return ctx.Err()
	}

	return g.reconcile(ctx)
}

// Close raises the session floor to a new leader's epoch (wire.Close):
// confirmed like a grant, under the grant slot, so no grant of an earlier
// incarnation is running when it returns or can start afterwards.
func (g *Granter) Close(ctx context.Context, c wire.Close) (int64, error) {
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-ctx.Done():
		return 0, ctx.Err()
	}

	return g.close(ctx, c)
}

func (g *Granter) close(ctx context.Context, c wire.Close) (int64, error) {
	if err := g.suspended(); err != nil {
		return 0, err
	}

	f, err := g.floor()
	if err != nil {
		return 0, err
	}

	if c.Epoch < f {
		return 0, fmt.Errorf("the incarnation of epoch %d is closed: a successor of epoch %d took over", c.Epoch, f)
	}

	if c.Epoch == f {
		return f, nil
	}

	confirm := g.confirm
	if confirm == nil {
		confirm = func(ctx context.Context, t ConfirmTarget, revision int64, operation, inputsHash string) (wire.Confirmation, time.Time, error) {
			return g.Channel.Confirm(ctx, g.ClientTLS, t, revision, operation, inputsHash)
		}
	}

	conf, until, err := confirm(ctx, ConfirmTarget{Addr: c.MgrAddr, Mgr: c.Mgr}, 0, "close-"+strconv.FormatInt(c.GID, 10), wire.CloseInputs(c))
	if err != nil {
		return 0, err
	}

	if conf.GID != c.GID || conf.Epoch != c.Epoch || !g.now().Before(until) {
		return 0, errors.New("the close is not confirmed for this incarnation")
	}

	b, err := json.Marshal(session{Schema: ownershipSchema, Floor: c.Epoch})
	if err != nil {
		return 0, err
	}

	return c.Epoch, g.Records.Write(sessionRecord, b)
}

// HandleClose serves POST /v1/close from a new leader.
func (g *Granter) HandleClose(w http.ResponseWriter, r *http.Request) {
	leader, err := g.leaderOf(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	var c wire.Close

	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&c); err != nil {
		http.Error(w, "malformed close", http.StatusBadRequest)

		return
	}

	gr := wire.Grant{Version: c.Version, FSID: c.FSID, Host: c.Host, Mgr: c.Mgr, MgrAddr: c.MgrAddr, GID: c.GID, Epoch: c.Epoch, Revision: 1, Operation: "close", Docs: []wire.GrantDoc{{Kind: "-", Name: "-"}}}
	if err := g.checkGrant(gr, leader); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), grantTimeout)
	defer cancel()

	floor, err := g.Close(ctx, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wire.CloseReply{Version: wire.Version, Floor: floor})
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
	gr := wire.Grant{Version: a.Version, FSID: a.FSID, Host: a.Host, Mgr: a.Mgr, MgrAddr: a.MgrAddr, GID: a.GID, Epoch: a.Epoch, Revision: a.Revision, Operation: a.Operation, Docs: []wire.GrantDoc{{Kind: "-", Name: "-"}}}
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

	// an apply left undecided is decided first, if no grant is running
	select {
	case g.mu <- struct{}{}:
		err := g.reconcile(ctx)
		<-g.mu

		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)

			return
		}
	default:
	}

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

	// under the grant slot, which a suspension takes after its record: a
	// handoff admitted before it ends before the receipt, a later one is refused
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-r.Context().Done():
		http.Error(w, "the agent is busy", http.StatusServiceUnavailable)

		return
	}

	if err := g.suspended(); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

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

// tombRecord prefixes the tombstones of acknowledged jobs, never pruned.
const tombRecord = "tomb-"

// jobOf finds the job a grant runs (at most one, not a tombstoned id) and the
// job record an acknowledgement in it matches. A grant that removes a job
// document whose result is not acknowledged needs that acknowledgement.
func (g *Granter) jobOf(gr wire.Grant) (*wire.JobRef, *wire.Operation, error) {
	var job *wire.JobRef

	for _, d := range gr.Docs {
		if d.Kind != "ContainerConfig" || d.YAML == nil {
			continue
		}

		ref, ok := g.Node.Policy.jobOf(Doc{Kind: d.Kind, Name: d.Name, YAML: []byte(*d.YAML)})
		if !ok {
			continue
		}

		if job != nil {
			return nil, nil, errors.New("a grant with more than one job")
		}

		if _, err := g.Records.Read(tombRecord + ref.ID); err == nil {
			return nil, nil, fmt.Errorf("job %s is finished and acknowledged", ref.ID)
		}

		job = &ref
	}

	names, err := g.Records.List("op-")
	if err != nil {
		return nil, nil, err
	}

	var ack *wire.Operation

	acked := false // the acknowledgement names a job acknowledged before: no change

	for _, n := range names {
		op, found, err := g.readOp(strings.TrimPrefix(n, "op-"))
		if err != nil {
			return nil, nil, err
		}

		if !found || op.Job == nil {
			continue
		}

		if op.Acked {
			acked = acked || (gr.Ack != nil && gr.Ack.Job == op.Job.ID && gr.Ack.Inputs == op.Job.Inputs)

			continue
		}

		// a removal, or a replacement by anything but the same job again
		removed := false

		for _, d := range gr.Docs {
			if d.Kind != "ContainerConfig" || d.Name != op.Job.Doc {
				continue
			}

			same := false
			if d.YAML != nil {
				ref, ok := g.Node.Policy.jobOf(Doc{Kind: d.Kind, Name: d.Name, YAML: []byte(*d.YAML)})
				same = ok && ref.ID == op.Job.ID && ref.Inputs == op.Job.Inputs
			}

			removed = removed || !same
		}

		rc := -1
		if op.Result != nil {
			rc = op.Result.RC
		}

		matches := gr.Ack != nil && gr.Ack.Job == op.Job.ID && gr.Ack.Inputs == op.Job.Inputs && gr.Ack.RC == rc
		ended := op.State != wire.OpReserved && op.State != wire.OpStarted

		switch {
		case matches && ended:
			o := op
			ack = &o
		case removed:
			return nil, nil, fmt.Errorf("the job document %s is removed without an acknowledgement of its outcome", op.Job.Doc)
		}
	}

	if gr.Ack != nil && ack == nil && !acked {
		if _, err := g.Records.Read(tombRecord + gr.Ack.Job); err != nil {
			return nil, nil, errors.New("the acknowledgement matches no ended job's recorded outcome")
		}
	}

	return job, ack, nil
}

// acknowledge marks a job's outcome acknowledged: its tombstone (in the
// records and next to its result, for the job script) comes first; the result
// files go once the document and its instance are gone (reconcile).
func (g *Granter) acknowledge(op wire.Operation) error {
	if err := g.Records.Write(tombRecord+op.Job.ID, []byte(op.Job.Inputs)); err != nil {
		return err
	}

	if err := g.Node.writeJobFile(op.Job.ID, "tombstone", op.Job.Inputs); err != nil {
		return err
	}

	op.Acked = true

	return g.writeOp(op)
}
