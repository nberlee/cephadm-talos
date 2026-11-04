package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// suspensionRecord holds the agent's suspension for a recovery session (plan
// 03, step 7 slice D): while it exists the agent admits no grant, close,
// abandon or handoff but the session's re-adoption, and runs no leader tick,
// also after a restart.
const suspensionRecord = "suspension"

type suspension struct {
	Schema  int    `json:"schema"`
	Session string `json:"session"`
}

// errSuspended refuses what a suspended agent does not do.
type errSuspended struct{ session string }

func (e errSuspended) Error() string {
	return "the agent is suspended for recovery session " + e.session
}

// suspendWait bounds how long one suspend or receipt call waits for the grant
// slot and the leader's tick; the CLI asks again.
const suspendWait = 30 * time.Second

// readSuspension reads the suspension record; found is false when the agent
// is not suspended.
func (g *Granter) readSuspension() (suspension, bool, error) {
	b, err := g.Records.Read(suspensionRecord)
	if errors.Is(err, records.ErrNotFound) {
		return suspension{}, false, nil
	}

	if err != nil {
		return suspension{}, false, err
	}

	var s suspension
	if err := json.Unmarshal(b, &s); err != nil || s.Schema != ownershipSchema || !uuidRe.MatchString(s.Session) {
		return suspension{}, false, fmt.Errorf("record %s: damaged", suspensionRecord)
	}

	return s, true, nil
}

// suspended refuses while the agent is suspended; an unreadable record counts
// as a suspension.
func (g *Granter) suspended() error {
	s, found, err := g.readSuspension()
	if err != nil {
		return fmt.Errorf("the suspension record: %w", err)
	}

	if found {
		return errSuspended{s.Session}
	}

	return nil
}

// Suspended reports whether the agent is suspended (or cannot tell), for the
// leader's loop.
func (g *Granter) Suspended() bool { return g.suspended() != nil }

// Suspend records the suspension for a session, then cancels the leader's
// tick and waits for it: from the record on, nothing new starts.
func (g *Granter) Suspend(ctx context.Context, session string) error {
	s, found, err := g.readSuspension()
	if err != nil {
		return err
	}

	if !found {
		b, err := json.Marshal(suspension{Schema: ownershipSchema, Session: session})
		if err != nil {
			return err
		}

		// a claim: of two suspensions at once, one session wins
		if err := g.Records.Create(suspensionRecord, b); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}

		if s, found, err = g.readSuspension(); err != nil {
			return err
		}
	}

	if !found || s.Session != session {
		return fmt.Errorf("suspended already for recovery session %s", s.Session)
	}

	if g.Leader != nil {
		return g.Leader.Pause(ctx)
	}

	return nil
}

// SuspendState says what a suspended agent still waits for, or gives its
// receipt once nothing it started runs. It takes the grant slot, so no grant
// is half-way, and reconciles first.
func (g *Granter) SuspendState(ctx context.Context) (wire.SuspendState, error) {
	s, found, err := g.readSuspension()
	if err != nil {
		return wire.SuspendState{}, err
	}

	if !found {
		return wire.SuspendState{}, errors.New("the agent is not suspended")
	}

	st := wire.SuspendState{Version: wire.Version, Session: s.Session}

	if g.Leader != nil {
		if err := g.Leader.Pause(ctx); err != nil {
			st.Waiting = append(st.Waiting, "the leader's tick")

			return st, nil
		}
	}

	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-ctx.Done():
		st.Waiting = append(st.Waiting, "a grant")

		return st, nil
	}

	if err := g.reconcile(ctx); err != nil {
		return wire.SuspendState{}, err
	}

	snap, err := g.Node.Snapshot(ctx)
	if err != nil {
		return wire.SuspendState{}, err
	}

	// an apply that may still land is waited for; one that settled but the
	// node cannot decide stays an uncertain operation in the receipt
	if snap.Intent {
		boot, err := g.Node.Talos.BootID(ctx, "")
		if err != nil || boot == snap.IntentBoot && time.Since(snap.IntentAt) < ApplySettle {
			st.Waiting = append(st.Waiting, "an apply that may still land")
		}
	}

	unresolved, waiting, err := g.unfinished(ctx)
	if err != nil {
		return wire.SuspendState{}, err
	}

	st.Waiting = append(st.Waiting, waiting...)

	intents, waiting, err := g.drainIntents(ctx)
	if err != nil {
		return wire.SuspendState{}, err
	}

	st.Waiting = append(st.Waiting, waiting...)

	if len(st.Waiting) > 0 {
		return st, nil
	}

	floor, err := g.floor()
	if err != nil {
		return wire.SuspendState{}, err
	}

	prepared, err := g.Node.preparedSerials()
	if err != nil {
		return wire.SuspendState{}, err
	}

	st.Receipt = &wire.SuspendReceipt{
		Version: wire.Version, Session: s.Session, Host: g.Channel.Self.Name,
		Revision: snap.Own.Revision, Fence: snap.Fence, Floor: floor,
		Unresolved: unresolved, Intents: intents, Owned: snap.Own.Docs, Prepared: prepared, ApplyPending: snap.Intent,
	}

	return st, nil
}

// unfinished sorts the agent's open operations: a job whose container still
// exists, a reboot or a restart still being decided, waits; any other
// uncertain operation is listed in the receipt and keeps its reservation.
func (g *Granter) unfinished(ctx context.Context) (unresolved []wire.Operation, waiting []string, err error) {
	names, err := g.Records.List("op-")
	if err != nil {
		return nil, nil, err
	}

	unresolved = []wire.Operation{}

	for _, n := range names {
		op, found, err := g.readOp(strings.TrimPrefix(n, "op-"))
		if err != nil {
			return nil, nil, err
		}

		if !found || (op.State != wire.OpStarted && op.State != wire.OpUncertain) {
			continue
		}

		// a reboot or restart, started or without an answer, is waited for
		// within its limit (the reconcile decides it once another boot or a newer
		// instance shows); after the limit an undecided one is listed
		switch {
		case op.Job != nil:
			ended, err := g.Node.ended(ctx, op.Job.Doc)
			if err != nil {
				return nil, nil, err
			}

			if !ended {
				waiting = append(waiting, "job "+op.Job.ID+" of operation "+op.Operation)

				continue
			}
		case op.Reboot && time.Since(time.Unix(0, op.At)) < rebootWithin:
			waiting = append(waiting, "the reboot of operation "+op.Operation)

			continue
		case op.Instance != "" && time.Since(time.Unix(0, op.At)) < ApplySettle:
			waiting = append(waiting, "the restart of operation "+op.Operation)

			continue
		}

		unresolved = append(unresolved, op)
	}

	sort.Slice(unresolved, func(i, j int) bool { return unresolved[i].Revision < unresolved[j].Revision })

	return unresolved, waiting, nil
}

// drainIntents fetches the outcome of every open bridge intent from the
// module on this host: a known outcome settles it, a pending one is waited
// for, and one the module cannot answer (gone, restarted, or not this host's)
// stays open in the receipt.
func (g *Granter) drainIntents(ctx context.Context) (open []wire.BridgeIntent, waiting []string, err error) {
	intents, err := OpenIntents(g.Records)
	if err != nil {
		return nil, nil, err
	}

	open = []wire.BridgeIntent{}

	for _, in := range intents {
		if g.Leader != nil {
			b := g.Leader.bridge()

			_, err := b.Outcome(ctx, in.Dispatch)

			switch {
			case err == nil || errors.Is(err, errBridgeRan):
				continue // settled: the record is gone
			case errors.Is(err, errOutcomePending):
				waiting = append(waiting, "the bridge call "+in.Call+" of operation "+in.Operation)

				continue
			}
		}

		open = append(open, in)
	}

	return open, waiting, nil
}

// operatorOf checks that a request comes with the cluster's operator
// certificate.
func (g *Granter) operatorOf(r *http.Request) error {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("no client certificate")
	}

	id, err := pki.CertIdentity(r.TLS.PeerCertificates[0])
	if err != nil || id.FSID != g.Channel.Self.FSID || id.Role != pki.RoleOperator {
		return errors.New("only the operator calls this")
	}

	return nil
}

// HandleSuspend serves POST /v1/suspend from the CLI's operator certificate:
// the agent suspends for the session and answers its state.
func (g *Granter) HandleSuspend(w http.ResponseWriter, r *http.Request) {
	if err := g.operatorOf(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	var s wire.Suspend

	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&s); err != nil || s.Version != wire.Version || s.FSID != g.Channel.Self.FSID || s.Host != g.Channel.Self.Name || !uuidRe.MatchString(s.Session) {
		http.Error(w, "malformed suspension", http.StatusBadRequest)

		return
	}

	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2*suspendWait + 10*time.Second))

	ctx, cancel := context.WithTimeout(r.Context(), suspendWait)
	defer cancel()

	if err := g.Suspend(ctx, s.Session); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	actx, acancel := context.WithTimeout(r.Context(), suspendWait)
	defer acancel()

	g.answerSuspension(actx, w)
}

// HandleSuspendState serves GET /v1/suspend: the suspended agent's state.
func (g *Granter) HandleSuspendState(w http.ResponseWriter, r *http.Request) {
	if err := g.operatorOf(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(suspendWait + 10*time.Second))

	ctx, cancel := context.WithTimeout(r.Context(), suspendWait)
	defer cancel()

	g.answerSuspension(ctx, w)
}

// answerSuspension answers 200 with the receipt, or 202 with what the agent
// still waits for.
func (g *Granter) answerSuspension(ctx context.Context, w http.ResponseWriter) {
	st, err := g.SuspendState(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	w.Header().Set("Content-Type", "application/json")

	if st.Receipt == nil {
		w.WriteHeader(http.StatusAccepted)
	}

	_ = json.NewEncoder(w).Encode(st)
}
