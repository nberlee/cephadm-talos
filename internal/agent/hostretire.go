package agent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// A removed host's retirement (`ceph orch host rm`, plan 04 step 6 part A).
// The removal (remove_host) checks the host has no daemons, has the module
// mark it retiring in its fold (`retire start`, which records the
// certificates its enrollment record carries), records State.Retiring with
// the agent's identity (address, certificates, key names) and drops the host
// from the hosts, then ends: nothing of it needs the agent. The retirement's
// steps run between ledger operations, so an agent that does not answer never
// holds the ledger: the strip (every document the agent owns off its node,
// journaled <op>.strip.<n>), the retirement grant (the agent removes its own
// documents and retires its records, journaled <op>.retire.<n>, granted while
// it answers /v1/node at the journaled address), then the end (`retire done`:
// the module revokes and deletes its credentials and retires the host) and
// the record cleared. The retirement is taken as done once the agent answers
// 410 Gone (retired), or once a grant was sent and it has not answered for
// retireSilence. An agent that never answers waits for the operator
// (TALOS_HOST_RETIRING; `host forget`).

// KindRetire is the journal kind of a retirement grant.
const KindRetire = "retire"

// retireSilence is how long an agent that was sent its retirement grant must
// not answer before the retirement is taken as done: Talos stops it once its
// own documents are gone, which may cut the grant's answer off.
const retireSilence = 2 * time.Minute

// retireRetry is how long a strip or a retirement grant that ended without
// completing waits before its next attempt.
const retireRetry = time.Minute

// retireProbe bounds a retiring agent's probe, so a node that is off does not
// stall every tick.
const retireProbe = 10 * time.Second

// retireStepRe are the journal ids of a retirement's steps: resolved by the
// retirement while the agent answers, never by the request loop.
var retireStepRe = regexp.MustCompile(`^op-[0-9a-f]{16}\.(?:start|(?:strip|retire)\.[0-9]+)$`)

// removeHost removes a host without daemons (plan 04, step 6): the module
// marks it retiring, then its retirement is recorded in the state and the
// host leaves the hosts; its steps run between ledger operations.
func (l *LeaderLoop) removeHost(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	// retire start's own journal record: from before the call until the
	// record below is published its state is granting, which keeps unstick
	// from giving the removal up: the fold may hold the host retiring, and
	// only a published record lets retireSteps advance it. A takeover imports
	// it, finds the same state and asks again (retire start is idempotent);
	// no grant is behind it, so the request loop does not resolve it. Only
	// the module's definite refusal (400: no retiring entry of this operation
	// after its ledger settled) ends it, and the removal can be given up
	startKey := JournalPrefix(gid) + "op/" + op.ID + ".start"
	start := JournalOp{Version: journalVersion, Kind: "retire_start", Host: op.Host, State: JournalGranting}

	if r, ok := st.Retiring[op.Host]; ok {
		if r.Op == op.ID {
			start.State = wire.OpCompleted
			if err := writeJSONKey(ctx, js, startKey, start); err != nil {
				return err
			}

			return finish(ctx, js, gid, op, wire.OpCompleted, nil) // recorded already
		}

		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s is retiring (operation %s)", op.Host, r.Op))
	}

	h, member := st.Host(op.Host)
	member = member && h.Name == op.Host

	prev, found, err := readJSONKey[JournalOp](ctx, js, startKey)
	if err != nil {
		return err
	}

	// started, as far as anything here knows: not given up by these checks
	started := found && prev.State != wire.OpRefused

	if member && !started {
		for _, d := range st.Daemons {
			if d.Host == op.Host {
				return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s still has %s.%s", op.Host, d.Type, d.ID))
			}
		}

		if op.Host == l.Self.Name {
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s runs the leader", op.Host))
		}
	}

	// the module's fold marks the host retiring first, with the certificates
	// of its enrollment record
	b.reserve(op.ID, "", op.Host)

	if err := writeJSONKey(ctx, js, startKey, start); err != nil {
		return err
	}

	enroll, err := b.RetireStart(ctx, op.ID)
	if errors.Is(err, errBridgeBad) {
		start.State, start.Error = wire.OpRefused, err.Error()

		return errors.Join(err, writeJSONKey(ctx, js, startKey, start))
	}

	if err != nil {
		return err
	}

	now := l.clock().UTC().Truncate(time.Second)

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		if _, ok := st.Retiring[op.Host]; ok {
			return nil
		}

		r := &state.Retiring{Op: op.ID, Step: state.RetireStrip, Attempt: 1, Since: now, Tried: now,
			EnrollCert: enroll.AgentCert, EnrollClientCert: enroll.AgentClientCert}

		if h, ok := st.Host(op.Host); ok && h.Name == op.Host {
			r.Addr, r.AgentCert, r.AgentClientCert, r.AgentKeys = h.Addr, h.AgentCert, h.AgentClientCert, h.AgentKeys
		} else {
			// not in the leader's state: nothing to reach, its credentials go
			r.Step, r.Attempt = state.RetireEnd, 0
		}

		if st.Retiring == nil {
			st.Retiring = map[string]*state.Retiring{}
		}

		st.Retiring[op.Host] = r
		st.RemoveHost(op.Host)

		return nil
	}); err != nil {
		return err
	}

	start.State = wire.OpCompleted
	if err := writeJSONKey(ctx, js, startKey, start); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// contact is a host to reach: a member, or a retiring host by its journaled
// identity, whose agent must then serve the journaled server certificate.
func (l *LeaderLoop) contact(st *state.State, name string) (state.Host, bool) {
	if h, ok := st.Host(name); ok && h.Name == name {
		l.pins.Delete(name)

		return h, true
	}

	h, _, ok := st.RetiringHost(name)
	if ok {
		l.pins.Store(name, h.AgentCert)
	}

	return h, ok
}

// pinned is the server certificate (DER) a retiring host's agent must serve,
// nil for any other host. Every member after the handoff has its agent
// certificate in the state (the handoff and add_host require it), so a
// retirement always journals one; without one nothing would match.
func (l *LeaderLoop) pinned(name string) ([]byte, bool) {
	v, ok := l.pins.Load(name)
	if !ok {
		return nil, false
	}

	blk, _ := pem.Decode([]byte(v.(string)))
	if blk == nil {
		return []byte{}, true // nothing journaled: nothing matches
	}

	return blk.Bytes, true
}

// retireSteps advances every retirement in progress, each on its own.
func (l *LeaderLoop) retireSteps(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	names := make([]string, 0, len(st.Retiring))
	for n := range st.Retiring {
		names = append(names, n)
	}

	sort.Strings(names)

	var errs []error

	for _, n := range names {
		if !l.stillLeader(gid, epoch) {
			return nil
		}

		if err := l.retireStep(ctx, b, js, gid, epoch, n); err != nil {
			errs = append(errs, fmt.Errorf("retirement of %s: %w", n, err))
		}
	}

	return errors.Join(errs...)
}

// changeRetiring changes a retirement's record, if it is still the one of op.
func (l *LeaderLoop) changeRetiring(ctx context.Context, b *Bridge, gid int64, host, op string, change func(*state.Retiring)) error {
	return l.changeState(ctx, b, gid, func(st *state.State) error {
		if r, ok := st.Retiring[host]; ok && r.Op == op {
			change(r)
		}

		return nil
	})
}

// retireStep advances one retirement by a step.
func (l *LeaderLoop) retireStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, name string) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	h, rec, ok := st.RetiringHost(name)
	if !ok {
		return nil
	}

	r := *rec
	b.reserve(r.Op, "", name)

	if r.Step == state.RetireEnd {
		return l.retireEnd(ctx, b, js, gid, name, r)
	}

	l.contact(st, name) // its agent must serve the journaled certificate

	now := l.clock().UTC().Truncate(time.Second)
	code, perr := l.probeRetiring(ctx, h)

	// retired: it refuses everything, its records are moved aside
	if code == http.StatusGone {
		return l.retireDone(ctx, b, js, gid, name, r, "the agent answered that it is retired")
	}

	sent := false

	if r.Step == state.RetireGrant && r.Attempt > 0 {
		s, err := l.journalState(ctx, b, js, gid, retireID(r))
		if err != nil {
			return err
		}

		sent = s == JournalGranting || s == wire.OpUncertain || s == wire.OpCompleted
	}

	notAnswering := fmt.Sprintf("the agent does not answer at %s", r.Addr)

	// no answer at all (a status code is an answer, as is a refusal)
	if code == 0 {
		l.log("retirement of %s: %v", name, perr)

		silent := r.Silent
		if silent.IsZero() {
			silent = now
		}

		if sent && now.Sub(silent) >= retireSilence {
			return l.retireDone(ctx, b, js, gid, name, r, fmt.Sprintf("the agent has not answered for %s since its retirement grant", retireSilence))
		}

		why := r.Error
		if !sent {
			why = notAnswering
		}

		if silent.Equal(r.Silent) && sent == r.Sent && why == r.Error {
			return nil
		}

		return l.changeRetiring(ctx, b, gid, name, r.Op, func(x *state.Retiring) { x.Silent, x.Sent, x.Error = silent, sent, why })
	}

	// it answers
	if !r.Silent.IsZero() || r.Sent != sent || r.Error == notAnswering {
		if err := l.changeRetiring(ctx, b, gid, name, r.Op, func(x *state.Retiring) {
			x.Silent, x.Sent = time.Time{}, sent
			if x.Error == notAnswering {
				x.Error = ""
			}
		}); err != nil {
			return err
		}

		r.Silent, r.Sent = time.Time{}, sent
	}

	if perr != nil {
		return perr // it cannot report its node now: asked again
	}

	if r.Step == state.RetireStrip {
		return l.retireStrip(ctx, b, js, gid, epoch, name, r, now)
	}

	return l.retireGrant(ctx, b, js, gid, epoch, name, r, now)
}

// retireID is the journal id of a retirement's current step.
func retireID(r state.Retiring) string {
	if r.Step == state.RetireStrip {
		return fmt.Sprintf("%s.strip.%d", r.Op, r.Attempt)
	}

	return fmt.Sprintf("%s.retire.%d", r.Op, r.Attempt)
}

// probeRetiring asks a retiring host's agent for its node report, within
// retireProbe: its status code (410 once it is retired) and an error when it
// does not answer as an agent that is not retired.
func (l *LeaderLoop) probeRetiring(ctx context.Context, h state.Host) (int, error) {
	pctx, cancel := context.WithTimeout(ctx, retireProbe)
	defer cancel()

	var rep wire.NodeReport

	return l.call(pctx, h, http.MethodGet, "/v1/node", nil, &rep)
}

// retireStrip removes every document the agent owns, as the removal did
// before (plan 03); one that ends without completing runs again under a new
// attempt after retireRetry.
func (l *LeaderLoop) retireStrip(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, name string, r state.Retiring, now time.Time) error {
	id := retireID(r)

	done, ok, err := l.step(ctx, b, js, gid, epoch, id, name, revisionMode{strip: true})
	if err != nil || !done {
		return err
	}

	if ok {
		return l.changeRetiring(ctx, b, gid, name, r.Op, func(x *state.Retiring) {
			if x.Step == state.RetireStrip && x.Attempt == r.Attempt {
				x.Step, x.Attempt, x.Error = state.RetireGrant, 0, ""
			}
		})
	}

	rec, _, err := l.journalRecord(ctx, b, js, gid, id)
	if err != nil {
		return err
	}

	return l.retireAgain(ctx, b, gid, name, r, now, fmt.Sprintf("the strip of its documents (%s) ended %s: %s", id, rec.State, rec.Error))
}

// retireAgain records why an attempt did not complete and, once retireRetry
// passed since it was sent, starts the next one.
func (l *LeaderLoop) retireAgain(ctx context.Context, b *Bridge, gid int64, name string, r state.Retiring, now time.Time, why string) error {
	next := now.Sub(r.Tried) >= retireRetry
	if !next && why == r.Error {
		return nil
	}

	return l.changeRetiring(ctx, b, gid, name, r.Op, func(x *state.Retiring) {
		if x.Step != r.Step || x.Attempt != r.Attempt {
			return
		}

		x.Error = why

		if next {
			x.Attempt, x.Tried = x.Attempt+1, now
		}
	})
}

// retireGrant grants the agent its retirement under the current attempt, or
// resolves the attempt's grant; one refused, failed or abandoned is followed
// by a new attempt after retireRetry. One that completed waits for the
// agent's 410 or silence.
func (l *LeaderLoop) retireGrant(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, name string, r state.Retiring, now time.Time) error {
	if r.Attempt == 0 {
		if err := l.changeRetiring(ctx, b, gid, name, r.Op, func(x *state.Retiring) {
			if x.Step == state.RetireGrant && x.Attempt == 0 {
				x.Attempt, x.Tried = 1, now
			}
		}); err != nil {
			return err
		}

		r.Attempt, r.Tried = 1, now
	}

	id := retireID(r)

	done, ok, err := l.agentGrant(ctx, b, js, gid, epoch, id, name, KindRetire, func(g *wire.Grant) error {
		g.Retire = true

		return nil
	})

	// the grant's intent may be in the journal now: sent, whatever the answer
	s, jerr := l.journalState(ctx, b, js, gid, id)
	if jerr != nil {
		return errors.Join(err, jerr)
	}

	if sent := s == JournalGranting || s == wire.OpUncertain || s == wire.OpCompleted; sent != r.Sent {
		if serr := l.changeRetiring(ctx, b, gid, name, r.Op, func(x *state.Retiring) {
			if x.Step == state.RetireGrant && x.Attempt == r.Attempt {
				x.Sent = sent
				if sent {
					x.Error = ""
				}
			}
		}); serr != nil {
			return errors.Join(err, serr)
		}
	}

	if err != nil || !done || ok {
		return err // in progress, or completed: its 410 or its silence ends it
	}

	rec, _, err := l.journalRecord(ctx, b, js, gid, id)
	if err != nil {
		return err
	}

	r.Sent = false

	return l.retireAgain(ctx, b, gid, name, r, now, fmt.Sprintf("the retirement grant %s ended %s: %s", id, rec.State, rec.Error))
}

// retireDone takes the retirement as done: the grant or strip of the step in
// progress whose outcome is not known is decided by it (the agent no longer
// answers, or answers that it is retired), then the end.
func (l *LeaderLoop) retireDone(ctx context.Context, b *Bridge, js store.Backend, gid int64, name string, r state.Retiring, why string) error {
	if r.Attempt > 0 {
		id := retireID(r)
		opKey := JournalPrefix(gid) + "op/" + id

		cur, found, err := readJSONKey[JournalOp](ctx, js, opKey)
		if err != nil {
			return err
		}

		if found && (cur.State == JournalGranting || cur.State == wire.OpUncertain) {
			cur.State, cur.Error = wire.OpCompleted, "taken as done: "+why
			if err := writeJSONKey(ctx, js, opKey, cur); err != nil {
				return err
			}
		}
	}

	l.log("retirement of %s: done (%s)", name, why)

	if err := l.changeRetiring(ctx, b, gid, name, r.Op, func(x *state.Retiring) {
		x.Step, x.Retired, x.Silent, x.Error = state.RetireEnd, true, time.Time{}, ""
	}); err != nil {
		return err
	}

	r.Step, r.Retired = state.RetireEnd, true

	return l.retireEnd(ctx, b, js, gid, name, r)
}

// retireEnd has the module revoke and delete the retired agent's credentials
// and retire the host, then clears the record.
func (l *LeaderLoop) retireEnd(ctx context.Context, b *Bridge, _ store.Backend, gid int64, name string, r state.Retiring) error {
	if err := b.RetireDone(ctx, r.Op, []string{r.AgentCert, r.AgentClientCert}); err != nil {
		return err
	}

	l.pins.Delete(name)

	return l.changeState(ctx, b, gid, func(st *state.State) error {
		if x, ok := st.Retiring[name]; ok && x.Op == r.Op {
			delete(st.Retiring, name)

			if len(st.Retiring) == 0 {
				st.Retiring = nil
			}
		}

		return nil
	})
}

// pinnedPeer refuses a retiring host's agent that does not serve its
// journaled server certificate (a re-enrolled agent of that name).
func (l *LeaderLoop) pinnedPeer(name string, c *x509.Certificate) error {
	want, ok := l.pinned(name)
	if !ok {
		return nil
	}

	if string(c.Raw) != string(want) {
		return fmt.Errorf("%s does not serve the certificate its retirement journaled", name)
	}

	return nil
}
