package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// A host's drain (`ceph orch host drain`, plan 04 step 5): the module accepts
// drain_host once and marks the host draining in its fold; the leader records
// Host.Drain in the state and runs its steps between ledger operations, one
// at a time, each journaled under the drain as <op>.d<attempt>: every OSD of
// the host marked out at once, each OSD's removal (drained until safe to
// destroy, purged, zapped with --zap-osd-devices), its RGW, its mgr (failed
// over first when it is the active one), its mon (only while the rest keep
// quorum), then the module's drain_done entry and the record cleared. A step
// does not hold the ledger: an OSD's drain waits as long as recovery takes.
// A step that fails for stuckAfter pauses the drain (drain_resume, from
// `ceph orch host drain` again); drain_stop lets no new step start.

// isDrainControl reports whether a kind is one of a drain's controls.
func isDrainControl(kind string) bool {
	return kind == KindDrainStop || kind == KindDrainResume
}

// draining reports whether a host of the state has a drain.
func draining(st *state.State) bool {
	for _, h := range st.Hosts {
		if h.Drain != nil {
			return true
		}
	}

	return false
}

// drainStepOut is the drain's first step: every OSD of the host out at once,
// so data moves once, not once per OSD onto the next OSD of the same host.
const drainStepOut = "out"

// drainStart records an accepted drain in the state. One that cannot start
// (its host gone, another drain recorded) ends failed, closed in the fold.
func (l *LeaderLoop) drainStart(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	refuse := func(cause error) error {
		if err := l.drainRefused(ctx, b, op); err != nil {
			return err
		}

		return finish(ctx, js, gid, op, JournalFailed, cause)
	}

	h, ok := st.Host(op.Host)
	if !ok {
		return refuse(fmt.Errorf("no host %s", op.Host))
	}

	if h.Drain != nil && h.Drain.Op == op.ID {
		return finish(ctx, js, gid, op, wire.OpCompleted, nil)
	}

	for _, x := range st.Hosts {
		if x.Drain != nil {
			return refuse(fmt.Errorf("%s is draining (operation %s)", x.Name, x.Drain.Op))
		}
	}

	if h.Maintenance {
		return refuse(fmt.Errorf("%s is in maintenance", h.Name))
	}

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		h, ok := st.Host(op.Host)
		if !ok {
			return fmt.Errorf("no host %s", op.Host)
		}

		if h.Drain == nil {
			h.Drain = &state.Drain{Op: op.ID, Zap: op.Zap}
			st.AddHost(h)
		}

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// drainRefused closes a drain that never got recorded in the module's fold.
func (l *LeaderLoop) drainRefused(ctx context.Context, b *Bridge, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	if h, ok := st.Host(op.Host); ok && h.Drain != nil && h.Drain.Op == op.ID {
		return nil // recorded: its steps end it
	}

	return b.Retire(ctx, "drain done", op.ID)
}

// drainControl carries out a drain's stop or resume: they change its record
// alone. A stop lets no new step start (one in progress finishes); a resume
// lifts a pause.
func (l *LeaderLoop) drainControl(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		h, ok := st.Host(op.Host)
		if !ok || h.Drain == nil || h.Drain.Op != op.Drain {
			return nil // ended already
		}

		switch {
		case op.Kind == KindDrainStop && h.Drain.Paused && mustFinish(st, *h.Drain):
			// a removal whose daemon left the state is finished first: retried
			h.Drain.Stopped, h.Drain.Paused, h.Drain.Error = true, false, ""
			h.Drain.Attempt++
		case op.Kind == KindDrainStop && h.Drain.Paused:
			// the failed step is given up: the drain ends
			h.Drain.Stopped, h.Drain.Paused, h.Drain.Step = true, false, ""
		case op.Kind == KindDrainStop:
			h.Drain.Stopped = true
		case h.Drain.Paused:
			// the failed step runs again first, under a new attempt
			h.Drain.Paused, h.Drain.Error = false, ""
			if h.Drain.Step != "" {
				h.Drain.Attempt++
			}
		}

		st.AddHost(h)

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// drainControlsAhead carries out the drain controls among the executable
// operations after a ledger key, ahead of their turn.
func (l *LeaderLoop) drainControlsAhead(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, after string) error {
	for {
		entries, more, err := b.Ledger(ctx, after)
		if err != nil {
			return err
		}

		for _, e := range entries {
			if isDrainControl(e.Op.Kind) {
				if _, err := l.ledgerOp(ctx, b, js, gid, epoch, e); err != nil {
					return err
				}
			}

			after = e.Key
		}

		if !more || len(entries) == 0 {
			return nil
		}
	}
}

// mustFinish reports whether a drain's step is a removal past its point of no
// return: a mgr, RGW or mon taken out of the state (removeDaemon drops it
// before the revision and the retirement), or an OSD whose retirement was
// asked for (marked Retiring before the module's purge, Purged after it,
// both before its zap and its state entry go). It is finished before
// the drain record goes, also after a stop. An OSD absent is removed (it
// leaves the state last); a daemon still in the state, not purged, may be
// abandoned by a stop.
func mustFinish(st *state.State, d state.Drain) bool {
	typ, _, _ := strings.Cut(d.Step, ".")
	if d.Step == "" || d.Step == drainStepOut {
		return false
	}

	if typ == state.TypeOSD {
		x, ok := daemonOf(st, d.Step)

		return ok && (x.Retiring || x.Purged)
	}

	x, ok := st.Find(d.Step)

	return !ok || x.Host != strings.TrimPrefix(d.Step, typ+".")
}

// drainNext is a drain's next step on its host: the OSDs out, each OSD (the
// lowest id first), the RGW, the mgr, the mon; "" when nothing is left.
func drainNext(st *state.State, h state.Host, d state.Drain) string {
	var osds []int

	for _, x := range st.DaemonsOf(state.TypeOSD, h.Name) {
		if x.OSDID != nil && x.OSDUUID != "" && !x.LocalOnly && !x.Purged {
			osds = append(osds, *x.OSDID)
		}
	}

	sort.Ints(osds)

	if len(osds) > 0 && !slices.Contains(d.Done, drainStepOut) {
		return drainStepOut
	}

	if len(osds) > 0 {
		return fmt.Sprintf("osd.%d", osds[0])
	}

	for _, typ := range []string{state.TypeRGW, state.TypeMgr, state.TypeMon} {
		if x, ok := st.Find(typ + "." + h.Name); ok && x.Host == h.Name {
			return typ + "." + h.Name
		}
	}

	return ""
}

// drainStep carries out the drain's next step, or the one in progress: chosen
// and recorded in the state, run under its own journal id until it ended,
// then recorded as done or the drain paused with its error. A drain stopped
// or with nothing left ends: the module closes it (drain_done), then the
// record goes.
func (l *LeaderLoop) drainStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	var h state.Host

	found := false

	for _, x := range st.Hosts {
		if x.Drain != nil {
			h, found = x, true

			break
		}
	}

	if !found {
		return nil
	}

	d := *h.Drain

	// paused: its failed step stays recorded until a resume or a stop
	if d.Paused {
		return nil
	}

	if d.Step == "" {
		next := ""
		if !d.Stopped {
			next = drainNext(st, h, d)
		}

		if next == "" {
			// closed in the fold, then cleared: a retry finds it closed already
			if err := b.Retire(ctx, "drain done", d.Op); err != nil {
				return err
			}

			return l.changeState(ctx, b, gid, func(st *state.State) error {
				if x, ok := st.Host(h.Name); ok && x.Drain != nil && x.Drain.Op == d.Op && x.Drain.Step == "" {
					x.Drain = nil
					st.AddHost(x)
				}

				return nil
			})
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			if x, ok := st.Host(h.Name); ok && x.Drain != nil && x.Drain.Op == d.Op && x.Drain.Step == "" {
				x.Drain.Step, x.Drain.Attempt, x.Drain.First = next, x.Drain.Attempt+1, x.Drain.Attempt+1
				st.AddHost(x)
			}

			return nil
		}); err != nil {
			return err
		}

		d.Step, d.Attempt, d.First = next, d.Attempt+1, d.Attempt+1
	}

	id := fmt.Sprintf("%s.d%d", d.Op, d.Attempt)
	key := JournalPrefix(gid) + "op/" + id

	s, err := l.journalState(ctx, b, js, gid, id)
	if err != nil {
		return err
	}

	if !terminal(s) {
		run := l.drainRun(ctx, b, js, gid, epoch, st, h, d, id)
		if err := l.unstick(ctx, js, key, key, LedgerOp{ID: id, Kind: KindDrain, Host: h.Name}, nil, run); err != nil {
			return err
		}

		if s, err = l.journalState(ctx, b, js, gid, id); err != nil || !terminal(s) {
			return err
		}
	}

	rec, _, err := l.journalRecord(ctx, b, js, gid, id)
	if err != nil {
		return err
	}

	ok := s == wire.OpCompleted || s == JournalNoChange

	return l.changeState(ctx, b, gid, func(st *state.State) error {
		x, found := st.Host(h.Name)
		if !found || x.Drain == nil || x.Drain.Op != d.Op || x.Drain.Step != d.Step || x.Drain.Attempt != d.Attempt {
			return nil
		}

		if !ok && (!x.Drain.Stopped || mustFinish(st, *x.Drain)) {
			// the step stays: a resume continues its removal first; a stop
			// does not give up a removal whose daemon left the state
			x.Drain.Paused, x.Drain.Error = true, fmt.Sprintf("%s: %s %s", d.Step, s, rec.Error)
			st.AddHost(x)

			return nil
		}

		if ok && d.Step == drainStepOut && !slices.Contains(x.Drain.Done, drainStepOut) {
			x.Drain.Done = append(x.Drain.Done, drainStepOut)
		}

		x.Drain.Step = ""
		st.AddHost(x)

		return nil
	})
}

// drainRun advances a drain's step under its journal id; nil once the step
// ended in the journal.
func (l *LeaderLoop) drainRun(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, st *state.State, h state.Host, d state.Drain, id string) error {
	op := LedgerOp{ID: d.Op, Kind: KindDrain, Host: h.Name, Zap: d.Zap}
	r := removal{op: op, id: id, daemon: d.Step, zap: d.Zap, base: fmt.Sprintf("%s.d%d", d.Op, max(d.First, 1))}

	if d.Step == drainStepOut {
		r.daemon = "" // every OSD of the host
		if err := r.call(ctx, b, "osd out"); err != nil {
			return err
		}

		return r.finish(ctx, js, gid, wire.OpCompleted, nil)
	}

	// a daemon absent from the state is not done: a removal takes it out of
	// the state before its revision, the instance's end and its retirement,
	// so the removal is continued under the step's journal id and the step
	// ends only with the removal's record (an OSD leaves the state last)
	typ, id2, _ := strings.Cut(d.Step, ".")

	switch typ {
	case state.TypeOSD:
		x, ok := daemonOf(st, d.Step)
		if ok && x.Host == h.Name {
			r.uuid = x.OSDUUID
		} else if d.Attempt != d.First {
			// resumed after its removal ended: an OSD leaves the state last
			// (purged, zapped or not, which the pause reported)
			return r.finish(ctx, js, gid, wire.OpCompleted, nil)
		}

		return l.removeOSDAs(ctx, b, js, gid, epoch, r)
	case state.TypeMgr:
		rs, err := l.journalState(ctx, b, js, gid, id+".rev")
		if err != nil {
			return err
		}

		// the active mgr fails over first, by its gid; a removal grant already
		// sent is resolved by the removal
		if rs == "" {
			active, agid, err := b.ActiveMgrGID(ctx)
			if err != nil {
				return err
			}

			if active == id2 {
				if err := writeJSONKey(ctx, js, JournalPrefix(gid)+"op/"+id+".fail", JournalOp{Version: journalVersion, Kind: "mgr_fail", Host: h.Name, State: wire.OpStarted, MgrGID: agid}); err != nil {
					return err
				}

				if err := b.MgrFail(ctx, d.Op, agid, id2, h.Name); err != nil {
					return fmt.Errorf("%w: failing the active mgr on %s over: %w", errRetry, h.Name, err)
				}

				return fmt.Errorf("%w: the active mgr on %s is failing over", errRetry, h.Name)
			}
		}

		return l.removeDaemonAs(ctx, b, js, gid, epoch, r)
	case state.TypeRGW, state.TypeMon:
		return l.removeDaemonAs(ctx, b, js, gid, epoch, r)
	}

	return r.finish(ctx, js, gid, JournalFailed, errors.New(d.Step+" is not removed by a drain"))
}
