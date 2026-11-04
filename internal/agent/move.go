package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// A host's address change (`ceph orch host set-addr`, plan 04 step 5): the
// module accepts set_host_addr once and marks the host moving in its fold;
// the leader records Host.Move in the state and runs its steps between
// ledger operations, one at a time, each journaled under the move as
// <op>.m<attempt>, as a drain's (drain.go): the agent confirmed at the new
// address (the module's addr_moved makes it the host's address in the fold,
// Addr switches), the RGW with its keepalived off until the peers on the
// other ingress hosts name the new address, the mgr (failed over first when
// it is the active one), the OSDs under a noout reason "move", the mon (out
// of the monmap, back as a new generation with a fresh store), mon_host in
// every ceph.conf, the agent's and the mgr's certificates reissued, then the
// module's addr_set entry and the record cleared. Each daemon keeps the old
// address until its own step moves it (state.DaemonAddr). A step that fails
// for stuckAfter pauses the move (move_resume, from `ceph orch host
// set-addr` again).

// The steps of a move, in order.
const (
	moveConfirm = "confirm"
	moveRGW     = "rgw"
	moveMgr     = "mgr"
	moveOSD     = "osd"
	moveMon     = "mon"
	moveConf    = "conf"
	moveCerts   = "certs"
)

// isMoveControl reports whether a kind is a move's control.
func isMoveControl(kind string) bool { return kind == KindMoveResume }

// moving reports whether a host of the state has a move.
func moving(st *state.State) bool {
	return slices.ContainsFunc(st.Hosts, func(h state.Host) bool { return h.Move != nil })
}

// moveStart records an accepted move in the state. One that cannot start
// (its host gone, another move recorded, the host in maintenance or
// draining) ends failed, closed in the fold.
func (l *LeaderLoop) moveStart(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	refuse := func(cause error) error {
		if err := l.moveRefused(ctx, b, op); err != nil {
			return err
		}

		return finish(ctx, js, gid, op, JournalFailed, cause)
	}

	h, ok := st.Host(op.Host)
	if !ok {
		return refuse(fmt.Errorf("no host %s", op.Host))
	}

	if h.Move != nil && h.Move.Op == op.ID {
		return finish(ctx, js, gid, op, wire.OpCompleted, nil)
	}

	for _, x := range st.Hosts {
		if x.Move != nil {
			return refuse(fmt.Errorf("the address of %s is changing (operation %s)", x.Name, x.Move.Op))
		}

		if x.Drain != nil {
			return refuse(fmt.Errorf("%s is draining (operation %s)", x.Name, x.Drain.Op))
		}
	}

	switch {
	case h.Maintenance:
		return refuse(fmt.Errorf("%s is in maintenance", h.Name))
	case h.Addr == op.Addr:
		return refuse(fmt.Errorf("%s has the address %s already", h.Name, op.Addr))
	}

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		h, ok := st.Host(op.Host)
		if !ok {
			return fmt.Errorf("no host %s", op.Host)
		}

		if h.Move == nil {
			h.Move = &state.Move{Op: op.ID, From: h.Addr, To: op.Addr}
			st.AddHost(h)
		}

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// moveRefused closes a move that never got recorded in the state.
func (l *LeaderLoop) moveRefused(ctx context.Context, b *Bridge, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	if h, ok := st.Host(op.Host); ok && h.Move != nil && h.Move.Op == op.ID {
		return nil // recorded: its steps end it
	}

	return b.Retire(ctx, "addr set", op.ID)
}

// moveControl carries out a move's resume: a paused step runs again, under a
// new attempt.
func (l *LeaderLoop) moveControl(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		h, ok := st.Host(op.Host)
		if !ok || h.Move == nil || h.Move.Op != op.Move || !h.Move.Paused {
			return nil // ended, or not paused
		}

		h.Move.Paused, h.Move.Error = false, ""
		if h.Move.Step != "" {
			h.Move.Attempt++
		}

		st.AddHost(h)

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// moveOSDs are the OSDs of a host a move moves: prepared, rendered.
func moveOSDs(st *state.State, host string) []state.Daemon {
	var out []state.Daemon

	for _, d := range st.DaemonsOf(state.TypeOSD, host) {
		if d.OSDID != nil && d.OSDUUID != "" && !d.LocalOnly && !d.Purged && !d.Leaving {
			out = append(out, d)
		}
	}

	return out
}

// moveNext is a move's next step: the first not done that applies to its
// host; "" when nothing is left.
func moveNext(st *state.State, h state.Host, m state.Move) string {
	has := func(typ string) bool {
		x, ok := st.Find(typ + "." + h.Name)

		return ok && x.Host == h.Name
	}

	for _, step := range []string{moveConfirm, moveRGW, moveMgr, moveOSD, moveMon, moveConf, moveCerts} {
		if slices.Contains(m.Done, step) {
			continue
		}

		switch step {
		case moveRGW:
			if !has(state.TypeRGW) && len(vipDocs(st, h.Name)) == 0 {
				continue
			}
		case moveMgr:
			if !has(state.TypeMgr) {
				continue
			}
		case moveOSD:
			if len(moveOSDs(st, h.Name)) == 0 {
				continue
			}
		case moveMon:
			if !has(state.TypeMon) {
				continue
			}
		}

		return step
	}

	return ""
}

// moveStep carries out the move's next step, or the one in progress: chosen
// and recorded in the state, run under its own journal id until it ended,
// then recorded as done or the move paused with its error. With nothing
// left, the module closes it (addr_set), then the record goes.
func (l *LeaderLoop) moveStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	i := slices.IndexFunc(st.Hosts, func(h state.Host) bool { return h.Move != nil })
	if i < 0 {
		return nil
	}

	// a drain recorded holds the move's steps until it ends: they exclude
	// each other cluster-wide
	if draining(st) {
		return nil
	}

	h := st.Hosts[i]
	m := *h.Move

	if m.Paused {
		return nil
	}

	if m.Step == "" {
		next := moveNext(st, h, m)
		if next == "" {
			// closed in the fold, then cleared: a retry finds it closed already
			if err := b.Retire(ctx, "addr set", m.Op); err != nil {
				return err
			}

			return l.changeMove(ctx, b, gid, h.Name, m, func(x *state.Move) bool { return x.Step == "" }, func(h *state.Host) { h.Move = nil })
		}

		if err := l.changeMove(ctx, b, gid, h.Name, m, func(x *state.Move) bool { return x.Step == "" }, func(h *state.Host) {
			h.Move.Step, h.Move.Attempt = next, h.Move.Attempt+1
		}); err != nil {
			return err
		}

		m.Step, m.Attempt = next, m.Attempt+1
	}

	id := fmt.Sprintf("%s.m%d", m.Op, m.Attempt)
	key := JournalPrefix(gid) + "op/" + id

	s, err := l.journalState(ctx, b, js, gid, id)
	if err != nil {
		return err
	}

	if !terminal(s) {
		mv := mover{op: LedgerOp{ID: m.Op, Kind: KindSetAddr, Host: h.Name, Addr: m.To}, id: id}
		if err := l.unstick(ctx, js, key, key, LedgerOp{ID: id, Kind: KindSetAddr, Host: h.Name}, nil, l.moveRun(ctx, b, js, gid, epoch, mv, m)); err != nil {
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

	return l.changeMove(ctx, b, gid, h.Name, m, func(x *state.Move) bool { return x.Step == m.Step && x.Attempt == m.Attempt }, func(h *state.Host) {
		if !ok {
			// the step stays: a resume runs it again
			h.Move.Paused, h.Move.Error = true, fmt.Sprintf("%s: %s %s", m.Step, s, rec.Error)

			return
		}

		if !slices.Contains(h.Move.Done, m.Step) {
			h.Move.Done = append(h.Move.Done, m.Step)
		}

		h.Move.Step = ""
	})
}

// changeMove changes a host's move record in the state while it is still
// the move m and matches.
func (l *LeaderLoop) changeMove(ctx context.Context, b *Bridge, gid int64, host string, m state.Move, match func(*state.Move) bool, change func(*state.Host)) error {
	return l.changeState(ctx, b, gid, func(st *state.State) error {
		h, ok := st.Host(host)
		if !ok || h.Move == nil || h.Move.Op != m.Op || !match(h.Move) {
			return nil
		}

		change(&h)
		st.AddHost(h)

		return nil
	})
}

// mover is what a move's step runs under: the accepted operation the module
// authorizes its calls by, and the step's journal id.
type mover struct {
	op LedgerOp
	id string
}

// finish ends the step in the journal.
func (mv mover) finish(ctx context.Context, js store.Backend, gid int64, s string, err error) error {
	rec := JournalOp{Version: journalVersion, Kind: KindSetAddr, Host: mv.op.Host, State: s}
	if err != nil {
		rec.Error = err.Error()
	}

	return writeJSONKey(ctx, js, JournalPrefix(gid)+"op/"+mv.id, rec)
}

// moveRun advances a move's step; nil once the step ended in the journal.
func (l *LeaderLoop) moveRun(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, mv mover, m state.Move) error {
	switch m.Step {
	case moveConfirm:
		return l.moveConfirm(ctx, b, js, gid, mv, m)
	case moveRGW:
		return l.moveRGWStep(ctx, b, js, gid, epoch, mv)
	case moveMgr:
		return l.moveMgrStep(ctx, b, js, gid, epoch, mv)
	case moveOSD:
		return l.moveOSDStep(ctx, b, js, gid, epoch, mv)
	case moveMon:
		return l.moveMonStep(ctx, b, js, gid, epoch, mv)
	case moveConf:
		st, _, err := l.clusterState(ctx, b)
		if err != nil {
			return err
		}

		fail := func(err error) error { return mv.finish(ctx, js, gid, JournalFailed, err) }
		if done, err := l.confEverywhere(ctx, b, js, gid, epoch, st, mv.id, fail); err != nil || !done {
			return err
		}

		return mv.finish(ctx, js, gid, wire.OpCompleted, nil)
	case moveCerts:
		return l.moveCertsStep(ctx, b, js, gid, epoch, mv)
	}

	return mv.finish(ctx, js, gid, JournalFailed, errors.New(m.Step+" is not a step of a move"))
}

// hostOf is the moving host and its record in the state.
func (l *LeaderLoop) hostOf(ctx context.Context, b *Bridge, mv mover) (*state.State, state.Host, state.Move, error) {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return nil, state.Host{}, state.Move{}, err
	}

	h, ok := st.Host(mv.op.Host)
	if !ok || h.Move == nil || h.Move.Op != mv.op.ID {
		return nil, state.Host{}, state.Move{}, fmt.Errorf("%w: the move of %s is not in the state", errRetry, mv.op.Host)
	}

	return st, h, *h.Move, nil
}

// moveConfirm is the move's first step: the host's agent answers at the new
// address, by its identity (its certificates may name the old one), and its
// node reports the address; then the module makes it the host's address in
// the fold and the state's Addr follows.
func (l *LeaderLoop) moveConfirm(ctx context.Context, b *Bridge, js store.Backend, gid int64, mv mover, m state.Move) error {
	_, h, _, err := l.hostOf(ctx, b, mv)
	if err != nil {
		return err
	}

	if h.Addr != m.To {
		at := h
		at.Addr = m.To

		var rep wire.NodeReport
		if _, err := l.call(ctx, at, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			return fmt.Errorf("%w: the agent of %s does not answer at %s: %v", errRetry, h.Name, m.To, err)
		}

		if !slices.Contains(rep.Addrs, m.To) {
			return mv.finish(ctx, js, gid, JournalFailed, fmt.Errorf("the node of %s does not have the address %s (it has %s)", h.Name, m.To, strings.Join(rep.Addrs, ", ")))
		}
	}

	if err := b.Retire(ctx, "addr moved", mv.op.ID); err != nil {
		return err
	}

	if err := l.changeMove(ctx, b, gid, h.Name, m, func(*state.Move) bool { return true }, func(h *state.Host) { h.Addr = m.To }); err != nil {
		return err
	}

	return mv.finish(ctx, js, gid, wire.OpCompleted, nil)
}

// markMoved records daemons as moved (their renders take the new address),
// with more changes to the record.
func (l *LeaderLoop) markMoved(ctx context.Context, b *Bridge, gid int64, mv mover, names []string, more func(*state.State, *state.Host)) error {
	return l.changeState(ctx, b, gid, func(st *state.State) error {
		h, ok := st.Host(mv.op.Host)
		if !ok || h.Move == nil || h.Move.Op != mv.op.ID {
			return nil
		}

		for _, n := range names {
			if !slices.Contains(h.Move.Moved, n) {
				h.Move.Moved = append(h.Move.Moved, n)
			}
		}

		if more != nil {
			more(st, &h)
		}

		st.AddHost(h)

		return nil
	})
}

// moveDone records a sub-step a step must not repeat.
func (l *LeaderLoop) moveDone(ctx context.Context, b *Bridge, gid int64, mv mover, mark string, more func(*state.Host)) error {
	return l.markMoved(ctx, b, gid, mv, nil, func(_ *state.State, h *state.Host) {
		if !slices.Contains(h.Move.Done, mark) {
			h.Move.Done = append(h.Move.Done, mark)
		}

		if more != nil {
			more(h)
		}
	})
}

// moveRGWStep moves the host's RGW: its keepalived off (and not rendered)
// first, a generated certificate naming the new address issued for the
// move, the RGW rendered at the new address with it and serving it there,
// the other RGWs rolled to it, the keepalived peers on the other ingress
// hosts re-rendered for the new address, and only then the host's
// keepalived back with its new source address: no two keepalived instances
// miss each other's advertisements.
func (l *LeaderLoop) moveRGWStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, mv mover) error {
	l.holding = holdAll

	st, h, m, err := l.hostOf(ctx, b, mv)
	if err != nil {
		return err
	}

	vips := vipDocs(st, h.Name)
	vipName := state.TypeVIP + "." + h.Name

	if len(vips) > 0 && !m.VIPOff && !slices.Contains(m.Done, "rgw.peers") {
		if err := l.markMoved(ctx, b, gid, mv, nil, func(_ *state.State, h *state.Host) { h.Move.VIPOff = true }); err != nil {
			return err
		}

		m.VIPOff = true
	}

	// the host's keepalived record (its start markers before) is the move's,
	// its grants the attempt's
	vipRec := mv.op.ID + ".mvip"

	if m.VIPOff {
		if done, err := l.vipOffAs(ctx, b, js, gid, epoch, vipRec, mv.id, h, vips); err != nil || !done {
			return err
		}
	}

	d, hasRGW := st.Find(state.TypeRGW + "." + h.Name)
	hasRGW = hasRGW && d.Host == h.Name
	target := ""

	if hasRGW {
		rgwName := state.MoveName(d)

		if !slices.Contains(m.Moved, rgwName) {
			cur, _, ok := st.RGWCertOf(d)
			if !ok {
				return mv.finish(ctx, js, gid, JournalFailed, fmt.Errorf("rgw.%s has no serving certificate", d.ID))
			}

			// the operator's certificate is the operator's to cover the new
			// address; a generated one is issued again for it
			if !cur.User {
				c, err := b.RGWCert(ctx, mv.op.ID)
				if err != nil {
					return err
				}

				target = "issued/" + mv.op.ID + "/" + c.Attempt

				if err := l.markMoved(ctx, b, gid, mv, []string{rgwName}, func(st *state.State, _ *state.Host) {
					if !slices.ContainsFunc(st.RGW.Certs, func(x state.RGWCert) bool { return x.ID == target }) {
						st.RGW.Certs = append(st.RGW.Certs, state.RGWCert{ID: target, Cert: c.Cert})
					}

					if x, ok := st.Find(state.TypeRGW + "." + h.Name); ok {
						x.Cert = target
						st.AddDaemon(x)
					}
				}); err != nil {
					return err
				}
			} else if err := l.markMoved(ctx, b, gid, mv, []string{rgwName}, nil); err != nil {
				return err
			}

			if st, h, m, err = l.hostOf(ctx, b, mv); err != nil {
				return err
			}

			d, _ = st.Find(state.TypeRGW + "." + h.Name)
		}

		if strings.HasPrefix(d.Cert, "issued/"+mv.op.ID+"/") {
			target = d.Cert
		}

		done, ok, err := l.step(ctx, b, js, gid, epoch, mv.id+".rev", h.Name, revisionMode{})
		if err != nil || !done {
			return err
		}

		if !ok {
			return mv.finish(ctx, js, gid, JournalFailed, fmt.Errorf("the revision of %s for its RGW did not apply", h.Name))
		}

		cert, _, ok := st.RGWCertOf(d)
		if !ok {
			return mv.finish(ctx, js, gid, JournalFailed, fmt.Errorf("rgw.%s has no serving certificate", d.ID))
		}

		var rep wire.NodeReport
		if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			return err
		}

		if doc := st.DocName(d); rep.Running[doc] == "" || !l.servesCert(m.To, st.RGW.Port, cert.Cert) {
			return fmt.Errorf("%w: %s does not serve at %s yet", errRetry, doc, m.To)
		}
	}

	if len(vips) > 0 && !slices.Contains(m.Moved, vipName) {
		if err := l.markMoved(ctx, b, gid, mv, []string{vipName}, nil); err != nil {
			return err
		}
	}

	if !slices.Contains(m.Done, "rgw.peers") {
		// the other RGWs roll to the new certificate; their keepalived come
		// back with the peers naming the new address
		rolled := map[string]bool{}

		if target != "" {
			// one roll per move: a peer whose roll began in an earlier attempt
			// is finished, its grants anew under this attempt
			if done, err := l.rollRGWTry(ctx, b, js, gid, epoch, mv.op, target, "roll", ".t"+strconv.Itoa(attemptOf(mv.id))); err != nil || !done {
				return err
			}

			if err := b.RGWCertDone(ctx, mv.op.ID, target); err != nil {
				return err
			}

			for _, x := range st.DaemonsOf(state.TypeRGW, "") {
				rolled[x.Host] = true
			}
		}

		// an ingress host the roll did not visit: its keepalived renders the
		// peers again, taken off and brought back as a roll does
		for _, o := range st.Hosts {
			ovips := vipDocs(st, o.Name)
			if o.Name == h.Name || rolled[o.Name] || o.Maintenance || len(ovips) == 0 {
				continue
			}

			base, grant := mv.op.ID+".mpeers."+o.Name, mv.id+".peers."+o.Name

			if back, err := l.restoring(ctx, b, js, gid, grant); err != nil {
				return err
			} else if !back {
				if done, err := l.vipOffAs(ctx, b, js, gid, epoch, base, grant, o, ovips); err != nil || !done {
					return err
				}
			}

			if done, err := l.vipBackAs(ctx, b, js, gid, epoch, base, grant, o, ovips); err != nil || !done {
				return err
			}
		}

		if err := l.moveDone(ctx, b, gid, mv, "rgw.peers", func(h *state.Host) { h.Move.VIPOff = false }); err != nil {
			return err
		}
	} else if m.VIPOff {
		if err := l.markMoved(ctx, b, gid, mv, nil, func(_ *state.State, h *state.Host) { h.Move.VIPOff = false }); err != nil {
			return err
		}
	}

	// the host's keepalived last, with its new source address
	if done, err := l.vipBackAs(ctx, b, js, gid, epoch, vipRec, mv.id, h, vips); err != nil || !done {
		return err
	}

	return mv.finish(ctx, js, gid, wire.OpCompleted, nil)
}

// attemptOf is the attempt of a move step's journal id (<op>.m<attempt>).
func attemptOf(id string) int {
	_, a, _ := strings.Cut(id, ".m")
	n, _ := strconv.Atoi(a)

	return n
}

// moveMgrStep moves the host's mgr: failed over first when it is the active
// one, its public_addr set to the new address in the monitors' configuration
// database (Ceph picks its address from there, not from the document), its
// host's revision, and done once it is back as a standby with another gid
// (the mgr map shows a standby's address only once it is active).
func (l *LeaderLoop) moveMgrStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, mv mover) error {
	_, h, m, err := l.hostOf(ctx, b, mv)
	if err != nil {
		return err
	}

	name := state.TypeMgr + "." + h.Name

	if !slices.Contains(m.Moved, name) {
		active, agid, standbys, err := b.MgrGIDs(ctx)
		if err != nil {
			return err
		}

		if active == h.Name {
			if err := writeJSONKey(ctx, js, JournalPrefix(gid)+"op/"+mv.id+".fail", JournalOp{Version: journalVersion, Kind: "mgr_fail", Host: h.Name, State: wire.OpStarted, MgrGID: agid}); err != nil {
				return err
			}

			if err := b.MgrFail(ctx, mv.op.ID, agid, h.Name, h.Name); err != nil {
				return fmt.Errorf("%w: failing the active mgr on %s over: %w", errRetry, h.Name, err)
			}

			return fmt.Errorf("%w: the active mgr on %s is failing over", errRetry, h.Name)
		}

		before, ok := standbys[h.Name]
		if !ok {
			return fmt.Errorf("%w: mgr.%s is not a standby yet", errRetry, h.Name)
		}

		if err := b.MoveAddr(ctx, mv.op.ID, name); err != nil {
			return err
		}

		if err := l.markMoved(ctx, b, gid, mv, []string{name}, func(_ *state.State, h *state.Host) {
			h.Move.Before = strconv.FormatInt(before, 10)
		}); err != nil {
			return err
		}

		m.Before = strconv.FormatInt(before, 10)
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, mv.id+".rev", h.Name, revisionMode{})
	if err != nil || !done {
		return err
	}

	if !ok {
		return mv.finish(ctx, js, gid, JournalFailed, fmt.Errorf("the revision of %s for its mgr did not apply", h.Name))
	}

	_, _, standbys, err := b.MgrGIDs(ctx)
	if err != nil {
		return err
	}

	if g, ok := standbys[h.Name]; ok && strconv.FormatInt(g, 10) != m.Before {
		return mv.finish(ctx, js, gid, wire.OpCompleted, nil)
	}

	// back as the active one (another mgr failed meanwhile): done when the
	// mgr map shows it at the new address, else failed over again and
	// awaited as a standby
	active, agid, addr, err := b.ActiveMgrAddr(ctx)
	if err != nil {
		return err
	}

	if active == h.Name && strconv.FormatInt(agid, 10) != m.Before {
		if addr == m.To {
			return mv.finish(ctx, js, gid, wire.OpCompleted, nil)
		}

		if err := writeJSONKey(ctx, js, JournalPrefix(gid)+"op/"+mv.id+".fail", JournalOp{Version: journalVersion, Kind: "mgr_fail", Host: h.Name, State: wire.OpStarted, MgrGID: agid}); err != nil {
			return err
		}

		if err := b.MgrFail(ctx, mv.op.ID, agid, h.Name, h.Name); err != nil {
			return fmt.Errorf("%w: failing the active mgr on %s over: %w", errRetry, h.Name, err)
		}

		return fmt.Errorf("%w: mgr.%s is active at %s, not %s: failing it over", errRetry, h.Name, addr, m.To)
	}

	return fmt.Errorf("%w: mgr.%s is not back as a standby yet", errRetry, h.Name)
}

// moveOSDStep moves the host's OSDs together, as maintenance stops them,
// under a noout reason "move" of the host: each OSD's public_addr and
// cluster_addr set to the new address in the monitors' configuration
// database, the host's revision, and done once the OSD map shows every one
// up advertising the new address; then the reason goes.
func (l *LeaderLoop) moveOSDStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, mv mover) error {
	st, h, m, err := l.hostOf(ctx, b, mv)
	if err != nil {
		return err
	}

	osds := moveOSDs(st, h.Name)

	if !slices.Contains(m.Done, "osd.up") {
		var names []string

		for _, d := range osds {
			names = append(names, state.MoveName(d))
		}

		if slices.ContainsFunc(names, func(n string) bool { return !slices.Contains(m.Moved, n) }) {
			if err := b.Retire(ctx, "noout set", mv.op.ID); err != nil {
				return err
			}

			for _, n := range names {
				if err := b.MoveAddr(ctx, mv.op.ID, n); err != nil {
					return err
				}
			}

			if err := l.markMoved(ctx, b, gid, mv, names, nil); err != nil {
				return err
			}
		}

		done, ok, err := l.step(ctx, b, js, gid, epoch, mv.id+".rev", h.Name, revisionMode{})
		if err != nil || !done {
			return err
		}

		if !ok {
			return mv.finish(ctx, js, gid, JournalFailed, fmt.Errorf("the revision of %s for its OSDs did not apply", h.Name))
		}

		cur, err := b.OSDs(ctx)
		if err != nil {
			return err
		}

		for _, d := range osds {
			i := slices.IndexFunc(cur, func(o OSD) bool { return o.ID == *d.OSDID && o.UUID == d.OSDUUID })
			if i < 0 || !cur[i].Up || cur[i].PublicAddr != m.To || cur[i].ClusterAddr != m.To {
				return fmt.Errorf("%w: %s is not up at %s yet", errRetry, state.MoveName(d), m.To)
			}
		}

		if err := l.moveDone(ctx, b, gid, mv, "osd.up", nil); err != nil {
			return err
		}
	}

	if err := b.Retire(ctx, "noout unset", mv.op.ID); err != nil {
		return err
	}

	return mv.finish(ctx, js, gid, wire.OpCompleted, nil)
}

// moveMonStep moves the host's mon: it leaves the monmap (the module's
// quorum check), recorded at once so a retry never removes the mon that
// joined again; it is deployed again as a new generation with a fresh store
// at the new address (a joining mon, from mon_host) and awaited in the
// quorum.
func (l *LeaderLoop) moveMonStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, mv mover) error {
	st, h, m, err := l.hostOf(ctx, b, mv)
	if err != nil {
		return err
	}

	name := state.TypeMon + "." + h.Name

	if !slices.Contains(m.Done, "mon.rm") {
		if err := b.RetireDaemon(ctx, "mon rm", mv.op.ID, name, nil); err != nil {
			return err
		}

		deploy := make([]byte, 8)
		if _, err := rand.Read(deploy); err != nil {
			return err
		}

		if err := l.markMoved(ctx, b, gid, mv, []string{name}, func(st *state.State, h *state.Host) {
			if !slices.Contains(h.Move.Done, "mon.rm") {
				h.Move.Done = append(h.Move.Done, "mon.rm")
			}

			if x, ok := st.Find(name); ok && x.Host == h.Name {
				x.DeployID, x.Joining = hex.EncodeToString(deploy), true
				st.AddDaemon(x)
			}
		}); err != nil {
			return err
		}

		if st, _, _, err = l.hostOf(ctx, b, mv); err != nil {
			return err
		}
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, mv.id+".rev", h.Name, revisionMode{})
	if err != nil || !done {
		return err
	}

	if !ok {
		return mv.finish(ctx, js, gid, JournalFailed, fmt.Errorf("the revision of %s for its mon did not apply", h.Name))
	}

	if d, ok := st.Find(name); ok && d.Joining {
		q, err := b.Quorum(ctx)
		if err != nil {
			return err
		}

		if !slices.Contains(q, h.Name) {
			return fmt.Errorf("%w: mon.%s has not joined the quorum at %s yet", errRetry, h.Name, m.To)
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			if x, ok := st.Find(name); ok {
				x.Joining = false
				st.AddDaemon(x)
			}

			return nil
		}); err != nil {
			return err
		}
	}

	return mv.finish(ctx, js, gid, wire.OpCompleted, nil)
}

// moveCertsStep reissues the host's agent and mgr certificates for the new
// address through the renewals' paths (A1), under the move's operation (the
// module issues them as renewals of it from its addr_moved entry): the
// agent's first, then the mgr's, each recorded done in the move.
func (l *LeaderLoop) moveCertsStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, mv mover) error {
	st, h, m, err := l.hostOf(ctx, b, mv)
	if err != nil {
		return err
	}

	fail := func(s string, cause error) error {
		if s == wire.OpCompleted {
			return nil
		}

		return mv.finish(ctx, js, gid, JournalFailed, cause)
	}

	if !slices.Contains(m.Done, "certs.agent") {
		var ended string

		// the issuance and the certificates before are the move's, the
		// grant the attempt's: a resume after a failed grant grants anew
		r := renewing{op: mv.op, base: mv.op.ID + ".magent", grant: mv.id + ".magent", end: func(s string, err error) error { ended = s; return fail(s, err) }}
		if err := l.renewAgentAs(ctx, b, js, gid, epoch, r); err != nil || ended != wire.OpCompleted {
			return err
		}

		if err := l.moveDone(ctx, b, gid, mv, "certs.agent", nil); err != nil {
			return err
		}
	}

	if x, ok := st.Find(state.TypeMgr + "." + h.Name); ok && x.Host == h.Name && !slices.Contains(m.Done, "certs.mgr") {
		var ended string

		op := mv.op
		op.Daemon = state.TypeMgr + "." + h.Name
		r := renewing{op: op, base: mv.op.ID + ".mmgr", grant: mv.id + ".mmgr", end: func(s string, err error) error { ended = s; return fail(s, err) }}

		if err := l.renewMgrAs(ctx, b, js, gid, epoch, r); err != nil || ended != wire.OpCompleted {
			return err
		}

		if err := l.moveDone(ctx, b, gid, mv, "certs.mgr", nil); err != nil {
			return err
		}
	}

	return mv.finish(ctx, js, gid, wire.OpCompleted, nil)
}
