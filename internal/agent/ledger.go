package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// The leader carries out the operations the mgr module accepted (plan 03,
// step 6b, part 3): it reads the module's ledger through the bridge every
// tick and runs its executable operations strictly one at a time, in ledger
// order. After each one it publishes its state with that operation's ledger
// key as LedgerApplied; a successor starts after it. Progress goes into the
// journal under the operation's id; a journal record proves nothing to the
// module, which authorizes only from its ledger.

// Ledger operation kinds (internal/mgrmodule ledger.py KINDS).
const (
	KindRestart      = "restart"
	KindRedeploy     = "redeploy"
	KindAddDaemon    = "add_daemon"
	KindRemoveDaemon = "remove_daemon"
	KindEnterMaint   = "enter_maintenance"
	KindExitMaint    = "exit_maintenance"
	KindPowercycle   = "powercycle_host"
	KindUpgrade      = "upgrade_start"
	KindUpPause      = "upgrade_pause"
	KindUpResume     = "upgrade_resume"
	KindUpStop       = "upgrade_stop"
	KindIngress      = "apply_ingress"
	KindAddHost      = "add_host"
	KindRemoveHost   = "remove_host"
	KindCreateOSD    = "create_osd"
	KindRemoveOSD    = "remove_osd"
	KindRenewMgr     = "renew_mgr"
	KindRenewRGW     = "renew_rgw_cert"
	KindRenewAgent   = "renew_agent"
	KindAgentUpgrade = "upgrade_agent"
	KindAgentResume  = "upgrade_agent_resume"
	KindAgentStop    = "upgrade_agent_stop"
)

// errWait is a step that waits as long as it takes (a drain), which does not
// count toward stuckAfter.
var errWait = errors.New("waiting")

// maxAckAttempts bounds the attempts to acknowledge a failed creation's job.
const maxAckAttempts = 50

// stuckAfter is how long an operation waits for an agent that does not answer
// before it fails and the next one runs.
const stuckAfter = 10 * time.Minute

var (
	ledgerIDRe     = regexp.MustCompile(`^op-[0-9a-f]{16}$`)
	ledgerDaemonRe = regexp.MustCompile(`^(mon|mgr|osd|rgw|keepalived)\.([A-Za-z0-9][A-Za-z0-9._-]{0,127})$`)
)

// terminal reports whether a journal state ends an operation.
func terminal(s string) bool {
	switch s {
	case wire.OpCompleted, wire.OpRefused, wire.OpAbandoned, JournalNoChange, JournalFailed:
		return true
	}

	return false
}

// ledgerOps runs the module's accepted operations after the checkpoint.
func (l *LeaderLoop) ledgerOps(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64) error {
	// every host until the ledger was read: a maintenance may be in progress
	l.holding = holdAll
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	after := st.LedgerApplied

	for {
		entries, more, err := b.Ledger(ctx, after)
		if err != nil {
			return err
		}

		for _, e := range entries {
			if !l.stillLeader(gid, epoch) {
				return nil // the next leader carries on
			}

			// an upgrade step in progress, or an upgrade ending, holds the slot:
			// only the upgrade's controls, which change its record alone, run
			// beside it, also those queued behind other operations (their
			// journal records make them run once)
			if st.Upgrade != nil && !isControl(e.Op.Kind) {
				cur, _, err := l.clusterState(ctx, b)
				if err != nil {
					return err
				}

				if u := cur.Upgrade; u != nil && (u.Step != "" || u.Finished || u.Stopped) {
					if err := l.controlsAhead(ctx, b, js, gid, epoch, after, u.Op); err != nil {
						return err
					}

					return l.upgradeStep(ctx, b, js, gid, epoch)
				}
			}

			// an unfinished agent upgrade's controls (resumes, stops) run ahead of
			// queued operations, with a step in progress or not; then a step in
			// progress holds the slot, and a stop turns into its rollback and that
			// rollback's first step before queued work. A paused upgrade without
			// a control holds nothing
			if au := st.AgentUpgrade; au != nil && !au.Finished && !isAgentControl(e.Op.Kind) {
				if err := l.agentResumeAhead(ctx, b, js, gid, epoch, after, au.Op); err != nil {
					return err
				}

				cur, _, err := l.clusterState(ctx, b)
				if err != nil {
					return err
				}

				if u := cur.AgentUpgrade; u != nil && rollbackPending(*u, l.clock()) {
					// the transition, if it is still to make; then the first step
					if u.Stopping {
						if err := l.agentUpgradeStep(ctx, b, js, gid, epoch); err != nil && !errors.Is(err, errRetry) {
							return err
						}
					}

					return l.agentUpgradeStep(ctx, b, js, gid, epoch)
				}

				if u := cur.AgentUpgrade; u != nil && !u.Finished && u.Step != "" {
					return l.agentUpgradeStep(ctx, b, js, gid, epoch)
				}
			}

			done, err := l.ledgerOp(ctx, b, js, gid, epoch, e)
			if err != nil || !done {
				l.holding = ""

				switch {
				case st.Upgrade != nil, strings.HasPrefix(e.Op.Daemon, "rgw."), e.Op.Kind == KindIngress, e.Op.Kind == KindRenewRGW:
					l.holding = holdAll // a step may be in progress, or an RGW's VIP moved
				case st.AgentUpgrade != nil && st.AgentUpgrade.Step != "":
					l.holding = holdAll // an agent upgrade's step may be in progress
				case e.Op.Kind == KindEnterMaint || e.Op.Kind == KindExitMaint || e.Op.Kind == KindPowercycle || e.Op.Kind == KindRenewAgent:
					l.holding = e.Op.Host
				}

				return err // in progress or retried: nothing after it runs
			}

			if err := l.checkpoint(ctx, b, gid, e.Key); err != nil {
				return err
			}

			after = e.Key
		}

		if !more || len(entries) == 0 {
			// between ledger operations: the upgrade's next step, which releases
			// the hold once it read that no step is in progress, then the agent
			// upgrade's
			if err := l.upgradeStep(ctx, b, js, gid, epoch); err != nil {
				return err
			}

			return l.agentUpgradeStep(ctx, b, js, gid, epoch)
		}
	}
}

// holdAll holds every host's revision requests (LeaderLoop.holding).
const holdAll = "*"

// checkpoint publishes the leader's state with key as the last applied ledger
// operation.
func (l *LeaderLoop) checkpoint(ctx context.Context, b *Bridge, gid int64, key string) error {
	return l.changeState(ctx, b, gid, func(st *state.State) error {
		st.LedgerApplied = key

		return nil
	})
}

// changeState reads the leader's state, changes it and publishes it with its
// inventory record, as the CLI does (render.InventoryRecord).
func (l *LeaderLoop) changeState(ctx context.Context, b *Bridge, gid int64, change func(*state.State) error) error {
	own := strconv.FormatInt(gid, 10)

	recs, _, err := l.readRecords(ctx, b, own)
	if err != nil {
		return err
	}

	st := state.New(l.Self.FSID)
	if err := st.ApplyRecords(recs); err != nil {
		return err
	}

	if err := change(st); err != nil {
		return err
	}

	inv, rev, err := render.InventoryRecord(st, l.clock())
	if err != nil {
		return err
	}

	st.Inventory = rev

	next, err := st.Records()
	if err != nil {
		return err
	}

	next["inventory"] = inv

	bs, err := b.Store(ctx, store.Prefix+"inc/"+own+"/")
	if err != nil {
		return err
	}

	_, err = (store.Store{B: bs, Incarnation: own}).Publish(ctx, next)

	return err
}

// journalState is the state of an operation in any incarnation's journal: a
// terminal one wins, else this incarnation's own.
func (l *LeaderLoop) journalState(ctx context.Context, b *Bridge, js store.Backend, gid int64, id string) (string, error) {
	all, err := b.Store(ctx, store.Prefix+"inc/")
	if err != nil {
		return "", err
	}

	keys, err := all.List(ctx, store.Prefix+"inc/")
	if err != nil {
		return "", err
	}

	for _, k := range keys {
		if !strings.HasSuffix(k, "/journal/op/"+id) {
			continue
		}

		op, found, err := readJSONKey[JournalOp](ctx, all, k)
		if err != nil {
			return "", err
		}

		if found && terminal(op.State) {
			return op.State, nil
		}
	}

	op, found, err := readJSONKey[JournalOp](ctx, js, JournalPrefix(gid)+"op/"+id)
	if err != nil || !found {
		return "", err
	}

	return op.State, nil
}

// ledgerOp advances one operation; done reports that it ended.
func (l *LeaderLoop) ledgerOp(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, e LedgerEntry) (bool, error) {
	op := e.Op
	opKey := JournalPrefix(gid) + "op/" + op.ID

	known := map[string]bool{KindRestart: true, KindRedeploy: true, KindAddDaemon: true, KindRemoveDaemon: true, KindRemoveHost: true, KindCreateOSD: true, KindRemoveOSD: true,
		KindEnterMaint: true, KindExitMaint: true, KindPowercycle: true, KindUpgrade: true, KindUpPause: true, KindUpResume: true, KindUpStop: true,
		KindIngress: true, KindAddHost: true, KindRenewMgr: true, KindRenewRGW: true, KindRenewAgent: true, KindAgentUpgrade: true, KindAgentResume: true, KindAgentStop: true}
	cluster := op.Kind == KindUpgrade || isControl(op.Kind) || op.Kind == KindIngress || op.Kind == KindRenewRGW || op.Kind == KindAgentUpgrade || isAgentControl(op.Kind)
	noDaemon := cluster || op.Kind == KindRemoveHost || op.Kind == KindAddHost || op.Kind == KindCreateOSD || op.Kind == KindEnterMaint || op.Kind == KindExitMaint || op.Kind == KindPowercycle ||
		op.Kind == KindRenewAgent
	bound := isControl(op.Kind) || isAgentControl(op.Kind)
	if !ledgerIDRe.MatchString(op.ID) || cluster != (op.Host == "") || !cluster && pki.ValidName(op.Host) != nil || !known[op.Kind] ||
		(op.Kind == KindUpgrade || op.Kind == KindIngress || op.Kind == KindAgentUpgrade) != (op.Image != "") || (op.Kind == KindIngress) != (op.VIP != "") || bound != ledgerIDRe.MatchString(op.Upgrade) ||
		noDaemon != (op.Daemon == "") || (op.Daemon != "" && !ledgerDaemonRe.MatchString(op.Daemon)) ||
		(op.Kind == KindCreateOSD) != strings.HasPrefix(op.Device, "/dev/") {
		return true, writeJSONKey(ctx, js, opKey, JournalOp{Version: journalVersion, Kind: op.Kind, Host: op.Host, State: JournalFailed, Error: "unknown or malformed operation"})
	}

	s, err := l.journalState(ctx, b, js, gid, op.ID)
	if err != nil || terminal(s) {
		return err == nil, err
	}

	switch op.Kind {
	case KindAgentUpgrade, KindAgentResume, KindAgentStop:
		phase := func() error { return l.agentUpgradeResume(ctx, b, js, gid, op) }

		switch op.Kind {
		case KindAgentUpgrade:
			phase = func() error { return l.upgradeAgent(ctx, b, js, gid, op) }
		case KindAgentStop:
			phase = func() error { return l.agentUpgradeStop(ctx, b, js, gid, op) }
		}

		if err := l.unstick(ctx, js, opKey, opKey, op, nil, phase()); err != nil {
			return false, err
		}

		s, err = l.journalState(ctx, b, js, gid, op.ID)

		return err == nil && terminal(s), err
	case KindRenewRGW:
		// keepalived the roll took off come back
		restore := func() error { return l.restoreVIPs(ctx, b, js, gid, epoch, op) }
		if err := l.unstick(ctx, js, opKey, opKey, op, restore, l.renewRGWCert(ctx, b, js, gid, epoch, op)); err != nil {
			return false, err
		}

		s, err = l.journalState(ctx, b, js, gid, op.ID)

		return err == nil && terminal(s), err
	case KindIngress:
		// keepalived a certificate roll took off come back first, then the
		// added ones never granted leave the state
		cleanup := func() error {
			note := l.restoreVIPs(ctx, b, js, gid, epoch, op)

			var n failNote
			if note != nil && !errors.As(note, &n) {
				return note
			}

			if err := l.ingressFailed(ctx, b, js, gid, op); err != nil {
				return err
			}

			return note
		}
		if err := l.unstick(ctx, js, opKey, opKey, op, cleanup, l.applyIngress(ctx, b, js, gid, epoch, op)); err != nil {
			return false, err
		}

		s, err = l.journalState(ctx, b, js, gid, op.ID)

		return err == nil && terminal(s), err
	case KindUpgrade, KindUpPause, KindUpResume, KindUpStop:
		phase := func() error { return l.upgradeControl(ctx, b, js, gid, op) }

		var onFail func() error

		if op.Kind == KindUpgrade {
			phase = func() error { return l.upgradeStart(ctx, b, js, gid, epoch, op) }

			// a start that never got recorded is closed in the module's fold
			onFail = func() error {
				st, _, err := l.clusterState(ctx, b)
				if err != nil || st.Upgrade != nil && st.Upgrade.Op == op.ID {
					return err
				}

				return b.Retire(ctx, "upgrade refused", op.ID)
			}
		}

		if err := l.unstick(ctx, js, opKey, opKey, op, onFail, phase()); err != nil {
			return false, err
		}

		s, err = l.journalState(ctx, b, js, gid, op.ID)

		return err == nil && terminal(s), err
	case KindAddDaemon, KindRemoveDaemon, KindRemoveHost, KindCreateOSD, KindRemoveOSD, KindEnterMaint, KindExitMaint, KindPowercycle, KindAddHost, KindRenewMgr, KindRenewAgent:
		var phase func() error

		switch op.Kind {
		case KindRenewAgent:
			phase = func() error { return l.renewAgent(ctx, b, js, gid, epoch, op) }
		case KindRenewMgr:
			phase = func() error { return l.renewMgr(ctx, b, js, gid, epoch, op) }
		case KindAddHost:
			phase = func() error { return l.addHost(ctx, b, js, gid, epoch, op) }
		case KindPowercycle:
			phase = func() error { return l.powercycle(ctx, b, js, gid, epoch, op) }
		case KindEnterMaint:
			phase = func() error { return l.enterMaintenance(ctx, b, js, gid, epoch, op) }
		case KindExitMaint:
			phase = func() error { return l.exitMaintenance(ctx, b, js, gid, epoch, op) }
		case KindRemoveOSD:
			phase = func() error { return l.removeOSD(ctx, b, js, gid, epoch, op) }
		case KindCreateOSD:
			phase = func() error { return l.createOSD(ctx, b, js, gid, epoch, op) }
		case KindAddDaemon:
			phase = func() error { return l.addDaemon(ctx, b, js, gid, epoch, op) }
		case KindRemoveDaemon:
			phase = func() error { return l.removeDaemon(ctx, b, js, gid, epoch, op) }
		default:
			phase = func() error { return l.removeHost(ctx, b, js, gid, epoch, op) }
		}

		var onFail func() error
		if op.Kind == KindCreateOSD {
			onFail = func() error { return l.cleanCreate(ctx, b, js, gid, epoch, op) }
		}

		if op.Kind == KindAddDaemon && strings.HasPrefix(op.Daemon, "rgw.") {
			onFail = func() error { return l.restoreVIPs(ctx, b, js, gid, epoch, op) }
		}

		if op.Kind == KindEnterMaint {
			onFail = func() error { return l.unmark(ctx, b, js, gid, op.Host, op.ID) }
		}

		if op.Kind == KindRenewMgr {
			onFail = func() error { return l.renewMgrFailed(ctx, b, js, gid, op) }
		}

		if op.Kind == KindRenewAgent {
			onFail = func() error { return l.renewAgentFailed(ctx, b, js, gid, op) }
		}

		if op.Kind == KindPowercycle {
			onFail = func() error { return l.unmark(ctx, b, js, gid, op.Host, op.ID+".in") }
		}

		if err := l.unstick(ctx, js, opKey, opKey, op, onFail, phase()); err != nil {
			return false, err
		}

		s, err = l.journalState(ctx, b, js, gid, op.ID)

		return err == nil && terminal(s), err
	}

	// an RGW beside a keepalived restarts with the VIP moved first; without the
	// state it is not known whether one is beside it
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return false, err
	}

	if d, ok := daemonOf(st, op.Daemon); ok && d.Type == state.TypeRGW {
		if h, ok := st.Host(d.Host); ok && len(vipDocs(st, h.Name)) > 0 {
			restore := func() error { return l.restoreVIPs(ctx, b, js, gid, epoch, op) }
			if err := l.unstick(ctx, js, opKey, opKey, op, restore, l.rgwRestart(ctx, b, js, gid, epoch, op, h, vipDocs(st, h.Name))); err != nil {
				return false, err
			}

			s, err = l.journalState(ctx, b, js, gid, op.ID)

			return err == nil && terminal(s), err
		}
	}

	if op.Kind == KindRedeploy {
		// first the host's revision, then the restart
		rev := op.ID + ".rev"

		rs, err := l.journalState(ctx, b, js, gid, rev)
		if err != nil {
			return false, err
		}

		if !terminal(rs) {
			if err := l.unstick(ctx, js, opKey, opKey, op, nil, l.runRevision(ctx, b, js, gid, epoch, rev, op.Host, revisionMode{})); err != nil {
				return false, err
			}

			if rs, err = l.journalState(ctx, b, js, gid, rev); err != nil || !terminal(rs) {
				return false, err
			}
		}

		if rs != wire.OpCompleted && rs != JournalNoChange {
			return true, writeJSONKey(ctx, js, opKey, JournalOp{Version: journalVersion, Kind: op.Kind, Host: op.Host, State: JournalFailed, Error: "the revision before the restart ended " + rs})
		}
	}

	if err := l.unstick(ctx, js, opKey, opKey, op, nil, l.restartOp(ctx, b, js, gid, epoch, op)); err != nil {
		return false, err
	}

	// an operation that ended does not hold the next one for a tick
	s, err = l.journalState(ctx, b, js, gid, op.ID)

	return err == nil && terminal(s), err
}

// unstick fails an operation (opKey) that has kept failing for stuckAfter, so
// the next one runs, unless a grant of it or of one of its phases (journal keys
// phaseKey and phaseKey.*) has an unknown outcome; the time it started failing
// is kept in memory only.
func (l *LeaderLoop) unstick(ctx context.Context, js store.Backend, opKey, phaseKey string, op LedgerOp, onFail func() error, err error) error {
	if err == nil || errors.Is(err, errWait) {
		delete(l.failing, op.ID)

		return err
	}

	if l.failing == nil {
		l.failing = map[string]time.Time{}
	}

	since, ok := l.failing[op.ID]
	if !ok {
		l.failing[op.ID] = l.clock()

		return err
	}

	if l.clock().Sub(since) < stuckAfter {
		return err
	}

	// a grant whose outcome is not known, of the operation or any of its
	// phases (<id>.rev, <id>.strip, <id>.conf.<host>), is never given up this way;
	// listed by their directory, the only kind of prefix the bridge lists
	keys, rerr := js.List(ctx, phaseKey[:strings.LastIndex(phaseKey, "/")+1])
	if rerr != nil {
		return rerr
	}

	for _, k := range keys {
		if k != phaseKey && !strings.HasPrefix(k, phaseKey+".") {
			continue
		}

		cur, found, rerr := readJSONKey[JournalOp](ctx, js, k)
		if rerr != nil {
			return rerr
		}

		if found && (cur.State == JournalGranting || cur.State == wire.OpUncertain) {
			return err
		}
	}

	// what failing leaves behind is cleaned up first (a creation is closed); a
	// cleanup that could not finish says what is left
	note := ""

	if onFail != nil {
		if ferr := onFail(); ferr != nil {
			var n failNote
			if !errors.As(ferr, &n) {
				return ferr
			}

			note = "; " + string(n)
		}
	}

	delete(l.failing, op.ID)

	return writeJSONKey(ctx, js, opKey, JournalOp{Version: journalVersion, Kind: op.Kind, Host: op.Host, State: JournalFailed, Error: fmt.Sprintf("failing for %s: %v%s", stuckAfter, err, note)})
}

// failNote is a cleanup's account of what it could not undo: the operation
// fails with it in its error.
type failNote string

func (n failNote) Error() string { return string(n) }

// daemonOf finds a ledger daemon name ("<type>.<id>") in the cluster state.
func daemonOf(st *state.State, name string) (state.Daemon, bool) {
	m := ledgerDaemonRe.FindStringSubmatch(name)
	if m == nil {
		return state.Daemon{}, false
	}

	typ := m[1]
	if typ == "keepalived" {
		typ = state.TypeVIP
	}

	for _, d := range st.Daemons {
		if d.Type != typ {
			continue
		}

		if d.ID == m[2] || (typ == state.TypeOSD && d.OSDID != nil && strconv.Itoa(*d.OSDID) == m[2]) {
			return d, true
		}
	}

	return state.Daemon{}, false
}

// restartOp restarts a daemon's current instance through its agent, or
// resolves a restart whose outcome was not recorded.
func (l *LeaderLoop) restartOp(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, lop LedgerOp) error {
	opKey := JournalPrefix(gid) + "op/" + lop.ID

	cur, found, err := readJSONKey[JournalOp](ctx, js, opKey)
	if err != nil {
		return err
	}

	if found {
		if cur.State == JournalGranting || cur.State == wire.OpUncertain {
			return l.resolve(ctx, b, js, gid, epoch, opKey, cur, lop.ID)
		}

		return nil
	}

	op := JournalOp{Version: journalVersion, Kind: lop.Kind, Host: lop.Host}

	fail := func(err error) error {
		op.State, op.Error = JournalFailed, err.Error()

		return writeJSONKey(ctx, js, opKey, op)
	}

	st, seq, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	op.Seq = seq

	d, ok := daemonOf(st, lop.Daemon)
	if !ok || d.Host != lop.Host || d.LocalOnly {
		return fail(fmt.Errorf("%s is not a daemon of %s in the cluster state", lop.Daemon, lop.Host))
	}

	h, ok := st.Host(lop.Host)
	if !ok {
		return fail(fmt.Errorf("no host %s in the cluster state", lop.Host))
	}

	if !l.closed[h.Name] {
		return fmt.Errorf("%w: %s's earlier sessions are not closed yet", errRetry, h.Name)
	}

	if h.Maintenance {
		return fail(fmt.Errorf("%s is in maintenance", h.Name))
	}

	me, ok := st.Host(l.Self.Name)
	if !ok {
		return fail(fmt.Errorf("the leader's host %s is not in the cluster state", l.Self.Name))
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return err // retried
	}

	if rep.State != "owned" {
		return fmt.Errorf("%s is %s %v: nothing is restarted until that is resolved", h.Name, rep.State, rep.Drift)
	}

	key := "ContainerConfig/" + st.DocName(d)

	hash := rep.Owned[key]
	if hash == "" {
		return fail(fmt.Errorf("%s has no document %s", h.Name, key))
	}

	op.Docs = map[string]string{key: hash}
	op.Revision = max(rep.Revision+1, l.clock().UnixNano())
	op.State = JournalGranting

	if !l.stillLeader(gid, epoch) {
		return nil
	}

	// the intent is in the journal before anything is sent
	if err := writeJSONKey(ctx, js, opKey, op); err != nil {
		return err
	}

	if !l.stillLeader(gid, epoch) {
		return nil
	}

	g := wire.Grant{
		Version: wire.Version, FSID: l.Self.FSID, Host: h.Name, Mgr: l.Self.Name, MgrAddr: me.Addr, GID: gid, Epoch: epoch,
		Revision: op.Revision, Operation: lop.ID, Restart: &wire.GrantRestart{Kind: "ContainerConfig", Name: st.DocName(d), Hash: hash}, Approval: l.approval,
	}

	var res wire.Operation
	if _, err := l.call(ctx, h, http.MethodPost, "/v1/grant", g, &res); err != nil {
		return fmt.Errorf("restart %s on %s: %w", lop.ID, h.Name, err)
	}

	return l.record(ctx, js, opKey, op, res)
}

// finish ends an operation in the journal.
func finish(ctx context.Context, js store.Backend, gid int64, op LedgerOp, state string, err error) error {
	rec := JournalOp{Version: journalVersion, Kind: op.Kind, Host: op.Host, State: state}
	if err != nil {
		rec.Error = err.Error()
	}

	return writeJSONKey(ctx, js, JournalPrefix(gid)+"op/"+op.ID, rec)
}

// step runs a revision of an operation's phase under its own id until it ends;
// done reports that it ended, ok that it applied or changed nothing.
func (l *LeaderLoop) step(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, id, host string, mode revisionMode) (done, ok bool, err error) {
	s, err := l.journalState(ctx, b, js, gid, id)
	if err != nil {
		return false, false, err
	}

	if !terminal(s) {
		if err := l.runRevision(ctx, b, js, gid, epoch, id, host, mode); err != nil {
			return false, false, err
		}

		if s, err = l.journalState(ctx, b, js, gid, id); err != nil || !terminal(s) {
			return false, false, err
		}
	}

	return true, s == wire.OpCompleted || s == JournalNoChange, nil
}

// addDaemon deploys a mon or a mgr. A mon joins first, named nowhere else;
// once it is in the quorum ceph.conf names it on every host. A mgr gets its
// key and the module's certificates, then its host's revision.
func (l *LeaderLoop) addDaemon(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	typ, id, _ := strings.Cut(op.Daemon, ".")

	if typ == state.TypeRGW {
		return l.addRGW(ctx, b, js, gid, epoch, op)
	}

	h, ok := st.Host(op.Host)
	if !ok || h.Name != op.Host || id != op.Host || (typ != state.TypeMon && typ != state.TypeMgr) {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s cannot be deployed on %s", op.Daemon, op.Host))
	}

	d, exists := st.Find(op.Daemon)

	if typ == state.TypeMgr && !exists {
		if _, err := b.AuthGetOrCreate(ctx, "mgr."+id, op.ID); err != nil {
			return err
		}

		certs, err := b.MgrCert(ctx, op.ID)
		if err != nil {
			return err
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			h, ok := st.Host(op.Host)
			if !ok {
				return fmt.Errorf("no host %s", op.Host)
			}

			h.MgrServerCert, h.MgrClientCert, h.MgrKeys = certs.ServerCert, certs.ClientCert, op.ID+"/"+certs.Attempt
			st.AddHost(h)
			st.AddDaemon(st.Created(state.Daemon{Type: state.TypeMgr, ID: id, Host: h.Name}))

			return nil
		}); err != nil {
			return err
		}
	}

	if typ == state.TypeMon && !exists {
		deploy := make([]byte, 8)
		if _, err := rand.Read(deploy); err != nil {
			return err
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			st.AddDaemon(st.Created(state.Daemon{Type: state.TypeMon, ID: id, Host: op.Host, DeployID: hex.EncodeToString(deploy), Joining: true}))

			return nil
		}); err != nil {
			return err
		}

		d.Joining = true
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".rev", op.Host, revisionMode{})
	if err != nil || !done {
		return err
	}

	if !ok {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the revision of %s did not apply", op.Host))
	}

	if typ == state.TypeMon {
		if d.Joining {
			q, err := b.Quorum(ctx)
			if err != nil {
				return err
			}

			if !slices.Contains(q, id) {
				return fmt.Errorf("%w: mon.%s has not joined the quorum yet", errRetry, id)
			}

			if err := l.changeState(ctx, b, gid, func(st *state.State) error {
				d, ok := st.Find(op.Daemon)
				if !ok {
					return fmt.Errorf("no %s", op.Daemon)
				}

				d.Joining = false
				st.AddDaemon(d)

				return nil
			}); err != nil {
				return err
			}
		}

		// only now ceph.conf names it, so clients never start against an empty address
		if done, err := l.confEverywhere(ctx, b, js, gid, epoch, st, op); err != nil || !done {
			return err
		}
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// confEverywhere grants every host not in maintenance the revision of its
// ceph.conf after a mon change, one phase per host; done reports that all
// ended (a host it did not reach fails the operation).
func (l *LeaderLoop) confEverywhere(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, st *state.State, op LedgerOp) (bool, error) {
	for _, h := range st.Hosts {
		if h.Maintenance {
			continue
		}

		done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".conf."+h.Name, h.Name, revisionMode{})
		if err != nil || !done {
			return false, err
		}

		if !ok {
			return false, finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("ceph.conf did not reach %s", h.Name))
		}
	}

	return true, nil
}

// removeDaemon removes a mgr that is not the active one, or a mon: out of the
// state, its documents off its host, then, once its instance is gone, the
// module retires it (auth rm and its keys for a mgr). A mon leaves the monmap
// first, as in cephadm, and ceph.conf stops naming it on every host before
// its retirement.
func (l *LeaderLoop) removeDaemon(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	typ, id, _ := strings.Cut(op.Daemon, ".")

	h, ok := st.Host(op.Host)
	if !ok || (typ != state.TypeMgr && typ != state.TypeMon && typ != state.TypeRGW) || id != op.Host {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s cannot be removed from %s", op.Daemon, op.Host))
	}

	// the VIP leaves a host before its RGW (the module refuses this too)
	if typ == state.TypeRGW && len(vipDocs(st, h.Name)) > 0 {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s has a keepalived: the ingress leaves it first", h.Name))
	}

	doc := st.DocName(state.Daemon{Type: typ, ID: id, Host: h.Name})

	rs, err := l.journalState(ctx, b, js, gid, op.ID+".rev")
	if err != nil {
		return err
	}

	// the module checks the quorum without it and takes it out of the monmap
	// (done once it is out), before its document goes
	if typ == state.TypeMon && !terminal(rs) {
		if err := b.Retire(ctx, "mon rm", op.ID); err != nil {
			return err
		}
	}

	// checked again before every step up to the removal of its document, also
	// on a resumed operation: a standby may have become the active one
	if typ == state.TypeMgr && !terminal(rs) {
		active, err := b.ActiveMgr(ctx)
		if err != nil {
			return err
		}

		if active == id {
			if rs != "" {
				// a removal grant whose outcome is not known is resolved first
				return l.runRevision(ctx, b, js, gid, epoch, op.ID+".rev", op.Host, revisionMode{extra: []string{"ContainerConfig/" + doc}})
			}

			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s is the active mgr", op.Daemon))
		}
	}

	if d, exists := st.Find(op.Daemon); exists {
		// a mgr's certificates, journaled before the state drops them: the
		// module revokes them with its retirement (plan 04, step 3)
		if typ == state.TypeMgr && (h.MgrServerCert != "" || h.MgrClientCert != "") {
			if _, found, err := l.readJournal(ctx, b, js, gid, op.ID+".certs"); err != nil {
				return err
			} else if !found {
				if err := writeJSONKey(ctx, js, rollKey(gid, op.ID+".certs"), removedCerts{ServerCert: h.MgrServerCert, ClientCert: h.MgrClientCert}); err != nil {
					return err
				}
			}
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			st.RemoveDaemon(d)

			if h, ok := st.Host(op.Host); ok && typ == state.TypeMgr {
				h.MgrServerCert, h.MgrClientCert, h.MgrKeys = "", "", ""
				st.AddHost(h)
			}

			return nil
		}); err != nil {
			return err
		}
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".rev", op.Host, revisionMode{extra: []string{"ContainerConfig/" + doc}})
	if err != nil || !done {
		return err
	}

	if !ok {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the revision of %s did not apply", op.Host))
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return err
	}

	if slices.Contains(rep.Instances, doc) {
		return fmt.Errorf("%w: %s has not stopped yet", errRetry, op.Daemon)
	}

	if typ == state.TypeMon {
		if done, err := l.confEverywhere(ctx, b, js, gid, epoch, st, op); err != nil || !done {
			return err
		}
	}

	certs, _, err := l.readJournal(ctx, b, js, gid, op.ID+".certs")
	if err != nil {
		return err
	}

	if err := b.RetireWith(ctx, op.ID, []string{certs.ServerCert, certs.ClientCert}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// removeHost removes a host without daemons: every document its agent owns
// off it, the host out of the state, then the module retires it. The agent and
// its records stay: their documents are the CLI's.
func (l *LeaderLoop) removeHost(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	if h, ok := st.Host(op.Host); ok && h.Name == op.Host {
		for _, d := range st.Daemons {
			if d.Host == op.Host {
				return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s still has %s.%s", op.Host, d.Type, d.ID))
			}
		}

		if op.Host == l.Self.Name {
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s runs the leader", op.Host))
		}

		done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".strip", op.Host, revisionMode{strip: true})
		if err != nil || !done {
			return err
		}

		if !ok {
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the documents of %s were not removed", op.Host))
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			st.RemoveHost(op.Host)

			return nil
		}); err != nil {
			return err
		}
	}

	if err := b.Retire(ctx, "retire host", op.ID); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// journalRecord is an operation's record in any incarnation's journal: a
// terminal one wins, else this incarnation's own.
func (l *LeaderLoop) journalRecord(ctx context.Context, b *Bridge, js store.Backend, gid int64, id string) (JournalOp, bool, error) {
	all, err := b.Store(ctx, store.Prefix+"inc/")
	if err != nil {
		return JournalOp{}, false, err
	}

	keys, err := all.List(ctx, store.Prefix+"inc/")
	if err != nil {
		return JournalOp{}, false, err
	}

	for _, k := range keys {
		if !strings.HasSuffix(k, "/journal/op/"+id) {
			continue
		}

		op, found, err := readJSONKey[JournalOp](ctx, all, k)
		if err != nil {
			return JournalOp{}, false, err
		}

		if found && terminal(op.State) {
			return op, true, nil
		}
	}

	return readJSONKey[JournalOp](ctx, js, JournalPrefix(gid)+"op/"+id)
}

// deployOf is the deployment id of an OSD creation: its preparation job's id.
func deployOf(op string) string {
	sum := sha256.Sum256([]byte(op + ":prepare"))

	return hex.EncodeToString(sum[:8])
}

// prepared reads the OSD id and uuid a preparation job reported.
func prepared(out string) (int, string, bool) {
	id, uuid := -1, ""

	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "osd_id "); ok {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				id = n
			}
		}

		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "osd_uuid "); ok {
			uuid = v
		}
	}

	return id, uuid, id >= 0 && uuid != ""
}

// createOSD creates an OSD on a disk: the module binds the creation to the
// disk, the deployment goes into the state before the preparation job, the
// job's OSD id and uuid follow, then one revision with the OSD daemon and the
// job's acknowledgement, the OSD up in the OSD map, and the module's
// confirmation. A creation that fails is closed by the module.
func (l *LeaderLoop) createOSD(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	h, ok := st.Host(op.Host)
	if !ok || h.Name != op.Host {
		return l.failCreate(ctx, b, js, gid, epoch, op, fmt.Errorf("no host %s", op.Host))
	}

	deploy := deployOf(op.ID)

	var d state.Daemon

	found := false

	for _, x := range st.Daemons {
		if x.Type == state.TypeOSD && x.DeployID == deploy {
			d, found = x, true
		}
	}

	if !found {
		var rep wire.NodeReport
		if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			return err
		}

		serial, link, seen := "", "", false

		for _, disk := range rep.Disks {
			if disk.DevPath != op.Device && !slices.Contains(disk.Symlinks, op.Device) {
				continue
			}

			seen = true

			serial = strings.TrimSpace(disk.Serial)

			for _, s := range disk.Symlinks {
				if serial != "" && strings.HasPrefix(s, "/dev/disk/by-id/") && strings.Contains(s, serial) {
					link = s
				}
			}
		}

		if !seen {
			return l.failCreate(ctx, b, js, gid, epoch, op, fmt.Errorf("%s has no disk %s", op.Host, op.Device))
		}

		if serial == "" || link == "" {
			return l.failCreate(ctx, b, js, gid, epoch, op, fmt.Errorf("%s on %s has no serial and /dev/disk/by-id link: an OSD cannot be bound to it", op.Device, op.Host))
		}

		d = state.Daemon{Type: state.TypeOSD, ID: op.Host + "-" + filepath.Base(op.Device), Host: op.Host, Device: op.Device, DeployID: deploy, DiskSerial: serial, DevicePath: link}
		if x, exists := st.Find("osd." + d.ID); exists && x.DeployID != deploy {
			return l.failCreate(ctx, b, js, gid, epoch, op, fmt.Errorf("%s already has an OSD on %s", op.Host, op.Device))
		}

		// the module binds the creation to this disk and job before anything else
		if err := b.BindDisk(ctx, op.ID, serial, link, deploy); err != nil {
			return err
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			d = st.Created(d) // the target's image during an upgrade, also for the preparation
			st.AddDaemon(d)

			return nil
		}); err != nil {
			return err
		}
	}

	prep := op.ID + ".prep"

	if d.OSDID == nil {
		key, err := b.AuthGetFor(ctx, "client.bootstrap-osd", op.ID)
		if err != nil {
			return err
		}

		job, err := render.OSDPrepare(st, h, d, func(string) (string, error) { return key, nil })
		if err != nil {
			return l.failCreate(ctx, b, js, gid, epoch, op, err)
		}

		y, err := spec.Render(job)
		if err != nil {
			return err
		}

		done, _, err := l.step(ctx, b, js, gid, epoch, prep, op.Host, revisionMode{add: []Doc{{Kind: "ContainerConfig", Name: job.MetaName, YAML: y}}})
		if err != nil || !done {
			return err
		}

		rec, _, err := l.journalRecord(ctx, b, js, gid, prep)
		if err != nil {
			return err
		}

		if rec.State != wire.OpCompleted || rec.Result == nil {
			return l.failCreate(ctx, b, js, gid, epoch, op, fmt.Errorf("the preparation ended %s %s", rec.State, rec.Error))
		}

		id, uuid, ok := prepared(rec.Result.Output)
		if !ok {
			return l.failCreate(ctx, b, js, gid, epoch, op, errors.New("the preparation reported no OSD id and uuid"))
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			x, ok := st.Find("osd." + d.ID)
			if !ok || x.DeployID != deploy {
				return fmt.Errorf("the deployment of %s is gone", d.ID)
			}

			x.OSDID, x.OSDUUID = &id, uuid
			st.AddDaemon(x)

			return nil
		}); err != nil {
			return err
		}

		d.OSDID, d.OSDUUID = &id, uuid
	}

	// the OSD daemon, and the job's result acknowledged with its document's removal
	rec, _, err := l.journalRecord(ctx, b, js, gid, prep)
	if err != nil {
		return err
	}

	mode := revisionMode{}
	if rec.Job != nil && rec.Result != nil {
		mode.extra = []string{"ContainerConfig/" + rec.Job.Doc}
		mode.ack = &wire.JobAck{Job: rec.Job.ID, Inputs: rec.Job.Inputs, RC: rec.Result.RC}
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".rev", op.Host, mode)
	if err != nil || !done {
		return err
	}

	if !ok {
		return l.failCreate(ctx, b, js, gid, epoch, op, fmt.Errorf("the revision of %s did not apply", op.Host))
	}

	osds, err := b.OSDs(ctx)
	if err != nil {
		return err
	}

	up := false
	for _, o := range osds {
		up = up || (o.ID == *d.OSDID && o.UUID == d.OSDUUID && o.Up)
	}

	if !up {
		return fmt.Errorf("%w: osd.%d is not up yet", errRetry, *d.OSDID)
	}

	if _, err := b.do(ctx, "confirm osd", map[string]any{"operation": op.ID, "osd": *d.OSDID}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// failCreate ends a creation that failed: its preparation job's outcome is
// acknowledged with its document's removal, a deployment that never got an
// OSD leaves the state (so the disk can be tried again), the module closes the
// creation (no more bootstrap-osd for it), and it ends as failed. Each step is
// asked again on the next tick until it is done.
func (l *LeaderLoop) failCreate(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp, cause error) error {
	if err := l.cleanCreate(ctx, b, js, gid, epoch, op); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, JournalFailed, cause)
}

// cleanCreate is what a failed or timed-out creation leaves behind, undone:
// an error means not done yet, asked again on the next tick.
func (l *LeaderLoop) cleanCreate(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	rec, found, err := l.journalRecord(ctx, b, js, gid, op.ID+".prep")
	if err != nil {
		return err
	}

	if found && rec.Job != nil && terminal(rec.State) {
		rc := -1
		if rec.Result != nil {
			rc = rec.Result.RC
		}

		if err := l.ackJob(ctx, b, js, gid, epoch, op.ID, op.Host, rec, rc); err != nil {
			return err
		}
	}

	deploy := deployOf(op.ID)

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		for _, d := range st.Daemons {
			if d.Type == state.TypeOSD && d.DeployID == deploy && d.OSDID == nil {
				st.RemoveDaemon(d)
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return b.Retire(ctx, "close create", op.ID)
}

// ackJob acknowledges a job's recorded outcome with its document's removal.
// Attempts are numbered (<base>.ack.<n>): one that ended without applying (a
// refused confirmation, among others) is followed by a new one, one
// unresolved is asked again; an error means not done yet.
func (l *LeaderLoop) ackJob(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, base, host string, rec JournalOp, rc int) error {
	mode := revisionMode{extra: []string{"ContainerConfig/" + rec.Job.Doc}, ack: &wire.JobAck{Job: rec.Job.ID, Inputs: rec.Job.Inputs, RC: rc}}

	for n := 1; n <= maxAckAttempts; n++ {
		id := fmt.Sprintf("%s.ack.%d", base, n)

		s, err := l.journalState(ctx, b, js, gid, id)
		if err != nil {
			return err
		}

		if terminal(s) && s != wire.OpCompleted && s != JournalNoChange {
			continue // a new attempt
		}

		done, ok, err := l.step(ctx, b, js, gid, epoch, id, host, mode)
		if err != nil {
			return err
		}

		if !done {
			return fmt.Errorf("%w: the acknowledgement of %s is not decided yet", errRetry, base)
		}

		if ok {
			return nil
		}
	}

	return fmt.Errorf("%w: the job outcome of %s is not acknowledged yet", errRetry, base)
}

// zapOf is the job id of a removal's zap: sixteen hex digits, as tombstones
// are kept for good.
func zapOf(op string) string {
	sum := sha256.Sum256([]byte(op + ":zap"))

	return hex.EncodeToString(sum[:8])
}

// removeOSD removes an OSD: out and drained by the module (safe to destroy
// while it runs, unless forced), marked leaving in the state (not rendered,
// its identity kept) and its document removed, its instance gone, retired by
// the module (down, purged), with zap its disk zapped (the job checks the
// label of this cluster and OSD), and only then out of the state.
func (l *LeaderLoop) removeOSD(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	h, ok := st.Host(op.Host)
	if !ok {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("no host %s", op.Host))
	}

	d, found := daemonOf(st, op.Daemon)
	if !found {
		// out of the state: the removal ended before its journal record; a zap
		// it was asked for counts only if its job completed
		if op.Zap {
			rec, ok, err := l.journalRecord(ctx, b, js, gid, op.ID+".zap")
			if err != nil {
				return err
			}

			if !ok || rec.State != wire.OpCompleted {
				return finish(ctx, js, gid, op, JournalFailed, errors.New("purged, not zapped"))
			}
		}

		return finish(ctx, js, gid, op, wire.OpCompleted, nil)
	}

	if d.Host != op.Host || d.OSDUUID != op.UUID {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s in the state is another OSD", op.Daemon))
	}

	// out and drained for this removal also when an earlier one marked the OSD
	// leaving and failed (the module's calls are idempotent per removal)
	if err := b.Retire(ctx, "osd out", op.ID); err != nil {
		return err
	}

	// a drain takes as long as recovery does: waiting for it does not fail
	if err := b.Retire(ctx, "drain", op.ID); err != nil {
		return fmt.Errorf("%w: %v", errWait, err)
	}

	if !d.Leaving {
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			x, ok := daemonOf(st, op.Daemon)
			if !ok {
				return fmt.Errorf("no %s", op.Daemon)
			}

			x.Leaving = true
			st.AddDaemon(x)

			return nil
		}); err != nil {
			return err
		}
	}

	doc := st.DocName(d)

	done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".rev", op.Host, revisionMode{extra: []string{"ContainerConfig/" + doc}})
	if err != nil || !done {
		return err
	}

	if !ok {
		return fmt.Errorf("%w: the revision of %s did not apply", errRetry, op.Host)
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return err
	}

	if slices.Contains(rep.Instances, doc) {
		return fmt.Errorf("%w: %s has not stopped yet", errRetry, op.Daemon)
	}

	if err := b.Retire(ctx, "retire", op.ID); err != nil {
		return fmt.Errorf("%w: %v", errRetry, err)
	}

	var zapFailed error

	if op.Zap {
		var zf errZapFailed
		if err := l.zapOSD(ctx, b, js, gid, epoch, op, st, h, d); errors.As(err, &zf) {
			zapFailed = zf.error
		} else if err != nil {
			return err
		}
	}

	// purged: the OSD leaves the state, zapped or not
	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		if x, ok := daemonOf(st, op.Daemon); ok {
			st.RemoveDaemon(x)
		}

		return nil
	}); err != nil {
		return err
	}

	if zapFailed != nil {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("purged, not zapped: %w", zapFailed))
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// zapOSD zaps a removed OSD's disk with a job that requires a BlueStore label
// of this cluster and of that OSD, and acknowledges its outcome; a zap that
// fails ends the removal as failed (the OSD is purged, its disk kept).
func (l *LeaderLoop) zapOSD(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp, st *state.State, h state.Host, d state.Daemon) error {
	if d.DevicePath == "" || d.DiskSerial == "" {
		return errZapFailed{fmt.Errorf("%s has no stable device and serial to zap", op.Daemon)}
	}

	id := zapOf(op.ID)
	job := daemons.Zap(daemons.Params{
		Name: st.DocName(state.Daemon{Type: "job", ID: id}), Image: st.Image, FSID: st.FSID, ID: "job",
		Device: d.DevicePath, DiskSerial: d.DiskSerial, OSDUUID: d.OSDUUID,
	}, id, daemons.ZapInputs(h.Name, d.DevicePath, d.DiskSerial, false, d.OSDUUID))

	y, err := spec.Render(job)
	if err != nil {
		return err
	}

	zap := op.ID + ".zap"

	done, _, err := l.step(ctx, b, js, gid, epoch, zap, op.Host, revisionMode{add: []Doc{{Kind: "ContainerConfig", Name: job.MetaName, YAML: y}}})
	if err != nil {
		return err
	}

	// a sub-step: the removal goes on only once the zap ended
	if !done {
		return fmt.Errorf("%w: the zap of %s has not ended yet", errRetry, op.Daemon)
	}

	rec, _, err := l.journalRecord(ctx, b, js, gid, zap)
	if err != nil {
		return err
	}

	if rec.Job != nil {
		rc := -1
		if rec.Result != nil {
			rc = rec.Result.RC
		}

		if err := l.ackJob(ctx, b, js, gid, epoch, op.ID+".zap", op.Host, rec, rc); err != nil {
			return err
		}
	}

	if rec.State != wire.OpCompleted {
		return errZapFailed{fmt.Errorf("the zap of %s ended %s %s", op.Daemon, rec.State, rec.Error)}
	}

	return nil
}

// errZapFailed ends a removal as failed: the OSD is purged and leaves the
// state, its disk keeps its label (zapping it is the operator's, with the CLI).
type errZapFailed struct{ error }

// enterMaintenance puts a host into maintenance (stopHost).
func (l *LeaderLoop) enterMaintenance(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	done, err := l.stopHost(ctx, b, js, gid, epoch, op, op.ID)
	if err != nil || !done {
		return ended(err)
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// exitMaintenance takes a host out of maintenance (startHost).
func (l *LeaderLoop) exitMaintenance(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	done, err := l.startHost(ctx, b, js, gid, epoch, op, op.ID)
	if err != nil || !done {
		return ended(err)
	}

	if err := b.Retire(ctx, "maintained", op.ID); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// powercycle reboots a host as one operation: into maintenance (stopHost),
// the agent's reboot of its node, out of maintenance (startHost).
func (l *LeaderLoop) powercycle(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	// the stop phase ends where the reboot step begins: once that is
	// journaled, the host's daemons may be starting again
	bs, err := l.journalState(ctx, b, js, gid, op.ID+".boot")
	if err != nil {
		return err
	}

	if bs == "" {
		done, err := l.stopHost(ctx, b, js, gid, epoch, op, op.ID+".in")
		if err != nil || !done {
			return ended(err)
		}
	}

	done, ok, err := l.rebootStep(ctx, b, js, gid, epoch, op.ID+".boot", op.Host)
	if err != nil || !done {
		return err
	}

	if !ok {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s did not reboot; it stays in maintenance", op.Host))
	}

	if done, err := l.startHost(ctx, b, js, gid, epoch, op, op.ID+".out"); err != nil || !done {
		return ended(err)
	}

	if err := b.Retire(ctx, "maintained", op.ID); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// errEnded: a phase function ended the operation in the journal itself.
var errEnded = errors.New("the operation ended")

// ended is a phase function's error as its operation returns it.
func ended(err error) error {
	if errors.Is(err, errEnded) {
		return nil
	}

	return err
}

// end ends an operation as failed and returns errEnded.
func end(ctx context.Context, js store.Backend, gid int64, op LedgerOp, cause error) error {
	if err := finish(ctx, js, gid, op, JournalFailed, cause); err != nil {
		return err
	}

	return errEnded
}

// stopHost stops a host's daemons, as cephadm's maintenance enter, in phases
// below base: Ceph's checks that they can stop (force overrides neither, as
// in Ceph), the active mgr failed over if it runs there, keepalived off first,
// noout for its OSDs (recorded in the state first, so the exit clears it), the
// host marked in maintenance (its daemons stay in the state, not rendered),
// then every document off and every instance gone. The checks and the active
// mgr are checked again until the stop grant is sent.
func (l *LeaderLoop) stopHost(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp, base string) (bool, error) {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return false, err
	}

	h, ok := st.Host(op.Host)
	if !ok {
		return false, end(ctx, js, gid, op, fmt.Errorf("no host %s", op.Host))
	}

	var docs, vips []string

	osds := false

	for _, d := range st.Daemons {
		if d.Host != h.Name || d.LocalOnly || d.Purged {
			continue
		}

		docs = append(docs, st.DocName(d))
		osds = osds || d.Type == state.TypeOSD

		if d.Type == state.TypeVIP {
			vips = append(vips, st.DocName(d))
		}
	}

	rs, err := l.journalState(ctx, b, js, gid, base+".rev")
	if err != nil {
		return false, err
	}

	// right before the stop grant is sent, also on a resumed operation; a
	// grant already sent is resolved by its step
	if rs == "" {
		if err := b.Retire(ctx, "ok to stop", op.ID); err != nil {
			return false, err
		}
	}

	// also on a resumed operation: leadership may have moved onto this host
	if !terminal(rs) {
		active, agid, err := b.ActiveMgrGID(ctx)
		if err != nil {
			return false, err
		}

		if active == h.Name {
			// recorded first: the module that answers is the one failed over
			if err := writeJSONKey(ctx, js, JournalPrefix(gid)+"op/"+base+".fail", JournalOp{Version: journalVersion, Kind: "mgr_fail", Host: h.Name, State: wire.OpStarted, MgrGID: agid}); err != nil {
				return false, err
			}

			// no answer is expected; a refusal (no standby) is retried until the
			// operation fails, and the successor checks the mgr map again
			if err := b.MgrFail(ctx, op.ID, agid, active, h.Name); err != nil {
				return false, fmt.Errorf("%w: failing the active mgr on %s over: %w", errRetry, h.Name, err)
			}

			return false, fmt.Errorf("%w: the active mgr on %s is failing over", errRetry, h.Name)
		}
	}

	if !h.Maintenance && len(vips) > 0 {
		keys := make([]string, 0, len(vips))
		for _, v := range vips {
			keys = append(keys, "ContainerConfig/"+v)
		}

		done, ok, err := l.step(ctx, b, js, gid, epoch, base+".vip", h.Name, revisionMode{stop: keys})
		if err != nil || !done {
			return false, err
		}

		if !ok {
			return false, end(ctx, js, gid, op, fmt.Errorf("keepalived on %s did not stop", h.Name))
		}

		// the VIP moves once keepalived has exited, not when its document is gone
		if err := l.gone(ctx, h, vips); err != nil {
			return false, err
		}
	}

	if !h.Maintenance && osds && !h.NoOut {
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			h, ok := st.Host(op.Host)
			if !ok {
				return fmt.Errorf("no host %s", op.Host)
			}

			h.NoOut = true
			st.AddHost(h)

			return nil
		}); err != nil {
			return false, err
		}

		h.NoOut = true
	}

	// before the host is marked: from then on any revision stops its OSDs
	if h.NoOut {
		if err := b.Retire(ctx, "noout set", op.ID); err != nil {
			return false, err
		}
	}

	if !h.Maintenance {
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			h, ok := st.Host(op.Host)
			if !ok {
				return fmt.Errorf("no host %s", op.Host)
			}

			h.Maintenance = true
			st.AddHost(h)

			return nil
		}); err != nil {
			return false, err
		}
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, base+".rev", h.Name, revisionMode{})
	if err != nil || !done {
		return false, err
	}

	if !ok {
		if err := l.unmark(ctx, b, js, gid, op.Host, base); err != nil {
			return false, err
		}

		return false, end(ctx, js, gid, op, fmt.Errorf("the revision of %s did not apply", h.Name))
	}

	if err := l.gone(ctx, h, docs); err != nil {
		return false, err
	}

	return true, nil
}

// unmark undoes the mark of a maintenance whose stop grant (base.rev) was
// never sent or never applied (its checks kept refusing, or the node refused
// it): revisions would stop the host's daemons without the checks. noout
// stays recorded, so the exit clears it.
func (l *LeaderLoop) unmark(ctx context.Context, b *Bridge, js store.Backend, gid int64, host, base string) error {
	rs, err := l.journalState(ctx, b, js, gid, base+".rev")
	if err != nil {
		return err
	}

	switch rs {
	case wire.OpCompleted, JournalNoChange, JournalGranting, wire.OpUncertain:
		return nil // stopped, or maybe: the mark stays
	}

	return l.changeState(ctx, b, gid, func(st *state.State) error {
		if h, ok := st.Host(host); ok && h.Maintenance {
			h.Maintenance = false
			st.AddHost(h)
		}

		return nil
	})
}

// gone waits until none of a host's documents has an instance left.
func (l *LeaderLoop) gone(ctx context.Context, h state.Host, docs []string) error {
	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return err
	}

	for _, doc := range docs {
		if slices.Contains(rep.Instances, doc) {
			return fmt.Errorf("%w: %s has not stopped yet", errRetry, doc)
		}
	}

	return nil
}

// startHost starts a host's daemons again, in phases below base: its mon
// first, in the quorum before the rest is rendered (other documents on the
// node are left as they are), then its OSDs up in the OSD map, noout cleared.
func (l *LeaderLoop) startHost(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp, base string) (bool, error) {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return false, err
	}

	h, ok := st.Host(op.Host)
	if !ok {
		return false, end(ctx, js, gid, op, fmt.Errorf("no host %s", op.Host))
	}

	if h.Maintenance {
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			h, ok := st.Host(op.Host)
			if !ok {
				return fmt.Errorf("no host %s", op.Host)
			}

			h.Maintenance = false
			st.AddHost(h)

			return nil
		}); err != nil {
			return false, err
		}
	}

	var rest []string

	mon := false

	for _, d := range st.Daemons {
		if d.Host != h.Name {
			continue
		}

		if d.Type == state.TypeMon {
			mon = true
		} else {
			rest = append(rest, "ContainerConfig/"+st.DocName(d))
		}
	}

	if mon {
		done, ok, err := l.step(ctx, b, js, gid, epoch, base+".mon", h.Name, revisionMode{hold: rest})
		if err != nil || !done {
			return false, err
		}

		if !ok {
			return false, end(ctx, js, gid, op, fmt.Errorf("the mon of %s did not start", h.Name))
		}

		q, err := b.Quorum(ctx)
		if err != nil {
			return false, err
		}

		if !slices.Contains(q, h.Name) {
			return false, fmt.Errorf("%w: mon.%s is not in the quorum yet", errRetry, h.Name)
		}
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, base+".rev", h.Name, revisionMode{})
	if err != nil || !done {
		return false, err
	}

	if !ok {
		return false, end(ctx, js, gid, op, fmt.Errorf("the revision of %s did not apply", h.Name))
	}

	osds, err := b.OSDs(ctx)
	if err != nil {
		return false, err
	}

	for _, d := range st.DaemonsOf(state.TypeOSD, h.Name) {
		if d.OSDID == nil || d.LocalOnly || d.Purged || d.Leaving {
			continue
		}

		up := false

		for _, o := range osds {
			up = up || o.ID == *d.OSDID && o.UUID == d.OSDUUID && o.Up
		}

		if !up {
			return false, fmt.Errorf("%w: osd.%d is not up yet", errRetry, *d.OSDID)
		}
	}

	if h.NoOut {
		if err := b.Retire(ctx, "noout unset", op.ID); err != nil {
			return false, err
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			h, ok := st.Host(op.Host)
			if !ok {
				return fmt.Errorf("no host %s", op.Host)
			}

			h.NoOut = false
			st.AddHost(h)

			return nil
		}); err != nil {
			return false, err
		}
	}

	return true, nil
}

// rebootStep has the agent of a host reboot its node, as one grant under its
// own id (journaled before it is sent): done once the agent decided it, ok
// once it completed, which it records when the node runs another boot.
func (l *LeaderLoop) rebootStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, id, host string) (done, ok bool, err error) {
	opKey := JournalPrefix(gid) + "op/" + id

	cur, found, err := readJSONKey[JournalOp](ctx, js, opKey)
	if err != nil {
		return false, false, err
	}

	if found {
		if cur.State == JournalGranting || cur.State == wire.OpUncertain {
			if err := l.resolve(ctx, b, js, gid, epoch, opKey, cur, id); err != nil {
				return false, false, err
			}

			if cur, _, err = readJSONKey[JournalOp](ctx, js, opKey); err != nil || !terminal(cur.State) {
				return false, false, err
			}
		}

		return true, cur.State == wire.OpCompleted, nil
	}

	st, seq, err := l.clusterState(ctx, b)
	if err != nil {
		return false, false, err
	}

	h, ok := st.Host(host)
	if !ok {
		return false, false, fmt.Errorf("no host %s in the cluster state", host)
	}

	if !l.closed[h.Name] {
		return false, false, fmt.Errorf("%w: %s's earlier sessions are not closed yet", errRetry, h.Name)
	}

	me, ok := st.Host(l.Self.Name)
	if !ok {
		return false, false, fmt.Errorf("the leader's host %s is not in the cluster state", l.Self.Name)
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return false, false, err
	}

	if rep.State != "owned" {
		return false, false, fmt.Errorf("%w: %s is %s %v", errRetry, h.Name, rep.State, rep.Drift)
	}

	op := JournalOp{Version: journalVersion, Kind: "reboot", Host: h.Name, Seq: seq, State: JournalGranting, Revision: max(rep.Revision+1, l.clock().UnixNano())}

	if !l.stillLeader(gid, epoch) {
		return false, false, nil
	}

	// the intent is in the journal before anything is sent
	if err := writeJSONKey(ctx, js, opKey, op); err != nil {
		return false, false, err
	}

	if !l.stillLeader(gid, epoch) {
		return false, false, nil
	}

	g := wire.Grant{
		Version: wire.Version, FSID: l.Self.FSID, Host: h.Name, Mgr: l.Self.Name, MgrAddr: me.Addr, GID: gid, Epoch: epoch,
		Revision: op.Revision, Operation: id, Reboot: true, Approval: l.approval,
	}

	var res wire.Operation
	if _, err := l.call(ctx, h, http.MethodPost, "/v1/grant", g, &res); err != nil {
		return false, false, fmt.Errorf("reboot %s: %w", h.Name, err)
	}

	if err := l.record(ctx, js, opKey, op, res); err != nil {
		return false, false, err
	}

	return false, false, nil // decided on a later tick
}

// controlsAhead carries out the controls of the upgrade in progress (op) among
// the executable operations after a ledger key, ahead of their turn; another
// upgrade's wait for it.
func (l *LeaderLoop) controlsAhead(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, after, op string) error {
	for {
		entries, more, err := b.Ledger(ctx, after)
		if err != nil {
			return err
		}

		for _, e := range entries {
			if isControl(e.Op.Kind) && e.Op.Upgrade == op {
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

// isControl reports whether a kind is one of an upgrade's controls.
func isControl(kind string) bool {
	return kind == KindUpPause || kind == KindUpResume || kind == KindUpStop
}

// probeOf is the job id of an upgrade's image probe.
func probeOf(op string) string {
	sum := sha256.Sum256([]byte(op + ":probe"))

	return hex.EncodeToString(sum[:8])
}

var (
	cephVersionRe = regexp.MustCompile(`ceph version (\d+)\.(\d+)\.(\d+)`)
	probeArchRe   = regexp.MustCompile(`(?m)^arch (\S+)$`)
)

// versionOf reads "20.2.4" into its numbers.
func versionOf(v string) ([3]int, bool) {
	var n [3]int

	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return n, false
	}

	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil {
			return n, false
		}

		n[i] = x
	}

	return n, true
}

// upgradeStart validates an upgrade and records it in the state (plan 03,
// step 6d): the image in the operator's approval, its Ceph version and
// architecture from a probe job, no downgrade, at most two majors up, the
// cluster's architecture. The steps follow between ledger operations. A
// refused upgrade is closed in the module's fold.
func (l *LeaderLoop) upgradeStart(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	refuse := func(cause error) error {
		if err := b.Retire(ctx, "upgrade refused", op.ID); err != nil {
			return err
		}

		return finish(ctx, js, gid, op, JournalFailed, cause)
	}

	if u := st.Upgrade; u != nil {
		switch {
		case u.Op == op.ID:
			return finish(ctx, js, gid, op, wire.OpCompleted, nil)
		case u.Finished || u.Stopped:
			// the module accepted this start once that one was closed: it ends first
			return fmt.Errorf("%w: upgrade %s is ending", errRetry, u.Op)
		default:
			return refuse(fmt.Errorf("upgrade %s is in progress", u.Op))
		}
	}

	// an agent upgrade and a Ceph upgrade exclude each other
	if au := st.AgentUpgrade; au != nil && !au.Finished {
		return refuse(fmt.Errorf("agent upgrade %s is in progress", au.Op))
	}

	if l.appr == nil || !l.appr.Image(op.Image) {
		return refuse(fmt.Errorf("the operator has not approved %s", op.Image))
	}

	// the probe runs on the host of the first mon by name: the same for every leader
	var host string

	for _, d := range st.DaemonsOf(state.TypeMon, "") {
		if h, ok := st.Host(d.Host); ok && !h.Maintenance && !d.Joining && (host == "" || d.Host < host) {
			host = d.Host
		}
	}

	if host == "" {
		return refuse(errors.New("no host to probe the image on"))
	}

	id := probeOf(op.ID)
	job := daemons.ProbeJob(daemons.Params{Name: st.DocName(state.Daemon{Type: "job", ID: id}), Image: op.Image, FSID: st.FSID, ID: "job"}, id, host)

	y, err := spec.Render(job)
	if err != nil {
		return err
	}

	done, _, err := l.step(ctx, b, js, gid, epoch, op.ID+".probe", host, revisionMode{add: []Doc{{Kind: "ContainerConfig", Name: job.MetaName, YAML: y}}})
	if err != nil {
		return err
	}

	if !done {
		return fmt.Errorf("%w: the probe of %s has not ended yet", errRetry, op.Image)
	}

	rec, _, err := l.journalRecord(ctx, b, js, gid, op.ID+".probe")
	if err != nil {
		return err
	}

	var out string

	rc := -1
	if rec.Result != nil {
		rc, out = rec.Result.RC, rec.Result.Output
	}

	if rec.Job != nil {
		if err := l.ackJob(ctx, b, js, gid, epoch, op.ID+".probe", host, rec, rc); err != nil {
			return err
		}
	}

	m, a := cephVersionRe.FindStringSubmatch(out), probeArchRe.FindStringSubmatch(out)
	if rec.State != wire.OpCompleted || rc != 0 || m == nil || a == nil {
		return refuse(fmt.Errorf("the probe of %s ended %s (rc %d) without a version and architecture", op.Image, rec.State, rc))
	}

	version := m[1] + "." + m[2] + "." + m[3]
	to, _ := versionOf(version)

	if from, ok := versionOf(st.CephVersion); ok {
		switch {
		case to[0] < from[0] || to[0] == from[0] && (to[1] < from[1] || to[1] == from[1] && to[2] < from[2]):
			return refuse(fmt.Errorf("%s is Ceph %s, older than the cluster's %s", op.Image, version, st.CephVersion))
		case to[0]-from[0] > 2:
			return refuse(fmt.Errorf("Ceph %s is more than two majors after the cluster's %s", version, st.CephVersion))
		}
	}

	if st.Arch != "" && a[1] != st.Arch {
		return refuse(fmt.Errorf("%s is for %s, the cluster runs %s", op.Image, a[1], st.Arch))
	}

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		if st.Upgrade == nil {
			st.Upgrade = &state.Upgrade{Op: op.ID, Image: op.Image, Version: version, Done: []string{}}
		}

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// upgradeControl carries out pause, resume or stop of the upgrade it names:
// they change its record alone. A stop leaves the images already changed (no
// rollback) and the cluster's image as it was; with a step in progress the
// upgrade ends with that step.
func (l *LeaderLoop) upgradeControl(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		u := st.Upgrade
		if u == nil || u.Op != op.Upgrade {
			return nil // ended already
		}

		switch {
		case op.Kind == KindUpPause:
			u.Paused = true
		case op.Kind == KindUpResume:
			// a step that is failing keeps its cause until it ended (paused again)
			u.Paused = false
			if u.Step == "" {
				u.Error = ""
			}
		case u.Step != "":
			u.Paused, u.Stopped = true, true // it ends with its step
		default:
			st.Upgrade = nil
		}

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// upgradeOrder is the order of an upgrade's steps, as Ceph's: the standby
// mgrs, the active one, the mons, the OSDs, the RGWs (keepalived keeps its
// own image).
func upgradeOrder(st *state.State, active string) []state.Daemon {
	var out []state.Daemon

	rank := func(d state.Daemon) int {
		switch {
		case d.Type == state.TypeMgr && d.ID != active:
			return 0
		case d.Type == state.TypeMgr:
			return 1
		case d.Type == state.TypeMon:
			return 2
		case d.Type == state.TypeOSD:
			return 3
		default:
			return 4
		}
	}

	for _, d := range st.Daemons {
		switch {
		case d.LocalOnly || d.Purged || d.Leaving || d.Joining:
		case d.Type == state.TypeOSD && (d.OSDID == nil || d.OSDUUID == ""):
		case d.Type == state.TypeMgr, d.Type == state.TypeMon, d.Type == state.TypeOSD, d.Type == state.TypeRGW:
			out = append(out, d)
		}
	}

	slices.SortStableFunc(out, func(a, b state.Daemon) int { return rank(a) - rank(b) })

	return out
}

// upgradeStep carries out the upgrade's next step, one daemon (plan 03, step
// 6d): chosen and recorded in the state, Ceph's check that it can stop (mon
// only with more than two mons), the active mgr failed over first, an RGW's
// keepalived moved off first, its image set and its host's revision granted,
// then the daemon running the target with a newer instance and back in Ceph.
// While a step is unfinished, no revision request starts. A step not done
// within 10 minutes (of its start before the grant, of the grant's end after
// it) pauses the upgrade with an error and ends; a grant whose outcome is
// unknown keeps it. A stopped upgrade ends with its step; one not granted yet
// is dropped. Without a daemon left, the target becomes the cluster's image,
// recorded as finished before the module closes the upgrade.
func (l *LeaderLoop) upgradeStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err // the hold stays
	}

	if st.Upgrade == nil {
		l.holding = ""

		return nil
	}

	u := *st.Upgrade

	// before any read that can fail: no revision request beside a step
	l.holding = ""
	if u.Step != "" {
		l.holding = holdAll
	}

	if u.Finished {
		// closed in the fold, then cleared: a retry finds it closed already
		if err := b.Retire(ctx, "upgrade done", u.Op); err != nil {
			return err
		}

		return l.changeState(ctx, b, gid, func(st *state.State) error {
			if st.Upgrade != nil && st.Upgrade.Op == u.Op && st.Upgrade.Finished {
				st.Upgrade = nil
			}

			return nil
		})
	}

	active, agid, standbys, err := b.MgrMap(ctx)
	if err != nil {
		return err
	}

	if u.Step == "" {
		if u.Stopped {
			return l.changeState(ctx, b, gid, func(st *state.State) error {
				if st.Upgrade != nil && st.Upgrade.Op == u.Op && st.Upgrade.Step == "" {
					st.Upgrade = nil
				}

				return nil
			})
		}

		var next *state.Daemon

		for _, d := range upgradeOrder(st, active) {
			if !slices.Contains(u.Done, st.DocName(d)) {
				next = &d

				break
			}
		}

		if next == nil {
			return l.changeState(ctx, b, gid, func(st *state.State) error {
				if st.Upgrade == nil || st.Upgrade.Op != u.Op || st.Upgrade.Step != "" {
					return nil
				}

				st.Image, st.CephVersion, st.Upgrade.Finished = st.Upgrade.Image, st.Upgrade.Version, true

				for _, d := range st.Daemons {
					if d.Image != "" {
						d.Image = ""
						st.AddDaemon(d)
					}
				}

				return nil
			})
		}

		// nor beside an agent upgrade's step in progress
		if u.Paused || st.AgentUpgrade != nil && !st.AgentUpgrade.Finished && st.AgentUpgrade.Step != "" {
			return nil
		}

		l.holding = holdAll
		name := st.DocName(*next)

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			if cur := st.Upgrade; cur != nil && cur.Op == u.Op && cur.Step == "" && !cur.Paused {
				cur.Step, cur.Attempt, cur.StepAt, cur.GrantedAt, cur.Before = name, cur.Attempt+1, l.clock().UTC(), time.Time{}, ""
			}

			return nil
		}); err != nil {
			return err
		}

		return fmt.Errorf("%w: upgrading %s", errRetry, name)
	}

	// a step in progress holds the slot for every host
	l.holding = holdAll

	var d state.Daemon

	found := false

	for _, x := range st.Daemons {
		if st.DocName(x) == u.Step {
			d, found = x, true
		}
	}

	h, ok := st.Host(d.Host)
	if !found || !ok {
		return l.endStep(ctx, b, gid, u, "", false) // gone meanwhile (removed)
	}

	since := u.StepAt
	if !u.GrantedAt.IsZero() {
		since = u.GrantedAt
	}

	sid := fmt.Sprintf("%s.u%d", u.Op, u.Attempt)

	var vips []string

	if d.Type == state.TypeRGW {
		for _, x := range st.DaemonsOf(state.TypeVIP, h.Name) {
			vips = append(vips, st.DocName(x))
		}
	}

	stop := make([]string, 0, len(vips))
	for _, v := range vips {
		stop = append(stop, "ContainerConfig/"+v)
	}

	phase := map[string]string{}

	// the states of the step's grants, read again before any decision to give up
	unresolved := func() (bool, error) {
		open := false

		for _, p := range []string{"vip", "rev", "back"} {
			s, err := l.journalState(ctx, b, js, gid, sid+"."+p)
			if err != nil {
				return true, err
			}

			phase[p], open = s, open || s == JournalGranting || s == wire.OpUncertain
		}

		return open, nil
	}

	if _, err := unresolved(); err != nil {
		return err
	}

	// keepalived back beside its RGW, before the step ends either way
	restore := func() (bool, error) {
		if len(vips) == 0 || phase["vip"] == "" {
			return true, nil
		}

		done, ok, err := l.step(ctx, b, js, gid, epoch, sid+".back", h.Name, revisionMode{})
		if err != nil {
			// a host that cannot be reached past the step's time, every grant's
			// outcome known: paused, the daemon not done (resume retries it)
			if open, uerr := unresolved(); uerr == nil && !open && l.clock().Sub(since) > stuckAfter {
				cause := strings.TrimPrefix(u.Error+"; ", "; ") + "keepalived on " + h.Name + " not restored: " + err.Error()

				return false, l.endStep(ctx, b, gid, u, cause, false)
			}

			return false, err
		}

		if !done {
			return false, nil
		}

		if !ok {
			return false, l.endStep(ctx, b, gid, u, "keepalived on "+h.Name+" did not come back", false)
		}

		return true, nil
	}

	// a step that fails records why before it restores keepalived: from then
	// on it only finishes (restore, then pause), whatever the next tick finds
	fail := func(cause string) error {
		if u.Error == "" {
			if err := l.changeState(ctx, b, gid, func(st *state.State) error {
				if st.Upgrade != nil && st.Upgrade.Op == u.Op && st.Upgrade.Step == u.Step {
					st.Upgrade.Error = cause
				}

				return nil
			}); err != nil {
				return err
			}

			u.Error = cause
		}

		if done, err := restore(); err != nil || !done {
			return err
		}

		return l.endStep(ctx, b, gid, u, u.Error, false)
	}

	if u.Error != "" {
		return fail(u.Error)
	}

	// keepalived's restoration began after the daemon was back: it only finishes
	if phase["back"] != "" {
		if done, err := restore(); err != nil || !done {
			return err
		}

		return l.endStep(ctx, b, gid, u, "", true)
	}

	// waiting counts against the step's 10 minutes, then it pauses the upgrade;
	// never while a grant of the step has an unknown outcome
	wait := func(why string) error {
		if l.clock().Sub(since) <= stuckAfter {
			return fmt.Errorf("%w: %s", errRetry, why)
		}

		if open, err := unresolved(); err != nil || open {
			return fmt.Errorf("%w: %s", errRetry, why)
		}

		return fail(fmt.Sprintf("%s not done within %s: %s", u.Step, stuckAfter, why))
	}

	if phase["rev"] == "" {
		if u.Stopped && phase["vip"] == "" {
			return l.endStep(ctx, b, gid, u, "", false) // nothing granted: dropped
		}

		// a mgr that is the active one fails over first, by its gid
		if d.Type == state.TypeMgr && d.ID == active {
			if len(standbys) == 0 {
				return wait(fmt.Sprintf("mgr.%s is the active mgr and there is no standby", d.ID))
			}

			if err := writeJSONKey(ctx, js, JournalPrefix(gid)+"op/"+sid+".fail", JournalOp{Version: journalVersion, Kind: "mgr_fail", Host: h.Name, State: wire.OpStarted, MgrGID: agid}); err != nil {
				return err
			}

			if err := b.MgrFail(ctx, u.Op, agid, d.ID, h.Name); err != nil {
				return wait(fmt.Sprintf("failing the active mgr over: %v", err))
			}

			return fmt.Errorf("%w: the active mgr is failing over", errRetry)
		}

		check := d.Type == state.TypeOSD
		if d.Type == state.TypeMon {
			check = len(st.DaemonsOf(state.TypeMon, "")) > 2
		}

		if check && phase["vip"] == "" {
			if err := b.OKToStop(ctx, u.Op, ledgerName(d)); err != nil {
				return wait(fmt.Sprintf("%s: %v", ledgerName(d), err))
			}
		}

		// an RGW's VIP moves to a peer before the RGW restarts
		if len(vips) > 0 {
			done, ok, err := l.step(ctx, b, js, gid, epoch, sid+".vip", h.Name, revisionMode{stop: stop})
			if err != nil {
				return wait(err.Error())
			}

			if !done {
				return nil
			}

			if !ok {
				return l.endStep(ctx, b, gid, u, "keepalived on "+h.Name+" did not stop", false)
			}

			phase["vip"] = wire.OpCompleted

			if err := l.gone(ctx, h, vips); err != nil {
				return wait(err.Error())
			}
		}

		var rep wire.NodeReport
		if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			return wait(err.Error())
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			x, ok := st.Find(ledgerName(d))
			if !ok || st.DocName(x) != u.Step || st.Upgrade == nil || st.Upgrade.Op != u.Op {
				return nil
			}

			x.Image, st.Upgrade.Before = u.Image, rep.Current[u.Step]
			st.AddDaemon(x)

			return nil
		}); err != nil {
			return err
		}
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, sid+".rev", h.Name, revisionMode{stop: stop})
	if err != nil {
		return wait(err.Error())
	}

	if !done {
		return nil // a grant whose outcome is unknown is never given up
	}

	if !ok {
		return fail(fmt.Sprintf("the revision of %s for %s did not apply", h.Name, u.Step))
	}

	// readiness is timed from the grant's end
	if u.GrantedAt.IsZero() {
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			if st.Upgrade != nil && st.Upgrade.Op == u.Op && st.Upgrade.Step == u.Step {
				st.Upgrade.GrantedAt = l.clock().UTC()
			}

			return nil
		}); err != nil {
			return err
		}

		return fmt.Errorf("%w: %s granted", errRetry, u.Step)
	}

	// a revision that changed nothing (the document had the target already)
	// starts no new instance: running the target is enough
	before := u.Before
	if s, err := l.journalState(ctx, b, js, gid, sid+".rev"); err != nil {
		return err
	} else if s == JournalNoChange {
		before = ""
	}

	back, why, err := l.backInCeph(ctx, b, d, h, u.Image, before, active, standbys)
	if err != nil {
		why = err.Error()
	}

	if !back {
		return wait(why)
	}

	if done, err := restore(); err != nil || !done {
		return err
	}

	return l.endStep(ctx, b, gid, u, "", true)
}

// ledgerName is a daemon's name as the ledger has it ("<type>.<id>").
func ledgerName(d state.Daemon) string {
	if d.Type == state.TypeOSD && d.OSDID != nil {
		return fmt.Sprintf("osd.%d", *d.OSDID)
	}

	return d.Type + "." + d.ID
}

// backInCeph reports whether a daemon runs again after its step: running
// the target's digest, with a newer instance on its node than before (unless
// before is empty), and the mon in the quorum, the mgr in the mgr map, the OSD
// up.
func (l *LeaderLoop) backInCeph(ctx context.Context, b *Bridge, d state.Daemon, h state.Host, target, before, active string, standbys []string) (bool, string, error) {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return false, "", err
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return false, "", err
	}

	name := st.DocName(d)

	if cur := rep.Current[name]; cur == "" || before != "" && cur == before {
		return false, name + " has no new instance yet", nil
	}

	if _, digest, _ := strings.Cut(target, "@"); rep.Running[name] != digest {
		return false, name + " does not run " + digest + " yet", nil
	}

	switch d.Type {
	case state.TypeMon:
		q, err := b.Quorum(ctx)
		if err != nil {
			return false, "", err
		}

		return slices.Contains(q, d.ID), "mon." + d.ID + " is not in the quorum yet", nil
	case state.TypeMgr:
		return d.ID == active || slices.Contains(standbys, d.ID), "mgr." + d.ID + " is not in the mgr map yet", nil
	case state.TypeOSD:
		osds, err := b.OSDs(ctx)
		if err != nil {
			return false, "", err
		}

		for _, o := range osds {
			if d.OSDID != nil && o.ID == *d.OSDID && o.UUID == d.OSDUUID && o.Up {
				return true, "", nil
			}
		}

		return false, ledgerName(d) + " is not up yet", nil
	}

	return true, "", nil
}

// endStep ends the upgrade's step: done, or the upgrade paused with an error.
func (l *LeaderLoop) endStep(ctx context.Context, b *Bridge, gid int64, u state.Upgrade, cause string, done bool) error {
	return l.changeState(ctx, b, gid, func(st *state.State) error {
		cur := st.Upgrade
		if cur == nil || cur.Op != u.Op || cur.Step != u.Step {
			return nil
		}

		if done && !slices.Contains(cur.Done, cur.Step) {
			cur.Done = append(cur.Done, cur.Step)
		}

		if cause != "" {
			cur.Paused, cur.Error = true, cause
		}

		cur.Step, cur.StepAt, cur.GrantedAt = "", time.Time{}, time.Time{}

		return nil
	})
}

// addHost adds a node the CLI enrolled (plan 03, step 7): the host with its
// agent certificates in the state, earlier sessions on it closed (a removed
// host's agent may have some) and recorded with the takeover's, then its first
// revision (ceph.conf).
func (l *LeaderLoop) addHost(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	if pki.ValidName(op.Host) != nil || op.Addr == "" || op.AgentCert == "" || op.AgentClientCert == "" {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("add_host %s: malformed", op.Host))
	}

	closedKey := rollKey(gid, op.ID+".closed")
	takeoverKey := JournalPrefix(gid) + "takeover"

	closed, _, err := readJSONKey[rollRecord](ctx, js, closedKey)
	if err != nil {
		return err
	}

	// an earlier host of that name counts as closed no longer, before this one
	// is published: the name may be another node's now
	if !closed.Done {
		to, _, err := readJSONKey[Takeover](ctx, js, takeoverKey)
		if err != nil {
			return err
		}

		if i := slices.Index(to.Closed, op.Host); i >= 0 {
			to.Closed = slices.Delete(to.Closed, i, i+1)
			if err := writeJSONKey(ctx, js, takeoverKey, to); err != nil {
				return err
			}
		}

		delete(l.closed, op.Host)
	}

	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	if _, ok := st.Host(op.Host); !ok {
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			st.AddHost(state.Host{Name: op.Host, Addr: op.Addr, AgentCert: op.AgentCert, AgentClientCert: op.AgentClientCert, Labels: op.Labels})

			return nil
		}); err != nil {
			return err
		}

		if st, _, err = l.clusterState(ctx, b); err != nil {
			return err
		}
	}

	h, _ := st.Host(op.Host)

	// once per add
	if !closed.Done {
		me, ok := st.Host(l.Self.Name)
		if !ok {
			return fmt.Errorf("the leader's host %s is not in the cluster state", l.Self.Name)
		}

		c := wire.Close{Version: wire.Version, FSID: l.Self.FSID, Host: h.Name, Mgr: l.Self.Name, MgrAddr: me.Addr, GID: gid, Epoch: epoch}

		var res wire.CloseReply
		if _, err := l.call(ctx, h, http.MethodPost, "/v1/close", c, &res); err != nil {
			return fmt.Errorf("%w: closing earlier sessions on %s: %w", errRetry, h.Name, err)
		}

		to, _, err := readJSONKey[Takeover](ctx, js, takeoverKey)
		if err != nil {
			return err
		}

		if !slices.Contains(to.Closed, h.Name) {
			to.Closed = append(to.Closed, h.Name)
			if err := writeJSONKey(ctx, js, takeoverKey, to); err != nil {
				return err
			}
		}

		if err := writeJSONKey(ctx, js, closedKey, rollRecord{Done: true}); err != nil {
			return err
		}

		l.closed[h.Name] = true
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".rev", h.Name, revisionMode{})
	if err != nil || !done {
		return err
	}

	if !ok {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the first revision of %s did not apply", h.Name))
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}
