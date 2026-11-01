package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
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
	KindRemoveHost   = "remove_host"
)

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

			done, err := l.ledgerOp(ctx, b, js, gid, epoch, e)
			if err != nil || !done {
				return err // in progress or retried: nothing after it runs
			}

			if err := l.checkpoint(ctx, b, gid, e.Key); err != nil {
				return err
			}

			after = e.Key
		}

		if !more || len(entries) == 0 {
			return nil
		}
	}
}

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

	known := map[string]bool{KindRestart: true, KindRedeploy: true, KindAddDaemon: true, KindRemoveDaemon: true, KindRemoveHost: true}
	if !ledgerIDRe.MatchString(op.ID) || pki.ValidName(op.Host) != nil || !known[op.Kind] ||
		(op.Kind == KindRemoveHost) != (op.Daemon == "") || (op.Daemon != "" && !ledgerDaemonRe.MatchString(op.Daemon)) {
		return true, writeJSONKey(ctx, js, opKey, JournalOp{Version: journalVersion, Kind: op.Kind, Host: op.Host, State: JournalFailed, Error: "unknown or malformed operation"})
	}

	s, err := l.journalState(ctx, b, js, gid, op.ID)
	if err != nil || terminal(s) {
		return err == nil, err
	}

	switch op.Kind {
	case KindAddDaemon, KindRemoveDaemon, KindRemoveHost:
		var phase func() error

		switch op.Kind {
		case KindAddDaemon:
			phase = func() error { return l.addDaemon(ctx, b, js, gid, epoch, op) }
		case KindRemoveDaemon:
			phase = func() error { return l.removeDaemon(ctx, b, js, gid, epoch, op) }
		default:
			phase = func() error { return l.removeHost(ctx, b, js, gid, epoch, op) }
		}

		if err := l.unstick(ctx, js, opKey, opKey, op, phase()); err != nil {
			return false, err
		}

		s, err = l.journalState(ctx, b, js, gid, op.ID)

		return err == nil && terminal(s), err
	}

	if op.Kind == KindRedeploy {
		// first the host's revision, then the restart
		rev := op.ID + ".rev"

		rs, err := l.journalState(ctx, b, js, gid, rev)
		if err != nil {
			return false, err
		}

		if !terminal(rs) {
			if err := l.unstick(ctx, js, opKey, opKey, op, l.runRevision(ctx, b, js, gid, epoch, rev, op.Host, revisionMode{})); err != nil {
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

	if err := l.unstick(ctx, js, opKey, opKey, op, l.restartOp(ctx, b, js, gid, epoch, op)); err != nil {
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
func (l *LeaderLoop) unstick(ctx context.Context, js store.Backend, opKey, phaseKey string, op LedgerOp, err error) error {
	if err == nil {
		delete(l.failing, op.ID)

		return nil
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
	// phases (<id>.rev, <id>.strip, <id>.conf.<host>), is never given up this way
	keys, rerr := js.List(ctx, phaseKey)
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

	delete(l.failing, op.ID)

	return writeJSONKey(ctx, js, opKey, JournalOp{Version: journalVersion, Kind: op.Kind, Host: op.Host, State: JournalFailed, Error: fmt.Sprintf("failing for %s: %v", stuckAfter, err)})
}

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
		Revision: op.Revision, Operation: lop.ID, Restart: &wire.GrantRestart{Kind: "ContainerConfig", Name: st.DocName(d), Hash: hash},
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
			st.AddDaemon(state.Daemon{Type: state.TypeMgr, ID: id, Host: h.Name})

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
			st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: id, Host: op.Host, DeployID: hex.EncodeToString(deploy), Joining: true})

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
		for _, h := range st.Hosts {
			if h.Maintenance {
				continue
			}

			done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".conf."+h.Name, h.Name, revisionMode{})
			if err != nil || !done {
				return err
			}

			if !ok {
				return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("ceph.conf did not reach %s", h.Name))
			}
		}
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// removeDaemon removes a mgr that is not the active one: out of the state, its
// documents off its host, then, once its instance is gone, the module retires
// it (auth rm, its keys).
func (l *LeaderLoop) removeDaemon(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	typ, id, _ := strings.Cut(op.Daemon, ".")

	h, ok := st.Host(op.Host)
	if !ok || typ != state.TypeMgr || id != op.Host {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s cannot be removed from %s", op.Daemon, op.Host))
	}

	doc := st.DocName(state.Daemon{Type: state.TypeMgr, ID: id, Host: h.Name})

	rs, err := l.journalState(ctx, b, js, gid, op.ID+".rev")
	if err != nil {
		return err
	}

	// checked again before every step up to the removal of its document, also
	// on a resumed operation: a standby may have become the active one
	if !terminal(rs) {
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
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			st.RemoveDaemon(d)

			if h, ok := st.Host(op.Host); ok {
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

	if err := b.Retire(ctx, "retire", op.ID); err != nil {
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
