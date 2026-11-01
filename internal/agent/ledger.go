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
	KindRemoveHost   = "remove_host"
	KindCreateOSD    = "create_osd"
	KindRemoveOSD    = "remove_osd"
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

	known := map[string]bool{KindRestart: true, KindRedeploy: true, KindAddDaemon: true, KindRemoveDaemon: true, KindRemoveHost: true, KindCreateOSD: true, KindRemoveOSD: true}
	noDaemon := op.Kind == KindRemoveHost || op.Kind == KindCreateOSD
	if !ledgerIDRe.MatchString(op.ID) || pki.ValidName(op.Host) != nil || !known[op.Kind] ||
		noDaemon != (op.Daemon == "") || (op.Daemon != "" && !ledgerDaemonRe.MatchString(op.Daemon)) ||
		(op.Kind == KindCreateOSD) != strings.HasPrefix(op.Device, "/dev/") {
		return true, writeJSONKey(ctx, js, opKey, JournalOp{Version: journalVersion, Kind: op.Kind, Host: op.Host, State: JournalFailed, Error: "unknown or malformed operation"})
	}

	s, err := l.journalState(ctx, b, js, gid, op.ID)
	if err != nil || terminal(s) {
		return err == nil, err
	}

	switch op.Kind {
	case KindAddDaemon, KindRemoveDaemon, KindRemoveHost, KindCreateOSD, KindRemoveOSD:
		var phase func() error

		switch op.Kind {
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

		if err := l.unstick(ctx, js, opKey, opKey, op, onFail, phase()); err != nil {
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

	// what failing leaves behind is cleaned up first (a creation is closed)
	if onFail != nil {
		if ferr := onFail(); ferr != nil {
			return ferr
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
