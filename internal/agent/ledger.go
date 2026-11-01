package agent

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	KindRestart  = "restart"
	KindRedeploy = "redeploy"
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
// operation, keeping every other record as it is.
func (l *LeaderLoop) checkpoint(ctx context.Context, b *Bridge, gid int64, key string) error {
	own := strconv.FormatInt(gid, 10)

	recs, _, err := l.readRecords(ctx, b, own)
	if err != nil {
		return err
	}

	st := state.New(l.Self.FSID)
	if err := st.ApplyRecords(recs); err != nil {
		return err
	}

	st.LedgerApplied = key

	next, err := st.Records()
	if err != nil {
		return err
	}

	recs["cluster"] = next["cluster"]

	bs, err := b.Store(ctx, store.Prefix+"inc/"+own+"/")
	if err != nil {
		return err
	}

	_, err = (store.Store{B: bs, Incarnation: own}).Publish(ctx, recs)

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

	if !ledgerIDRe.MatchString(op.ID) || !ledgerDaemonRe.MatchString(op.Daemon) || (op.Kind != KindRestart && op.Kind != KindRedeploy) {
		return true, writeJSONKey(ctx, js, opKey, JournalOp{Version: journalVersion, Kind: op.Kind, Host: op.Host, State: JournalFailed, Error: "unknown or malformed operation"})
	}

	s, err := l.journalState(ctx, b, js, gid, op.ID)
	if err != nil || terminal(s) {
		return err == nil, err
	}

	if op.Kind == KindRedeploy {
		// first the host's revision, then the restart
		rev := op.ID + ".rev"

		rs, err := l.journalState(ctx, b, js, gid, rev)
		if err != nil {
			return false, err
		}

		if !terminal(rs) {
			if err := l.unstick(ctx, js, opKey, JournalPrefix(gid)+"op/"+rev, op, l.runRevision(ctx, b, js, gid, epoch, rev, op.Host)); err != nil {
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
// the next one runs, unless the grant of its current phase (phaseKey) has an
// unknown outcome; the time it started failing is kept in memory only.
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

	cur, found, rerr := readJSONKey[JournalOp](ctx, js, phaseKey)
	if rerr != nil {
		return rerr
	}

	// a grant whose outcome is not known is never given up this way
	if found && (cur.State == JournalGranting || cur.State == wire.OpUncertain) {
		return err
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
