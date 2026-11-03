package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// agentUpgradeWithin bounds one step of an agent upgrade: an agent that has
// not pulled the image, or does not answer on it, within it pauses the
// upgrade (plan 04, step 2).
const agentUpgradeWithin = 10 * time.Minute

// agentGrant has a host's agent update its own documents or pull an image
// (fill sets the grant's self-update or pull), as one grant under its own id,
// journaled before it is sent: done once the agent decided it, ok once it
// completed. A grant whose answer was lost is resolved on a later tick.
func (l *LeaderLoop) agentGrant(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, id, host, kind string, fill func(*wire.Grant) error) (done, ok bool, err error) {
	opKey := JournalPrefix(gid) + "op/" + id

	// decided by this incarnation or an earlier one
	s, err := l.journalState(ctx, b, js, gid, id)
	if err != nil {
		return false, false, err
	}

	if terminal(s) {
		return true, s == wire.OpCompleted, nil
	}

	cur, found, err := readJSONKey[JournalOp](ctx, js, opKey)
	if err != nil {
		return false, false, err
	}

	if found {
		if err := l.resolve(ctx, b, js, gid, epoch, opKey, cur, id); err != nil {
			return false, false, err
		}

		if cur, _, err = readJSONKey[JournalOp](ctx, js, opKey); err != nil || !terminal(cur.State) {
			return false, false, err
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

	op := JournalOp{Version: journalVersion, Kind: kind, Host: h.Name, Seq: seq, State: JournalGranting, Revision: max(rep.Revision+1, l.clock().UnixNano())}

	g := wire.Grant{
		Version: wire.Version, FSID: l.Self.FSID, Host: h.Name, Mgr: l.Self.Name, MgrAddr: me.Addr, GID: gid, Epoch: epoch,
		Revision: op.Revision, Operation: id, Approval: l.approval,
	}

	if err := fill(&g); err != nil {
		return false, false, err
	}

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

	// the leader's own agent may be replaced before it answers: this process
	// ends with it, and the next one resolves the grant
	var res wire.Operation
	if _, err := l.call(ctx, h, http.MethodPost, "/v1/grant", g, &res); err != nil {
		return false, false, fmt.Errorf("%s %s: %w", kind, h.Name, err)
	}

	if err := l.record(ctx, js, opKey, op, res); err != nil {
		return false, false, err
	}

	if !terminal(res.State) {
		return false, false, nil
	}

	return true, res.State == wire.OpCompleted, nil
}

// renewAgent renews an agent's certificates (plan 04, step 2): the module
// issues them once per renewal; the ones before are journaled, the new ones
// recorded in the state and granted to the agent as a self-update (its image
// as it is); once the agent serves the new server certificate, the module
// retires the others. A host in maintenance is renewed like any other: its
// agent keeps running. The leader's own agent restarts with its renewal and
// continues it from the journal.
func (l *LeaderLoop) renewAgent(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	rec, found, err := l.readRenewal(ctx, b, js, gid, op.ID)
	if err != nil {
		return err
	}

	if !rec.Retiring {
		st, _, err := l.clusterState(ctx, b)
		if err != nil {
			return err
		}

		h, ok := st.Host(op.Host)
		if !ok || h.Name != op.Host {
			return l.endAgentRenewal(ctx, b, js, gid, op, fmt.Errorf("no host %s in the cluster state", op.Host))
		}

		if !strings.HasPrefix(h.AgentKeys, op.ID+"/") {
			certs, err := b.AgentCert(ctx, op.ID)
			if err != nil {
				return err
			}

			// the certificates before, journaled once, before the state changes
			if !found {
				rec = mgrRenewal{ServerCert: h.AgentCert, ClientCert: h.AgentClientCert, Keys: h.AgentKeys}
				if err := writeJSONKey(ctx, js, rollKey(gid, op.ID+".renew"), rec); err != nil {
					return err
				}
			}

			keys := op.ID + "/" + certs.Attempt

			if err := l.changeState(ctx, b, gid, func(st *state.State) error {
				h, ok := st.Host(op.Host)
				if !ok {
					return fmt.Errorf("no host %s", op.Host)
				}

				h.AgentCert, h.AgentClientCert, h.AgentKeys = certs.ServerCert, certs.ClientCert, keys
				st.AddHost(h)

				return nil
			}); err != nil {
				return err
			}

			h.AgentCert, h.AgentClientCert, h.AgentKeys = certs.ServerCert, certs.ClientCert, keys
		}

		// the keys only for the grant, through the bridge, which releases them
		// for this renewal
		done, ok, err := l.agentGrant(ctx, b, js, gid, epoch, op.ID+".self", h.Name, "self_update", func(g *wire.Grant) error {
			su := &wire.SelfUpdate{Cert: h.AgentCert, ClientCert: h.AgentClientCert}

			var err error
			if su.Key, err = b.Secret(ctx, h.AgentKeySecret(state.SecretAgentServer)); err != nil {
				return err
			}

			if su.ClientKey, err = b.Secret(ctx, h.AgentKeySecret(state.SecretAgentClient)); err != nil {
				return err
			}

			g.SelfUpdate = su

			return nil
		})
		if err != nil || !done {
			return err
		}

		if !ok {
			return l.endAgentRenewal(ctx, b, js, gid, op, fmt.Errorf("the self-update of %s's agent did not apply", h.Name))
		}

		if !l.servesCert(h.Addr, Port, h.AgentCert) {
			return fmt.Errorf("%w: the agent on %s does not serve its new certificate yet", errRetry, h.Name)
		}

		// from here the new certificates stay: the module is asked until it answers
		rec.Retiring = true
		if err := writeJSONKey(ctx, js, rollKey(gid, op.ID+".renew"), rec); err != nil {
			return err
		}
	}

	if err := b.AgentCertDone(ctx, op.ID, []string{rec.ServerCert, rec.ClientCert}); err != nil {
		return fmt.Errorf("%w: %v", errWait, err)
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// endAgentRenewal ends an agent's renewal failed, its certificates before
// restored.
func (l *LeaderLoop) endAgentRenewal(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp, cause error) error {
	if err := l.renewAgentFailed(ctx, b, js, gid, op); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, JournalFailed, cause)
}

// renewAgentFailed is an agent renewal's cleanup when it fails: before it
// asked the module to retire the others, the journaled certificates come
// back in the state (their keys still exist), so the module renews anew;
// after, the module is asked once more.
func (l *LeaderLoop) renewAgentFailed(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	rec, found, err := l.readRenewal(ctx, b, js, gid, op.ID)
	if err != nil || !found {
		return err
	}

	if rec.Retiring {
		return b.AgentCertDone(ctx, op.ID, []string{rec.ServerCert, rec.ClientCert})
	}

	return l.changeState(ctx, b, gid, func(st *state.State) error {
		h, ok := st.Host(op.Host)
		if !ok || !strings.HasPrefix(h.AgentKeys, op.ID+"/") {
			return nil
		}

		h.AgentCert, h.AgentClientCert, h.AgentKeys = rec.ServerCert, rec.ClientCert, rec.Keys
		st.AddHost(h)

		return nil
	})
}

// digestOf is the digest of an image reference by digest ("sha256:<hex>"),
// as a node report's running images have it.
func digestOf(ref string) string {
	_, d, _ := strings.Cut(ref, "@")

	return d
}

// upgradeAgent starts an agent upgrade (plan 04, step 2), as upgradeStart
// starts the Ceph upgrade: the image checked again (by digest, approved, from
// the agent image's repository), no other agent upgrade or Ceph upgrade in
// progress, and the upgrade recorded in the state (AgentUpgrade), after which
// the operation ends. Its steps follow between ledger operations
// (agentUpgradeStep).
func (l *LeaderLoop) upgradeAgent(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	if st.Agent == nil {
		return finish(ctx, js, gid, op, JournalFailed, errors.New("the cluster has no agents"))
	}

	if u := st.AgentUpgrade; u == nil || u.Op != op.ID {
		switch {
		case u != nil && !u.Finished:
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("agent upgrade %s is in progress", u.Op))
		case st.Upgrade != nil:
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("upgrade %s is in progress", st.Upgrade.Op))
		case op.Image == st.Agent.Image:
			return finish(ctx, js, gid, op, wire.OpCompleted, nil)
		}

		// the agents check it again, each against its own image
		if err := selfImage(op.Image, st.Agent.Image, l.appr); err != nil {
			return finish(ctx, js, gid, op, JournalFailed, err)
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			if st.AgentUpgrade == nil || st.AgentUpgrade.Op != op.ID {
				st.AgentUpgrade = &state.AgentUpgrade{Op: op.ID, From: st.Agent.Image, Image: op.Image, Last: l.Self.Name}
			}

			return nil
		}); err != nil {
			return err
		}
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// agentUpgradeStep carries out the agent upgrade's next step (plan 04, step
// 2), between ledger operations, one at a time: every agent pulls the target
// first (a pull grant), then each agent but the leader's gets a self-update
// with the target, one host at a time, done once its node report shows its
// agent's container on the target's digest; the leader's own host comes last:
// with a standby mgr the active one fails over and the successor upgrades it
// like any other, without one the leader's agent updates itself and
// continues after its restart. The step in progress and its start are in the
// record, so a successor or the restarted agent continues it; while it is
// unfinished no revision request starts. A step not done within
// agentUpgradeWithin pauses the upgrade and ends (a grant left without an
// outcome is resolved by the tick once its agent answers again); a paused
// upgrade holds nothing until upgrade_agent_resume. Without a step left, the
// target becomes the agents' image and the one before the known good.
func (l *LeaderLoop) agentUpgradeStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err // the hold stays
	}

	u := st.AgentUpgrade
	if u == nil || u.Finished || st.Agent == nil {
		return nil
	}

	if u.Step != "" {
		l.holding = holdAll
	}

	// a stop takes effect once no step is in progress, also on a paused upgrade
	if u.Stopping && u.Step == "" {
		return l.rollBack(ctx, b, gid, st, *u)
	}

	if u.Paused {
		return nil
	}

	// a step in progress is continued as recorded, whoever leads now (a
	// successor, the leader's restarted agent): the order chooses the next
	// step only
	if kind, host, ok := strings.Cut(u.Step, "/"); ok {
		switch {
		case kind == "fail" && host != l.Self.Name:
			// failed over: this successor upgrades the old leader's host
			return l.agentHostStep(ctx, b, js, gid, epoch, st, *u, "self", host)
		case kind == "fail":
			_, agid, _, err := b.MgrMap(ctx)
			if err != nil {
				return err
			}

			return l.agentHostStep(ctx, b, js, gid, epoch, st, *u, "fail", host, agid)
		default:
			return l.agentHostStep(ctx, b, js, gid, epoch, st, *u, kind, host)
		}
	}

	// beside the Ceph upgrade's step in progress no step starts
	if st.Upgrade != nil && st.Upgrade.Step != "" {
		return nil
	}

	// after a resume, the hosts done are checked again: a restore may have
	// put one back on an earlier image
	if u.Verify {
		return l.verifyDone(ctx, b, gid, st, *u)
	}

	var hosts []string
	for _, h := range st.Hosts {
		hosts = append(hosts, h.Name)
	}

	slices.Sort(hosts)

	// every agent has the image before any is updated
	for _, name := range hosts {
		if !slices.Contains(u.Pulled, name) {
			return l.agentHostStep(ctx, b, js, gid, epoch, st, *u, "pull", name)
		}
	}

	// the others first, then the host left for last, then the leader's own
	var order []string

	for _, name := range hosts {
		if name != u.Last && name != l.Self.Name {
			order = append(order, name)
		}
	}

	for _, name := range []string{u.Last, l.Self.Name} {
		if slices.Contains(hosts, name) && !slices.Contains(order, name) {
			order = append(order, name)
		}
	}

	for _, name := range order {
		if slices.Contains(u.Done, name) {
			continue
		}

		if name == l.Self.Name {
			// with a standby, a successor upgrades this host like any other
			active, agid, standbys, err := b.MgrMap(ctx)
			if err != nil {
				return err
			}

			if active == l.Self.Name && len(standbys) > 0 {
				return l.agentHostStep(ctx, b, js, gid, epoch, st, *u, "fail", name, agid)
			}
		}

		return l.agentHostStep(ctx, b, js, gid, epoch, st, *u, "self", name)
	}

	// the target is the agents' image only once every host runs it
	if err := l.verifyDone(ctx, b, gid, st, *u); err != nil {
		return err
	}

	return l.changeState(ctx, b, gid, func(st *state.State) error {
		au := st.AgentUpgrade
		if au == nil || au.Op != u.Op || au.Finished || st.Agent == nil {
			return nil
		}

		// a stopped upgrade's rollback leaves the agents' images as they were
		if au.Stopped == "" {
			st.Agent.PreviousImage, st.Agent.Image = au.From, au.Image
		}

		au.Finished, au.Step, au.StepAt, au.Starting = true, "", time.Time{}, false

		return nil
	})
}

// agentHostStep advances one step of an agent upgrade on a host: "pull" (a
// pull grant), "self" (a self-update with the target, then the agent
// answering with its container on the target's digest) or "fail" (the active
// mgr on the leader's host failed over, gid its own). The step is recorded
// when it begins, which holds revision requests until it ends; past its limit
// the upgrade pauses.
func (l *LeaderLoop) agentHostStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, st *state.State, u state.AgentUpgrade, kind, host string, mgrGID ...int64) error {
	step := kind + "/" + host
	l.holding = holdAll

	if u.Step != step {
		u.Step, u.StepAt = step, l.clock()

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			if au := st.AgentUpgrade; au != nil && au.Op == u.Op && !au.Paused {
				au.Step, au.StepAt, au.Starting = u.Step, u.StepAt, false
			}

			return nil
		}); err != nil {
			return err
		}
	}

	overdue := l.clock().Sub(u.StepAt) > agentUpgradeWithin
	wait := func(cause error) error {
		if overdue {
			return l.pauseAgentUpgrade(ctx, b, gid, u.Op, fmt.Sprintf("%s did not end within %s: %v", step, agentUpgradeWithin, cause))
		}

		return fmt.Errorf("%w: %s: %w", errRetry, step, cause)
	}

	if kind == "fail" {
		// recorded first: the module that answers is the one failed over
		if err := writeJSONKey(ctx, js, JournalPrefix(gid)+"op/"+u.Op+".fail", JournalOp{Version: journalVersion, Kind: "mgr_fail", Host: host, State: wire.OpStarted, MgrGID: mgrGID[0]}); err != nil {
			return err
		}

		if err := b.MgrFail(ctx, u.Op, mgrGID[0], host, host); err != nil {
			return wait(fmt.Errorf("failing the active mgr on %s over: %w", host, err))
		}

		return wait(fmt.Errorf("the active mgr on %s is failing over", host))
	}

	id := fmt.Sprintf("%s.%s.%s.%d", u.Op, kind, host, u.Attempt)

	done, ok, err := l.agentGrant(ctx, b, js, gid, epoch, id, host, map[string]string{"pull": "pull", "self": "self_update"}[kind], func(g *wire.Grant) error {
		if kind == "pull" {
			g.Pull = u.Image
		} else {
			g.SelfUpdate = &wire.SelfUpdate{Image: u.Image}
		}

		return nil
	})

	switch {
	case err != nil:
		return wait(err)
	case !done:
		return wait(errors.New("in progress"))
	case !ok:
		rec, _, _ := l.journalRecord(ctx, b, js, gid, id)

		return l.pauseAgentUpgrade(ctx, b, gid, u.Op, fmt.Sprintf("%s: %s %s", step, rec.State, rec.Error))
	}

	if kind == "self" {
		h, _ := st.Host(host)

		rep, err := l.nodeReport(ctx, h)
		if err != nil {
			return wait(err)
		}

		if !runsAgent(st, rep, host, u.Image) {
			return wait(fmt.Errorf("the agent of %s does not run %s yet", host, u.Image))
		}
	}

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		au := st.AgentUpgrade
		if au == nil || au.Op != u.Op {
			return nil
		}

		if kind == "pull" && !slices.Contains(au.Pulled, host) {
			au.Pulled = append(au.Pulled, host)
		}

		if kind == "self" && !slices.Contains(au.Done, host) {
			au.Done = append(au.Done, host)
		}

		au.Step, au.StepAt = "", time.Time{}

		return nil
	}); err != nil {
		return err
	}

	return fmt.Errorf("%w: %s done", errRetry, step)
}

// runsAgent reports whether a node report shows a host's agent container
// running an image's digest.
func runsAgent(st *state.State, rep wire.NodeReport, host, image string) bool {
	return rep.Running[st.DocName(state.Daemon{Type: "agent", ID: host})] == digestOf(image)
}

// nodeReport is a host's node report: the leader's own agent's from its node
// directly when it has it (OwnReport), any other through the agent.
func (l *LeaderLoop) nodeReport(ctx context.Context, h state.Host) (wire.NodeReport, error) {
	if h.Name == l.Self.Name && l.OwnReport != nil {
		return l.OwnReport(ctx)
	}

	var rep wire.NodeReport
	_, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep)

	return rep, err
}

// verifyDone checks that every host an agent upgrade did still runs the
// target (a recovery or `agent restore` may have restored an earlier image)
// and takes those that do not out of Done, so they are upgraded again; it
// clears the record's Verify. A host whose report cannot be read is retried.
func (l *LeaderLoop) verifyDone(ctx context.Context, b *Bridge, gid int64, st *state.State, u state.AgentUpgrade) error {
	var drop []string

	for _, name := range u.Done {
		h, ok := st.Host(name)
		if !ok {
			continue // left the cluster: nothing to upgrade
		}

		rep, err := l.nodeReport(ctx, h)
		if err != nil {
			return fmt.Errorf("%w: checking the agent of %s: %w", errRetry, name, err)
		}

		if !runsAgent(st, rep, name, u.Image) {
			drop = append(drop, name)
		}
	}

	if len(drop) == 0 && !u.Verify {
		return nil
	}

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		if au := st.AgentUpgrade; au != nil && au.Op == u.Op && !au.Finished {
			au.Done = slices.DeleteFunc(au.Done, func(h string) bool { return slices.Contains(drop, h) })
			au.Verify = false

			// a new attempt: their grants of before completed
			if len(drop) > 0 {
				au.Attempt++
			}
		}

		return nil
	}); err != nil {
		return err
	}

	if len(drop) > 0 {
		l.log("agent upgrade %s: %v no longer run the target, upgraded again", u.Op, drop)
	}

	return fmt.Errorf("%w: the hosts done are checked", errRetry)
}

// pauseAgentUpgrade pauses an agent upgrade with its cause; its step ends, so
// it holds nothing while paused.
func (l *LeaderLoop) pauseAgentUpgrade(ctx context.Context, b *Bridge, gid int64, op, cause string) error {
	l.log("agent upgrade %s paused: %s", op, cause)

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		if au := st.AgentUpgrade; au != nil && au.Op == op && !au.Finished {
			au.Paused, au.Error, au.Step, au.StepAt, au.Starting = true, cause, "", time.Time{}, false
		}

		return nil
	}); err != nil {
		return err
	}

	l.holding = ""

	return fmt.Errorf("%w: agent upgrade %s paused: %s", errRetry, op, cause)
}

// rollBack turns a stopped agent upgrade into its rollback (plan 04, step 2,
// item 7): the target it gave up recorded as Stopped, the image it upgraded
// from the target (From stays, the known good), a new attempt, not paused,
// no host pulled (nothing guarantees a node kept the old image) and the
// hosts done those whose agent runs the old image's digest. The same steps
// follow.
func (l *LeaderLoop) rollBack(ctx context.Context, b *Bridge, gid int64, st *state.State, u state.AgentUpgrade) error {
	var done []string

	for _, h := range st.Hosts {
		// a host whose report cannot be read is updated again
		if rep, err := l.nodeReport(ctx, h); err == nil && runsAgent(st, rep, h.Name, u.From) {
			done = append(done, h.Name)
		}
	}

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		au := st.AgentUpgrade
		if au == nil || au.Op != u.Op || au.Finished || !au.Stopping || au.Step != "" {
			return nil
		}

		au.Stopped, au.Image, au.Stopping = au.Image, au.From, false
		au.Attempt, au.Paused, au.Error, au.Verify = au.Attempt+1, false, "", false
		// its first step runs before queued operations (rollbackPending)
		au.Pulled, au.Done, au.StepAt, au.Starting = nil, done, l.clock(), true

		return nil
	}); err != nil {
		return err
	}

	l.log("agent upgrade %s stopped: rolling back to %s", u.Op, u.From)

	return fmt.Errorf("%w: agent upgrade %s rolls back to %s", errRetry, u.Op, u.From)
}

// agentUpgradeStop stops an agent upgrade (upgrade_agent_stop), changing its
// record alone: marked stopping, it becomes its rollback once no step is in
// progress (rollBack). A rollback is not stopped again.
func (l *LeaderLoop) agentUpgradeStop(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		au := st.AgentUpgrade
		if au == nil || au.Op != op.Upgrade || au.Finished || au.Stopping || au.Stopped != "" {
			return nil // ended already, or stopping
		}

		au.Stopping = true

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// agentUpgradeResume resumes a paused agent upgrade (upgrade_agent_resume),
// changing its record alone: the paused step starts again, with grants of a
// new attempt.
func (l *LeaderLoop) agentUpgradeResume(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		au := st.AgentUpgrade
		if au == nil || au.Op != op.Upgrade || au.Finished || !au.Paused {
			return nil // ended already, or not paused
		}

		au.Paused, au.Error, au.Step, au.StepAt = false, "", "", time.Time{}
		au.Attempt, au.Verify = au.Attempt+1, true

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// agentResumeAhead carries out the controls (resumes, stops) of the agent
// upgrade in progress (op) among the executable operations after a ledger
// key, ahead of their turn, as controlsAhead does the Ceph upgrade's.
func (l *LeaderLoop) agentResumeAhead(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, after, op string) error {
	for {
		entries, more, err := b.Ledger(ctx, after)
		if err != nil {
			return err
		}

		for _, e := range entries {
			if isAgentControl(e.Op.Kind) && e.Op.Upgrade == op {
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

// isAgentControl reports whether a kind is one of an agent upgrade's controls.
func isAgentControl(kind string) bool { return kind == KindAgentResume || kind == KindAgentStop }

// rollbackPending reports whether a stopped agent upgrade's rollback has not
// started its first step yet, from the published record alone (a successor
// sees it as the leader that made the transition did): stopping without a
// step in progress, or the rollback the stop just made (Starting, cleared
// once its first step is recorded or it pauses), within agentUpgradeWithin of
// the transition. It runs before queued operations; a resumed rollback gets
// no priority beyond its resume, as any upgrade between steps.
func rollbackPending(u state.AgentUpgrade, now time.Time) bool {
	if u.Finished || u.Step != "" {
		return false
	}

	return u.Stopping || u.Starting && !u.Paused && now.Sub(u.StepAt) <= agentUpgradeWithin
}
