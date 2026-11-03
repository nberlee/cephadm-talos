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

	if err := b.AgentCertDone(ctx, op.ID); err != nil {
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
		return b.AgentCertDone(ctx, op.ID)
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

	if u.Paused {
		return nil
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

	return l.changeState(ctx, b, gid, func(st *state.State) error {
		au := st.AgentUpgrade
		if au == nil || au.Op != u.Op || au.Finished || st.Agent == nil {
			return nil
		}

		st.Agent.PreviousImage, st.Agent.Image = au.From, au.Image
		au.Finished, au.Step, au.StepAt = true, "", time.Time{}

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
				au.Step, au.StepAt = u.Step, u.StepAt
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

		var rep wire.NodeReport
		if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			return wait(err)
		}

		if doc := st.DocName(state.Daemon{Type: "agent", ID: host}); rep.Running[doc] != digestOf(u.Image) {
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

// pauseAgentUpgrade pauses an agent upgrade with its cause; its step ends, so
// it holds nothing while paused.
func (l *LeaderLoop) pauseAgentUpgrade(ctx context.Context, b *Bridge, gid int64, op, cause string) error {
	l.log("agent upgrade %s paused: %s", op, cause)

	if err := l.changeState(ctx, b, gid, func(st *state.State) error {
		if au := st.AgentUpgrade; au != nil && au.Op == op && !au.Finished {
			au.Paused, au.Error, au.Step, au.StepAt = true, cause, "", time.Time{}
		}

		return nil
	}); err != nil {
		return err
	}

	l.holding = ""

	return fmt.Errorf("%w: agent upgrade %s paused: %s", errRetry, op, cause)
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
		au.Attempt++

		return nil
	}); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// agentResumeAhead carries out the resumes of the agent upgrade in progress
// (op) among the executable operations after a ledger key, ahead of their
// turn, as controlsAhead does the Ceph upgrade's.
func (l *LeaderLoop) agentResumeAhead(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, after, op string) error {
	for {
		entries, more, err := b.Ledger(ctx, after)
		if err != nil {
			return err
		}

		for _, e := range entries {
			if e.Op.Kind == KindAgentResume && e.Op.Upgrade == op {
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
