package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// agentSetup is a leader setup whose h1 node holds its agent's documents of
// the module's CA, the agents on agentImage, the agent images approved.
func agentSetup(t *testing.T) (*leaderSetup, state.Host) {
	t.Helper()

	s := newLeaderSetup(t)
	ctx := context.Background()
	s.withCA(t)

	sc := withAgentDocs(t, s.agent.Node, s.agent.fake, *s.module.ca)

	appr, err := json.Marshal(agentApproval(t, 2))
	must(t, err)

	s.module.mu.Lock()
	s.module.approval = string(appr)
	s.module.mu.Unlock()

	s.st.Agent.Image = agentImage
	h, _ := s.st.Host("h1")
	h.AgentCert, h.AgentClientCert = sc, "client"
	s.st.AddHost(h)
	publish(t, s.leader, s.module, s.st)

	must(t, s.leader.Tick(ctx, 42, 5)) // the takeover closes the earlier sessions

	return s, h
}

// acceptOp is accept with the operation changed (an image, the upgrade a
// resume controls).
func (s *leaderSetup) acceptOp(kind string, seq int64, change func(*LedgerOp)) LedgerEntry {
	s.accept(kind, "", "", seq)

	s.module.mu.Lock()
	defer s.module.mu.Unlock()

	change(&s.module.ledger[len(s.module.ledger)-1].Op)

	return s.module.ledger[len(s.module.ledger)-1]
}

func TestARenewalRenewsAnAgentsCertificates(t *testing.T) {
	s, before := agentSetup(t)
	ctx := context.Background()

	served := before.AgentCert
	s.leader.serves = func(_ string, port int, chain string) bool { return port == Port && chain == served }

	renew := s.accept(KindRenewAgent, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// new certificates in the state, the old ones journaled, the self-update applied
	h := s.host(t, "h1")
	if !strings.HasPrefix(h.AgentKeys, renew.Op.ID+"/") || h.AgentCert == before.AgentCert || h.AgentClientCert == before.AgentClientCert {
		t.Fatalf("state: %+v", h)
	}

	var rec mgrRenewal

	s.module.mu.Lock()
	err := json.Unmarshal([]byte(s.module.kv[rollKey(42, renew.Op.ID+".renew")]), &rec)
	s.module.mu.Unlock()

	if err != nil || rec.ServerCert != before.AgentCert || rec.ClientCert != before.AgentClientCert || rec.Keys != "" || rec.Retiring {
		t.Fatalf("journaled %+v %v", rec, err)
	}

	if op := s.op(t, renew.Op.ID+".self"); op.State != wire.OpCompleted || op.Kind != "self_update" {
		t.Fatalf("self-update %+v", op)
	}

	d := ownOnNode(t, s.agent.Node)
	if cert, _ := d.pemOf(daemons.EnvCert); cert != h.AgentCert || d.image != agentImage {
		t.Fatalf("the agent's document: %s", d.image)
	}

	// the agent does not serve the new certificate yet: nothing retired
	must(t, s.leader.Tick(ctx, 42, 5))

	if s.ended(renew.Op.ID) || slices.Contains(s.calls(), "agent cert done "+renew.Op.ID) {
		t.Fatal("retired before the agent served the new certificate")
	}

	served = h.AgentCert
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("renewal: %+v", op)
	}

	if got := s.calls(); !slices.Equal(got, []string{"agent cert " + renew.Op.ID, "agent cert done " + renew.Op.ID}) {
		t.Fatalf("calls %v", got)
	}
}

func TestAFailedAgentRenewalRestoresTheCertificatesBefore(t *testing.T) {
	s, before := agentSetup(t)
	ctx := context.Background()

	// the agent never serves the new certificate
	s.leader.serves = func(string, int, string) bool { return false }

	renew := s.accept(KindRenewAgent, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if h := s.host(t, "h1"); !strings.HasPrefix(h.AgentKeys, renew.Op.ID+"/") {
		t.Fatalf("state: %+v", h)
	}

	s.leader.failing[renew.Op.ID] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != JournalFailed {
		t.Fatalf("renewal: %+v", op)
	}

	if h := s.host(t, "h1"); h.AgentKeys != "" || h.AgentCert != before.AgentCert || h.AgentClientCert != before.AgentClientCert {
		t.Fatalf("not restored: %+v", h)
	}

	if slices.Contains(s.calls(), "agent cert done "+renew.Op.ID) {
		t.Fatal("the other certificates retired by a failed renewal")
	}
}

func TestAgentOperationsOfTheWrongShapeFail(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	bad := []LedgerEntry{
		s.accept(KindRenewAgent, "mgr.h1", "h1", 1),                                                                     // a daemon
		s.accept(KindAgentUpgrade, "", "", 2),                                                                           // no image
		s.acceptOp(KindAgentUpgrade, 3, func(op *LedgerOp) { op.Image, op.Host = agentImage2, "h1" }),                   // a host
		s.acceptOp(KindAgentResume, 4, func(op *LedgerOp) { op.Image = agentImage2 }),                                   // no upgrade
		s.acceptOp(KindAgentUpgrade, 5, func(op *LedgerOp) { op.Image = foreignImage }),                                 // another repository
		s.acceptOp(KindAgentUpgrade, 6, func(op *LedgerOp) { op.Image = strings.Replace(agentImage2, "22", "44", -1) }), // not approved
	}

	for range bad {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	for _, e := range bad {
		if op := s.op(t, e.Op.ID); op.State != JournalFailed {
			t.Errorf("%s %+v: %+v", e.Op.Kind, e.Op, op)
		}
	}

	if st, _, _ := s.leader.clusterState(ctx, s.leader.bridge()); st.AgentUpgrade != nil {
		t.Fatalf("recorded %+v", st.AgentUpgrade)
	}
}

// ownRunning is the leader's own node report (h0) with its agent on an image.
func ownRunning(s *leaderSetup, image string) func(context.Context) (wire.NodeReport, error) {
	return func(context.Context) (wire.NodeReport, error) {
		return wire.NodeReport{Running: map[string]string{s.st.DocName(state.Daemon{Type: "agent", ID: "h0"}): digestOf(image)}}, nil
	}
}

// agentRunning makes h1's agent container run an image's digest.
func agentRunning(t *testing.T, s *leaderSetup, image string) {
	t.Helper()

	ctx := context.Background()
	name := s.st.DocName(state.Daemon{Type: "agent", ID: "h1"})

	cs := containers.NewContainerStatus(containers.NamespaceName, name)
	cs.TypedSpec().State, cs.TypedSpec().Image = containers.ContainerStateRunning, digestOf(image)

	_ = s.agent.fake.St.Destroy(ctx, cs.Metadata()) // a status of before goes
	must(t, s.agent.fake.St.Create(ctx, cs))
}

func (s *leaderSetup) agentUpgrade(t *testing.T) state.AgentUpgrade {
	t.Helper()

	st, _, err := s.leader.clusterState(context.Background(), s.leader.bridge())
	must(t, err)

	if st.AgentUpgrade == nil {
		t.Fatal("no agent upgrade recorded")
	}

	return *st.AgentUpgrade
}

func (s *leaderSetup) changeUpgrade(t *testing.T, change func(*state.AgentUpgrade)) {
	t.Helper()

	must(t, s.leader.changeState(context.Background(), s.leader.bridge(), 42, func(st *state.State) error {
		change(st.AgentUpgrade)

		return nil
	}))
}

// startUpgrade accepts an agent upgrade to agentImage2 and runs it until h1
// is being updated; h0, the leader's own host, which this harness cannot
// grant to, counts as having pulled.
func startUpgrade(t *testing.T, s *leaderSetup) LedgerEntry {
	t.Helper()

	ctx := context.Background()

	up := s.acceptOp(KindAgentUpgrade, 1, func(op *LedgerOp) { op.Image = agentImage2 })
	must(t, s.leader.Tick(ctx, 42, 5))

	// the operation ends once the upgrade is recorded; its steps follow
	// between ledger operations
	if u := s.agentUpgrade(t); u.Op != up.Op.ID || u.From != agentImage || u.Image != agentImage2 || u.Last != "h0" {
		t.Fatalf("recorded %+v", u)
	}

	if op := s.op(t, up.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("upgrade %+v", op)
	}

	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.Pulled, u.Step = []string{"h0"}, "" })

	// h1 pulls first, then updates itself
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); !slices.Equal(u.Pulled, []string{"h0", "h1"}) || len(u.Done) != 0 {
		t.Fatalf("after the pull %+v", u)
	}

	if op := s.op(t, up.Op.ID+".pull.h1.0"); op.State != wire.OpCompleted {
		t.Fatalf("pull %+v", op)
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, up.Op.ID+".self.h1.0"); op.State != wire.OpCompleted {
		t.Fatalf("self-update %+v", op)
	}

	if d := ownOnNode(t, s.agent.Node); d.image != agentImage2 {
		t.Fatalf("the agent's document: %s", d.image)
	}

	return up
}

func TestAnAgentUpgradeGoesHostByHostAndTheLeadersLast(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	up := startUpgrade(t, s)

	// not done before the agent answers on the new image
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); len(u.Done) != 0 || u.Step != "self/h1" {
		t.Fatalf("before it answers on the image %+v", u)
	}

	agentRunning(t, s, agentImage2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); !slices.Equal(u.Done, []string{"h1"}) {
		t.Fatalf("after h1 %+v", u)
	}

	// the leader's own host last: with a standby, the active mgr fails over
	s.module.mu.Lock()
	s.module.standbys = []string{"h1"}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if !slices.Contains(s.calls(), "mgr fail "+up.Op.ID+" 42") {
		t.Fatalf("calls %v", s.calls())
	}

	if op := s.op(t, up.Op.ID+".fail"); op.MgrGID != 42 || op.Host != "h0" {
		t.Fatalf("failover %+v", op)
	}

	if u := s.agentUpgrade(t); u.Step != "fail/h0" || u.Finished {
		t.Fatalf("while failing over %+v", u)
	}

	// the successor upgrades the old leader's host like any other; the
	// target is the agents' image once every host runs it
	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.Done, u.Step = append(u.Done, "h0"), "" })
	s.leader.OwnReport = ownRunning(s, agentImage2)

	// a recovery restored h1's agent on the earlier image meanwhile: it is
	// upgraded again, with a new attempt, before the upgrade finishes
	agentRunning(t, s, agentImage)
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); u.Finished || !slices.Equal(u.Done, []string{"h0"}) || u.Attempt != 1 {
		t.Fatalf("after the check %+v", u)
	}

	must(t, s.leader.Tick(ctx, 42, 5)) // h1's self-update again, waiting for it on the target

	if op := s.op(t, up.Op.ID+".self.h1.1"); op.State != wire.OpCompleted {
		t.Fatalf("h1 again %+v", op)
	}

	agentRunning(t, s, agentImage2)
	must(t, s.leader.Tick(ctx, 42, 5)) // h1 done
	must(t, s.leader.Tick(ctx, 42, 5)) // every host runs the target

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if st.Agent.Image != agentImage2 || st.Agent.PreviousImage != agentImage || !st.AgentUpgrade.Finished {
		t.Fatalf("after the upgrade %+v %+v", st.Agent, st.AgentUpgrade)
	}
}

func TestAnAgentThatDoesNotComeBackPausesTheUpgrade(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	up := startUpgrade(t, s)

	// still not on the image after ten minutes
	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.StepAt = time.Now().Add(-agentUpgradeWithin - time.Minute) })
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); !u.Paused || !strings.Contains(u.Error, "self/h1") {
		t.Fatalf("not paused %+v", u)
	}

	// paused, it holds neither the ledger nor revision requests: a renewal runs
	if u := s.agentUpgrade(t); u.Step != "" {
		t.Fatalf("a paused upgrade keeps its step %+v", u)
	}

	s.leader.serves = func(string, int, string) bool { return true }

	renew := s.accept(KindRenewAgent, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("a renewal beside a paused upgrade: %+v", op)
	}

	if u := s.agentUpgrade(t); !u.Paused || len(u.Done) != 0 {
		t.Fatalf("still paused %+v", u)
	}

	// the operator restored the agent and resumes: the step again, with a
	// new attempt
	agentRunning(t, s, agentImage2)

	res := s.acceptOp(KindAgentResume, 3, func(op *LedgerOp) { op.Upgrade = up.Op.ID })
	must(t, s.leader.Tick(ctx, 42, 5)) // the resume, then the hosts done checked
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, res.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("resume %+v", op)
	}

	if u := s.agentUpgrade(t); u.Paused || u.Attempt != 1 || !slices.Equal(u.Done, []string{"h1"}) {
		t.Fatalf("after the resume %+v", u)
	}

	if op := s.op(t, up.Op.ID+".self.h1.1"); op.State != wire.OpCompleted {
		t.Fatalf("the step again %+v", op)
	}
}

func TestAnAgentUpgradeStepHoldsTheOperationsBehindIt(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	startUpgrade(t, s) // h1's self-update waits for its agent on the image
	s.leader.serves = func(string, int, string) bool { return true }

	renew := s.accept(KindRenewAgent, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if s.ended(renew.Op.ID) || s.leader.holding != holdAll {
		t.Fatalf("an operation beside a step in progress, holding %q", s.leader.holding)
	}

	// the step ends, then the operation runs
	agentRunning(t, s, agentImage2)
	must(t, s.leader.Tick(ctx, 42, 5))
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("renewal after the step: %+v", op)
	}

	if u := s.agentUpgrade(t); !slices.Equal(u.Done, []string{"h1"}) {
		t.Fatalf("after h1 %+v", u)
	}
}

// successor makes incarnation gid (epoch) on host the module's and the h1
// agent's active one: a leader loop on host, the module's bridge serving it.
func (s *leaderSetup) successor(t *testing.T, host string, gid, epoch int64) *LeaderLoop {
	t.Helper()

	l := s.leader

	if host != "h0" {
		cc, ck := s.ca.pair(pki.RoleAgent, host, x509.ExtKeyUsageClientAuth, testFSID)
		clientTLS, err := ClientTLSConfig([]byte(s.ca.cert), []byte(cc), []byte(ck))
		must(t, err)

		ch, err := NewChannel(pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: host})
		must(t, err)

		// the module on the successor's host, over the same store
		_, port := s.module.serve(t, s.ca, host)
		bridgePort, dialPort = func() string { return port }, func() string { return port }

		l = &LeaderLoop{
			Self: pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: host}, Channel: ch, ClientTLS: clientTLS,
			Repos: s.leader.Repos, CACert: s.leader.CACert, bridgeAddr: s.leader.bridgeAddr, agentURL: s.leader.agentURL, logf: t.Logf,
			ApprovalKey: testApprovalPub,
		}
	}

	l.Channel.mu.Lock()
	l.Channel.leader = &Leader{Mgr: host, GID: gid, Epoch: epoch, At: time.Now()}
	l.Channel.mu.Unlock()

	s.module.mu.Lock()
	s.module.own = strconv.FormatInt(gid, 10)
	s.module.mu.Unlock()

	s.agent.gid, s.agent.epoch = gid, epoch

	return l
}

func TestASuccessorContinuesTheRecordedStep(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	up := s.acceptOp(KindAgentUpgrade, 1, func(op *LedgerOp) { op.Image = agentImage2 })
	must(t, s.leader.Tick(ctx, 42, 5))

	// the predecessor began h1's pull, which the host order would not choose
	// now (h0 comes first)
	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.Step, u.StepAt = "pull/h1", time.Now() })

	l := s.successor(t, "h0", 30, 9)
	must(t, l.Tick(ctx, 30, 9))

	st, _, err := l.clusterState(ctx, l.bridge())
	must(t, err)

	if u := st.AgentUpgrade; !slices.Equal(u.Pulled, []string{"h1"}) || u.Step != "" {
		t.Fatalf("the successor's step %+v", u)
	}

	s.module.mu.Lock()
	_, pulled := s.module.kv[JournalPrefix(30)+"op/"+up.Op.ID+".pull.h1.0"]
	_, other := s.module.kv[JournalPrefix(30)+"op/"+up.Op.ID+".pull.h0.0"]
	s.module.mu.Unlock()

	if !pulled || other {
		t.Fatalf("the successor's grants: h1 %v, h0 %v", pulled, other)
	}
}

func TestTheSuccessorOfAFailoverUpgradesTheOldLeadersHost(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	s.acceptOp(KindAgentUpgrade, 1, func(op *LedgerOp) { op.Image = agentImage2 })
	must(t, s.leader.Tick(ctx, 42, 5))

	// the old leader on h0 failed its mgr over, every other host done
	s.changeUpgrade(t, func(u *state.AgentUpgrade) {
		u.Pulled, u.Done, u.Step, u.StepAt = []string{"h0", "h1"}, []string{"h1"}, "fail/h0", time.Now()
	})

	s.module.mu.Lock()
	s.module.active, s.module.standbys, s.module.retired = "h1", []string{"h0"}, nil
	s.module.mu.Unlock()

	l := s.successor(t, "h1", 30, 9)
	must(t, l.Tick(ctx, 30, 9))

	st, _, err := l.clusterState(ctx, l.bridge())
	must(t, err)

	// h0's self-update, not another failover
	if u := st.AgentUpgrade; u.Step != "self/h0" || u.Finished {
		t.Fatalf("the successor's step %+v", u)
	}

	if calls := s.calls(); slices.ContainsFunc(calls, func(c string) bool { return strings.HasPrefix(c, "mgr fail") }) {
		t.Fatalf("calls %v", calls)
	}
}

func TestTheCephAndTheAgentUpgradeExcludeEachOther(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()
	b := s.leader.bridge()

	set := func(change func(*state.State)) {
		t.Helper()

		must(t, s.leader.changeState(ctx, b, 42, func(st *state.State) error { change(st); return nil }))
	}

	// a Ceph upgrade does not start beside an unfinished agent upgrade
	set(func(st *state.State) {
		st.AgentUpgrade = &state.AgentUpgrade{Op: "op-00000000000000aa", From: agentImage, Image: agentImage2, Paused: true}
	})

	start := s.acceptOp(KindUpgrade, 1, func(op *LedgerOp) { op.Image = testImage })
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, start.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "agent upgrade") {
		t.Fatalf("a Ceph upgrade beside an agent upgrade: %+v", op)
	}

	// the agent upgrade's step does not start beside the Ceph upgrade's step
	set(func(st *state.State) {
		st.AgentUpgrade.Paused = false
		st.Upgrade = &state.Upgrade{Op: "op-00000000000000bb", Image: testImage, Step: "ceph-x-mon-h1"}
	})
	must(t, s.leader.agentUpgradeStep(ctx, b, nil, 42, 5))

	if u := s.agentUpgrade(t); u.Step != "" {
		t.Fatalf("an agent step beside a Ceph step: %+v", u)
	}

	// nor the Ceph upgrade's beside the agent upgrade's
	set(func(st *state.State) {
		st.AgentUpgrade.Step, st.AgentUpgrade.StepAt = "pull/h1", time.Now()
		st.Upgrade.Step = ""
	})
	_ = s.leader.upgradeStep(ctx, b, nil, 42, 5)

	st, _, err := s.leader.clusterState(ctx, b)
	must(t, err)

	if st.Upgrade.Step != "" {
		t.Fatalf("a Ceph step beside an agent step: %+v", st.Upgrade)
	}
}

func TestAStoppedAgentUpgradeRollsBack(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	up := startUpgrade(t, s) // h1's self-update waits for its agent on the target
	s.leader.OwnReport = ownRunning(s, agentImage)

	// the stop runs ahead of its turn; the step in progress ends first
	stop := s.acceptOp(KindAgentStop, 2, func(op *LedgerOp) { op.Upgrade = up.Op.ID })
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, stop.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("stop %+v", op)
	}

	if u := s.agentUpgrade(t); !u.Stopping || u.Stopped != "" || u.Step != "self/h1" {
		t.Fatalf("while the step ends %+v", u)
	}

	agentRunning(t, s, agentImage2)
	must(t, s.leader.Tick(ctx, 42, 5)) // h1's step ends
	must(t, s.leader.Tick(ctx, 42, 5)) // the rollback

	// the target gave up, from the target; h0 runs the old image, h1 does not
	u := s.agentUpgrade(t)
	if u.Stopped != agentImage2 || u.Image != agentImage || u.From != agentImage || u.Stopping || u.Paused || u.Attempt != 1 ||
		len(u.Pulled) != 0 || !slices.Equal(u.Done, []string{"h0"}) {
		t.Fatalf("the rollback %+v", u)
	}

	// a rollback is not stopped again
	again := s.acceptOp(KindAgentStop, 3, func(op *LedgerOp) { op.Upgrade = up.Op.ID })
	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.Pulled = []string{"h0"} }) // the harness cannot grant h0
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, again.Op.ID); op.State != wire.OpCompleted || s.agentUpgrade(t).Stopping {
		t.Fatalf("a stop of the rollback %+v %+v", op, s.agentUpgrade(t))
	}

	// the same steps: h1 pulls the old image and updates itself back
	for i := 0; i < 3; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if d := ownOnNode(t, s.agent.Node); d.image != agentImage {
		t.Fatalf("h1's document %s", d.image)
	}

	agentRunning(t, s, agentImage)
	must(t, s.leader.Tick(ctx, 42, 5)) // h1 done
	must(t, s.leader.Tick(ctx, 42, 5)) // finished

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if st.Agent.Image != agentImage || st.Agent.PreviousImage != "" || !st.AgentUpgrade.Finished || st.AgentUpgrade.Stopped != agentImage2 {
		t.Fatalf("after the rollback %+v %+v", st.Agent, st.AgentUpgrade)
	}
}

func TestAStopOfAPausedUpgradeRollsBackAndAResumeContinuesIt(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	up := startUpgrade(t, s)
	s.leader.OwnReport = ownRunning(s, agentImage)

	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.StepAt = time.Now().Add(-agentUpgradeWithin - time.Minute) })
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); !u.Paused {
		t.Fatalf("not paused %+v", u)
	}

	// stopped while paused: the rollback, not paused
	s.acceptOp(KindAgentStop, 2, func(op *LedgerOp) { op.Upgrade = up.Op.ID })
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); u.Paused || u.Stopped != agentImage2 || u.Image != agentImage {
		t.Fatalf("the rollback %+v", u)
	}

	// the rollback pauses as the upgrade did, and a resume continues it
	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.Paused, u.Error = true, "self/h1 did not end" })
	res := s.acceptOp(KindAgentResume, 3, func(op *LedgerOp) { op.Upgrade = up.Op.ID })
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); s.op(t, res.Op.ID).State != wire.OpCompleted || u.Paused || u.Attempt != 2 || u.Stopped != agentImage2 || u.Image != agentImage {
		t.Fatalf("after the resume %+v", u)
	}
}

func TestAStopRunsAheadOfAStalledOperation(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	up := startUpgrade(t, s)
	s.leader.OwnReport = ownRunning(s, agentImage)
	s.leader.serves = func(string, int, string) bool { return false } // a renewal that stalls

	// paused: no step in progress
	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.StepAt = time.Now().Add(-agentUpgradeWithin - time.Minute) })
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); !u.Paused || u.Step != "" {
		t.Fatalf("not paused %+v", u)
	}

	renew := s.accept(KindRenewAgent, "", "h1", 2)
	stop := s.acceptOp(KindAgentStop, 3, func(op *LedgerOp) { op.Upgrade = up.Op.ID })
	must(t, s.leader.Tick(ctx, 42, 5))

	// the stop ran ahead, the rollback and its first step before the renewal
	if op := s.op(t, stop.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("stop %+v", op)
	}

	if u := s.agentUpgrade(t); u.Stopped != agentImage2 || u.Paused || u.Step == "" {
		t.Fatalf("the rollback %+v", u)
	}

	if s.ended(renew.Op.ID) || s.ended(renew.Op.ID+".self") {
		t.Fatal("the renewal ran before the rollback's step")
	}
}

func TestAStopDuringAStepRollsBackBeforeQueuedWork(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	up := startUpgrade(t, s) // h1's step in progress
	s.leader.OwnReport = ownRunning(s, agentImage)
	s.leader.serves = func(string, int, string) bool { return false }

	renew := s.accept(KindRenewAgent, "", "h1", 2)
	s.acceptOp(KindAgentStop, 3, func(op *LedgerOp) { op.Upgrade = up.Op.ID })
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := s.agentUpgrade(t); !u.Stopping || u.Step != "self/h1" {
		t.Fatalf("while the step ends %+v", u)
	}

	agentRunning(t, s, agentImage2)
	must(t, s.leader.Tick(ctx, 42, 5)) // the step ends
	must(t, s.leader.Tick(ctx, 42, 5)) // the rollback and its first step, ahead of the renewal

	if u := s.agentUpgrade(t); u.Stopping || u.Stopped != agentImage2 || u.Step == "" {
		t.Fatalf("the rollback %+v", u)
	}

	if s.ended(renew.Op.ID + ".self") {
		t.Fatal("the renewal ran before the rollback")
	}
}

func TestASuccessorStartsTheRollbackBeforeQueuedWork(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	up := startUpgrade(t, s)
	s.leader.serves = func(string, int, string) bool { return false } // a renewal that stalls

	// the transition was published, then leadership moved before its first
	// step; the stop's journal is complete
	s.changeUpgrade(t, func(u *state.AgentUpgrade) {
		u.Stopped, u.Image, u.Attempt, u.Pulled, u.Done, u.Step, u.StepAt, u.Starting = agentImage2, agentImage, 1, nil, nil, "", time.Now(), true
	})

	renew := s.accept(KindRenewAgent, "", "h1", 2)

	l := s.successor(t, "h0", 30, 9)
	l.serves = s.leader.serves
	must(t, l.Tick(ctx, 30, 9))

	st, _, err := l.clusterState(ctx, l.bridge())
	must(t, err)

	if u := st.AgentUpgrade; u.Step == "" || u.Stopped != agentImage2 || u.Op != up.Op.ID {
		t.Fatalf("the successor's rollback %+v", u)
	}

	s.module.mu.Lock()
	_, ran := s.module.kv[JournalPrefix(30)+"op/"+renew.Op.ID+".self"]
	s.module.mu.Unlock()

	if ran {
		t.Fatal("the renewal ran before the rollback's first step")
	}
}

func TestAResumedRollbackDoesNotHoldQueuedWork(t *testing.T) {
	s, _ := agentSetup(t)
	ctx := context.Background()

	startUpgrade(t, s)
	s.leader.serves = func(string, int, string) bool { return true }

	// a rollback whose first pull paused, resumed: nothing pulled, its done
	// hosts to check again, and h0's report not readable
	s.changeUpgrade(t, func(u *state.AgentUpgrade) {
		u.Stopped, u.Image, u.Attempt, u.Pulled, u.Done, u.Step, u.StepAt = agentImage2, agentImage, 2, nil, []string{"h0"}, "", time.Time{}
		u.Verify, u.Paused, u.Starting = true, false, false
	})
	s.leader.OwnReport = func(context.Context) (wire.NodeReport, error) { return wire.NodeReport{}, errors.New("unreachable") }

	renew := s.accept(KindRenewAgent, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("a queued renewal behind a resumed rollback: %+v", op)
	}

	// nor does a rollback the stop made more than a step's limit ago
	if rollbackPending(state.AgentUpgrade{Stopped: agentImage2, Starting: true, StepAt: time.Now().Add(-agentUpgradeWithin - time.Minute)}, time.Now()) {
		t.Fatal("a stale rollback start keeps its priority")
	}
}
