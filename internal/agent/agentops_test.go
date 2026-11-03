package agent

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/daemons"
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

// agentRunning makes h1's agent container run an image's digest.
func agentRunning(t *testing.T, s *leaderSetup, image string) {
	t.Helper()

	ctx := context.Background()
	name := s.st.DocName(state.Daemon{Type: "agent", ID: "h1"})

	cs := containers.NewContainerStatus(containers.NamespaceName, name)
	cs.TypedSpec().State, cs.TypedSpec().Image = containers.ContainerStateRunning, digestOf(image)

	if err := s.agent.fake.St.Create(ctx, cs); err != nil {
		must(t, s.agent.fake.St.Update(ctx, cs))
	}
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

	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.Pulled = []string{"h0"} })

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

	// the successor upgrades the old leader's host like any other
	s.changeUpgrade(t, func(u *state.AgentUpgrade) { u.Done, u.Step = append(u.Done, "h0"), "" })
	must(t, s.leader.Tick(ctx, 42, 5))

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
