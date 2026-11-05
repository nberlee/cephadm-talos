package agent

import (
	"context"
	"crypto/x509"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// retiringSetup is a leader setup whose h1 has no daemons, its agent serving
// the certificate the state names and its records listing serial 12.
func retiringSetup(t *testing.T) *leaderSetup {
	t.Helper()

	s := newLeaderSetup(t)
	s.st.Daemons = nil

	h, _ := s.st.Host("h1")
	h.AgentCert, h.AgentClientCert = s.agentCert, "client-of-h1"
	s.st.AddHost(h)
	publish(t, s.leader, s.module, s.st)

	must(t, RecordIdentity(s.agent.Records, "12"))

	return s
}

func (s *leaderSetup) retiring(t *testing.T) map[string]*state.Retiring {
	t.Helper()

	st, _, err := s.leader.clusterState(context.Background(), s.leader.bridge())
	must(t, err)

	if _, ok := st.Host("h1"); ok && st.Retiring["h1"] != nil {
		t.Fatal("h1 is both a member and retiring")
	}

	return st.Retiring
}

func (s *leaderSetup) moduleCalls() []string {
	s.module.mu.Lock()
	defer s.module.mu.Unlock()

	return slices.Clone(s.module.retired)
}

// at sets the leader's clock, its heartbeat fresh at that time.
func (s *leaderSetup) at(now time.Time) {
	s.leader.now = func() time.Time { return now }

	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader.At = now
	s.leader.Channel.mu.Unlock()
}

// unreachable points the leader at a closed port for h1's agent.
func (s *leaderSetup) unreachable() {
	s.leader.agentURL = func(state.Host) string { return "https://127.0.0.1:1" }
}

func TestARemovedHostsAgentRetiresAndItsCredentialsGo(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()

	s.module.mu.Lock()
	s.module.enroll = `{"agent_cert":"enrolled-server","agent_client_cert":"enrolled-client"}`
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5)) // the takeover

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// the removal ended at once: the host left the hosts, retiring with the
	// identity it journaled; the strip ran in the same tick
	if op := s.op(t, rm.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("removal: %+v", op)
	}

	r := s.retiring(t)["h1"]
	if r == nil || r.Op != rm.Op.ID || r.Addr != "10.5.0.3" || r.AgentCert != s.agentCert || r.AgentClientCert != "client-of-h1" ||
		r.EnrollCert != "enrolled-server" || r.EnrollClientCert != "enrolled-client" || r.Step != state.RetireGrant {
		t.Fatalf("retiring %+v", r)
	}

	if op := s.op(t, rm.Op.ID+".strip.1"); op.State != wire.OpCompleted {
		t.Fatalf("strip %+v", op)
	}

	if rep, err := s.agent.Node.Report(ctx); err != nil || len(rep.Owned) != 0 {
		t.Fatalf("still owned: %+v %v", rep.Owned, err)
	}

	// the grant: the agent retires itself
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, rm.Op.ID+".retire.1"); op.State != wire.OpCompleted || op.Kind != KindRetire {
		t.Fatalf("retire grant %+v", op)
	}

	if !s.agent.Retired() {
		t.Fatal("the agent did not retire")
	}

	// 410 Gone: done, the module ends it and the record goes
	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.retiring(t); len(r) != 0 {
		t.Fatalf("still retiring %+v", r)
	}

	calls := s.moduleCalls()
	if !slices.Contains(calls, "retire start "+rm.Op.ID) || !slices.Contains(calls, "retire done "+rm.Op.ID) ||
		slices.Contains(calls, "retire host "+rm.Op.ID) {
		t.Fatalf("module calls %v", calls)
	}

	s.module.mu.Lock()
	certs := s.module.certs["retire done "+rm.Op.ID]
	s.module.mu.Unlock()

	if !slices.Equal(certs, []string{s.agentCert, "client-of-h1"}) {
		t.Fatalf("revoked with the end: %v", certs)
	}

	// nothing more is asked of it
	n := len(s.moduleCalls())
	must(t, s.leader.Tick(ctx, 42, 5))

	if len(s.moduleCalls()) != n {
		t.Fatalf("more calls %v", s.moduleCalls()[n:])
	}
}

func TestARetirementWaitsForAnAgentThatNeverAnswered(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()
	now := time.Now()
	s.at(now)

	must(t, s.leader.Tick(ctx, 42, 5))

	// powered off before the removal
	s.unreachable()

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, rm.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("an offline host's removal ends: %+v", op)
	}

	// no grant was ever sent: it waits however long it takes
	now = now.Add(time.Hour)
	s.at(now)
	must(t, s.leader.Tick(ctx, 42, 5))

	r := s.retiring(t)["h1"]
	if r == nil || r.Step != state.RetireStrip || r.Sent || r.Silent.IsZero() || !strings.Contains(r.Error, "does not answer at 10.5.0.3") {
		t.Fatalf("retiring %+v", r)
	}

	if slices.Contains(s.moduleCalls(), "retire done "+rm.Op.ID) {
		t.Fatal("ended without a grant")
	}

	// a later operation runs meanwhile: the retirement holds no ledger
	other := s.accept(KindRemoveHost, "", "h9", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, other.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("a later operation: %+v", op)
	}
}

func TestARetirementEndsAfterTwoMinutesOfSilenceOnceGranted(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()
	now := time.Now()
	s.at(now)

	must(t, s.leader.Tick(ctx, 42, 5))

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5)) // removal and strip

	// the agent stops before it answers the grant (Talos stops its container):
	// the grant's answer is lost and the agent does not answer anymore
	s.onRequest = func(r *http.Request) {
		if r.URL.Path == "/v1/grant" {
			s.unreachable()
			panic(http.ErrAbortHandler)
		}
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	r := s.retiring(t)["h1"]
	if op := s.op(t, rm.Op.ID+".retire.1"); op.State != JournalGranting || r == nil || !r.Sent {
		t.Fatalf("grant %+v, retiring %+v", op, r)
	}

	// silent, but not for two minutes yet
	must(t, s.leader.Tick(ctx, 42, 5))
	now = now.Add(retireSilence - time.Second)
	s.at(now)
	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.retiring(t)["h1"]; r == nil || r.Silent.IsZero() || r.Retired {
		t.Fatalf("retiring %+v", r)
	}

	now = now.Add(2 * time.Second)
	s.at(now)
	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.retiring(t); len(r) != 0 {
		t.Fatalf("still retiring %+v", r)
	}

	// the lost grant is decided by the retirement, never asked again
	if op := s.op(t, rm.Op.ID+".retire.1"); op.State != wire.OpCompleted || !strings.Contains(op.Error, "taken as done") {
		t.Fatalf("grant %+v", op)
	}

	if !slices.Contains(s.moduleCalls(), "retire done "+rm.Op.ID) {
		t.Fatalf("module calls %v", s.moduleCalls())
	}
}

func TestARefusedRetirementIsGrantedAgain(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()
	now := time.Now()
	s.at(now)

	must(t, s.leader.Tick(ctx, 42, 5))

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// the agent's records have no identity record: it refuses the retirement
	must(t, s.agent.Records.Remove(identityRecord))
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, rm.Op.ID+".retire.1"); op.State != wire.OpRefused {
		t.Fatalf("grant %+v", op)
	}

	r := s.retiring(t)["h1"]
	if r == nil || r.Attempt != 1 || r.Sent || !strings.Contains(r.Error, "ended refused") {
		t.Fatalf("retiring %+v", r)
	}

	// not again within retireRetry; then a new attempt that completes
	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.retiring(t)["h1"]; r.Attempt != 1 {
		t.Fatalf("retried at once: %+v", r)
	}

	must(t, RecordIdentity(s.agent.Records, "12"))

	now = now.Add(retireRetry)
	s.at(now)
	must(t, s.leader.Tick(ctx, 42, 5)) // attempt 2 recorded
	must(t, s.leader.Tick(ctx, 42, 5)) // granted

	if op := s.op(t, rm.Op.ID+".retire.2"); op.State != wire.OpCompleted || !s.agent.Retired() {
		t.Fatalf("grant %+v", op)
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.retiring(t); len(r) != 0 {
		t.Fatalf("still retiring %+v", r)
	}
}

func TestATakeoverContinuesARetirement(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// an earlier leader recorded h1's retirement before its strip
	s.st.Daemons = nil
	s.st.RemoveHost("h1")
	s.st.Retiring = map[string]*state.Retiring{"h1": {
		Op: "op-0000000000000001", Addr: "10.5.0.3", AgentCert: s.agentCert, Step: state.RetireStrip, Attempt: 1, Since: time.Now().UTC().Truncate(time.Second),
	}}
	publish(t, s.leader, s.module, s.st)
	must(t, RecordIdentity(s.agent.Records, "12"))

	s.accept(KindRemoveHost, "", "h1", 1)

	// the new leader closes the retiring agent's earlier sessions, then carries on
	must(t, s.leader.Tick(ctx, 42, 5))

	if f, err := s.agent.floor(); err != nil || f != 5 {
		t.Fatalf("floor %d %v", f, err)
	}

	for range 3 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if r := s.retiring(t); len(r) != 0 || !s.agent.Retired() {
		t.Fatalf("still retiring %+v (retired %v)", r, s.agent.Retired())
	}
}

func TestAnotherAgentAtTheAddressIsNotTheRetiringOne(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	// the state journals another server certificate than the agent serves
	other, _ := s.ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		h, _ := st.Host("h1")
		h.AgentCert = other
		st.AddHost(h)

		return nil
	}))

	s.accept(KindRemoveHost, "", "h1", 1)

	for range 3 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	r := s.retiring(t)["h1"]
	if r == nil || r.Step != state.RetireStrip || !strings.Contains(r.Error, "does not answer") {
		t.Fatalf("retiring %+v", r)
	}

	if _, err := s.agent.Node.Report(ctx); err != nil || s.agent.Retired() {
		t.Fatalf("the agent was reached: %v", err)
	}
}

// publicationFails has every publication of the state fail, the journal not.
func (s *leaderSetup) publicationFails(on bool) {
	s.module.mu.Lock()
	defer s.module.mu.Unlock()

	s.module.refuseKey = ""
	if on {
		s.module.refuseKey = "/manifest/"
	}
}

// Codex round 3 of slice 2: once retire start was sent the fold may hold the
// host retiring, so the removal is never given up before its record is published.
func TestAStartedRemovalIsNotGivenUpBeforeItsRecordIsPublished(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	s.publicationFails(true)
	must(t, s.leader.Tick(ctx, 42, 5))

	if !slices.Contains(s.moduleCalls(), "retire start "+rm.Op.ID) {
		t.Fatalf("module calls %v", s.moduleCalls())
	}

	// failing since longer than stuckAfter: not given up
	s.leader.failing[rm.Op.ID] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	raw, ended := s.module.kv[JournalPrefix(42)+"op/"+rm.Op.ID]
	s.module.mu.Unlock()

	if ended {
		t.Fatalf("given up: %s", raw)
	}

	if op := s.op(t, rm.Op.ID+".start"); op.State != JournalGranting {
		t.Fatalf("start %+v", op)
	}

	// published at last: the retirement advances
	s.publicationFails(false)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, rm.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("removal %+v", op)
	}

	if op := s.op(t, rm.Op.ID+".start"); op.State != wire.OpCompleted {
		t.Fatalf("start %+v", op)
	}

	if r := s.retiring(t)["h1"]; r == nil || r.Op != rm.Op.ID || r.AgentCert != s.agentCert {
		t.Fatalf("retiring %+v", r)
	}
}

func TestATakeoverContinuesAStartedRemoval(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	s.publicationFails(true)
	must(t, s.leader.Tick(ctx, 42, 5))
	s.publicationFails(false)

	// the next active mgr, which finds the state without the record
	s.module.mu.Lock()
	s.module.own = "43"
	s.module.mu.Unlock()
	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = &Leader{Mgr: "h0", GID: 43, Epoch: 6, At: time.Now()}
	s.leader.Channel.mu.Unlock()

	abandoned := false
	s.onRequest = func(r *http.Request) { abandoned = abandoned || r.URL.Path == "/v1/abandon" }

	must(t, s.leader.Tick(ctx, 43, 6))

	if abandoned {
		t.Fatal("no grant is behind retire start: nothing to abandon")
	}

	n := 0

	for _, c := range s.moduleCalls() {
		if c == "retire start "+rm.Op.ID {
			n++
		}
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if r := st.Retiring["h1"]; n < 2 || r == nil || r.Op != rm.Op.ID {
		t.Fatalf("%d starts, retiring %+v", n, r)
	}

	if _, ok := st.Host("h1"); ok {
		t.Fatal("h1 stayed a member")
	}
}

// A definite refusal started nothing: the removal is given up as any operation.
func TestARefusedStartIsGivenUp(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	s.module.refuse = "retire start"
	s.module.mu.Unlock()

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, rm.Op.ID+".start"); op.State != wire.OpRefused {
		t.Fatalf("start %+v", op)
	}

	s.leader.failing[rm.Op.ID] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, rm.Op.ID); op.State != JournalFailed {
		t.Fatalf("removal %+v", op)
	}

	if r := s.retiring(t); len(r) != 0 {
		t.Fatalf("retiring %+v", r)
	}
}

// forgotten accepts `ceph orch talos host forgotten` of h1's removal.
func (s *leaderSetup) forgotten(remove string, seq int64) LedgerEntry {
	return s.acceptOp(KindRetireForgotten, seq, func(op *LedgerOp) { op.Host, op.Remove = "h1", remove })
}

// The operator's assertion ends a retirement waiting for an agent that never
// answered: without it, it waits however long it takes.
func TestAForgottenHostsRetirementEnds(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()
	now := time.Now()
	s.at(now)

	must(t, s.leader.Tick(ctx, 42, 5))
	s.unreachable()

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// another removal's assertion changes nothing, and is done
	other := s.forgotten("op-00000000000000ff", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, other.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("another removal's: %+v", op)
	}

	if r := s.retiring(t)["h1"]; r == nil || r.Step != state.RetireStrip || r.Reason != "" {
		t.Fatalf("retiring %+v", r)
	}

	// an assertion: the end follows, which revokes the journaled certificates
	f := s.forgotten(rm.Op.ID, 3)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, f.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("forgotten: %+v", op)
	}

	if r := s.retiring(t); len(r) != 0 {
		t.Fatalf("still retiring %+v", r)
	}

	if calls := s.moduleCalls(); !slices.Contains(calls, "retire done "+rm.Op.ID) {
		t.Fatalf("module calls %v", calls)
	}

	s.module.mu.Lock()
	certs := s.module.certs["retire done "+rm.Op.ID]
	s.module.mu.Unlock()

	if !slices.Equal(certs, []string{s.agentCert, "client-of-h1"}) {
		t.Fatalf("revoked with the end: %v", certs)
	}
}

// The record shows why it ended, and an end the module refuses is asked again
// with the retirement's steps: the assertion itself is done.
func TestAForgottenRetirementRecordsItsReason(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))
	s.unreachable()

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	s.module.refuse = "retire done"
	s.module.mu.Unlock()

	f := s.forgotten(rm.Op.ID, 2)
	_ = s.leader.Tick(ctx, 42, 5)

	if op := s.op(t, f.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("forgotten: %+v", op)
	}

	if r := s.retiring(t)["h1"]; r == nil || r.Step != state.RetireEnd || r.Reason != "forgotten" || !r.Retired {
		t.Fatalf("retiring %+v", r)
	}

	s.module.mu.Lock()
	s.module.refuse = ""
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.retiring(t); len(r) != 0 {
		t.Fatalf("still retiring %+v", r)
	}
}

// A queued operation that does not end holds the ledger, not the assertion.
func TestAForgottenRunsAheadOfAQueuedOperation(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))
	s.unreachable()

	rm := s.accept(KindRemoveHost, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// a queued removal the module does not start keeps the ledger at it
	s.module.mu.Lock()
	s.module.refuse = "retire start"
	s.module.mu.Unlock()

	s.accept(KindRemoveHost, "", "h9", 2)
	f := s.forgotten(rm.Op.ID, 3)
	_ = s.leader.Tick(ctx, 42, 5)

	// held: no retirement step ran after the ledger
	if slices.Contains(s.moduleCalls(), "retire done "+rm.Op.ID) {
		t.Fatal("the ledger was not held")
	}

	if op := s.op(t, f.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("forgotten: %+v", op)
	}

	if r := s.retiring(t)["h1"]; r == nil || r.Step != state.RetireEnd || r.Reason != "forgotten" {
		t.Fatalf("retiring %+v", r)
	}
}

func TestAMalformedForgottenFails(t *testing.T) {
	s := retiringSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	bad := s.acceptOp(KindRetireForgotten, 1, func(op *LedgerOp) { op.Host, op.Remove = "h1", "not-an-op" })
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, bad.Op.ID); op.State != JournalFailed {
		t.Fatalf("malformed: %+v", op)
	}
}
