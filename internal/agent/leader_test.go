package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// leaderSetup is a leader on h0 with a fake module, the CLI's cluster state
// published in it, and a real agent for h1 on a fake Talos node.
type leaderSetup struct {
	leader *LeaderLoop
	module *fakeBridge
	agent  *testGranter
	st     *state.State
	// onRequest sees every request to the agent first
	onRequest func(*http.Request)
}

func newLeaderSetup(t *testing.T) *leaderSetup {
	t.Helper()

	ca := newTestCA(t)

	m := &fakeBridge{kv: map[string]string{}, outcomes: map[string]map[string]any{}, page: 1000, fsid: testFSID}
	host, port := m.serve(t, ca, "h0")

	old := dialPort
	dialPort = func() string { return port }

	t.Cleanup(func() { dialPort = old })

	cc, ck := ca.pair(pki.RoleAgent, "h0", x509.ExtKeyUsageClientAuth, testFSID)
	clientTLS, err := ClientTLSConfig([]byte(ca.cert), []byte(cc), []byte(ck))
	must(t, err)

	ch, err := NewChannel(pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h0"})
	must(t, err)

	// the agent of h1, served over TLS with its server certificate
	tg := newTestGranter(t)
	sc, sk := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	srvTLS, err := TLSConfig([]byte(ca.cert), []byte(sc), []byte(sk))
	must(t, err)

	setup := &leaderSetup{agent: tg}
	h := (&Agent{Granter: tg.Granter}).Handler()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if setup.onRequest != nil {
			setup.onRequest(r)
		}

		h.ServeHTTP(w, r)
	}))
	srv.TLS = srvTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)

	l := &LeaderLoop{
		Self: pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h0"}, Channel: ch, ClientTLS: clientTLS,
		Repos: []string{"quay.io/ceph/ceph"}, bridgeAddr: host, agentURL: func(state.Host) string { return srv.URL }, logf: t.Logf,
	}

	// what the CLI publishes: two hosts, a mon on h1
	st := state.New(testFSID)
	st.Image = testImage
	st.AddHost(state.Host{Name: "h0", Addr: "10.5.0.2"})
	st.AddHost(state.Host{Name: "h1", Addr: "10.5.0.3"})
	st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1", DeployID: "0123456789abcdef"})

	publish(t, l, st)

	// the active mgr on h0 heartbeats its agent: the leader of gid 42
	ch.mu.Lock()
	ch.leader = &Leader{Mgr: "h0", GID: 42, At: time.Now()}
	ch.mu.Unlock()

	setup.leader, setup.module, setup.st = l, m, st

	return setup
}

func publish(t *testing.T, l *LeaderLoop, st *state.State) {
	t.Helper()

	ctx := context.Background()

	bs, err := l.bridge().Store(ctx, store.Prefix+"inc/cli/")
	must(t, err)

	recs, err := st.Records()
	must(t, err)

	if _, err := (store.Store{B: bs, Incarnation: "cli"}).Publish(ctx, recs); err != nil {
		t.Fatal(err)
	}
}

func (s *leaderSetup) request(id, body string) {
	s.module.mu.Lock()
	defer s.module.mu.Unlock()

	s.module.kv[JournalPrefix(42)+"req/"+id] = body
}

func (s *leaderSetup) op(t *testing.T, id string) JournalOp {
	t.Helper()

	s.module.mu.Lock()
	defer s.module.mu.Unlock()

	var op JournalOp
	if raw, ok := s.module.kv[JournalPrefix(42)+"op/"+id]; !ok || json.Unmarshal([]byte(raw), &op) != nil {
		t.Fatalf("no journal record for %s", id)
	}

	return op
}

func TestLeaderGrantsAHostRevision(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)

	if err := s.leader.Tick(ctx, 42); err != nil {
		t.Fatal(err)
	}

	op := s.op(t, "r1")
	if op.State != "completed" || op.Seq == 0 || len(op.Docs) == 0 {
		t.Fatalf("journal %+v", op)
	}

	// no keyring in the journal: only hashes
	s.module.mu.Lock()
	for k, v := range s.module.kv {
		if strings.Contains(k, "/journal/") && strings.Contains(v, fakeKey) {
			t.Errorf("%s carries a key", k)
		}
	}
	s.module.mu.Unlock()

	monKey := "ContainerConfig/ceph-" + testFSID[:8] + "-mon-h1"
	if _, ok := op.Docs[monKey]; !ok {
		t.Fatalf("the mon was not granted: %v", op.Docs)
	}

	rep, err := s.agent.Node.Report(ctx)
	if err != nil || rep.State != "owned" || rep.Owned[monKey] != op.Docs[monKey] {
		t.Fatalf("agent %+v %v", rep, err)
	}

	// the host has everything now: the next revision changes nothing
	s.request("r2", `{"version":1,"kind":"revision","host":"h1"}`)

	if err := s.leader.Tick(ctx, 42); err != nil {
		t.Fatal(err)
	}

	if op := s.op(t, "r2"); op.State != JournalNoChange {
		t.Fatalf("second revision %+v", op)
	}

	// a request done stays done
	if err := s.leader.Tick(ctx, 42); err != nil || s.op(t, "r1").State != "completed" {
		t.Fatalf("re-run: %v", err)
	}
}

func TestLeaderRefusesBadRequests(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.request("r1", `{"version":1,"kind":"revision","host":"nohost"}`)
	s.request("r2", `{"version":1,"kind":"shell","host":"h1"}`)
	s.request("r3", `{"version":1,"kind":"revision","host":"h1","extra":1}`)

	_ = s.leader.Tick(ctx, 42)

	for _, id := range []string{"r1", "r2", "r3"} {
		if op := s.op(t, id); op.State != JournalFailed {
			t.Errorf("%s: %+v", id, op)
		}
	}

	if s.agent.patches.n != 0 {
		t.Fatalf("%d patches", s.agent.patches.n)
	}
}

func TestLeaderResolvesALostAnswer(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// a grant the leader sent but whose answer it never recorded: the agent has no record
	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	s.module.mu.Lock()
	s.module.kv[JournalPrefix(42)+"op/r1"] = `{"version":1,"kind":"revision","host":"h1","state":"granting","revision":5}`
	s.module.mu.Unlock()

	if err := s.leader.Tick(ctx, 42); err != nil {
		t.Fatal(err)
	}

	if op := s.op(t, "r1"); op.State != "abandoned" || s.agent.patches.n != 0 {
		t.Fatalf("resolved %+v", op)
	}

	// the grant arriving late does not run
	gr := probeGrant(6, "r1", "aaaaaa")
	if res, err := s.agent.Grant(ctx, gr); err != nil || res.State != "abandoned" || s.agent.patches.n != 0 {
		t.Fatalf("late grant: %+v %v", res, err)
	}
}

func TestLeaderOnlyWhileHeartbeated(t *testing.T) {
	s := newLeaderSetup(t)

	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = nil
	s.leader.Channel.mu.Unlock()

	if s.leader.active() != nil {
		t.Fatal("leader without a heartbeat")
	}

	now := time.Now()
	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = &Leader{Mgr: "h0", GID: 42, At: now}
	s.leader.Channel.mu.Unlock()

	if lead := s.leader.active(); lead == nil || lead.GID != 42 {
		t.Fatal("not the leader with a fresh heartbeat")
	}

	s.leader.now = func() time.Time { return now.Add(leaderFresh + time.Second) }
	if s.leader.active() != nil {
		t.Fatal("still the leader after the heartbeats stopped")
	}

	s.leader.now = nil
	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = &Leader{Mgr: "h9", GID: 42, At: now}
	s.leader.Channel.mu.Unlock()

	if s.leader.active() != nil {
		t.Fatal("the leader of another host's mgr")
	}
}

func TestLeaderDoesNotHideDrift(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42))

	// someone changes ceph.conf on the node; the owned hash stays what the leader renders
	must(t, s.agent.patches.Client.Patch(ctx, "", yamlOf(t, conf("10.5.0.9"))))

	s.request("r2", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42))

	if op := s.op(t, "r2"); op.State != JournalFailed || !strings.Contains(op.Error, "drift") {
		t.Fatalf("revision on a drifted node: %+v", op)
	}
}

func TestLeaderRetriesWhenTheBridgeDoesNotAnswer(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.module.mu.Lock()
	s.module.hang = "auth get"
	s.module.mu.Unlock()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	_ = s.leader.Tick(ctx, 42)

	s.module.mu.Lock()
	_, decided := s.module.kv[JournalPrefix(42)+"op/r1"]
	s.module.hang = ""
	s.module.mu.Unlock()

	if decided {
		t.Fatalf("a request decided without the mon. key: %+v", s.op(t, "r1"))
	}

	must(t, s.leader.Tick(ctx, 42))

	if op := s.op(t, "r1"); op.State != "completed" {
		t.Fatalf("after the bridge answers: %+v", op)
	}
}

func TestLeaderStopsWhenItIsNoLongerTheLeader(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// another incarnation: nothing is done for gid 42
	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = &Leader{Mgr: "h0", GID: 43, At: time.Now()}
	s.leader.Channel.mu.Unlock()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42))

	s.module.mu.Lock()
	_, decided := s.module.kv[JournalPrefix(42)+"op/r1"]
	s.module.mu.Unlock()

	if decided {
		t.Fatal("a stale leader decided a request")
	}

	// leadership ends while the host is asked for its report: nothing is granted
	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = &Leader{Mgr: "h0", GID: 42, At: time.Now()}
	s.leader.Channel.mu.Unlock()

	s.onRequest = func(r *http.Request) {
		if r.URL.Path == "/v1/node" {
			s.leader.Channel.mu.Lock()
			s.leader.Channel.leader.GID = 43
			s.leader.Channel.mu.Unlock()
		}
	}

	must(t, s.leader.Tick(ctx, 42))

	if s.agent.patches.n != 0 {
		t.Fatalf("%d patches after leadership ended", s.agent.patches.n)
	}
}

func TestAgentEndpointBounds(t *testing.T) {
	s := newLeaderSetup(t)
	ca := newTestCA(t)
	leader := certOf(t, ca, pki.RoleAgent, "h0")
	g := s.agent

	// abandoning while a grant runs is refused, so a grant in flight cannot be overtaken
	g.mu <- struct{}{}

	ab := wire.Abandon{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Revision: 9, Operation: "r9"}

	w := httptest.NewRecorder()
	g.HandleAbandon(w, request(t, http.MethodPost, "/v1/abandon", ab, leader))

	<-g.mu

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("abandon during a grant: %d", w.Code)
	}

	// one report at a time, and a stalled one ends
	g.reports <- struct{}{}

	w = httptest.NewRecorder()
	g.HandleNode(w, request(t, http.MethodGet, "/v1/node", nil, leader))

	<-g.reports

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second report: %d", w.Code)
	}

	old := reportTimeout
	reportTimeout = 50 * time.Millisecond

	t.Cleanup(func() { reportTimeout = old })

	g.Node.Talos = stalledConfig{g.patches}

	start := time.Now()
	w = httptest.NewRecorder()
	g.HandleNode(w, request(t, http.MethodGet, "/v1/node", nil, leader))

	if w.Code == http.StatusOK || time.Since(start) > 5*time.Second {
		t.Fatalf("stalled report: %d after %s", w.Code, time.Since(start))
	}
}

// stalledConfig never answers a config read until its context ends.
type stalledConfig struct{ *countingPatch }

func (s stalledConfig) MachineConfig(ctx context.Context, _ string) (string, error) {
	<-ctx.Done()

	return "", ctx.Err()
}

func TestAbandonFencesItsRevision(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	ab := wire.Abandon{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Revision: 50, Operation: "lost-1"}

	// not confirmed: nothing recorded, nothing fenced
	g.refuse = errors.New("not the active mgr")
	if _, err := g.Abandon(ctx, ab); err == nil {
		t.Fatal("an unconfirmed abandon")
	}

	g.refuse = nil

	if f, _ := g.Node.fence(); f != 0 {
		t.Fatalf("fence %d after an unconfirmed abandon", f)
	}

	op, err := g.Abandon(ctx, ab)
	if err != nil || op.State != wire.OpAbandoned {
		t.Fatalf("abandon: %+v %v", op, err)
	}

	// even once the record is gone, the late grant cannot be applied
	must(t, g.Records.Remove(opRecord("lost-1")))

	res, err := g.Grant(ctx, probeGrant(50, "lost-1", "aaaaaa"))
	if err != nil || res.State != wire.OpRefused || g.patches.n != 0 {
		t.Fatalf("late grant after pruning: %+v %v, %d patches", res, err, g.patches.n)
	}

	// a newer revision still applies
	if res, err := g.Grant(ctx, probeGrant(51, "next", "bbbbbb")); err != nil || res.State != wire.OpCompleted {
		t.Fatalf("newer grant: %+v %v", res, err)
	}
}

func TestReportWaitsForTheNodeOnlyUntilItsDeadline(t *testing.T) {
	g := newTestGranter(t)
	ca := newTestCA(t)

	old := reportTimeout
	reportTimeout = 50 * time.Millisecond

	t.Cleanup(func() { reportTimeout = old })

	// an apply holds the node
	must(t, g.Node.lock(context.Background()))
	defer g.Node.unlock()

	start := time.Now()
	w := httptest.NewRecorder()
	g.HandleNode(w, request(t, http.MethodGet, "/v1/node", nil, certOf(t, ca, pki.RoleAgent, "h0")))

	if w.Code == http.StatusOK || time.Since(start) > 5*time.Second {
		t.Fatalf("report on a busy node: %d after %s", w.Code, time.Since(start))
	}
}

func TestLeaderLeavesMaintenanceHostsAlone(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	h, _ := s.st.Host("h1")
	h.Maintenance = true
	s.st.AddHost(h)
	publish(t, s.leader, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42))

	if op := s.op(t, "r1"); op.State != JournalFailed || !strings.Contains(op.Error, "maintenance") || s.agent.patches.n != 0 {
		t.Fatalf("revision of a host in maintenance: %+v", op)
	}
}

func TestAbandonFenceRespectsTheConfirmation(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	// the node is busy until the confirmation has run out
	must(t, g.Node.lock(ctx))

	confirm := g.confirm
	g.confirm = func(ctx context.Context, target ConfirmTarget, revision int64, operation, hash string) (wire.Confirmation, time.Time, error) {
		c, _, err := confirm(ctx, target, revision, operation, hash)

		go func() { time.Sleep(150 * time.Millisecond); g.Node.unlock() }()

		return c, time.Now().Add(100 * time.Millisecond), err
	}

	ab := wire.Abandon{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Revision: 50, Operation: "lost-2"}
	if _, err := g.Abandon(ctx, ab); err == nil {
		t.Fatal("abandon fenced after its confirmation expired")
	}

	if f, _ := g.Node.fence(); f != 0 {
		t.Fatalf("fence %d", f)
	}

	if _, found, _ := g.readOp("lost-2"); found {
		t.Fatal("abandoned without a fence")
	}
}

func TestLeaderDoesNotRestartLeavingDaemons(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// a mon stopped without the mons, a mgr purged: neither comes back, nor do mgr files
	mon, _ := s.st.Find("mon.h1")
	mon.LocalOnly = true
	s.st.AddDaemon(mon)
	s.st.AddDaemon(state.Daemon{Type: state.TypeMgr, ID: "h1", Host: "h1", Purged: true})
	publish(t, s.leader, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42))

	op := s.op(t, "r1")
	for k := range op.Docs {
		if strings.Contains(k, "-mon-") || strings.Contains(k, "-mgr-") || strings.Contains(k, "mgr/cephadm") {
			t.Errorf("granted %s", k)
		}
	}
}
