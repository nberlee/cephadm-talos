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

	oldDial, oldBridge := dialPort, bridgePort
	dialPort, bridgePort = func() string { return port }, func() string { return port }

	t.Cleanup(func() { dialPort, bridgePort = oldDial, oldBridge })

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
	st.Sealed = true // handed over

	publish(t, l, m, st)

	// the active mgr on h0 heartbeats its agent: the leader of gid 42
	ch.mu.Lock()
	ch.leader = &Leader{Mgr: "h0", GID: 42, Epoch: 5, At: time.Now()}
	ch.mu.Unlock()

	setup.leader, setup.module, setup.st = l, m, st

	// from here the module's incarnation writes only below its own namespace
	m.mu.Lock()
	m.own = "42"
	m.mu.Unlock()

	return setup
}

// publish publishes st as the CLI does, under "cli", which the module's own
// incarnation may not write.
func publish(t *testing.T, l *LeaderLoop, m *fakeBridge, st *state.State) {
	t.Helper()

	ctx := context.Background()

	m.mu.Lock()
	own := m.own
	m.own = ""
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.own = own
		m.mu.Unlock()
	}()

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

	if err := s.leader.Tick(ctx, 42, 5); err != nil {
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

	if err := s.leader.Tick(ctx, 42, 5); err != nil {
		t.Fatal(err)
	}

	if op := s.op(t, "r2"); op.State != JournalNoChange {
		t.Fatalf("second revision %+v", op)
	}

	// a request done stays done
	if err := s.leader.Tick(ctx, 42, 5); err != nil || s.op(t, "r1").State != "completed" {
		t.Fatalf("re-run: %v", err)
	}
}

func TestLeaderRendersMgrKeysFromTheSecrets(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// a mgr on h1: its certificates are in the published state, its keys only below the secret prefix
	ca := newTestCA(t)
	h, _ := s.st.Host("h1")
	h.MgrServerCert, h.MgrServerKey = ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	h.MgrClientCert, h.MgrClientKey = ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, testFSID)
	s.st.AddHost(h)
	s.st.Agent = &state.Agent{CACert: ca.cert}
	s.agent.Node.Policy.CACert, s.leader.CACert = ca.cert, ca.cert // the agents trust the same CA
	s.st.AddDaemon(state.Daemon{Type: state.TypeMgr, ID: "h1", Host: "h1"})
	publish(t, s.leader, s.module, s.st)

	s.module.mu.Lock()
	for k, v := range s.module.kv {
		if strings.Contains(v, "PRIVATE KEY") {
			t.Fatalf("%s carries a private key", k)
		}
	}
	s.module.mu.Unlock()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	_ = s.leader.Tick(ctx, 42, 5)

	// without its keys the host is not rendered: the request waits
	s.module.mu.Lock()
	if _, ok := s.module.kv[JournalPrefix(42)+"op/r1"]; ok || s.agent.patches.n != 0 {
		t.Fatal("rendered without the mgr keys")
	}
	s.module.mu.Unlock()

	s.module.mu.Lock()
	for name, v := range s.st.Secrets() {
		s.module.kv[store.SecretPrefix+name] = v
	}
	s.module.mu.Unlock()

	if err := s.leader.Tick(ctx, 42, 5); err != nil {
		t.Fatal(err)
	}

	op := s.op(t, "r1")
	if op.State != "completed" {
		t.Fatalf("journal %+v", op)
	}

	if _, ok := op.Docs["EtcFileConfig/ceph/talos/mgr-server.key"]; !ok {
		t.Fatalf("the mgr key was not granted: %v", op.Docs)
	}
}

func TestLeaderRefusesBadRequests(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.request("r1", `{"version":1,"kind":"revision","host":"nohost"}`)
	s.request("r2", `{"version":1,"kind":"shell","host":"h1"}`)
	s.request("r3", `{"version":1,"kind":"revision","host":"h1","extra":1}`)

	_ = s.leader.Tick(ctx, 42, 5)

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

	if err := s.leader.Tick(ctx, 42, 5); err != nil {
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
	s.leader.Channel.leader = &Leader{Mgr: "h0", GID: 42, Epoch: 5, At: now}
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
	s.leader.Channel.leader = &Leader{Mgr: "h9", GID: 42, Epoch: 5, At: now}
	s.leader.Channel.mu.Unlock()

	if s.leader.active() != nil {
		t.Fatal("the leader of another host's mgr")
	}
}

func TestLeaderDoesNotHideDrift(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	// someone changes ceph.conf on the node; the owned hash stays what the leader renders
	must(t, s.agent.patches.Client.Patch(ctx, "", yamlOf(t, conf("10.5.0.9"))))

	s.request("r2", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

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
	_ = s.leader.Tick(ctx, 42, 5)

	s.module.mu.Lock()
	_, decided := s.module.kv[JournalPrefix(42)+"op/r1"]
	s.module.hang = ""
	s.module.mu.Unlock()

	if decided {
		t.Fatalf("a request decided without the mon. key: %+v", s.op(t, "r1"))
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != "completed" {
		t.Fatalf("after the bridge answers: %+v", op)
	}
}

func TestLeaderStopsWhenItIsNoLongerTheLeader(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// another incarnation: nothing is done for gid 42
	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = &Leader{Mgr: "h0", GID: 43, Epoch: 6, At: time.Now()}
	s.leader.Channel.mu.Unlock()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	_, decided := s.module.kv[JournalPrefix(42)+"op/r1"]
	s.module.mu.Unlock()

	if decided {
		t.Fatal("a stale leader decided a request")
	}

	// leadership ends while the host is asked for its report: nothing is granted
	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = &Leader{Mgr: "h0", GID: 42, Epoch: 5, At: time.Now()}
	s.leader.Channel.mu.Unlock()

	s.onRequest = func(r *http.Request) {
		if r.URL.Path == "/v1/node" {
			s.leader.Channel.mu.Lock()
			s.leader.Channel.leader.GID = 43
			s.leader.Channel.mu.Unlock()
		}
	}

	must(t, s.leader.Tick(ctx, 42, 5))

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

	ab := wire.Abandon{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5, Revision: 9, Operation: "r9"}

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

	ab := wire.Abandon{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5, Revision: 50, Operation: "lost-1"}

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
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != JournalFailed || !strings.Contains(op.Error, "maintenance") || s.agent.patches.n != 0 {
		t.Fatalf("revision of a host in maintenance: %+v", op)
	}
}

func TestAbandonFenceRespectsTheConfirmation(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	// the node is busy from the confirmation until it has run out
	confirm := g.confirm
	g.confirm = func(ctx context.Context, target ConfirmTarget, revision int64, operation, hash string) (wire.Confirmation, time.Time, error) {
		c, _, err := confirm(ctx, target, revision, operation, hash)

		must(t, g.Node.lock(ctx))

		go func() { time.Sleep(150 * time.Millisecond); g.Node.unlock() }()

		return c, time.Now().Add(100 * time.Millisecond), err
	}

	ab := wire.Abandon{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5, Revision: 50, Operation: "lost-2"}
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
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	op := s.op(t, "r1")
	for k := range op.Docs {
		if strings.Contains(k, "-mon-") || strings.Contains(k, "-mgr-") || strings.Contains(k, "mgr/cephadm") {
			t.Errorf("granted %s", k)
		}
	}
}

func TestTakeoverClosesSessionsAndImports(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// incarnation 41 left a grant without its outcome and a request it never decided
	s.module.mu.Lock()
	s.module.kv[JournalPrefix(41)+"req/x"] = `{"version":1,"kind":"revision","host":"h1"}`
	s.module.kv[JournalPrefix(41)+"op/x"] = `{"version":1,"kind":"revision","host":"h1","state":"granting","revision":7}`
	s.module.kv[JournalPrefix(41)+"req/y"] = `{"version":1,"kind":"revision","host":"h1"}`
	s.module.kv[JournalPrefix(41)+"req/z"] = `{"version":1,"kind":"revision","host":"h1"}`
	s.module.kv[JournalPrefix(41)+"op/z"] = `{"version":1,"kind":"revision","host":"h1","state":"completed","revision":6}`
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	// h1's session closed; h0 has no agent here and stays to be closed
	if f, err := s.agent.floor(); err != nil || f != 5 {
		t.Fatalf("floor %d %v", f, err)
	}

	s.module.mu.Lock()
	raw := s.module.kv[JournalPrefix(42)+"takeover"]
	_, zImported := s.module.kv[JournalPrefix(42)+"req/z"]
	s.module.mu.Unlock()

	var to Takeover
	if json.Unmarshal([]byte(raw), &to) != nil || !to.Imported || len(to.Closed) != 1 || to.Closed[0] != "h1" {
		t.Fatalf("takeover %s", raw)
	}

	// the lost grant was abandoned under the new incarnation; the undecided request ran; the decided one stays
	if op := s.op(t, "x"); op.State != "abandoned" {
		t.Fatalf("imported grant: %+v", op)
	}

	if op := s.op(t, "y"); op.State != "completed" {
		t.Fatalf("imported request: %+v", op)
	}

	if zImported {
		t.Fatal("a decided request was imported")
	}

	// the fence of the abandoned grant holds
	if f, _ := s.agent.Node.fence(); f != 7 {
		t.Fatalf("fence %d", f)
	}
}

func TestNoGrantBeforeTheSessionIsClosed(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// the agent cannot confirm the close: its session stays open
	s.onRequest = func(r *http.Request) {
		if r.URL.Path == "/v1/close" {
			s.agent.refuse = errors.New("no confirmation")
		} else {
			s.agent.refuse = nil
		}
	}

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	_, decided := s.module.kv[JournalPrefix(42)+"op/r1"]
	s.module.mu.Unlock()

	if decided || s.agent.patches.n != 0 {
		t.Fatalf("granted before the session was closed: %v, %d patches", decided, s.agent.patches.n)
	}

	// once the close goes through, the request runs
	s.onRequest = nil
	s.agent.refuse = nil

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != "completed" {
		t.Fatalf("after the close: %+v", op)
	}
}

func TestALostJournalWriteIsResolvedNotResent(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	op := s.op(t, "r1")
	if op.State != "completed" || s.agent.patches.n != 1 {
		t.Fatalf("grant: %+v, %d patches", op, s.agent.patches.n)
	}

	// as if the mons went away after the grant and its outcome was never written
	op.State = JournalGranting

	b, _ := json.Marshal(op)

	s.module.mu.Lock()
	s.module.kv[JournalPrefix(42)+"op/r1"] = string(b)
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != "completed" || s.agent.patches.n != 1 {
		t.Fatalf("resolved: %+v, %d patches", op, s.agent.patches.n)
	}
}

func TestImportedGrantWithoutItsRequestIsResolved(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// an import that copied the operation but not its request
	s.module.mu.Lock()
	s.module.kv[JournalPrefix(42)+"op/x"] = `{"version":1,"kind":"revision","host":"h1","state":"granting","revision":7}`
	s.module.kv[JournalPrefix(42)+"takeover"] = `{"version":1,"closed":[],"imported":true}`
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "x"); op.State != "abandoned" {
		t.Fatalf("imported grant without its request: %+v", op)
	}
}

func TestTakeoverMergesHistoriesAcrossIncarnations(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// 40 left x undecided, 41 imported and completed it, 42 takes over
	s.module.mu.Lock()
	s.module.kv[JournalPrefix(40)+"req/x"] = `{"version":1,"kind":"revision","host":"h1"}`
	s.module.kv[JournalPrefix(41)+"req/x"] = `{"version":1,"kind":"revision","host":"h1"}`
	s.module.kv[JournalPrefix(41)+"op/x"] = `{"version":1,"kind":"revision","host":"h1","state":"completed","revision":6}`
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	_, req := s.module.kv[JournalPrefix(42)+"req/x"]
	_, op := s.module.kv[JournalPrefix(42)+"op/x"]
	s.module.mu.Unlock()

	if req || op || s.agent.patches.n != 0 {
		t.Fatalf("a completed request ran again: req %v op %v, %d patches", req, op, s.agent.patches.n)
	}
}

// A standby promoted later can have a smaller gid: epochs order incarnations.
func TestIncarnationsAreOrderedByEpoch(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	// the old active mgr, gid 90, captured at epoch 5, closed the sessions
	g.gid, g.epoch = 90, 5
	if _, err := g.Close(ctx, wire.Close{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 90, Epoch: 5}); err != nil {
		t.Fatal(err)
	}

	// the promoted standby has gid 42, captured at epoch 8: it takes over and grants
	g.gid, g.epoch = 42, 8
	if f, err := g.Close(ctx, wire.Close{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 8}); err != nil || f != 8 {
		t.Fatalf("successor with a smaller gid: %d %v", f, err)
	}

	gr := probeGrant(2, "next", "aaaaaa")
	gr.Epoch = 8

	if op, err := g.Grant(ctx, gr); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("grant of the successor: %+v %v", op, err)
	}

	// the old one, with its larger gid, is closed
	g.gid, g.epoch = 90, 5

	old := probeGrant(3, "old", "bbbbbb")
	old.GID = 90

	if _, err := g.Grant(ctx, old); err == nil {
		t.Fatal("the closed incarnation granted")
	}
}

func TestImportFollowsEpochsNotGIDs(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// incarnation 90 (epoch 3) is a predecessor of 42 (epoch 5); 30 (epoch 9) is not
	s.module.mu.Lock()
	s.module.kv[JournalPrefix(90)+"takeover"] = `{"version":1,"epoch":3,"closed":[],"imported":true}`
	s.module.kv[JournalPrefix(90)+"req/p"] = `{"version":1,"kind":"revision","host":"h1"}`
	s.module.kv[JournalPrefix(30)+"takeover"] = `{"version":1,"epoch":9,"closed":[],"imported":true}`
	s.module.kv[JournalPrefix(30)+"req/q"] = `{"version":1,"kind":"revision","host":"h1"}`
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "p"); op.State != "completed" {
		t.Fatalf("request of the predecessor with a larger gid: %+v", op)
	}

	s.module.mu.Lock()
	_, q := s.module.kv[JournalPrefix(42)+"req/q"]
	s.module.mu.Unlock()

	if q {
		t.Fatal("imported from a later incarnation")
	}
}

func TestUncertainIsAskedAgain(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	// as if the agent had answered uncertain and decided it since
	op := s.op(t, "r1")
	op.State = "uncertain"

	b, _ := json.Marshal(op)

	s.module.mu.Lock()
	s.module.kv[JournalPrefix(42)+"op/r1"] = string(b)
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != "completed" {
		t.Fatalf("uncertain not asked again: %+v", op)
	}
}

func TestTheLeaderPublishesItsBaseline(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	raw := s.module.kv[JournalPrefix(42)+"takeover"]
	s.module.mu.Unlock()

	var to Takeover
	if json.Unmarshal([]byte(raw), &to) != nil || !to.Published || to.From != "cli" || to.FromSeq == 0 {
		t.Fatalf("takeover %s", raw)
	}

	// the same records, under the incarnation
	b := s.leader.bridge()

	own, _, err := s.leader.readRecords(ctx, b, "42")
	must(t, err)

	cli, _, err := s.leader.readRecords(ctx, b, "cli")
	must(t, err)

	for name, rec := range cli {
		if string(own[name]) != string(rec) {
			t.Errorf("record %s differs", name)
		}
	}

	// from now on the leader reads its own: a later CLI publication is not its state
	h, _ := s.st.Host("h1")
	h.Maintenance = true
	s.st.AddHost(h)
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != "completed" {
		t.Fatalf("revision from the leader's own state: %+v", op)
	}

	// a successor takes its baseline from this incarnation, not from "cli"
	s.leader.Channel.mu.Lock()
	s.leader.Channel.leader = &Leader{Mgr: "h0", GID: 30, Epoch: 9, At: time.Now()}
	s.leader.Channel.mu.Unlock()

	s.module.mu.Lock()
	s.module.own = "30" // the successor's module writes below its own incarnation
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 30, 9))

	s.module.mu.Lock()
	raw = s.module.kv[JournalPrefix(30)+"takeover"]
	s.module.mu.Unlock()

	if json.Unmarshal([]byte(raw), &to) != nil || to.From != "42" {
		t.Fatalf("successor's takeover %s", raw)
	}
}

func TestTheLeaderWaitsForTheHandoff(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.st.Sealed = false
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)

	if err := s.leader.Tick(ctx, 42, 5); !errors.Is(err, errRetry) {
		t.Fatalf("tick before the handoff: %v", err)
	}

	s.module.mu.Lock()
	_, published := s.module.kv[store.Prefix+"inc/42/manifest/"]
	n := 0

	for k := range s.module.kv {
		if strings.HasPrefix(k, store.Prefix+"inc/42/") {
			n++
		}
	}
	s.module.mu.Unlock()

	if published || n != 1 || s.agent.patches.n != 0 {
		t.Fatalf("the leader acted before the handoff: %d keys of its own, %d patches", n, s.agent.patches.n)
	}
}
