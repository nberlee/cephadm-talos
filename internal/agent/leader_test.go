package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/siderolabs/talos/pkg/machinery/resources/block"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
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
	// ca issued the module's, the leader's and the agent's certificates
	ca testCA
}

func newLeaderSetup(t *testing.T) *leaderSetup {
	t.Helper()

	ca := newTestCA(t)

	appr, _ := json.Marshal(testApproval(t, 1))
	m := &fakeBridge{kv: map[string]string{}, outcomes: map[string]map[string]any{}, page: 1000, fsid: testFSID, approval: string(appr)}
	host, port := m.serve(t, ca, "h0")

	oldDial, oldBridge := dialPort, bridgePort
	dialPort, bridgePort = func() string { return port }, func() string { return port }

	t.Cleanup(func() { dialPort, bridgePort = oldDial, oldBridge })

	cc, ck := ca.pair(pki.RoleAgent, "h0", x509.ExtKeyUsageClientAuth, testFSID)
	clientTLS, err := ClientTLSConfig([]byte(ca.cert), []byte(cc), []byte(ck))
	must(t, err)

	ch, err := NewChannel(pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h0"})
	must(t, err)

	// the agent of h1, served over TLS with its server certificate, its node
	// pulling images
	tg := newTestGranter(t, &talostest.ImageService{Cache: map[string]string{}, Remote: map[string]string{}})
	sc, sk := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	srvTLS, err := TLSConfig([]byte(ca.cert), []byte(sc), []byte(sk))
	must(t, err)

	setup := &leaderSetup{agent: tg, ca: ca}
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
		ApprovalKey: testApprovalPub,
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

func TestARevisionOfAMaintenanceHostStartsNothing(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	h, _ := s.st.Host("h1")
	h.Maintenance = true
	s.st.AddHost(h)
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	op := s.op(t, "r1")
	if op.State != "completed" {
		t.Fatalf("revision of a host in maintenance: %+v", op)
	}

	for k := range op.Docs {
		if strings.HasPrefix(k, "ContainerConfig/") {
			t.Fatalf("a daemon granted on a host in maintenance: %+v", op)
		}
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

func (s *leaderSetup) accept(kind, daemon, host string, seq int64) LedgerEntry {
	id := fmt.Sprintf("op-%016x", seq)
	e := LedgerEntry{
		Key: fmt.Sprintf("cephadm-talos/ledger/%020d-%010d-%s", 5, seq, id),
		Op:  LedgerOp{Version: 1, ID: id, Kind: kind, Daemon: daemon, Host: host, GID: 42, Epoch: 5, Seq: seq},
	}

	s.module.mu.Lock()
	s.module.ledger = append(s.module.ledger, e)
	s.module.mu.Unlock()

	return e
}

func (s *leaderSetup) applied(t *testing.T) string {
	t.Helper()

	st, _, err := s.leader.clusterState(context.Background(), s.leader.bridge())
	must(t, err)

	return st.LedgerApplied
}

func TestLeaderRunsTheLedgerInOrder(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// the mon is on h1 first
	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != "completed" {
		t.Fatalf("revision %+v", op)
	}

	monDoc := "ceph-" + testFSID[:8] + "-mon-h1"
	addInstance(t, s.agent.fake, monDoc, 1)

	bad := s.accept("rm", "mgr.h1", "h1", 1)
	restart := s.accept(KindRestart, "mon.h1", "h1", 2)
	redeploy := s.accept(KindRedeploy, "mon.h1", "h1", 3)

	for range 4 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, bad.Op.ID); op.State != JournalFailed {
		t.Errorf("unknown kind: %+v", op)
	}

	if op := s.op(t, restart.Op.ID); op.State != "completed" {
		t.Fatalf("restart: %+v", op)
	}

	// the redeploy's revision changed nothing, then the restart ran
	if op := s.op(t, redeploy.Op.ID+".rev"); op.State != JournalNoChange {
		t.Errorf("redeploy's revision: %+v", op)
	}

	if op := s.op(t, redeploy.Op.ID); op.State != "completed" {
		t.Fatalf("redeploy: %+v", op)
	}

	if got := s.agent.fake.Restarted; len(got) != 2 || got[0] != monDoc+"-1" {
		t.Fatalf("restarted %v", got)
	}

	if got := s.applied(t); got != redeploy.Key {
		t.Fatalf("checkpoint %q", got)
	}

	// done is done: nothing runs again
	must(t, s.leader.Tick(ctx, 42, 5))

	if got := s.agent.fake.Restarted; len(got) != 2 {
		t.Fatalf("restarted again: %v", got)
	}
}

func TestLedgerOperationsThatCannotRunEnd(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5)) // the takeover closes the earlier sessions

	// no such document on the node, no such daemon, a refused confirmation:
	// each ends, and the next one runs in the same tick
	first := s.accept(KindRestart, "mon.h1", "h1", 1)
	second := s.accept(KindRestart, "mon.h0", "h0", 2)
	third := s.accept(KindRedeploy, "mon.h1", "h1", 3)

	s.agent.refuse = errors.New("no mgr")

	must(t, s.leader.Tick(ctx, 42, 5))

	for _, c := range []struct {
		e     LedgerEntry
		state string
	}{{first, JournalFailed}, {second, JournalFailed}, {third, JournalFailed}} {
		if op := s.op(t, c.e.Op.ID); op.State != c.state {
			t.Errorf("%s: %+v", c.e.Op.ID, op)
		}
	}

	if op := s.op(t, third.Op.ID+".rev"); op.State != wire.OpRefused {
		t.Errorf("redeploy's revision: %+v", op)
	}

	if got := s.applied(t); got != third.Key {
		t.Fatalf("checkpoint %q", got)
	}
}

// withCA makes the fake module issue mgr certificates of a CA the agent and
// the leader trust.
func (s *leaderSetup) withCA(t *testing.T) {
	t.Helper()

	ca := newTestCA(t)
	s.st.Agent = &state.Agent{CACert: ca.cert}
	publish(t, s.leader, s.module, s.st)

	s.module.mu.Lock()
	s.module.ca, s.module.active = &ca, "h0"
	s.module.mu.Unlock()

	s.agent.Node.Policy.CACert, s.leader.CACert = ca.cert, ca.cert
}

func TestLeaderAddsAndRemovesAMgr(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()
	s.withCA(t)

	must(t, s.leader.Tick(ctx, 42, 5)) // the takeover closes the earlier sessions

	add := s.accept(KindAddDaemon, "mgr.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add: %+v", op)
	}

	// the mgr, its module files and its certificates are on h1; its keys are the attempt's
	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	h, _ := st.Host("h1")
	if _, ok := st.Find("mgr.h1"); !ok || !strings.HasPrefix(h.MgrKeys, add.Op.ID+"/") || h.MgrServerCert == "" {
		t.Fatalf("state: %+v", h)
	}

	rev := s.op(t, add.Op.ID+".rev")
	mgrDoc := "ContainerConfig/ceph-" + testFSID[:8] + "-mgr-h1"

	// with its guard (plan 04, step 5, item 2b)
	guardDoc := "ContainerConfig/ceph-" + testFSID[:8] + "-mgr-guard-h1"
	if _, ok := rev.Docs[mgrDoc]; !ok || rev.Docs[guardDoc] == "" || rev.Docs["EtcFileConfig/ceph/talos/mgr-server.key"] == "" {
		t.Fatalf("granted %v", rev.Docs)
	}

	if inv := s.inventory(t); !strings.Contains(inv, `"daemon_id":"h1","service_name":"mgr"`) {
		t.Fatalf("inventory %s", inv)
	}

	// not the active one: out of the state, off the host, then retired
	s.module.mu.Lock()
	s.module.active = "h1"
	s.module.mu.Unlock()

	refused := s.accept(KindRemoveDaemon, "mgr.h1", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, refused.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "active") {
		t.Fatalf("removal of the active mgr: %+v", op)
	}

	s.module.mu.Lock()
	s.module.active = "h0"
	s.module.mu.Unlock()

	rm := s.accept(KindRemoveDaemon, "mgr.h1", "h1", 3)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, rm.Op.ID); op.State != "completed" {
		t.Fatalf("removal: %+v", op)
	}

	if rev := s.op(t, rm.Op.ID+".rev"); rev.Docs[mgrDoc] != "" || len(rev.Docs) == 0 {
		t.Fatalf("removal grant %v", rev.Docs)
	}

	// the guard removed with its mgr, in the same grant
	if rev, ok := s.op(t, rm.Op.ID+".rev").Docs[guardDoc]; !ok || rev != "" {
		t.Fatalf("removal grant: guard %q %t", rev, ok)
	}

	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned[mgrDoc] != "" || rep.Owned[guardDoc] != "" || rep.Owned["EtcFileConfig/ceph/talos/mgr-server.key"] != "" {
		t.Fatalf("still owned: %+v %v", rep.Owned, err)
	}

	s.module.mu.Lock()
	retired := slices.Clone(s.module.retired)
	revoked := s.module.certs["retire "+rm.Op.ID]
	s.module.mu.Unlock()

	if !slices.Equal(retired, []string{"retire " + rm.Op.ID}) {
		t.Fatalf("retired %v", retired)
	}

	// the mgr's certificates, journaled before the state dropped them, go with
	// the retirement for their revocation (plan 04, step 3)
	if !slices.Equal(revoked, []string{h.MgrServerCert, h.MgrClientCert}) {
		t.Fatalf("revoked with the retirement: %d certificates", len(revoked))
	}

	// a host with daemons is not removed
	host := s.accept(KindRemoveHost, "", "h1", 4)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, host.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "mon.h1") {
		t.Fatalf("host removal: %+v", op)
	}
}

func TestLeaderAddsAMonThatJoinsFirst(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// a cluster whose mon is on h0: h1 gets a second one
	s.st.RemoveDaemon(state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1"})
	s.st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h0", Host: "h0", DeployID: "0123456789abcdef"})
	publish(t, s.leader, s.module, s.st)

	must(t, s.leader.Tick(ctx, 42, 5))

	add := s.accept(KindAddDaemon, "mon.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// granted, joining: ceph.conf on h1 does not name it yet, and nothing ends
	// before it is in the quorum
	rev := s.op(t, add.Op.ID+".rev")
	if _, ok := rev.Docs["ContainerConfig/ceph-"+testFSID[:8]+"-mon-h1"]; !ok || rev.State != "completed" {
		t.Fatalf("joining mon: %+v", rev)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, _ := st.Find("mon.h1"); !d.Joining || len(st.MonAddrs()) != 1 {
		t.Fatalf("state %+v %v", d, st.MonAddrs())
	}

	s.module.mu.Lock()
	s.module.quorum = []string{"h0", "h1"}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	st, _, err = s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, _ := st.Find("mon.h1"); d.Joining || len(st.MonAddrs()) != 2 {
		t.Fatalf("after joining %+v %v", d, st.MonAddrs())
	}

	// ceph.conf goes to h0 first, whose agent this test does not serve: the
	// operation waits and holds the ledger
	s.module.mu.Lock()
	_, decided := s.module.kv[JournalPrefix(42)+"op/"+add.Op.ID]
	s.module.mu.Unlock()

	if decided {
		t.Fatal("completed before ceph.conf reached every host")
	}
}

func (s *leaderSetup) inventory(t *testing.T) string {
	t.Helper()

	recs, _, err := s.leader.readRecords(context.Background(), s.leader.bridge(), "42")
	must(t, err)

	return string(recs["inventory"])
}

func TestAResumedRemovalChecksTheActiveMgr(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()
	s.withCA(t)

	must(t, s.leader.Tick(ctx, 42, 5))

	add := s.accept(KindAddDaemon, "mgr.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add: %+v", op)
	}

	// a predecessor published the removal, then stopped before granting it;
	// meanwhile mgr.h1 became the active one
	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		d, _ := st.Find("mgr.h1")
		st.RemoveDaemon(d)

		return nil
	}))

	s.module.mu.Lock()
	s.module.active = "h1"
	s.module.mu.Unlock()

	rm := s.accept(KindRemoveDaemon, "mgr.h1", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, rm.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "active") {
		t.Fatalf("removal of the active mgr: %+v", op)
	}

	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned["ContainerConfig/ceph-"+testFSID[:8]+"-mgr-h1"] == "" {
		t.Fatalf("its document was removed: %v", err)
	}
}

func TestLeaderCreatesAnOSD(t *testing.T) {
	s, create := creationSetup(t)
	ctx := context.Background()
	deploy := deployOf(create.Op.ID)

	// bound, recorded, and the preparation job granted and running
	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, ok := st.Find("osd.h1-sdb"); !ok || d.DeployID != deploy || d.DiskSerial != "QM00003" || d.OSDID != nil {
		t.Fatalf("deployment %+v", d)
	}

	uuid := "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f"
	finishJob(t, s.agent, create.Op.ID+".prep", 0, "osd_id 5\nosd_uuid "+uuid)

	must(t, s.leader.Tick(ctx, 42, 5))

	// the OSD and the job's acknowledgement granted; not confirmed before it is up
	if op := s.op(t, create.Op.ID+".rev"); op.State != "completed" || op.Docs["ContainerConfig/ceph-"+testFSID[:8]+"-osd-h1-sdb"] == "" {
		t.Fatalf("revision %+v", op)
	}

	if op, _, _ := s.agent.readOp(create.Op.ID + ".prep"); !op.Acked {
		t.Fatalf("the job's result is not acknowledged: %+v", op)
	}

	s.module.mu.Lock()
	s.module.osds = []OSD{{ID: 5, UUID: uuid, Up: true}}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, create.Op.ID); op.State != "completed" {
		t.Fatalf("creation %+v", op)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Contains(calls, "bind disk "+create.Op.ID) || !slices.Contains(calls, "confirm osd "+create.Op.ID) {
		t.Fatalf("module calls %v", calls)
	}

	// address settings an earlier OSD of id 5 left were cleared before its
	// daemon was granted (plan 04, step 5), once
	if i := slices.Index(calls, "clear osd addr "+create.Op.ID+" 5"); i < 0 || slices.Index(calls, "confirm osd "+create.Op.ID) < i ||
		slices.Index(calls[i+1:], calls[i]) >= 0 {
		t.Fatalf("module calls %v", calls)
	}

	st, _, err = s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, _ := st.Find("osd.h1-sdb"); d.OSDID == nil || *d.OSDID != 5 || d.OSDUUID != uuid {
		t.Fatalf("osd %+v", d)
	}
}

// creationSetup is a leader with h1's disk sdb approved for one preparation
// and an accepted creation of an OSD on it, after its first tick.
func creationSetup(t *testing.T) (*leaderSetup, LedgerEntry) {
	t.Helper()

	s := newLeaderSetup(t)
	ctx := context.Background()

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, s.agent.fake.St.Create(ctx, disk))

	appr, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: testFSID, Serial: 2, Images: []string{testImage},
		Disks: []approval.Disk{{Host: "h1", Serial: "QM00003", Action: approval.Prepare, Since: 2}}})
	must(t, err)

	b, _ := json.Marshal(appr)
	s.module.mu.Lock()
	s.module.approval = string(b)
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	create := s.accept(KindCreateOSD, "", "h1", 1)
	create.Op.Device = "/dev/sdb"
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = create
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	return s, create
}

func TestAFailedPreparationClosesTheCreation(t *testing.T) {
	s, create := creationSetup(t)
	ctx := context.Background()

	finishJob(t, s.agent, create.Op.ID+".prep", 1, "ceph-volume failed")
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, create.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "failed") {
		t.Fatalf("creation %+v", op)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Contains(calls, "close create "+create.Op.ID) {
		t.Fatalf("not closed: %v", calls)
	}

	// the job's outcome acknowledged, and the deployment gone: the disk can be tried again
	if op, _, _ := s.agent.readOp(create.Op.ID + ".prep"); !op.Acked {
		t.Fatalf("the failed job is not acknowledged: %+v", op)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if _, ok := st.Find("osd.h1-sdb"); ok {
		t.Fatal("the deployment of a failed preparation stayed")
	}
}

func TestLeaderRemovesAnOSDAndZapsItsDisk(t *testing.T) {
	testRemoval(t, 0)
}

func TestAFailedZapEndsTheRemovalPurged(t *testing.T) {
	testRemoval(t, 67)
}

func TestAResolvedZapFailsTheRemoval(t *testing.T) {
	testRemoval(t, -1)
}

func testRemoval(t *testing.T, zapRC int) {
	t.Helper()

	s := newLeaderSetup(t)
	ctx := context.Background()

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, s.agent.fake.St.Create(ctx, disk))

	// an OSD on h1, deployed
	id, uuid := 3, "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f"
	s.st.AddDaemon(state.Daemon{Type: state.TypeOSD, ID: "h1-sdb", Host: "h1", OSDID: &id, OSDUUID: uuid, DeployID: "0123456789abcdef",
		DiskSerial: "QM00003", DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"})
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	osdDoc := "ContainerConfig/ceph-" + testFSID[:8] + "-osd-h1-sdb"
	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned[osdDoc] == "" {
		t.Fatalf("the OSD is not deployed: %v", err)
	}

	rm := s.accept(KindRemoveOSD, "osd.3", "h1", 1)
	rm.Op.UUID, rm.Op.Zap = uuid, true
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = rm
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	// out, drained, its document off the node, retired; the zap running
	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned[osdDoc] != "" {
		t.Fatalf("the OSD's document stayed: %v", err)
	}

	zap := s.op(t, rm.Op.ID+".zap")
	if zap.State != JournalGranting {
		t.Fatalf("zap %+v", zap)
	}

	// the removal waits for its zap
	s.module.mu.Lock()
	_, ended := s.module.kv[JournalPrefix(42)+"op/"+rm.Op.ID]
	s.module.mu.Unlock()

	if ended {
		t.Fatal("the removal ended before its zap")
	}

	if zapRC < 0 {
		// killed between its start and its result, then resolved by the operator (plan 04, step 4)
		uncertainJob(t, s.agent, rm.Op.ID+".zap")
		must(t, s.leader.Tick(ctx, 42, 5))

		if _, err := s.agent.Resolve(ctx, rm.Op.ID+".zap"); err != nil {
			t.Fatal(err)
		}
	} else {
		finishJob(t, s.agent, rm.Op.ID+".zap", zapRC, "zap output")
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	want := "completed"
	if zapRC != 0 {
		want = JournalFailed // purged, not zapped
	}

	if op := s.op(t, rm.Op.ID); op.State != want {
		t.Fatalf("removal %+v", op)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	for _, c := range []string{"osd out ", "drain ", "retire "} {
		if !slices.Contains(calls, c+rm.Op.ID) {
			t.Errorf("no %s: %v", c, calls)
		}
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if _, ok := st.Find("osd.h1-sdb"); ok {
		t.Fatal("the OSD stayed in the state")
	}

	if op, _, _ := s.agent.readOp(rm.Op.ID + ".zap"); !op.Acked {
		t.Fatalf("the zap is not acknowledged: %+v", op)
	}
}

func TestAnOperationFailingTooLongIsGivenUp(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()
	s.withCA(t)

	must(t, s.leader.Tick(ctx, 42, 5))

	// the module refuses the mgr's certificate every time
	s.module.mu.Lock()
	s.module.refuse = "mgr cert"
	s.module.mu.Unlock()

	add := s.accept(KindAddDaemon, "mgr.h1", "h1", 1)

	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	_, ended := s.module.kv[JournalPrefix(42)+"op/"+add.Op.ID]
	s.module.mu.Unlock()

	if ended {
		t.Fatal("given up at once")
	}

	// failing since longer than stuckAfter (the leader's own clock stays fresh)
	s.leader.failing[add.Op.ID] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "failing for") {
		t.Fatalf("the add was not given up: %+v", op)
	}
}

func TestLeaderRemovesAMonFromTheMonmapFirst(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// mons on h0 and h1: the one on h1 goes
	s.st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h0", Host: "h0", DeployID: "0123456789abcdef"})
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	monDoc := "ContainerConfig/ceph-" + testFSID[:8] + "-mon-h1"
	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned[monDoc] == "" {
		t.Fatalf("the mon is not deployed: %v", err)
	}

	rm := s.accept(KindRemoveDaemon, "mon.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// out of the monmap before its document went; ceph.conf next, on every host
	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	_, decided := s.module.kv[JournalPrefix(42)+"op/"+rm.Op.ID]
	s.module.mu.Unlock()

	if !slices.Equal(calls, []string{"mon rm " + rm.Op.ID}) {
		t.Fatalf("module calls %v", calls)
	}

	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned[monDoc] != "" {
		t.Fatalf("the mon's document stayed: %v", err)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if _, ok := st.Find("mon.h1"); ok || len(st.MonAddrs()) != 1 {
		t.Fatalf("state still has the mon: %v", st.MonAddrs())
	}

	// ceph.conf goes to h0 first, whose agent this test does not serve: no
	// retirement before it reached every host
	if decided {
		t.Fatal("completed before ceph.conf reached every host")
	}
}

func TestMaintenanceStopsAndStartsAHost(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()
	s.withCA(t)

	// h1 runs a mon and the active mgr, deployed
	must(t, s.leader.Tick(ctx, 42, 5))

	add := s.accept(KindAddDaemon, "mgr.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add: %+v", op)
	}

	s.module.mu.Lock()
	s.module.active, s.module.retired = "h1", nil
	s.module.mu.Unlock()

	daemonDocs := func() []string {
		rep, err := s.agent.Node.Report(ctx)
		must(t, err)

		var out []string

		for k := range rep.Owned {
			if strings.HasPrefix(k, "ContainerConfig/ceph-"+testFSID[:8]+"-m") {
				out = append(out, k)
			}
		}

		slices.Sort(out)

		return out
	}

	// the mon, the mgr and its guard (plan 04, step 5, item 2b)
	if len(daemonDocs()) != 3 {
		t.Fatalf("documents before: %v", daemonDocs())
	}

	// a revision request for h1 waits while its maintenance is in progress
	enter := s.accept(KindEnterMaint, "", "h1", 2)
	s.request("r9", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	_, held := s.module.kv[JournalPrefix(42)+"op/r9"]
	s.module.mu.Unlock()

	if held {
		t.Fatal("a revision request ran during the maintenance")
	}

	// checked, then the active mgr failed over by its gid, recorded first; nothing stopped yet
	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Equal(calls, []string{"ok to stop " + enter.Op.ID, "mgr fail " + enter.Op.ID + " 42"}) {
		t.Fatalf("calls %v", calls)
	}

	if f := s.op(t, enter.Op.ID+".fail"); f.MgrGID != 42 || len(daemonDocs()) != 3 {
		t.Fatalf("mgr fail record %+v, documents %v", f, daemonDocs())
	}

	// the successor finds the active mgr elsewhere and goes on
	s.module.mu.Lock()
	s.module.active, s.module.retired = "h0", nil
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, enter.Op.ID); op.State != "completed" || len(daemonDocs()) != 0 {
		t.Fatalf("enter: %+v, documents %v", op, daemonDocs())
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if h, _ := st.Host("h1"); !h.Maintenance || h.NoOut {
		t.Fatalf("host after enter: %+v", h)
	}

	if _, ok := st.Find("mgr.h1"); !ok {
		t.Fatal("the daemons left the state")
	}

	// the exit starts the mon first and waits for it in the quorum (the mgr's
	// guard is held with its mgr)
	exit := s.accept(KindExitMaint, "", "h1", 3)
	must(t, s.leader.Tick(ctx, 42, 5))

	if got := daemonDocs(); len(got) != 1 || !strings.Contains(got[0], "-mon-") {
		t.Fatalf("documents with the mon not in the quorum: %v", got)
	}

	s.module.mu.Lock()
	s.module.quorum = []string{"h1"}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, exit.Op.ID); op.State != "completed" || len(daemonDocs()) != 3 {
		t.Fatalf("exit: %+v, documents %v", op, daemonDocs())
	}

	s.module.mu.Lock()
	calls = slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Equal(calls, []string{"ok to stop " + enter.Op.ID, "maintained " + exit.Op.ID}) {
		t.Fatalf("calls %v", calls)
	}
}

func TestMaintenanceOfAnOSDHostSetsNoout(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, s.agent.fake.St.Create(ctx, disk))

	id, uuid := 3, "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f"
	s.st.AddDaemon(state.Daemon{Type: state.TypeOSD, ID: "h1-sdb", Host: "h1", OSDID: &id, OSDUUID: uuid, DeployID: "0123456789abcdef",
		DiskSerial: "QM00003", DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"})
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	s.module.active = "h0"
	s.module.mu.Unlock()

	// forced: Ceph's checks still run (force overrides neither)
	enter := s.accept(KindEnterMaint, "", "h1", 1)
	enter.Op.Force = true
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = enter
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, enter.Op.ID); op.State != "completed" {
		t.Fatalf("enter: %+v", op)
	}

	s.module.mu.Lock()
	s.module.quorum = []string{"h1"}
	s.module.mu.Unlock()

	exit := s.accept(KindExitMaint, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	// noout stays until the OSD is up again
	s.module.mu.Lock()
	_, ended := s.module.kv[JournalPrefix(42)+"op/"+exit.Op.ID]
	s.module.osds = []OSD{{ID: 3, UUID: uuid, Up: true}}
	s.module.mu.Unlock()

	if ended {
		t.Fatal("the exit ended before the OSD was up")
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	want := []string{"ok to stop " + enter.Op.ID, "noout set " + enter.Op.ID, "noout unset " + exit.Op.ID, "maintained " + exit.Op.ID}
	if op := s.op(t, exit.Op.ID); op.State != "completed" || !slices.Equal(calls, want) {
		t.Fatalf("exit: %+v, calls %v", op, calls)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if h, _ := st.Host("h1"); h.Maintenance || h.NoOut {
		t.Fatalf("host after exit: %+v", h)
	}
}

func TestAnExitAfterARefusedEnterStopsNothing(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()
	s.withCA(t)

	must(t, s.leader.Tick(ctx, 42, 5))

	add := s.accept(KindAddDaemon, "mgr.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add: %+v", op)
	}

	owned := func() int {
		rep, err := s.agent.Node.Report(ctx)
		must(t, err)

		return len(rep.Owned)
	}

	before := owned()

	// the enter never got past its checks: the exit's mon phase leaves the mgr running
	exit := s.accept(KindExitMaint, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if owned() != before {
		t.Fatalf("documents %d, want %d", owned(), before)
	}

	s.module.mu.Lock()
	s.module.quorum = []string{"h1"}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, exit.Op.ID); op.State != "completed" || owned() != before {
		t.Fatalf("exit: %+v, documents %d", op, owned())
	}
}

func TestRevisionRequestsWaitWithoutTheLedger(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// the takeover's import reads the ledger's snapshot too
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	s.module.refuse = "ledger"
	s.module.mu.Unlock()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	_, ran := s.module.kv[JournalPrefix(42)+"op/r1"]
	s.module.refuse = ""
	s.module.mu.Unlock()

	if ran {
		t.Fatal("a revision request ran without knowing whether a maintenance is in progress")
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != "completed" {
		t.Fatalf("r1: %+v", op)
	}
}

func TestAResumedEnterChecksAgainBeforeItStops(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.module.mu.Lock()
	s.module.active = "h0"
	s.module.mu.Unlock()

	// a predecessor marked h1 and stopped before its stop grant
	h, _ := s.st.Host("h1")
	h.Maintenance = true
	s.st.AddHost(h)
	publish(t, s.leader, s.module, s.st)

	enter := s.accept(KindEnterMaint, "", "h1", 1)
	s.module.mu.Lock()
	s.module.refuse = "ok to stop"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	_, granted := s.module.kv[JournalPrefix(42)+"op/"+enter.Op.ID+".rev"]
	s.module.mu.Unlock()

	if granted {
		t.Fatal("stopped without Ceph's checks")
	}
}

func TestAFailedEnterUnmarksTheHost(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.module.mu.Lock()
	s.module.active = "h0"
	s.module.mu.Unlock()

	h, _ := s.st.Host("h1")
	h.Maintenance = true
	s.st.AddHost(h)
	publish(t, s.leader, s.module, s.st)

	enter := s.accept(KindEnterMaint, "", "h1", 1)
	s.module.mu.Lock()
	s.module.refuse = "ok to stop"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	// refused for longer than stuckAfter: failed, and h1 no longer marked
	s.leader.failing[enter.Op.ID] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, enter.Op.ID); op.State != JournalFailed {
		t.Fatalf("enter: %+v", op)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if h, _ := st.Host("h1"); h.Maintenance {
		t.Fatal("h1 stays marked: a revision would stop its daemons without the checks")
	}
}

func TestPowercycleStopsRebootsAndStarts(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	s.module.mu.Lock()
	s.module.active, s.module.quorum = "h0", []string{"h0", "h1"}
	s.module.mu.Unlock()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	pc := s.accept(KindPowercycle, "", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// stopped, the reboot granted: started until the node runs another boot
	if s.agent.fake.Reboots != 1 {
		t.Fatalf("%d reboots", s.agent.fake.Reboots)
	}

	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.BootID != "boot-2" {
		t.Fatalf("report after the reboot: %+v %v", rep, err)
	}

	// the agent starts again on the new boot and decides the reboot; the mon
	// comes back first and is waited for, its stop not run again meanwhile
	must(t, s.agent.Reconcile(ctx))

	s.module.mu.Lock()
	s.module.quorum = []string{"h0"}
	s.module.mu.Unlock()

	monDoc := "ContainerConfig/ceph-" + testFSID[:8] + "-mon-h1"

	for i := 0; i < 3; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))

		if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned[monDoc] == "" {
			t.Fatalf("tick %d: the mon is not there while it is waited for: %v", i, err)
		}
	}

	s.module.mu.Lock()
	s.module.quorum = []string{"h0", "h1"}
	s.module.mu.Unlock()

	for i := 0; i < 2; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	op := s.op(t, pc.Op.ID)
	if op.State != "completed" || s.agent.fake.Reboots != 1 {
		t.Fatalf("powercycle: %+v, %d reboots", op, s.agent.fake.Reboots)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Equal(calls, []string{"ok to stop " + pc.Op.ID, "maintained " + pc.Op.ID}) {
		t.Fatalf("calls %v", calls)
	}

	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned["ContainerConfig/ceph-"+testFSID[:8]+"-mon-h1"] == "" {
		t.Fatalf("the mon did not come back: %v", err)
	}
}

func TestAnUpgradeProbesAndStepsDaemonByDaemon(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	target := "quay.io/ceph/ceph@sha256:" + strings.Repeat("cd", 32)

	appr, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: testFSID, Serial: 2, Images: []string{testImage, target}})
	must(t, err)

	b, _ := json.Marshal(appr)

	s.module.mu.Lock()
	s.module.approval, s.module.active, s.module.quorum = string(b), "h0", []string{"h1"}
	s.module.mu.Unlock()

	s.st.CephVersion, s.st.Arch = "20.2.4", "x86_64"
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	monName := "ceph-" + testFSID[:8] + "-mon-h1"
	addInstance(t, s.agent.fake, monName, 1)

	before, err := s.agent.Node.Report(ctx)
	must(t, err)

	up := s.accept(KindUpgrade, "", "", 1)
	up.Op.Image = target
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = up
	s.module.mu.Unlock()

	// the probe on the mon's host; its result gives the version and architecture
	must(t, s.leader.Tick(ctx, 42, 5))
	finishJob(t, s.agent, up.Op.ID+".probe", 0, "ceph version 20.2.5 (0123) tentacle (stable)\narch x86_64")

	for i := 0; i < 3; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, up.Op.ID); op.State != "completed" {
		t.Fatalf("start: %+v", op)
	}

	monDoc := "ContainerConfig/ceph-" + testFSID[:8] + "-mon-h1"

	// the mon's step: its image set, its host's revision granted; it waits for
	// a newer instance, then for the mon in the quorum
	for i := 0; i < 3; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if st, _, err := s.leader.clusterState(ctx, s.leader.bridge()); err != nil || st.Upgrade == nil || st.Upgrade.Step != monName {
		t.Fatalf("the step ended without a new instance: %+v %v", st.Upgrade, err)
	}

	addInstance(t, s.agent.fake, monName, 2)

	// running the target: its status has the target's digest
	cs := containers.NewContainerStatus(containers.NamespaceName, monName)
	cs.TypedSpec().State, cs.TypedSpec().Image = containers.ContainerStateRunning, "sha256:"+strings.Repeat("cd", 32)
	must(t, s.agent.fake.St.Create(ctx, cs))

	for i := 0; i < 4; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	after, err := s.agent.Node.Report(ctx)
	must(t, err)

	if before.Owned[monDoc] == after.Owned[monDoc] {
		t.Fatal("the mon's document did not change")
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if st.Upgrade != nil || st.Image != target || st.CephVersion != "20.2.5" {
		t.Fatalf("after the upgrade: %+v %s %s", st.Upgrade, st.Image, st.CephVersion)
	}

	if d, _ := st.Find("mon.h1"); d.Image != "" {
		t.Fatalf("the mon keeps its own image: %+v", d)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Contains(calls, "upgrade done "+up.Op.ID) {
		t.Fatalf("calls %v", calls)
	}
}

func TestAnUnapprovedUpgradeIsRefusedAndControlsChangeTheRecord(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	target := "quay.io/ceph/ceph@sha256:" + strings.Repeat("ef", 32)

	s.module.mu.Lock()
	s.module.active = "h0"
	s.module.mu.Unlock()

	up := s.accept(KindUpgrade, "", "", 1)
	up.Op.Image = target
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = up
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, up.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "approved") {
		t.Fatalf("unapproved: %+v", op)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Equal(calls, []string{"upgrade refused " + up.Op.ID}) {
		t.Fatalf("calls %v", calls)
	}

	// the controls of an upgrade in progress change its record alone
	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		st.Upgrade = &state.Upgrade{Op: "op-00000000000000aa", Image: target, Version: "20.2.5", Done: []string{}}

		return nil
	}))

	control := func(kind string, seq int64) {
		e := s.accept(kind, "", "", seq)
		e.Op.Upgrade = "op-00000000000000aa"
		s.module.mu.Lock()
		s.module.ledger[len(s.module.ledger)-1] = e
		s.module.mu.Unlock()
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	upgrade := func() *state.Upgrade {
		st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
		must(t, err)

		return st.Upgrade
	}

	control(KindUpPause, 2)

	if u := upgrade(); u == nil || !u.Paused || u.Step != "" {
		t.Fatalf("paused: %+v", u)
	}

	control(KindUpResume, 3)

	if u := upgrade(); u == nil || u.Paused {
		t.Fatalf("resumed: %+v", u)
	}

	// a stop with a step in progress ends with that step (one not granted is dropped)
	control(KindUpStop, 4)
	must(t, s.leader.Tick(ctx, 42, 5))
	must(t, s.leader.Tick(ctx, 42, 5))

	if u := upgrade(); u != nil {
		t.Fatalf("stopped: %+v", u)
	}
}

func TestLeaderAddsAnEnrolledHost(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// h1 is enrolled and owned by its agent, not a host of the state yet
	h, _ := s.st.Host("h1")
	for _, d := range s.st.DaemonsOf("", "h1") {
		s.st.RemoveDaemon(d)
	}

	s.st.RemoveHost("h1")
	publish(t, s.leader, s.module, s.st)

	s.module.mu.Lock()
	s.module.active = "h0"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	add := s.accept(KindAddHost, "", "h1", 1)
	add.Op.Addr, add.Op.AgentCert, add.Op.AgentClientCert, add.Op.Labels = h.Addr, "-----BEGIN CERTIFICATE-----a", "-----BEGIN CERTIFICATE-----b", []string{"rgw"}
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = add
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add host: %+v", op)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if got, ok := st.Host("h1"); !ok || got.AgentCert != add.Op.AgentCert || !slices.Equal(got.Labels, []string{"rgw"}) {
		t.Fatalf("host: %+v", got)
	}

	// its first revision: ceph.conf
	if rep, err := s.agent.Node.Report(ctx); err != nil || rep.Owned["EtcFileConfig/ceph/ceph.conf"] == "" {
		t.Fatalf("no ceph.conf on the new host: %v", err)
	}
}
