package orch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// fakeAgent serves /v1/suspend for one host with that host's agent
// certificate: waiting answers 202 that many times before the receipt.
type fakeAgent struct {
	mu       sync.Mutex
	session  string
	waiting  int
	posts    int
	gets     int
	srv      *httptest.Server
	revision int64
}

func (a *fakeAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if r.URL.Path != "/v1/suspend" || len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(http.StatusNotFound)

		return
	}

	if r.Method == http.MethodPost {
		var s wire.Suspend
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil || (a.session != "" && a.session != s.Session) {
			http.Error(w, "suspended already for recovery session "+a.session, http.StatusConflict)

			return
		}

		a.session = s.Session
		a.posts++
	} else {
		a.gets++
	}

	st := wire.SuspendState{Version: wire.Version, Session: a.session}
	if a.waiting > 0 {
		a.waiting--
		st.Waiting = []string{"job abc of operation op-1"}
		w.WriteHeader(http.StatusAccepted)
	} else {
		st.Receipt = &wire.SuspendReceipt{Version: wire.Version, Session: a.session, Host: "h1", Revision: a.revision, Unresolved: []wire.Operation{}, Intents: []wire.BridgeIntent{}}
	}

	_ = json.NewEncoder(w).Encode(st)
}

func suspendSetup(t *testing.T) (*Orch, state.Host, *fakeAgent) {
	t.Helper()

	f := talostest.New(t, images())
	o := fakeOrch(t, f)
	if err := o.setupAgent(context.Background(), "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	h := state.Host{Name: "h1", Addr: "127.0.0.1"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	o.St.AddHost(h)
	mon := state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1"}
	o.St.AddDaemon(mon)

	cs := containers.NewContainerStatus(containers.NamespaceName, o.St.DocName(mon))
	cs.TypedSpec().State = containers.ContainerStateRunning

	if err := f.St.Create(context.Background(), cs); err != nil {
		t.Fatal(err)
	}

	// a published state, as Open reads it again for the hosts
	if err := o.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}

	o.opened = true

	pair, err := tls.X509KeyPair([]byte(h.AgentCert), []byte(h.AgentKey))
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(o.St.Agent.CACert))

	a := &fakeAgent{revision: 7}
	a.srv = httptest.NewUnstartedServer(a)
	a.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	a.srv.StartTLS()
	t.Cleanup(a.srv.Close)

	oldAddr, oldPoll := agentAddr, suspendPoll
	agentAddr = func(state.Host) string { return a.srv.Listener.Addr().String() }
	suspendPoll = 10 * time.Millisecond

	t.Cleanup(func() { agentAddr, suspendPoll = oldAddr, oldPoll })

	return o, h, a
}

func TestSuspendWaitsForTheReceiptAndJournalsIt(t *testing.T) {
	o, _, a := suspendSetup(t)
	a.waiting = 2

	rec, err := o.Suspend(context.Background(), SuspendOptions{})
	if err != nil {
		t.Fatal(err)
	}

	if rec.Phase != state.PhaseSuspended || rec.Hosts["h1"].Receipt == nil || rec.Hosts["h1"].Receipt.Revision != 7 || a.posts != 1 || a.gets != 2 {
		t.Fatalf("journal %+v, %d posts, %d gets", rec, a.posts, a.gets)
	}

	// the journal is on disk; the same session continues, and a host with its
	// receipt is not asked again
	disk, err := state.LoadRecovery(o.St.FSID)
	if err != nil || disk == nil || disk.Session != rec.Session || disk.Hosts["h1"].Receipt == nil {
		t.Fatalf("on disk: %+v %v", disk, err)
	}

	again, err := o.Suspend(context.Background(), SuspendOptions{})
	if err != nil || again.Session != rec.Session || a.posts != 1 {
		t.Fatalf("again: %+v %v, %d posts", again, err, a.posts)
	}

	// the agent CA and image are kept locally for an offline suspension
	st, err := state.Load(o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	if st.Agent == nil || st.Agent.CACert != o.St.Agent.CACert || st.Agent.Image != o.St.Agent.Image {
		t.Fatalf("local copy: %+v %v", st.Agent, err)
	}
}

func TestAnAgentSuspendedForAnotherSessionStopsTheSuspension(t *testing.T) {
	o, h, a := suspendSetup(t)
	a.session = "11111111-2222-4333-8444-555555555555"

	if _, err := o.suspendAgent(context.Background(), h, "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f"); err == nil || errors.Is(err, errUnreachable) {
		t.Fatalf("another session: %v", err)
	}
}

func TestAnAgentThatDoesNotAnswerIsUnreachable(t *testing.T) {
	o, h, _ := suspendSetup(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := l.Addr().String()
	l.Close() //nolint:errcheck

	agentAddr = func(state.Host) string { return addr }

	old := unreachableAfter
	unreachableAfter = 50 * time.Millisecond

	t.Cleanup(func() { unreachableAfter = old })

	if _, err := o.suspendAgent(context.Background(), h, "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f"); !errors.Is(err, errUnreachable) {
		t.Fatalf("a closed port: %v", err)
	}
}

func TestNewSessionIsAUUID(t *testing.T) {
	s, err := newSession()
	if err != nil || len(s) != 36 || s[14] != '4' {
		t.Fatalf("%q %v", s, err)
	}
}

func TestAWrongAgentCertificateIsNoReasonToTakeTheNode(t *testing.T) {
	o, _, _ := suspendSetup(t)

	// the agent's certificate names h1: asking it as h2 fails verification
	if _, err := o.suspendAgent(context.Background(), state.Host{Name: "h2", Addr: "127.0.0.1"}, "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f"); err == nil || errors.Is(err, errUnreachable) {
		t.Fatalf("a certificate that does not verify: %v", err)
	}
}

func TestAnAnswerThatStallsIsAnAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("suspended"))
		w.(http.Flusher).Flush()
		time.Sleep(time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, code, err := callAgent(ctx, srv.Client(), http.MethodGet, srv.URL, nil)
	if err == nil || code != http.StatusConflict {
		t.Fatalf("a stalled body: %d %v", code, err)
	}
}

func TestSuspendHasNoDryRun(t *testing.T) {
	o, _, a := suspendSetup(t)
	o.Talos.DryRun = true

	if _, err := o.Suspend(context.Background(), SuspendOptions{}); err == nil || a.posts != 0 {
		t.Fatalf("a dry run suspended: %v, %d posts", err, a.posts)
	}

	if rec, err := state.LoadRecovery(o.St.FSID); err != nil || rec != nil {
		t.Fatalf("a dry run wrote a journal: %+v %v", rec, err)
	}
}

func TestAHostEnrolledMeanwhileIsSuspendedToo(t *testing.T) {
	o, _, _ := suspendSetup(t)
	ctx := context.Background()

	// an accepted `host add` of h2, not in the state yet: its enrollment record
	b, _ := json.Marshal(Enrollment{Version: 1, Name: "h2", Addr: "127.0.0.1"})
	if err := o.StoreBackend.SetMany(ctx, []store.KV{{Key: EnrollPrefix + "h2", Value: b}}); err != nil {
		t.Fatal(err)
	}

	// the fake agent answers as h1 only: h2 is asked, and its answer does not verify
	rec, err := o.Suspend(ctx, SuspendOptions{})
	if err == nil || !strings.Contains(err.Error(), "h2") || rec.Phase != state.PhaseSuspending || rec.Hosts["h1"].Receipt == nil {
		t.Fatalf("an enrolled host was not asked: %v, %+v", err, rec)
	}
}

func TestAnOfflineRetryKeepsTheHostsItFound(t *testing.T) {
	o, _, _ := suspendSetup(t)
	ctx := context.Background()

	// an earlier run found h2 through its enrollment and stopped before it;
	// the mons do not answer now
	rec := &state.Recovery{Schema: state.RecoverySchema, FSID: o.St.FSID, Session: "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f", Phase: state.PhaseSuspending,
		Hosts: map[string]*state.RecoveryHost{"h2": {Addr: "127.0.0.1"}}, Jobs: map[string]*state.RecoveryJob{}}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	o.opened = false

	got, err := o.Suspend(ctx, SuspendOptions{})
	if err == nil || !strings.Contains(err.Error(), "h2") || got.Phase != state.PhaseSuspending {
		t.Fatalf("a journaled host was skipped: %v, %+v", err, got)
	}
}
