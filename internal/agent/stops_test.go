package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/api/common"
	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/resources/runtime"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

func seqEv(seq string, action machine.SequenceEvent_Action, code *common.Code) *machine.SequenceEvent {
	ev := &machine.SequenceEvent{Sequence: seq, Action: action}
	if code != nil {
		ev.Error = &common.Error{Code: *code}
	}

	return ev
}

func code(c common.Code) *common.Code { return &c }

func TestAStopIsCancelledOnlyOnEvidence(t *testing.T) {
	t0 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

	// a reboot cancelled: cancelled once no stop sequence started for 60 seconds
	var tr stopTracker
	if tr.stageChanged(runtime.MachineStageRunning) || !tr.stageChanged(runtime.MachineStageRebooting) || tr.stageChanged(runtime.MachineStageRebooting) {
		t.Fatal("the stop stage signals once")
	}

	// an agent starting on a boot whose stage stayed in a stop stage (after a
	// cancelled sequence) reports nothing: the first stage is the baseline
	var restarted stopTracker
	if restarted.stageChanged(runtime.MachineStageRebooting) {
		t.Fatal("the first stage seen signalled")
	}

	if !tr.sequence(seqEv("reboot", machine.SequenceEvent_START, nil), t0) {
		t.Fatal("a START signals")
	}

	tr.sequence(seqEv("reboot", machine.SequenceEvent_STOP, nil), t0.Add(time.Second))
	tr.sequence(seqEv("reboot", machine.SequenceEvent_NOOP, code(common.Code_CANCELED)), t0.Add(time.Second))

	if tr.cancelled(t0.Add(59 * time.Second)) {
		t.Fatal("cancelled before 60 seconds without a START")
	}

	if !tr.cancelled(t0.Add(60 * time.Second)) {
		t.Fatal("not cancelled after 60 seconds")
	}

	// a later reboot on the same boot changes no stage: its START signals again
	if !tr.sequence(seqEv("reboot", machine.SequenceEvent_START, nil), t0.Add(2*time.Minute)) || tr.cancelled(t0.Add(10*time.Minute)) {
		t.Fatal("a later START re-arms the stop")
	}

	// a reboot replacing a reboot: the first's cancellation is no evidence
	var rr stopTracker
	rr.sequence(seqEv("reboot", machine.SequenceEvent_START, nil), t0)
	rr.sequence(seqEv("reboot", machine.SequenceEvent_START, nil), t0.Add(time.Second))
	rr.sequence(seqEv("reboot", machine.SequenceEvent_NOOP, code(common.Code_CANCELED)), t0.Add(time.Second))

	if rr.cancelled(t0.Add(time.Hour)) {
		t.Fatal("a replaced reboot counted as cancelled")
	}

	// any other outcome (FATAL: Talos reboots) is never evidence
	var ft stopTracker
	ft.sequence(seqEv("shutdown", machine.SequenceEvent_START, nil), t0)
	ft.sequence(seqEv("shutdown", machine.SequenceEvent_NOOP, code(common.Code_FATAL)), t0)

	if ft.cancelled(t0.Add(time.Hour)) {
		t.Fatal("a failed shutdown counted as cancelled")
	}

	// a sequence that never started (LOCKED) and other sequences change nothing
	var lt stopTracker
	if lt.sequence(seqEv("reboot", machine.SequenceEvent_NOOP, code(common.Code_LOCKED)), t0) ||
		lt.sequence(seqEv("boot", machine.SequenceEvent_START, nil), t0) || lt.cancelled(t0.Add(time.Hour)) {
		t.Fatal("a locked or non-stop sequence counted")
	}

	// no timer: a stop signalled by its stage alone never ends by itself
	var st stopTracker
	st.stageChanged(runtime.MachineStageRunning)
	st.stageChanged(runtime.MachineStageShuttingDown)

	if st.cancelled(t0.Add(24 * time.Hour)) {
		t.Fatal("a stop ended by a timer")
	}
}

func TestTheStopWatchReportsEveryStop(t *testing.T) {
	oldRetry, oldEvery := watchRetry, goingDownEvery
	watchRetry, goingDownEvery = 50*time.Millisecond, 20*time.Millisecond

	t.Cleanup(func() { watchRetry, goingDownEvery = oldRetry, oldEvery })

	f := talostest.New(t)
	tc := &talos.Client{Dial: func(ctx context.Context, _ talos.Conn) (*client.Client, error) { return f.Dial(ctx) }}

	t.Cleanup(func() { tc.Close() }) //nolint:errcheck

	var (
		mu    sync.Mutex
		boots []string
		fail  = 2 // the module does not answer the first attempts
		now   = time.Now()
	)

	w := &StopWatch{Talos: tc, Log: t.Logf, Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()

		return now
	}, Notify: func(_ context.Context, boot string) error {
		mu.Lock()
		defer mu.Unlock()

		if fail > 0 {
			fail--

			return errors.New("no module")
		}

		boots = append(boots, boot)

		return nil
	}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		w.Run(ctx)
		close(done)
	}()

	t.Cleanup(func() {
		cancel()
		<-done
		w.Wait()
	})

	sent := func(n int) {
		t.Helper()

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			got := len(boots)
			mu.Unlock()

			if got >= n {
				return
			}

			time.Sleep(10 * time.Millisecond)
		}

		t.Fatalf("%d reports, want %d", len(boots), n)
	}

	waitBoot := func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if b, _ := w.Report(); b == "boot-1" {
				return
			}

			time.Sleep(10 * time.Millisecond)
		}

		t.Fatal("no boot id")
	}

	waitBoot()
	time.Sleep(200 * time.Millisecond) // the watches are set up

	// the stage at a sequence's start: reported, retried until delivered
	f.SetStage(t, runtime.MachineStageRebooting)
	sent(1)

	// cancelled, then another reboot on the same boot: its START reports again
	f.PublishSequence("reboot", machine.SequenceEvent_START, nil)
	sent(2)
	f.PublishSequence("reboot", machine.SequenceEvent_NOOP, code(common.Code_CANCELED))

	deadline := time.Now().Add(5 * time.Second)

	for {
		mu.Lock()
		now = now.Add(time.Minute)
		mu.Unlock()

		if boot, cancelled := w.Report(); boot == "boot-1" && cancelled == "boot-1" {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("the cancellation was not reported")
		}

		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()

	if boots[0] != "boot-1" || boots[1] != "boot-1" {
		t.Fatalf("reports %v", boots)
	}
}

func TestTheGoingDownReportGoesToThePollingModule(t *testing.T) {
	ca := newTestCA(t)

	// the module of mgr h0, which takes the report
	var got goingDown

	mc, mk := ca.pair(pki.RoleMgr, "h0", x509.ExtKeyUsageServerAuth, testFSID)
	pair, err := tls.X509KeyPair([]byte(mc), []byte(mk))
	must(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca.cert))

	mod := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/going-down" || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no", http.StatusNotFound)

			return
		}

		if id, err := pki.CertIdentity(r.TLS.PeerCertificates[0]); err != nil || id.Role != pki.RoleAgent || id.Name != "h1" {
			http.Error(w, "not the agent of h1", http.StatusForbidden)

			return
		}

		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"outcome":"done"}`))
	}))
	mod.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	mod.StartTLS()
	t.Cleanup(mod.Close)

	_, port, _ := net.SplitHostPort(mod.Listener.Addr().String())
	old := dialPort
	dialPort = func() string { return port }

	t.Cleanup(func() { dialPort = old })

	cc, ck := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageClientAuth, testFSID)
	clientTLS, err := ClientTLSConfig([]byte(ca.cert), []byte(cc), []byte(ck))
	must(t, err)

	ch, err := NewChannel(pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h1"})
	must(t, err)

	a := &Agent{Channel: ch, ClientTLS: clientTLS, refresh: func(context.Context) error { return nil }}
	a.rec = &Record{Schema: Schema, Containers: map[string]Container{}}

	if err := a.NotifyDown(context.Background(), "boot-1"); err == nil {
		t.Fatal("reported before any module polled")
	}

	sc, sk := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, testFSID)
	srvTLS, err := TLSConfig([]byte(ca.cert), []byte(sc), []byte(sk))
	must(t, err)

	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = srvTLS
	srv.StartTLS()
	t.Cleanup(srv.Close)

	poll := func(mgr, addr string) {
		pc, pk := ca.pair(pki.RoleMgr, mgr, x509.ExtKeyUsageClientAuth, testFSID)
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/status", nil)
		must(t, err)
		req.Header.Set(moduleAddrHeader, addr)

		resp, err := ca.client(pc, pk).Do(req)
		must(t, err)
		resp.Body.Close() //nolint:errcheck
	}

	// a module whose certificate names another mgr than the server's: refused
	poll("h2", "127.0.0.1")

	if err := a.NotifyDown(context.Background(), "boot-1"); err == nil {
		t.Fatal("reported to a server that is not the polling mgr's")
	}

	poll("h0", "127.0.0.1")
	must(t, a.NotifyDown(context.Background(), "boot-1"))

	if got.Host != "h1" || got.Boot != "boot-1" || got.FSID != testFSID {
		t.Fatalf("report %+v", got)
	}
}
