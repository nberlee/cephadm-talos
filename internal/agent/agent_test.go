package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

func newAgent(t *testing.T, f *talostest.Node) *Agent {
	t.Helper()

	tc := &talos.Client{Dial: func(ctx context.Context, _ talos.Conn) (*client.Client, error) { return f.Dial(ctx) }}
	t.Cleanup(func() { tc.Close() }) //nolint:errcheck

	return &Agent{Talos: tc, logPrint: t.Logf}
}

func seed(t *testing.T, f *talostest.Node) {
	t.Helper()

	ctx := context.Background()

	hn := network.NewHostnameStatus(network.NamespaceName, network.HostnameID)
	hn.TypedSpec().Hostname = "node-1"
	must(t, f.St.Create(ctx, hn))

	cs := containers.NewContainerStatus(containers.NamespaceName, "ceph-mon")
	cs.TypedSpec().State = containers.ContainerStateRunning
	cs.TypedSpec().Image = "sha256:run"
	cs.TypedSpec().RestartCount = 2
	must(t, f.St.Create(ctx, cs))

	img := containers.NewContainerImageStatus(containers.NamespaceName, "ceph-osd")
	img.TypedSpec().Digest = "sha256:pulled"
	must(t, f.St.Create(ctx, img))

	inst := containers.NewContainerInstanceStatus(containers.NamespaceName, "ceph-gone-3")
	inst.TypedSpec().ContainerID = "ceph-gone"
	must(t, f.St.Create(ctx, inst))
}

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshBuildsTheRecord(t *testing.T) {
	f := talostest.New(t)
	seed(t, f)

	a := newAgent(t, f)
	must(t, a.Refresh(context.Background(), false))

	rec := a.Current()
	if rec.Schema != Schema || rec.Hostname != "node-1" || rec.TalosVersion != "v1.15.0-alpha.2" || rec.ObservedAt.IsZero() {
		t.Fatalf("record header %+v", rec)
	}

	want := map[string]Container{
		"ceph-mon":  {State: "running", ImageDigest: "sha256:run", Restarts: 2},
		"ceph-osd":  {ImageDigest: "sha256:pulled"},
		"ceph-gone": {Instances: true},
	}

	for name, w := range want {
		if got := rec.Containers[name]; got != w {
			t.Errorf("%s: got %+v, want %+v", name, got, w)
		}
	}
}

func TestFailedRefreshKeepsTheRecord(t *testing.T) {
	f := talostest.New(t)
	seed(t, f)

	a := newAgent(t, f)
	must(t, a.Refresh(context.Background(), false))

	before := a.Current().ObservedAt

	f.Srv.Stop()

	if err := a.observe(context.Background()); err == nil {
		t.Fatal("refresh against a stopped node succeeded")
	}

	if got := a.Current().ObservedAt; !got.Equal(before) {
		t.Errorf("observed_at moved from %v to %v after a failed refresh", before, got)
	}
}

func TestIdleNodeStaysFresh(t *testing.T) {
	f := talostest.New(t)
	seed(t, f)

	a := newAgent(t, f)
	clock := time.Now()
	a.Now = func() time.Time { return clock }

	must(t, a.Refresh(context.Background(), false))

	// nothing changes on the node, but every successful refresh renews observed_at
	clock = clock.Add(3 * time.Minute)
	must(t, a.Refresh(context.Background(), false))

	if got := a.Current().ObservedAt; !got.Equal(clock) {
		t.Errorf("observed_at %v, want %v", got, clock)
	}
}

func TestHandler(t *testing.T) {
	f := talostest.New(t)
	seed(t, f)

	a := newAgent(t, f)
	h := a.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/status", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("before the first refresh: %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/status?refresh=1", nil))

	var rec Record
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &rec) != nil || rec.Hostname != "node-1" {
		t.Fatalf("refresh=1: %d %s", rr.Code, rr.Body.String())
	}

	// a record over 32 KiB is refused, not truncated
	ctx := context.Background()

	for i := range 400 {
		cs := containers.NewContainerStatus(containers.NamespaceName, fmt.Sprintf("ceph-%s-%03d", strings.Repeat("x", 60), i))
		must(t, f.St.Create(ctx, cs))
	}

	must(t, a.Refresh(ctx, false))

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/status", nil))

	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "too large") {
		t.Errorf("oversized record: %d %s", rr.Code, rr.Body.String())
	}
}

func TestMutualTLS(t *testing.T) {
	caCert, caKey, err := pki.NewCA("agent CA", 10)
	must(t, err)

	id := func(fsid string, role pki.Role, name string) *pki.Identity {
		return &pki.Identity{FSID: fsid, Role: role, Name: name}
	}

	srvCert, srvKey, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "agent", IPs: []string{"127.0.0.1"}, Usage: x509.ExtKeyUsageServerAuth, Years: 3, Identity: id("f1", pki.RoleAgent, "h1")})
	must(t, err)

	mgrCert, mgrKey, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "mgr", Usage: x509.ExtKeyUsageClientAuth, Years: 3, Identity: id("f1", pki.RoleMgr, "h2")})
	must(t, err)

	foreignMgrCert, foreignMgrKey, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "mgr", Usage: x509.ExtKeyUsageClientAuth, Years: 3, Identity: id("f2", pki.RoleMgr, "h2")})
	must(t, err)

	agentClientCert, agentClientKey, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "agent", Usage: x509.ExtKeyUsageClientAuth, Years: 3, Identity: id("f1", pki.RoleAgent, "h3")})
	must(t, err)

	plainCert, plainKey, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "mgr", Usage: x509.ExtKeyUsageClientAuth, Years: 3})
	must(t, err)

	otherCA, otherKey, err := pki.NewCA("other CA", 10)
	must(t, err)

	strangerCert, strangerKey, err := pki.Issue(otherCA, otherKey, pki.Leaf{CommonName: "mgr", Usage: x509.ExtKeyUsageClientAuth, Years: 3, Identity: id("f1", pki.RoleMgr, "h2")})
	must(t, err)

	cfg, err := TLSConfig([]byte(caCert), []byte(srvCert), []byte(srvKey))
	must(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(caCert))

	get := func(certPEM, keyPEM string) error {
		tc := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}

		if certPEM != "" {
			c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
			must(t, err)

			tc.Certificates = []tls.Certificate{c}
		}

		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 5 * time.Second}

		resp, err := cl.Get(srv.URL)
		if err != nil {
			return err
		}

		defer resp.Body.Close() //nolint:errcheck

		return nil
	}

	if err := get(mgrCert, mgrKey); err != nil {
		t.Errorf("mgr client certificate refused: %v", err)
	}

	for name, pair := range map[string][2]string{
		"no certificate":               {"", ""},
		"certificate of another CA":    {strangerCert, strangerKey},
		"agent server certificate":     {srvCert, srvKey},
		"mgr of another cluster":       {foreignMgrCert, foreignMgrKey},
		"agent client certificate":     {agentClientCert, agentClientKey},
		"certificate without identity": {plainCert, plainKey},
	} {
		if err := get(pair[0], pair[1]); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRefreshIsSharedAndCoalesced(t *testing.T) {
	var runs atomic.Int32

	release := make(chan struct{})
	a := &Agent{logPrint: t.Logf, refresh: func(context.Context) error {
		runs.Add(1)
		<-release

		return nil
	}}

	// many requests during one slow refresh share it
	var wg sync.WaitGroup

	for range 5 {
		wg.Go(func() { _ = a.Refresh(context.Background(), true) })
	}

	time.Sleep(100 * time.Millisecond)

	// a waiter whose request is cancelled returns without waiting for the refresh
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := a.Refresh(ctx, true); err == nil {
		t.Error("cancelled waiter did not return its context error")
	}

	close(release)
	wg.Wait()

	if n := runs.Load(); n != 1 {
		t.Fatalf("%d refreshes for concurrent requests, want 1", n)
	}

	// right after it completed, a coalescing request starts nothing new
	must(t, a.Refresh(context.Background(), true))

	if n := runs.Load(); n != 1 {
		t.Errorf("coalescing request refreshed again (%d)", n)
	}

	// a scheduled refresh always runs
	must(t, a.Refresh(context.Background(), false))

	if n := runs.Load(); n != 2 {
		t.Errorf("scheduled refresh did not run (%d)", n)
	}
}

func TestShutdownJoinsARunningRefresh(t *testing.T) {
	life, cancel := context.WithCancel(context.Background())

	var finished atomic.Bool

	started := make(chan struct{})
	a := &Agent{Life: life, logPrint: t.Logf, refresh: func(ctx context.Context) error {
		close(started)
		<-ctx.Done() // a refresh stuck on the node until it is cancelled
		finished.Store(true)

		return ctx.Err()
	}}

	go func() { _ = a.Refresh(context.Background(), false) }()

	<-started
	cancel()
	a.Wait()

	if !finished.Load() {
		t.Fatal("Wait returned while the refresh was still running")
	}
}

func TestTLSConfigNeedsAnAgentIdentity(t *testing.T) {
	caCert, caKey, err := pki.NewCA("agent CA", 10)
	must(t, err)

	for name, ident := range map[string]*pki.Identity{
		"no identity":      nil,
		"a mgr's identity": {FSID: "f1", Role: pki.RoleMgr, Name: "h1"},
	} {
		c, k, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "agent", IPs: []string{"127.0.0.1"}, Usage: x509.ExtKeyUsageServerAuth, Years: 3, Identity: ident})
		must(t, err)

		if _, err := TLSConfig([]byte(caCert), []byte(c), []byte(k)); err == nil {
			t.Errorf("%s: accepted as the agent's certificate", name)
		}
	}
}
