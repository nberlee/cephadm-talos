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
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/cephx"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// fakeKey is the secret the fake module's mon auth has for every entity.
var fakeKey = func() string {
	k, err := cephx.NewKey()
	if err != nil {
		panic(err)
	}

	return k
}()

// fakeBridge is the module's bridge over an in-memory config-key store.
type fakeBridge struct {
	mu       sync.Mutex
	kv       map[string]string
	outcomes map[string]map[string]any
	calls    []string
	// hang makes the named call answer "unknown" after running it
	hang string
	// refuse makes the named call answer 400 without running it
	refuse string
	// page is how many keys one listing returns
	page int
	// fsid is the cluster in the module's certificate; "" is f1
	fsid string
}

func (m *fakeBridge) run(req wire.BridgeRequest) map[string]any {
	str := func(k string) string { s, _ := req.Args[k].(string); return s }

	switch req.Call {
	case "entry limit":
		return map[string]any{"outcome": "done", "r": 0, "out": `"65536"`}
	case "config-key keys":
		keys := []string{}

		for k := range m.kv {
			if strings.HasPrefix(k, str("prefix")) && k > str("after") {
				keys = append(keys, k)
			}
		}

		sort.Strings(keys)

		more := len(keys) > m.page
		if more {
			keys = keys[:m.page]
		}

		b, _ := json.Marshal(map[string]any{"keys": keys, "more": more})

		return map[string]any{"outcome": "done", "r": 0, "out": string(b)}
	case "config-key get":
		v, ok := m.kv[str("key")]
		if !ok {
			return map[string]any{"outcome": "done", "r": -2}
		}

		return map[string]any{"outcome": "done", "r": 0, "out": v}
	case "config-key set":
		m.kv[str("key")] = str("value")

		return map[string]any{"outcome": "done", "r": 0}
	case "config-key rm":
		delete(m.kv, str("key"))

		return map[string]any{"outcome": "done", "r": 0}
	case "secret get":
		v, ok := m.kv[store.SecretPrefix+str("name")]
		if !ok {
			return map[string]any{"outcome": "done", "r": -2}
		}

		return map[string]any{"outcome": "done", "r": 0, "out": v}
	case "auth get":
		if str("entity") == "osd.9" {
			return map[string]any{"outcome": "done", "r": -2, "outs": "failed to find osd.9"}
		}

		return map[string]any{"outcome": "done", "r": 0, "out": `[{"entity":"` + str("entity") + `","key":"` + fakeKey + `"}]`}
	}

	return nil
}

func (m *fakeBridge) serve(t *testing.T, ca testCA, mgr string) (host, port string) {
	t.Helper()

	fsid := m.fsid
	if fsid == "" {
		fsid = "f1"
	}

	cert, key := ca.pair(pki.RoleMgr, mgr, x509.ExtKeyUsageServerAuth, fsid)
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	must(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca.cert))

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()

		if r.Method == http.MethodGet {
			o, ok := m.outcomes[strings.TrimPrefix(r.URL.Path, "/v1/bridge/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)

				return
			}

			_ = json.NewEncoder(w).Encode(o)

			return
		}

		var req wire.BridgeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Deadline <= 0 || req.Deadline > 10 {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if req.Call == m.refuse {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		m.calls = append(m.calls, req.Call)
		out := m.run(req)
		m.outcomes[req.DispatchID] = out

		if req.Call == m.hang {
			out = map[string]any{"outcome": "unknown"}
		}

		_ = json.NewEncoder(w).Encode(out)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)

	srv.Listener = l
	srv.StartTLS()
	t.Cleanup(srv.Close)

	host, port, _ = net.SplitHostPort(l.Addr().String())

	return host, port
}

func testBridge(t *testing.T, mgr string) (*Bridge, *fakeBridge) {
	t.Helper()

	ca := newTestCA(t)
	m := &fakeBridge{kv: map[string]string{}, outcomes: map[string]map[string]any{}, page: 1000}
	host, port := m.serve(t, ca, mgr)

	old := dialPort
	dialPort = func() string { return port }

	t.Cleanup(func() { dialPort = old })

	cliCert, cliKey := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageClientAuth, "f1")
	cfg, err := ClientTLSConfig([]byte(ca.cert), []byte(cliCert), []byte(cliKey))
	must(t, err)

	return &Bridge{TLS: cfg, Addr: host, Mgr: "h1", FSID: "f1"}, m
}

func TestStoreThroughTheBridge(t *testing.T) {
	b, m := testBridge(t, "h1")
	ctx := context.Background()
	prefix := store.Prefix + "inc/42/"

	snap, err := b.Store(ctx, prefix)
	must(t, err)

	if snap.EntryLimit() != BridgeMaxValue {
		t.Errorf("entry limit %d, want the bridge's %d", snap.EntryLimit(), BridgeMaxValue)
	}

	s := store.Store{B: snap, Incarnation: "42"}
	big := strings.Repeat("0123456789", 20000)

	for range 3 {
		if _, err := s.Publish(ctx, map[string][]byte{"big": []byte(big)}); err != nil {
			t.Fatal(err)
		}
	}

	for k, v := range m.kv {
		if len(v) > BridgeMaxValue {
			t.Errorf("%s holds %d bytes", k, len(v))
		}
	}

	// a fresh reader, as after a takeover
	snap2, err := b.Store(ctx, prefix)
	must(t, err)

	s2 := store.Store{B: snap2, Incarnation: "42"}

	latest, err := s2.Latest(ctx)
	must(t, err)

	if v, err := s2.Read(ctx, latest, "big"); err != nil || string(v) != big {
		t.Fatalf("read back %d bytes: %v", len(v), err)
	}

	// a publication with an unknown outcome can be repeated
	m.hang = "config-key set"
	if _, err := s.Publish(ctx, map[string][]byte{"big": []byte("x")}); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("publish with an unknown outcome: %v", err)
	}

	m.hang = ""
	if _, err := s.Publish(ctx, map[string][]byte{"big": []byte("y")}); err != nil {
		t.Fatal(err)
	}

	if latest, err = s.Latest(ctx); err != nil {
		t.Fatal(err)
	}

	if v, _ := s.Read(ctx, latest, "big"); string(v) != "y" {
		t.Errorf("latest after the retry: %q", v)
	}

	// keys outside the prefix are refused before anything is sent
	n := len(m.calls)
	if err := snap.SetMany(ctx, []store.KV{{Key: "mgr/cephadm/inventory", Value: []byte("x")}}); err == nil || len(m.calls) != n {
		t.Errorf("write outside the prefix: %v, %d calls", err, len(m.calls)-n)
	}
}

func TestOrphanChunksDoNotBlockPublication(t *testing.T) {
	b, m := testBridge(t, "h1")
	ctx := context.Background()
	prefix := store.Prefix + "inc/42/"

	// interrupted publications left chunks without a manifest, more than one
	// listing page holds
	m.page = 50
	for i := range 120 {
		m.kv[prefix+"rec/"+strconv.Itoa(i+1)+"/big.0"] = "x"
	}

	snap, err := b.Store(ctx, prefix)
	must(t, err)

	s := store.Store{B: snap, Incarnation: "42"}
	for range 3 {
		if _, err := s.Publish(ctx, map[string][]byte{"n": []byte("1")}); err != nil {
			t.Fatal(err)
		}
	}

	keys, err := snap.List(ctx, prefix)
	must(t, err)

	// compaction removed the orphans below the kept manifests
	if len(keys) != 4 {
		t.Errorf("%d keys after publishing over orphans: %v", len(keys), keys)
	}
}

func TestBridgeOutcomes(t *testing.T) {
	b, m := testBridge(t, "h1")
	ctx := context.Background()

	m.hang = "health"
	id, _ := NewDispatchID()

	if _, err := b.Call(ctx, id, "health", nil, time.Second); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("hanging call: %v", err)
	}

	// the late outcome by dispatch id
	m.mu.Lock()
	m.outcomes[id] = map[string]any{"outcome": "done", "r": 0, "out": "late"}
	m.mu.Unlock()

	if res, err := b.Outcome(ctx, id); err != nil || res.Out != "late" {
		t.Errorf("outcome: %+v %v", res, err)
	}

	other, _ := NewDispatchID()
	if _, err := b.Outcome(ctx, other); !errors.Is(err, ErrDispatchUnknown) {
		t.Errorf("unknown dispatch: %v", err)
	}

	// a refusal is no unknown outcome: nothing was sent
	m.refuse = "status"
	if _, err := b.Call(ctx, other, "status", nil, time.Second); err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("refused call: %v", err)
	}

	if _, err := b.Call(ctx, other, "status", nil, 11*time.Second); err == nil {
		t.Error("a deadline above the module's maximum")
	}

	if k, found, err := b.AuthGet(ctx, "osd.1"); err != nil || !found || k != fakeKey {
		t.Errorf("auth get: %q %v %v", k, found, err)
	}

	if _, found, err := b.AuthGet(ctx, "osd.9"); err != nil || found {
		t.Errorf("auth get of a missing entity: %v %v", found, err)
	}
}

func TestBridgeOnlyToItsMgr(t *testing.T) {
	b, _ := testBridge(t, "h2") // the server is mgr h2, the client expects h1

	if _, err := b.do(context.Background(), "health", nil); err == nil {
		t.Fatal("bridge call to another mgr's certificate")
	}
}

func TestParseLimit(t *testing.T) {
	for in, want := range map[string]int{`65536`: 65536, `"65536"`: 65536, "65536\n": 65536} {
		if n, err := parseLimit(in); err != nil || n != want {
			t.Errorf("%q: %d %v", in, n, err)
		}
	}

	for _, in := range []string{`"x"`, `-1`, `0`, `{}`, ``} {
		if _, err := parseLimit(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
