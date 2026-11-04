package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
	// own is the module's incarnation: writes only below it; "" allows all
	own string
	// ledger is the module's executable ledger, in order, above its snapshot
	ledger []LedgerEntry
	// snapshot is the ledger snapshot's key, "" for none
	snapshot string
	// ca issues mgr certificates; quorum and active answer status and mgr dump
	ca      *testCA
	quorum  []string
	active  string
	retired []string
	// approval is the operator's newest approval in config-key, "" for none
	approval string
	// osds answer osd dump
	osds []OSD
	// rgwCert answers rgw cert (JSON: attempt and cert)
	rgwCert string
	// standbys are the standby mgrs mgr dump lists, gids their gids (100 if unset)
	standbys []string
	gids     map[string]int64
	// activeAddr is the active mgr's address mgr dump shows
	activeAddr string
	// certs are the certificates to revoke each call carried, by "<call> <operation>"
	certs map[string][]string
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
	case "mgr cert":
		attempt := fmt.Sprintf("%016x", len(m.calls))
		out := map[string]string{"attempt": attempt}

		for _, role := range []string{"server", "client"} {
			usage := x509.ExtKeyUsageClientAuth
			if role == "server" {
				usage = x509.ExtKeyUsageServerAuth
			}

			cert, key := m.ca.pair(pki.RoleMgr, "h1", usage, m.fsid)
			out[role+"_cert"] = cert
			m.kv[store.SecretPrefix+"issued/"+str("operation")+"/"+attempt+"/mgr-"+role+".key"] = key
		}

		b, _ := json.Marshal(out)

		return map[string]any{"outcome": "done", "r": 0, "out": string(b)}
	case "agent cert":
		// once per operation: asked again, the same certificates
		op := str("operation")
		if prev, ok := m.kv["agent-cert/"+op]; ok {
			return map[string]any{"outcome": "done", "r": 0, "out": prev}
		}

		m.retired = append(m.retired, req.Call+" "+op)
		attempt := fmt.Sprintf("%016x", len(m.calls))
		out := map[string]string{"attempt": attempt}

		for _, role := range []string{"server", "client"} {
			usage := x509.ExtKeyUsageClientAuth
			if role == "server" {
				usage = x509.ExtKeyUsageServerAuth
			}

			cert, key := m.ca.pair(pki.RoleAgent, "h1", usage, m.fsid)
			out[role+"_cert"] = cert
			m.kv[store.SecretPrefix+"issued/"+op+"/"+attempt+"/agent-"+role+".key"] = key
		}

		b, _ := json.Marshal(out)
		m.kv["agent-cert/"+op] = string(b)

		return map[string]any{"outcome": "done", "r": 0, "out": string(b)}
	case "clear osd addr":
		m.retired = append(m.retired, fmt.Sprintf("clear osd addr %s %v", str("operation"), req.Args["osd"]))

		return map[string]any{"outcome": "done", "r": 0, "out": ""}
	case "bind disk", "confirm osd", "close create", "osd out", "drain":
		m.retired = append(m.retired, strings.TrimSpace(req.Call+" "+str("operation")+" "+str("daemon")))

		return map[string]any{"outcome": "done", "r": 0, "out": ""}
	case "osd dump":
		b, _ := json.Marshal(m.osds)

		return map[string]any{"outcome": "done", "r": 0, "out": string(b)}
	case "retire", "retire host", "mon rm", "ok to stop", "noout set", "noout unset", "maintained", "upgrade done", "upgrade refused", "ok to stop daemon", "retire keepalived", "mgr cert done", "agent cert done", "drain done",
		"addr moved", "addr set", "move addr":
		if (req.Call == "retire" || req.Call == "mon rm" || req.Call == "move addr") && str("daemon") != "" {
			m.retired = append(m.retired, req.Call+" "+str("operation")+" "+str("daemon"))
		} else {
			m.retired = append(m.retired, req.Call+" "+str("operation"))
		}

		if list, ok := req.Args["certs"].([]any); ok {
			if m.certs == nil {
				m.certs = map[string][]string{}
			}

			for _, c := range list {
				s, _ := c.(string)
				m.certs[req.Call+" "+str("operation")] = append(m.certs[req.Call+" "+str("operation")], s)
			}
		}

		return map[string]any{"outcome": "done", "r": 0, "out": ""}
	case "rgw cert":
		m.retired = append(m.retired, req.Call+" "+str("operation"))

		return map[string]any{"outcome": "done", "r": 0, "out": m.rgwCert}
	case "rgw cert done":
		m.retired = append(m.retired, req.Call+" "+str("operation")+" "+str("keep"))

		return map[string]any{"outcome": "done", "r": 0, "out": ""}
	case "mgr fail":
		// the active mgr respawns: no answer comes back
		m.retired = append(m.retired, fmt.Sprintf("mgr fail %s %v", str("operation"), req.Args["gid"]))

		return map[string]any{"outcome": "unknown"}
	case "approval":
		return map[string]any{"outcome": "done", "r": 0, "out": m.approval}
	case "status":
		b, _ := json.Marshal(map[string]any{"quorum_names": m.quorum})

		return map[string]any{"outcome": "done", "r": 0, "out": string(b)}
	case "mgr dump":
		standbys := []map[string]any{}
		for _, n := range m.standbys {
			g, ok := m.gids[n]
			if !ok {
				g = 100
			}

			standbys = append(standbys, map[string]any{"name": n, "gid": g})
		}

		b, _ := json.Marshal(map[string]any{"active_name": m.active, "active_gid": 42, "active_addr": m.activeAddr, "standbys": standbys})

		return map[string]any{"outcome": "done", "r": 0, "out": string(b)}
	case "auth get-or-create":
		return map[string]any{"outcome": "done", "r": 0, "out": `[{"entity":"` + str("entity") + `","key":"` + fakeKey + `"}]`}
	case "ledger":
		page := [][2]any{}

		for _, e := range m.ledger {
			if e.Key > str("after") {
				page = append(page, [2]any{e.Key, e.Op})
			}
		}

		b, _ := json.Marshal(map[string]any{"entries": page, "more": false, "snapshot": m.snapshot})

		return map[string]any{"outcome": "done", "r": 0, "out": string(b)}
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

		if key, _ := req.Args["key"].(string); m.own != "" && (req.Call == "config-key set" || req.Call == "config-key rm") && !strings.HasPrefix(key, store.Prefix+"inc/"+m.own+"/") {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if req.Call == m.refuse {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		// the module lists directories only (STORE_DUMP_RE)
		if prefix, _ := req.Args["prefix"].(string); req.Call == "config-key keys" && !strings.HasSuffix(prefix, "/") {
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

	oldDial, oldBridge := dialPort, bridgePort
	dialPort, bridgePort = func() string { return port }, func() string { return port }

	t.Cleanup(func() { dialPort, bridgePort = oldDial, oldBridge })

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
