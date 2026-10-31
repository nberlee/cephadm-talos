package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

type testCA struct {
	t         *testing.T
	cert, key string
}

func newTestCA(t *testing.T) testCA {
	c, k, err := pki.NewCA("agent CA", 1)
	must(t, err)

	return testCA{t: t, cert: c, key: k}
}

func (ca testCA) pair(role pki.Role, name string, usage x509.ExtKeyUsage, fsid string) (string, string) {
	c, k, err := pki.Issue(ca.cert, ca.key, pki.Leaf{
		CommonName: string(role), IPs: []string{"127.0.0.1"}, Names: []string{name}, Usage: usage, Years: 1,
		Identity: &pki.Identity{FSID: fsid, Role: role, Name: name},
	})
	must(ca.t, err)

	return c, k
}

func (ca testCA) client(certPEM, keyPEM string) *http.Client {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	must(ca.t, err)

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(ca.cert))

	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: roots, MinVersion: tls.VersionTLS13}}, Timeout: 5 * time.Second}
}

func TestHeartbeatFromTheLocalMgrOnly(t *testing.T) {
	ca := newTestCA(t)
	srvCert, srvKey := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, "f1")

	cfg, err := TLSConfig([]byte(ca.cert), []byte(srvCert), []byte(srvKey))
	must(t, err)

	ch, err := NewChannel(pki.Identity{FSID: "f1", Role: pki.RoleAgent, Name: "h1"})
	must(t, err)

	a := &Agent{Channel: ch}
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	post := func(cl *http.Client, hb any) (int, string) {
		b, _ := json.Marshal(hb)

		resp, err := cl.Post(srv.URL+"/v1/heartbeat", "application/json", bytes.NewReader(b))
		if err != nil {
			return 0, err.Error()
		}

		defer resp.Body.Close() //nolint:errcheck

		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)

		return resp.StatusCode, buf.String()
	}

	local := ca.client(ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, "f1"))
	other := ca.client(ca.pair(pki.RoleMgr, "h2", x509.ExtKeyUsageClientAuth, "f1"))
	good := wire.Heartbeat{Version: wire.Version, FSID: "f1", Mgr: "h1", GID: 4178, Epoch: 13, Session: ""}

	if code, body := post(other, good); code != http.StatusForbidden {
		t.Errorf("another host's mgr: %d %s", code, body)
	}

	if ch.Leader() != nil {
		t.Fatal("leader recorded from a refused heartbeat")
	}

	for name, hb := range map[string]any{
		"wrong cluster":  wire.Heartbeat{Version: wire.Version, FSID: "f2", Mgr: "h1", GID: 1},
		"another mgr":    wire.Heartbeat{Version: wire.Version, FSID: "f1", Mgr: "h2", GID: 1},
		"no gid":         wire.Heartbeat{Version: wire.Version, FSID: "f1", Mgr: "h1"},
		"newer version":  wire.Heartbeat{Version: wire.Version + 1, FSID: "f1", Mgr: "h1", GID: 1},
		"unknown fields": map[string]any{"version": 1, "fsid": "f1", "mgr": "h1", "gid": 1, "epoch": 1, "session": "", "x": 1},
	} {
		if code, body := post(local, hb); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}

	code, body := post(local, good)
	if code != http.StatusOK {
		t.Fatalf("local mgr: %d %s", code, body)
	}

	var reply wire.HeartbeatReply
	must(t, json.Unmarshal([]byte(body), &reply))

	if reply.Version != wire.Version || reply.Session != ch.Session || len(ch.Session) != 32 {
		t.Errorf("reply %+v, session %q", reply, ch.Session)
	}

	if l := ch.Leader(); l == nil || l.GID != 4178 || l.Epoch != 13 || l.Mgr != "h1" {
		t.Errorf("leader %+v", l)
	}
}

// fakeModule answers confirmations the way bridge.py does, with a twist per test.
type fakeModule struct {
	gid     int64
	mgr     string
	status  int
	tamper  func(*wire.Confirmation)
	signKey *ecdsa.PrivateKey // nil: the server certificate's key
	delay   time.Duration
}

func (fm fakeModule) serve(t *testing.T, ca testCA, certPEM, keyPEM string) string {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	must(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(ca.cert))

	key := fm.signKey
	if key == nil {
		key = pair.PrivateKey.(*ecdsa.PrivateKey)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(fm.delay)

		if fm.status != 0 {
			http.Error(w, "refused", fm.status)

			return
		}

		var req wire.ConfirmRequest
		must(t, json.NewDecoder(r.Body).Decode(&req))

		conf := wire.Confirmation{
			Version: wire.Version, FSID: req.FSID, Mgr: fm.mgr, GID: fm.gid, Session: req.Session, Host: req.Host,
			Revision: req.Revision, Operation: req.Operation, InputsHash: req.InputsHash, Challenge: req.Challenge,
		}
		if fm.tamper != nil {
			fm.tamper(&conf)
		}

		payload, _ := json.Marshal(conf)
		sum := sha256.Sum256(payload)
		sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
		must(t, err)

		_ = json.NewEncoder(w).Encode(wire.ConfirmReply{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}

	// the module listens on wire.ModulePort; tests take a free port instead
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)

	srv.Listener = l
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return l.Addr().String()
}

func TestConfirm(t *testing.T) {
	ca := newTestCA(t)
	mgrCert, mgrKey := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageServerAuth, "f1")
	otherCert, otherKey := ca.pair(pki.RoleMgr, "h2", x509.ExtKeyUsageServerAuth, "f1")
	cliCert, cliKey := ca.pair(pki.RoleAgent, "h3", x509.ExtKeyUsageClientAuth, "f1")

	tlsCfg, err := ClientTLSConfig([]byte(ca.cert), []byte(cliCert), []byte(cliKey))
	must(t, err)

	ch, err := NewChannel(pki.Identity{FSID: "f1", Role: pki.RoleAgent, Name: "h3"})
	must(t, err)

	stranger, err := ecdsa.GenerateKey(mustCurve(), rand.Reader)
	must(t, err)

	confirm := func(addr, mgr string) error {
		host, port, _ := net.SplitHostPort(addr)

		// Confirm dials wire.ModulePort; point it at the test server through a dialer
		cfg := tlsCfg.Clone()
		old := dialPort
		dialPort = func() string { return port }

		defer func() { dialPort = old }()

		_, until, err := ch.Confirm(context.Background(), cfg, ConfirmTarget{Addr: host, Mgr: mgr}, 7, "op-1", strings.Repeat("ab", 32))
		if err == nil && time.Until(until) > ConfirmValidity {
			t.Errorf("validity beyond %s", ConfirmValidity)
		}

		return err
	}

	if err := confirm(fakeModule{gid: 4178, mgr: "h1"}.serve(t, ca, mgrCert, mgrKey), "h1"); err != nil {
		t.Fatalf("valid confirmation refused: %v", err)
	}

	for name, c := range map[string]struct {
		fm   fakeModule
		cert [2]string
		mgr  string
	}{
		"another mgr answers":     {fakeModule{gid: 1, mgr: "h2"}, [2]string{otherCert, otherKey}, "h1"},
		"module refuses":          {fakeModule{status: http.StatusConflict}, [2]string{mgrCert, mgrKey}, "h1"},
		"other challenge":         {fakeModule{gid: 1, mgr: "h1", tamper: func(c *wire.Confirmation) { c.Challenge = "00" }}, [2]string{mgrCert, mgrKey}, "h1"},
		"other revision":          {fakeModule{gid: 1, mgr: "h1", tamper: func(c *wire.Confirmation) { c.Revision++ }}, [2]string{mgrCert, mgrKey}, "h1"},
		"other mgr name":          {fakeModule{gid: 1, mgr: "h2"}, [2]string{mgrCert, mgrKey}, "h1"},
		"no gid":                  {fakeModule{mgr: "h1"}, [2]string{mgrCert, mgrKey}, "h1"},
		"signed with another key": {fakeModule{gid: 1, mgr: "h1", signKey: stranger}, [2]string{mgrCert, mgrKey}, "h1"},
		"after the validity":      {fakeModule{gid: 1, mgr: "h1", delay: 200 * time.Millisecond}, [2]string{mgrCert, mgrKey}, "h1"},
	} {
		if name == "after the validity" {
			// the clock jumps past the validity while the answer is on its way
			calls := 0
			ch.now = func() time.Time {
				calls++
				if calls > 1 {
					return time.Now().Add(ConfirmValidity)
				}

				return time.Now()
			}
		}

		if err := confirm(c.fm.serve(t, ca, c.cert[0], c.cert[1]), c.mgr); err == nil {
			t.Errorf("%s: confirmed", name)
		}

		ch.now = time.Now
	}
}

func TestDialPortIsTheModulePort(t *testing.T) {
	if dialPort() != strconv.Itoa(wire.ModulePort) {
		t.Errorf("dial port %s", dialPort())
	}
}

func mustCurve() elliptic.Curve { return elliptic.P256() }
