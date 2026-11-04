package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// movedPair is a server certificate of the CA whose IP SAN names another
// address than the one it is dialled at (127.0.0.1): a host that moved
// before its certificates were reissued (plan 04, step 5).
func (ca testCA) movedPair(role pki.Role, name, fsid string, lifetime time.Duration) (string, string) {
	c, k, err := pki.Issue(ca.cert, ca.key, pki.Leaf{
		CommonName: string(role), IPs: []string{"10.9.9.9"}, Names: []string{name}, Usage: x509.ExtKeyUsageServerAuth, Lifetime: lifetime,
		Identity: &pki.Identity{FSID: fsid, Role: role, Name: name},
	})
	must(ca.t, err)

	return c, k
}

// peerServer serves TLS with a certificate pair and answers 200.
func peerServer(t *testing.T, certPEM, keyPEM string) *httptest.Server {
	t.Helper()

	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	must(t, err)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

func TestClientsVerifyIdentityNotAddress(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	cc, ck := ca.pair(pki.RoleAgent, "h0", x509.ExtKeyUsageClientAuth, testFSID)

	base, err := ClientTLSConfig([]byte(ca.cert), []byte(cc), []byte(ck))
	must(t, err)

	moved, movedKey := ca.movedPair(pki.RoleAgent, "h1", testFSID, time.Hour)
	revoked := &crl.Holder{CA: ca.cert}

	if _, err := revoked.Install(ca.list(1, time.Now(), time.Hour, moved)); err != nil {
		t.Fatal(err)
	}

	get := func(cfg *tls.Config, url string) error {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, Timeout: 5 * time.Second}

		resp, err := cl.Get(url)
		if err == nil {
			resp.Body.Close() //nolint:errcheck
		}

		return err
	}

	want := func(holder *crl.Holder, name string) *tls.Config {
		return WithPeer(base, func(c *x509.Certificate) error {
			if _, err := pki.Require(c, pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: name}); err != nil {
				return err
			}

			return holder.Check(c)
		})
	}

	srv := peerServer(t, moved, movedKey)

	// the address is not in the certificate: accepted by its identity
	if err := get(want(&crl.Holder{CA: ca.cert}, "h1"), srv.URL); err != nil {
		t.Fatalf("a moved peer: %v", err)
	}

	// another identity, a revoked certificate: refused
	if err := get(want(&crl.Holder{CA: ca.cert}, "h2"), srv.URL); err == nil {
		t.Fatal("another identity accepted")
	}

	if err := get(want(revoked, "h1"), srv.URL); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a revoked peer: %v", err)
	}

	// another CA's chain with the right identity: refused
	oc, ok := other.movedPair(pki.RoleAgent, "h1", testFSID, time.Hour)
	if err := get(want(&crl.Holder{CA: ca.cert}, "h1"), peerServer(t, oc, ok).URL); err == nil {
		t.Fatal("another CA's chain accepted")
	}

	// an expired certificate: refused by the chain's verification
	ec, ek, err := pki.Issue(ca.cert, ca.key, pki.Leaf{
		CommonName: "agent", IPs: []string{"10.9.9.9"}, Usage: x509.ExtKeyUsageServerAuth, Lifetime: time.Nanosecond,
		Identity: &pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h1"},
	})
	must(t, err)
	time.Sleep(time.Millisecond)

	if err := get(want(&crl.Holder{CA: ca.cert}, "h1"), peerServer(t, ec, ek).URL); err == nil {
		t.Fatal("an expired certificate accepted")
	}

	// a client certificate offered as a server's: refused (server use)
	if err := get(want(&crl.Holder{CA: ca.cert}, "h0"), peerServer(t, cc, ck).URL); err == nil {
		t.Fatal("a client certificate accepted as a server's")
	}

	// without WithPeer the base still verifies the chain
	if err := get(base, peerServer(t, oc, ok).URL); err == nil {
		t.Fatal("the base configuration accepted another CA")
	}
}

func TestTheLeadersClientsVerifyIdentityNotAddress(t *testing.T) {
	ca := newTestCA(t)
	cc, ck := ca.pair(pki.RoleAgent, "h0", x509.ExtKeyUsageClientAuth, testFSID)

	clientTLS, err := ClientTLSConfig([]byte(ca.cert), []byte(cc), []byte(ck))
	must(t, err)

	l := &LeaderLoop{Self: pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h0"}, ClientTLS: clientTLS, CRL: &crl.Holder{CA: ca.cert}}

	moved, movedKey := ca.movedPair(pki.RoleAgent, "h1", testFSID, time.Hour)
	srv := peerServer(t, moved, movedKey)

	for name, wantOK := range map[string]bool{"h1": true, "h2": false} {
		resp, err := l.agentClient(state.Host{Name: name}).Get(srv.URL)
		if err == nil {
			resp.Body.Close() //nolint:errcheck
		}

		if (err == nil) != wantOK {
			t.Fatalf("agent %s: %v", name, err)
		}
	}

	// the bridge call keeps its host-name check on loopback: a mgr
	// certificate naming its host is accepted, one naming another refused
	for _, c := range []struct {
		dns string
		ok  bool
	}{{"h0", true}, {"elsewhere", false}} {
		mc, mk, err := pki.Issue(ca.cert, ca.key, pki.Leaf{
			CommonName: "mgr", Names: []string{c.dns}, Usage: x509.ExtKeyUsageServerAuth, Lifetime: time.Hour,
			Identity: &pki.Identity{FSID: testFSID, Role: pki.RoleMgr, Name: "h0"},
		})
		must(t, err)

		b := &Bridge{TLS: clientTLS, Mgr: "h0", FSID: testFSID, CRL: &crl.Holder{CA: ca.cert}}

		resp, err := b.client().Get(peerServer(t, mc, mk).URL)
		if err == nil {
			resp.Body.Close() //nolint:errcheck
		}

		if (err == nil) != c.ok {
			t.Fatalf("bridge with a certificate for %s: %v", c.dns, err)
		}
	}

	// an agent's going-down report goes to the mgr by its identity
	mc, mk := ca.movedPair(pki.RoleMgr, "h2", testFSID, time.Hour)
	msrv := peerServer(t, mc, mk)
	_, port, _ := strings.Cut(strings.TrimPrefix(msrv.URL, "https://"), ":")

	old := dialPort
	dialPort = func() string { return port }

	t.Cleanup(func() { dialPort = old })

	ch, err := NewChannel(pki.Identity{FSID: testFSID, Role: pki.RoleAgent, Name: "h0"})
	must(t, err)

	a := &Agent{Channel: ch, ClientTLS: clientTLS, CRL: &crl.Holder{CA: ca.cert}}
	a.module = moduleTarget{Addr: "127.0.0.1", Mgr: "h2"}

	if err := a.NotifyDown(context.Background(), "b1", "b1-1"); err != nil {
		t.Fatalf("going-down to a moved mgr: %v", err)
	}

	a.module = moduleTarget{Addr: "127.0.0.1", Mgr: "h3"}
	if err := a.NotifyDown(context.Background(), "b1", "b1-1"); err == nil {
		t.Fatal("going-down to another mgr accepted")
	}
}
