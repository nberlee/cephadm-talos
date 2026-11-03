package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// list is a revocation list of the test CA naming the certificates' serials.
func (ca testCA) list(number int64, thisUpdate time.Time, validity time.Duration, certs ...string) []byte {
	var serials []*big.Int

	for _, c := range certs {
		p, err := pki.Parse(c)
		must(ca.t, err)

		serials = append(serials, p.SerialNumber)
	}

	der, err := crl.Issue(ca.cert, ca.key, big.NewInt(number), serials, thisUpdate, validity)
	must(ca.t, err)

	return der
}

func deliver(t *testing.T, cl *http.Client, url string, der []byte) int {
	t.Helper()

	body, _ := json.Marshal(CRLDelivery{CRL: base64.StdEncoding.EncodeToString(der)})

	resp, err := cl.Post(url+"/v1/crl", "application/json", bytes.NewReader(body))
	must(t, err)

	defer resp.Body.Close() //nolint:errcheck

	return resp.StatusCode
}

func statusOf(t *testing.T, cl *http.Client, method, url string) int {
	t.Helper()

	req, _ := http.NewRequest(method, url, strings.NewReader("{}"))

	resp, err := cl.Do(req)
	must(t, err)

	defer resp.Body.Close() //nolint:errcheck

	return resp.StatusCode
}

// crlAgent serves an agent's handler with its TLS, a revocation list kept in
// its records and the given policy.
func crlAgent(t *testing.T, ca testCA, closed bool) (*Agent, *httptest.Server, *records.Store) {
	t.Helper()

	srvCert, srvKey := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth, "f1")
	cfg, err := TLSConfig([]byte(ca.cert), []byte(srvCert), []byte(srvKey))
	must(t, err)

	recs := &records.Store{Dir: t.TempDir()}

	pol, err := LoadCRLPolicy(recs, closed, testApprovalPub, "f1")
	must(t, err)

	ch, err := NewChannel(pki.Identity{FSID: "f1", Role: pki.RoleAgent, Name: "h1"})
	must(t, err)

	a := &Agent{rec: &Record{Schema: Schema, Containers: map[string]Container{}}, Records: recs, Channel: ch,
		CRL: NewCRLHolder(ca.cert, recs), CRLPolicy: pol, logPrint: func(string, ...any) {}}
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return a, srv, recs
}

func TestARevokedPeerIsRefusedOnEveryRequest(t *testing.T) {
	ca := newTestCA(t)
	_, srv, recs := crlAgent(t, ca, false)
	mgrCert, mgrKey := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, "f1")
	otherCert, otherKey := ca.pair(pki.RoleMgr, "h2", x509.ExtKeyUsageClientAuth, "f1")
	mgr, other := ca.client(mgrCert, mgrKey), ca.client(otherCert, otherKey)

	if s := statusOf(t, mgr, http.MethodGet, srv.URL+"/status"); s != http.StatusOK {
		t.Fatalf("status %d", s)
	}

	// another certificate of the agent CA delivers the list naming the mgr's
	if s := deliver(t, other, srv.URL, ca.list(5, time.Now(), time.Hour, mgrCert)); s != http.StatusOK {
		t.Fatalf("delivery %d", s)
	}

	// on the kept-alive connection opened before, and on a new one
	if s := statusOf(t, mgr, http.MethodGet, srv.URL+"/status"); s != http.StatusForbidden {
		t.Fatalf("a revoked peer answered %d", s)
	}

	// a revoked certificate delivers nothing either
	if s := deliver(t, ca.client(mgrCert, mgrKey), srv.URL, ca.list(6, time.Now(), time.Hour)); s != http.StatusForbidden {
		t.Fatalf("a revoked peer delivered: %d", s)
	}

	// the list survives a restart: from the records
	h := NewCRLHolder(ca.cert, recs)
	must(t, h.Load())

	if l := h.Current(); l == nil || l.Number.Int64() != 5 {
		t.Fatalf("after a restart: %+v", l)
	}
}

func TestTheAgentAcceptsOnlyANewerListOfItsCA(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	a, srv, _ := crlAgent(t, ca, false)
	cliCert, cliKey := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, "f1")
	cl := ca.client(cliCert, cliKey)
	now := time.Now()

	if s := deliver(t, cl, srv.URL, ca.list(10, now, time.Hour)); s != http.StatusOK || a.CRL.Current().Number.Int64() != 10 {
		t.Fatalf("a good list: %d", s)
	}

	for name, der := range map[string][]byte{
		"another CA's":                   other.list(20, now, time.Hour),
		"thisUpdate in the future":       ca.list(21, now.Add(10*time.Minute), time.Hour),
		"a validity of more than 7 days": ca.list(22, now, 7*24*time.Hour+time.Minute),
		"not a list":                     []byte("nope"),
	} {
		if s := deliver(t, cl, srv.URL, der); s != http.StatusBadRequest {
			t.Errorf("%s: %d", name, s)
		}
	}

	// a lower number changes nothing
	if s := deliver(t, cl, srv.URL, ca.list(9, now, time.Hour, cliCert)); s != http.StatusOK || a.CRL.Current().Number.Int64() != 10 {
		t.Fatalf("a lower number: %d %s", s, a.CRL.Current().Number)
	}

	if s := statusOf(t, cl, http.MethodGet, srv.URL+"/status"); s != http.StatusOK {
		t.Fatalf("an older list took effect: %d", s)
	}
}

func TestFailOpenAndFailClosed(t *testing.T) {
	ca := newTestCA(t)
	mgrCert, mgrKey := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, "f1")
	now := time.Now()
	later := now.Add(2 * time.Hour)

	for _, closed := range []bool{false, true} {
		a, srv, recs := crlAgent(t, ca, closed)
		mgr := ca.client(mgrCert, mgrKey)

		// before the handoff, no list is not stale
		if a.crlStale(now) {
			t.Fatal("stale before the handoff without a list")
		}

		must(t, recs.Write(ownershipRecord, []byte("{}")))

		if !a.crlStale(now) {
			t.Fatal("no list after the handoff is not stale")
		}

		if deliver(t, mgr, srv.URL, ca.list(3, now, time.Hour)) != http.StatusOK {
			t.Fatal("not delivered")
		}

		// the clock past nextUpdate
		a.Now = func() time.Time { return later }
		a.CRL.Now = a.Now

		if !a.crlStale(later) {
			t.Fatal("not stale past nextUpdate")
		}

		heartbeat := statusOf(t, mgr, http.MethodPost, srv.URL+"/v1/heartbeat")
		if closed != (heartbeat == http.StatusServiceUnavailable) {
			t.Fatalf("closed %v: the heartbeat answered %d", closed, heartbeat)
		}

		// the status, the policy and a new list are served also when closed
		if s := statusOf(t, mgr, http.MethodGet, srv.URL+"/status"); s != http.StatusOK {
			t.Fatalf("closed %v: status %d", closed, s)
		}

		if s := statusOf(t, mgr, http.MethodPost, srv.URL+"/v1/policy"); s == http.StatusServiceUnavailable {
			t.Fatalf("closed %v: the policy refused as stale", closed)
		}

		if s := deliver(t, mgr, srv.URL, ca.list(4, later, time.Hour)); s != http.StatusOK {
			t.Fatalf("closed %v: a new list refused: %d", closed, s)
		}

		if s := statusOf(t, mgr, http.MethodPost, srv.URL+"/v1/heartbeat"); s == http.StatusServiceUnavailable {
			t.Fatalf("closed %v: still refused with a list within its validity", closed)
		}
	}
}

func signedPolicy(t *testing.T, serial int64, crlPolicy string) approval.Signed {
	t.Helper()

	s, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: "f1", Serial: serial, CRL: crlPolicy})
	must(t, err)

	return s
}

func TestThePolicyOnlyTheOperatorLowers(t *testing.T) {
	recs := &records.Store{Dir: t.TempDir()}
	load := func(docClosed bool) *CRLPolicy {
		p, err := LoadCRLPolicy(recs, docClosed, testApprovalPub, "f1")
		must(t, err)

		return p
	}

	if load(false).Closed() {
		t.Fatal("closed by default")
	}

	// a document makes it stricter, and cannot weaken it afterwards
	if !load(true).Closed() || !load(false).Closed() {
		t.Fatal("a document weakened the policy")
	}

	p := load(false)

	if _, err := p.Set(signedPolicy(t, 3, approval.CRLOpen)); err != nil || p.Closed() {
		t.Fatalf("the operator's open: %v", err)
	}

	// the operator's setting wins over the document's, also after a restart
	if load(true).Closed() {
		t.Fatal("a document overrode the operator's setting")
	}

	p = load(true)
	if _, err := p.Set(signedPolicy(t, 3, approval.CRLOpen)); err != nil {
		t.Fatalf("the same approval again: %v", err)
	}

	if _, err := p.Set(signedPolicy(t, 2, approval.CRLClosed)); err == nil {
		t.Fatal("an older approval accepted")
	}

	if _, err := p.Set(signedPolicy(t, 4, approval.CRLClosed)); err != nil || !p.Closed() || !load(false).Closed() {
		t.Fatalf("the operator's closed: %v", err)
	}

	// an approval without the field, or of another key, sets nothing
	plain, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: "f1", Serial: 9})
	must(t, err)

	if _, err := p.Set(plain); err == nil {
		t.Fatal("an approval without a policy accepted")
	}

	otherPriv, _, err := approval.NewKey()
	must(t, err)

	forged, err := approval.Sign(otherPriv, approval.Approval{Version: approval.Version, FSID: "f1", Serial: 10, CRL: approval.CRLOpen})
	must(t, err)

	if _, err := p.Set(forged); err == nil || !p.Closed() {
		t.Fatal("a forged approval accepted")
	}
}

func TestThePolicyComesFromTheOperatorCertificate(t *testing.T) {
	ca := newTestCA(t)
	a, srv, _ := crlAgent(t, ca, false)
	mgrCert, mgrKey := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, "f1")
	opCert, opKey := ca.pair(pki.RoleOperator, "admin", x509.ExtKeyUsageClientAuth, "f1")
	body, _ := json.Marshal(signedPolicy(t, 5, approval.CRLClosed))

	post := func(cl *http.Client) int {
		resp, err := cl.Post(srv.URL+"/v1/policy", "application/json", bytes.NewReader(body))
		must(t, err)

		defer resp.Body.Close() //nolint:errcheck

		return resp.StatusCode
	}

	if s := post(ca.client(mgrCert, mgrKey)); s != http.StatusForbidden || a.CRLPolicy.Closed() {
		t.Fatalf("a mgr set the policy: %d", s)
	}

	if s := post(ca.client(opCert, opKey)); s != http.StatusOK || !a.CRLPolicy.Closed() {
		t.Fatalf("the operator's policy: %d", s)
	}
}

// revokedHolder is a holder whose list names the certificates.
func revokedHolder(ca testCA, certs ...string) *crl.Holder {
	h := &crl.Holder{CA: ca.cert}
	if _, err := h.Install(ca.list(1, time.Now(), time.Hour, certs...)); err != nil {
		ca.t.Fatal(err)
	}

	return h
}

func TestGoVerifiersRefuseRevokedPeers(t *testing.T) {
	ca := newTestCA(t)

	// the leader's bridge client: a revoked module
	m := &fakeBridge{kv: map[string]string{}, outcomes: map[string]map[string]any{}, page: 1000}
	host, port := m.serve(t, ca, "h1")

	oldDial, oldBridge := dialPort, bridgePort
	dialPort, bridgePort = func() string { return port }, func() string { return port }

	t.Cleanup(func() { dialPort, bridgePort = oldDial, oldBridge })

	cliCert, cliKey := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageClientAuth, "f1")
	cfg, err := ClientTLSConfig([]byte(ca.cert), []byte(cliCert), []byte(cliKey))
	must(t, err)

	conn, err := tls.Dial("tcp", net.JoinHostPort(host, port), cfg.Clone())
	must(t, err)

	served := conn.ConnectionState().PeerCertificates[0]
	conn.Close() //nolint:errcheck

	moduleCert := string(pemOf(served))
	b := &Bridge{TLS: cfg, Addr: host, Mgr: "h1", FSID: "f1"}

	if _, err := b.ActiveMgr(context.Background()); err != nil && strings.Contains(err.Error(), "revoked") {
		t.Fatalf("refused without a list: %v", err)
	}

	b.CRL = revokedHolder(ca, moduleCert)
	if _, err := b.ActiveMgr(context.Background()); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a revoked module answered: %v", err)
	}

	// the agent's confirmations: a revoked module
	mgrCert, mgrKey := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageServerAuth, "f1")
	addr := fakeModule{gid: 4178, mgr: "h1"}.serve(t, ca, mgrCert, mgrKey)
	mhost, mport, _ := net.SplitHostPort(addr)
	dialPort = func() string { return mport }

	ch, err := NewChannel(pki.Identity{FSID: "f1", Role: pki.RoleAgent, Name: "h1"})
	must(t, err)

	if _, _, err := ch.Confirm(context.Background(), cfg, ConfirmTarget{Addr: mhost, Mgr: "h1"}, 7, "op-1", strings.Repeat("ab", 32)); err != nil {
		t.Fatalf("confirmation refused: %v", err)
	}

	ch.CRL = revokedHolder(ca, mgrCert)
	if _, _, err := ch.Confirm(context.Background(), cfg, ConfirmTarget{Addr: mhost, Mgr: "h1"}, 7, "op-1", strings.Repeat("ab", 32)); err == nil {
		t.Fatal("a revoked module confirmed")
	}

	// the leader's agent client: a revoked agent
	agentCert, agentKey := ca.pair(pki.RoleAgent, "h2", x509.ExtKeyUsageServerAuth, "f1")
	acfg, err := TLSConfig([]byte(ca.cert), []byte(agentCert), []byte(agentKey))
	must(t, err)

	asrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	asrv.TLS = acfg
	asrv.StartTLS()
	t.Cleanup(asrv.Close)

	l := &LeaderLoop{Self: pki.Identity{FSID: "f1", Role: pki.RoleAgent, Name: "h1"}, ClientTLS: cfg}
	h := state.Host{Name: "h2", Addr: "127.0.0.1"}

	get := func() error {
		resp, err := l.agentClient(h).Get(asrv.URL)
		if err == nil {
			resp.Body.Close() //nolint:errcheck
		}

		return err
	}

	if err := get(); err != nil {
		t.Fatalf("agent refused: %v", err)
	}

	l.CRL = revokedHolder(ca, agentCert)
	if err := get(); err == nil {
		t.Fatal("a revoked agent answered the leader")
	}

	// admission of mgr files and of a self-update's certificates
	mgrClient, _ := ca.pair(pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth, "f1")
	p := &Policy{FSID: "f1", Host: "h1", CACert: ca.cert}

	if err := p.mgrCert(mgrClient, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatal(err)
	}

	p.CRL = revokedHolder(ca, mgrClient)
	if err := p.mgrCert(mgrClient, x509.ExtKeyUsageClientAuth); err == nil {
		t.Fatal("a revoked mgr certificate admitted")
	}

	selfCert, selfKey := ca.pair(pki.RoleAgent, "h1", x509.ExtKeyUsageClientAuth, "f1")
	n := &Node{FSID: "f1", Host: "h1", Policy: &Policy{}}

	if _, err := n.selfCert(ca.cert, selfCert, selfKey, x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatal(err)
	}

	n.Policy.CRL = revokedHolder(ca, selfCert)
	if _, err := n.selfCert(ca.cert, selfCert, selfKey, x509.ExtKeyUsageClientAuth); err == nil {
		t.Fatal("a revoked certificate admitted for a self-update")
	}
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}
