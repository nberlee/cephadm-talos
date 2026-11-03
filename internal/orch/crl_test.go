package orch

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

// publishCRL publishes a list as the module does: chunks and a manifest.
func publishCRL(t *testing.T, o *Orch, number int64, certs ...string) {
	t.Helper()

	var serials []*big.Int

	for _, c := range certs {
		p, err := pki.Parse(c)
		if err != nil {
			t.Fatal(err)
		}

		serials = append(serials, p.SerialNumber)
	}

	der, err := crl.Issue(o.St.Agent.CACert, o.St.Agent.CAKey, big.NewInt(number), serials, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	enc := base64.StdEncoding.EncodeToString(der)
	half := len(enc) / 2
	n := fmt.Sprint(number)
	m := crlManifest{Schema: 1, Number: n, Chunks: []string{CRLPrefix + n + "/0", CRLPrefix + n + "/1"}, Size: len(der)}
	m.SHA256 = sha256Hex(der)
	mb, _ := json.Marshal(m)

	if err := o.StoreBackend.SetMany(context.Background(), []store.KV{
		{Key: m.Chunks[0], Value: []byte(enc[:half])}, {Key: m.Chunks[1], Value: []byte(enc[half:])}, {Key: CRLManifest, Value: mb},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTheCLIKeepsTheHighestPublishedList(t *testing.T) {
	o := fakeOrch(t, talostest.New(t, images()))
	ctx := context.Background()

	if err := o.setupAgent(ctx, "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	// none published yet
	if err := o.RefreshCRL(ctx); err != nil || o.CRL().Current() != nil {
		t.Fatalf("before the first list: %v", err)
	}

	publishCRL(t, o, 7)

	if err := o.RefreshCRL(ctx); err != nil || o.CRL().Current().Number.Int64() != 7 {
		t.Fatalf("the published list: %v", err)
	}

	// a lower number does not replace it
	publishCRL(t, o, 6)

	if err := o.RefreshCRL(ctx); err != nil || o.CRL().Current().Number.Int64() != 7 {
		t.Fatalf("a lower number: %v", err)
	}

	// kept in the cluster directory, for when the mons do not answer
	o2 := &Orch{St: o.St, Talos: o.Talos}
	if l := o2.CRL().Current(); l == nil || l.Number.Int64() != 7 {
		t.Fatal("the saved list was not loaded")
	}

	// a damaged publication changes nothing
	if err := o.StoreBackend.SetMany(ctx, []store.KV{{Key: CRLPrefix + "6/0", Value: []byte("AAAA")}}); err != nil {
		t.Fatal(err)
	}

	if err := o.RefreshCRL(ctx); err == nil {
		t.Fatal("a damaged list read")
	}
}

func TestTheOperatorClientRefusesARevokedAgent(t *testing.T) {
	o, h, a := suspendSetup(t)

	call := func() error {
		cl, err := o.operatorClient(h)
		if err != nil {
			return err
		}

		resp, err := cl.Get(agentURL(h, "/v1/suspend"))
		if err == nil {
			resp.Body.Close() //nolint:errcheck
		}

		return err
	}

	if err := call(); err != nil {
		t.Fatal(err)
	}

	publishCRL(t, o, 3, h.AgentCert)

	if err := o.RefreshCRL(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := call(); err == nil {
		t.Fatal("a revoked agent answered the operator")
	}

	if a.gets != 1 {
		t.Fatalf("the agent was asked %d times", a.gets)
	}
}

func TestAReplacedOperatorCertificateIsRevokedUntilAccepted(t *testing.T) {
	o, _, _ := suspendSetup(t)
	ctx := context.Background()
	old := o.St.Agent.OperatorCert

	// before the handoff nothing is revoked
	o.pendingRevoke(old)

	if len(o.St.Agent.OperatorRevoke) != 0 {
		t.Fatal("a revocation before the handoff")
	}

	o.sealed = true
	o.pendingRevoke(old)

	if err := o.KeepLocal(); err != nil {
		t.Fatal(err)
	}

	var got []string

	o.RevokeCert = func(_ context.Context, serial string, until time.Time) error {
		got = append(got, serial)
		if len(got) == 1 {
			return errors.New("the mons do not answer")
		}

		return nil
	}

	if err := o.RevokePending(ctx); err == nil {
		t.Fatal("no error without the module's answer")
	}

	if st := reload(t, o); len(st.Agent.OperatorRevoke) != 1 {
		t.Fatal("the pending revocation was not kept")
	}

	if err := o.RevokePending(ctx); err != nil {
		t.Fatal(err)
	}

	c, _ := pki.Parse(old)
	if !slices.Equal(got, []string{c.SerialNumber.String(), c.SerialNumber.String()}) {
		t.Fatalf("revoked %v", got)
	}

	if st := reload(t, o); len(st.Agent.OperatorRevoke) != 0 {
		t.Fatal("the pending revocation was not cleared")
	}
}

func TestCRLPolicyThroughAnApproval(t *testing.T) {
	o, h, _ := suspendSetup(t)
	ctx := context.Background()

	cfg, err := agent.TLSConfig([]byte(o.St.Agent.CACert), []byte(h.AgentCert), []byte(h.AgentKey))
	if err != nil {
		t.Fatal(err)
	}

	pol, err := agent.LoadCRLPolicy(&records.Store{Dir: t.TempDir()}, false, o.St.Agent.ApprovalKey, o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	a := &agent.Agent{CRLPolicy: pol}
	srv := httptest.NewUnstartedServer(a.Handler())
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	agentAddr = func(state.Host) string { return srv.Listener.Addr().String() }

	if err := o.SetCRLPolicy(ctx, "sideways"); err == nil {
		t.Fatal("an unknown policy")
	}

	if err := o.SetCRLPolicy(ctx, approval.CRLClosed); err != nil || !pol.Closed() {
		t.Fatalf("closed: %v", err)
	}

	// kept on the workstation, rendered in the agents' documents, never published
	if !reload(t, o).Agent.CRLFailClosed {
		t.Fatal("not kept in local.json")
	}

	recs, err := o.St.Records()
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range recs {
		var m map[string]any
		if json.Unmarshal(v, &m) == nil {
			if ag, ok := m["agent"].(map[string]any); ok && ag["crl_fail_closed"] != nil {
				t.Fatalf("published in %s", k)
			}
		}
	}

	var env []string

	for _, d := range o.agentDocs(h) {
		if c, ok := d.(*spec.ContainerConfig); ok && c.MetaName == o.agentDocName(h) {
			env = c.ContainerEnvironment
		}
	}

	if !slices.Contains(env, daemons.EnvCRLFailClosed+"=1") {
		t.Fatal("the agent's document does not carry the setting")
	}

	if err := o.SetCRLPolicy(ctx, approval.CRLOpen); err != nil || pol.Closed() || reload(t, o).Agent.CRLFailClosed {
		t.Fatalf("open: %v", err)
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)

	return hex.EncodeToString(s[:])
}

func TestRemovingAClusterReadsTheListBeforeSuspending(t *testing.T) {
	o, h, a := suspendSetup(t)
	o.sealed = true // handed over: the agents own it

	publishCRL(t, o, 4, h.AgentCert)

	// the agent is refused as revoked, so it is never asked to suspend
	_ = o.RemoveCluster(context.Background(), false, SuspendOptions{})

	if l := o.CRL().Current(); l == nil || l.Number.Int64() != 4 {
		t.Fatal("rm-cluster did not read the published list")
	}

	if a.posts != 0 {
		t.Fatalf("a revoked agent was asked to suspend %d times", a.posts)
	}
}
