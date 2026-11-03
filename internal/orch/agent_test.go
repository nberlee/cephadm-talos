package orch

import (
	"context"
	"crypto/x509"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

func agentOrch(t *testing.T) *Orch {
	t.Helper()

	o := &Orch{Talos: &talos.Client{DryRun: true}, St: state.New("eb8dac3e-0ba7-4795-8feb-a80e8593331f"), Out: io.Discard}
	if err := o.setupAgent(context.Background(), "10.5.0.2", "registry/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false); err != nil {
		t.Fatal(err)
	}

	return o
}

func TestAgentDocument(t *testing.T) {
	o := agentOrch(t)
	h := state.Host{Name: "node-1", Addr: "10.5.0.2"}

	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	docs := mustDocs(t)(o.hostDocs(h))

	var a *spec.ContainerConfig

	for _, d := range docs {
		if c, ok := d.(*spec.ContainerConfig); ok && c.MetaName == o.agentDocName(h) {
			a = c
		}
	}

	if a == nil {
		t.Fatalf("no agent in the host documents")
	}

	if a.ContainerImage != "registry/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || a.RunAsConfig == nil || *a.RunAsConfig.RunAsUID != 50 || *a.RunAsConfig.RunAsGID != 50 ||
		a.SecurityConfig == nil || a.SecurityConfig.SecurityProfile != "restricted" || !a.SecurityConfig.SecurityMachinedAccess ||
		a.NetworkConfig == nil || a.NetworkConfig.NetworkMode != "host" {
		t.Errorf("agent document %+v", a)
	}

	env := strings.Join(a.ContainerEnvironment, "\n")
	for _, k := range []string{daemons.EnvCA, daemons.EnvCert, daemons.EnvKey} {
		if !strings.Contains(env, k+"=") {
			t.Errorf("agent document misses %s", k)
		}
	}

	// the server certificate covers the host and is valid for server auth only
	c, err := pki.Parse(h.AgentCert)
	if err != nil {
		t.Fatal(err)
	}

	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || c.IPAddresses[0].String() != "10.5.0.2" || c.DNSNames[0] != "node-1" {
		t.Errorf("agent certificate %v %v %v", c.ExtKeyUsage, c.IPAddresses, c.DNSNames)
	}

	if years := c.NotAfter.Sub(time.Now()).Hours() / 24 / 365; years < 2.9 || years > 3.1 {
		t.Errorf("agent certificate valid %.1f years, want 3", years)
	}

	// a new address gets a new certificate, an unchanged host keeps it
	old := h.AgentCert
	if err := o.ensureAgentCert(&h); err != nil || h.AgentCert != old {
		t.Errorf("unchanged host got a new certificate")
	}

	h.Addr = "10.5.0.9"
	if err := o.ensureAgentCert(&h); err != nil || h.AgentCert == old {
		t.Errorf("moved host kept its certificate")
	}
}

// images is a fake image service that has the test agent image.
func images() *talostest.ImageService {
	return &talostest.ImageService{Cache: map[string]string{}, Remote: map[string]string{"docker.io/registry/agent:dev": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
}

func TestRenewAgentCerts(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)

	if err := o.setupAgent(context.Background(), "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	fresh := state.Host{Name: "fresh", Addr: "10.5.0.2"}
	if err := o.ensureAgentCert(&fresh); err != nil {
		t.Fatal(err)
	}

	// a certificate that is already at its end (0 years)
	due := state.Host{Name: "due", Addr: "10.5.0.3"}
	if err := o.ensureAgentCert(&due); err != nil {
		t.Fatal(err)
	}

	due.AgentCert, due.AgentKey, _ = pki.Issue(o.St.Agent.CACert, o.St.Agent.CAKey, pki.Leaf{
		CommonName: "agent due", IPs: []string{"10.5.0.3"}, Names: []string{"due"}, Usage: x509.ExtKeyUsageServerAuth,
		Identity: &pki.Identity{FSID: o.St.FSID, Role: pki.RoleAgent, Name: "due"},
	})
	o.St.AddHost(fresh)
	o.St.AddHost(due)

	freshCert, dueCert, mgrCert := fresh.AgentCert, due.AgentCert, o.St.Agent.OperatorCert

	if err := o.RenewAgentCerts(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, h := range o.St.Hosts {
		got[h.Name] = h.AgentCert
	}

	if got["fresh"] != freshCert || got["due"] == dueCert || o.St.Agent.OperatorCert != mgrCert {
		t.Errorf("renewal: fresh changed %t, due changed %t, operator changed %t",
			got["fresh"] != freshCert, got["due"] != dueCert, o.St.Agent.OperatorCert != mgrCert)
	}

	if len(o.St.ConfPending) != 0 {
		t.Errorf("pending after a successful push: %v", o.St.ConfPending)
	}
}

func TestHostRmRemovesTheAgent(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)

	if err := o.setupAgent(context.Background(), "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	h := state.Host{Name: "h1", Addr: "node"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	o.St.AddHost(h)

	ctx := context.Background()
	if err := o.apply(ctx, "node", mustDocs(t)(o.hostDocs(h))...); err != nil {
		t.Fatal(err)
	}

	// the agent's process lingers for a moment after its document is gone
	inst := containers.NewContainerInstanceSpec(containers.NamespaceName, o.agentDocName(h)+"-0")
	inst.TypedSpec().ContainerID = o.agentDocName(h)

	if err := f.St.Create(ctx, inst); err != nil {
		t.Fatal(err)
	}

	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = f.St.Destroy(ctx, inst.Metadata())
	}()

	if err := o.RemoveHost(ctx, "h1"); err != nil {
		t.Fatal(err)
	}

	cfg, err := o.Talos.MachineConfig(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(cfg, o.recordsInitDocName(h)) {
		t.Errorf("records-init document left behind")
	}

	if strings.Contains(cfg, o.agentDocName(h)) {
		t.Errorf("agent document left behind")
	}

	if _, ok := o.St.Host("h1"); ok {
		t.Errorf("host still in the inventory")
	}
}

func TestRenewalPushIsRetriedAfterAFailure(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)

	if err := o.setupAgent(context.Background(), "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	due := state.Host{Name: "due", Addr: "10.5.0.3"}
	if err := o.ensureAgentCert(&due); err != nil {
		t.Fatal(err)
	}

	due.AgentCert, due.AgentKey, _ = pki.Issue(o.St.Agent.CACert, o.St.Agent.CAKey, pki.Leaf{
		CommonName: "agent due", IPs: []string{"10.5.0.3"}, Names: []string{"due"}, Usage: x509.ExtKeyUsageServerAuth,
		Identity: &pki.Identity{FSID: o.St.FSID, Role: pki.RoleAgent, Name: "due"},
	})
	o.St.AddHost(due)

	f.FailAfterApply = status.Error(codes.Unavailable, "connection lost")

	if err := o.RenewAgentCerts(context.Background()); err == nil {
		t.Fatal("a failed push was not reported")
	}

	// the renewed certificate and the pending host survive a reload of the state
	st := reload(t, o)

	h, _ := st.Host("due")
	if h.AgentCert == due.AgentCert || len(st.ConfPending) != 1 {
		t.Fatalf("after reload: renewed %t, pending %v", h.AgentCert != due.AgentCert, st.ConfPending)
	}

	o.St = st

	if err := o.RetryPendingConf(context.Background()); err != nil {
		t.Fatal(err)
	}

	if len(o.St.ConfPending) != 0 {
		t.Errorf("still pending: %v", o.St.ConfPending)
	}
}

func TestRemoveClusterRemovesAgentsWithoutStatus(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)
	ctx := context.Background()

	if err := o.setupAgent(ctx, "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	h := state.Host{Name: "h1", Addr: "node"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	o.St.AddHost(h)

	// the fake node has no controllers: the agent document exists, its status never appears
	if err := o.apply(ctx, "node", mustDocs(t)(o.hostDocs(h))...); err != nil {
		t.Fatal(err)
	}

	if err := o.St.Save(); err != nil {
		t.Fatal(err)
	}

	o.opened = true // the CLI still writes the state: nothing to suspend

	if err := o.RemoveCluster(ctx, false, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	cfg, err := o.Talos.MachineConfig(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(cfg, o.recordsInitDocName(h)) {
		t.Errorf("records-init document left behind")
	}

	if strings.Contains(cfg, o.agentDocName(h)) {
		t.Errorf("agent document left behind")
	}
}

func TestRemoveClusterWithoutItsState(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)
	ctx := context.Background()

	if err := o.setupAgent(ctx, "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	h := state.Host{Name: "h1", Addr: "node"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	if err := o.apply(ctx, "node", mustDocs(t)(o.hostDocs(h))...); err != nil {
		t.Fatal(err)
	}

	// what a workstation knows when no mon answers: the host, not the cluster
	gone := &Orch{Talos: o.Talos, St: state.New(o.St.FSID), Out: io.Discard}
	gone.St.AddHost(state.Host{Name: "h1", Addr: "node"})

	if err := gone.RemoveCluster(ctx, true, SuspendOptions{}); err == nil {
		t.Fatal("zap without the OSD devices")
	}

	cfg, err := o.Talos.MachineConfig(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(cfg, o.agentDocName(h)) {
		t.Fatal("a refused zap removed documents")
	}

	if err := gone.RemoveCluster(ctx, false, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	if cfg, err = o.Talos.MachineConfig(ctx, "node"); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{o.agentDocName(h), o.recordsInitDocName(h)} {
		if strings.Contains(cfg, name) {
			t.Errorf("%s left behind", name)
		}
	}
}

func TestCertIdentities(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)

	if err := o.setupAgent(context.Background(), "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	h := state.Host{Name: "h1", Addr: "10.5.0.2"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	if err := o.ensureMgrCerts(&h, true); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		pem   string
		role  pki.Role
		name  string
		usage x509.ExtKeyUsage
	}{
		{h.AgentCert, pki.RoleAgent, "h1", x509.ExtKeyUsageServerAuth},
		{h.AgentClientCert, pki.RoleAgent, "h1", x509.ExtKeyUsageClientAuth},
		{h.MgrServerCert, pki.RoleMgr, "h1", x509.ExtKeyUsageServerAuth},
		{h.MgrClientCert, pki.RoleMgr, "h1", x509.ExtKeyUsageClientAuth},
		{o.St.Agent.OperatorCert, pki.RoleOperator, "admin", x509.ExtKeyUsageClientAuth},
	} {
		cert, err := pki.Parse(c.pem)
		if err != nil {
			t.Fatal(err)
		}

		id, err := pki.CertIdentity(cert)
		if err != nil || id != (pki.Identity{FSID: o.St.FSID, Role: c.role, Name: c.name}) {
			t.Errorf("%s %s: identity %+v %v", c.role, c.name, id, err)
		}

		if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != c.usage {
			t.Errorf("%s %s: usage %v", c.role, c.name, cert.ExtKeyUsage)
		}
	}

	// unchanged certificates are kept; dropping the mgr drops its certificates
	server := h.AgentCert
	if err := o.ensureAgentCert(&h); err != nil || h.AgentCert != server {
		t.Errorf("valid agent certificate reissued (%v)", err)
	}

	if err := o.ensureMgrCerts(&h, false); err != nil || h.MgrServerCert != "" || h.MgrClientKey != "" {
		t.Errorf("mgr certificates kept without a mgr (%v)", err)
	}
}

func TestRenewRepairsAMismatchedOperatorCert(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)

	if err := o.setupAgent(context.Background(), "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	// valid for years, but another cluster's identity
	wrong, key, err := pki.Issue(o.St.Agent.CACert, o.St.Agent.CAKey, pki.Leaf{
		CommonName: "operator", Usage: x509.ExtKeyUsageClientAuth, Years: 3,
		Identity: &pki.Identity{FSID: "another", Role: pki.RoleOperator, Name: "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}

	o.St.Agent.OperatorCert, o.St.Agent.OperatorKey = wrong, key

	if err := o.RenewAgentCerts(context.Background()); err != nil {
		t.Fatal(err)
	}

	if o.St.Agent.OperatorCert == wrong || !certValid(o.St.Agent.OperatorCert, o.St.Agent.OperatorKey, o.identity(pki.RoleOperator, "admin"), false, nil, nil) {
		t.Error("mismatched operator certificate kept")
	}
}

// A key that is not its certificate's (the secrets were written, the state not
// published) gets a new certificate with the next command.
func TestRenewRepairsAKeyThatIsNotItsCertificates(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)

	if err := o.setupAgent(context.Background(), "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	h := state.Host{Name: "h1", Addr: "10.5.0.2"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	stale := h.AgentCert
	h.AgentKey = h.AgentClientKey
	o.St.AddHost(h)

	if err := o.RenewAgentCerts(context.Background()); err != nil {
		t.Fatal(err)
	}

	got, _ := o.St.Host("h1")
	if got.AgentCert == stale || !certValid(got.AgentCert, got.AgentKey, o.identity(pki.RoleAgent, "h1"), true, []string{"10.5.0.2"}, []string{"h1"}) {
		t.Error("a certificate without its key kept")
	}
}

// operatorCert issues the CLI an operator certificate that ends after lifetime.
func operatorCert(t *testing.T, o *Orch, lifetime time.Duration) {
	t.Helper()

	id := o.identity(pki.RoleOperator, "admin")

	c, k, err := pki.Issue(o.St.Agent.CACert, o.St.Agent.CAKey, pki.Leaf{CommonName: "operator admin", Usage: x509.ExtKeyUsageClientAuth, Lifetime: lifetime, Identity: &id})
	if err != nil {
		t.Fatal(err)
	}

	o.St.Agent.OperatorCert, o.St.Agent.OperatorKey = c, k
}

func publicOperatorCert(t *testing.T, o *Orch) string {
	t.Helper()

	v, err := o.StoreBackend.Get(context.Background(), OperatorCertKey)
	if err != nil {
		t.Fatal(err)
	}

	return string(v)
}

func TestTheOperatorCertificateIsRenewedAfterTheHandoff(t *testing.T) {
	o, _, _ := suspendSetup(t)
	ctx := context.Background()

	// due within 60 days; under a leader the CLI has no secrets but reads the
	// agent CA's key through exec
	operatorCert(t, o, 50*24*time.Hour)

	if err := o.secrets.SetMany(ctx, []store.KV{{Key: store.SecretPrefix + state.SecretAgentCA, Value: []byte(o.St.Agent.CAKey)}}); err != nil {
		t.Fatal(err)
	}

	due := o.St.Agent.OperatorCert
	o.St.Agent.CAKey, o.incarnation = "", "42"

	if !o.Managed() {
		t.Fatal("not managed")
	}

	if err := o.EnsureOperatorCert(ctx); err != nil {
		t.Fatal(err)
	}

	cert := o.St.Agent.OperatorCert
	if end, err := pki.NotAfter(cert); cert == due || err != nil || end.Before(time.Now().AddDate(2, 0, 0)) ||
		!certValid(cert, o.St.Agent.OperatorKey, o.identity(pki.RoleOperator, "admin"), false, nil, nil) {
		t.Fatalf("not renewed: ends %v (%v)", end, err)
	}

	// saved in local.json, and its public copy is the new certificate
	if st, err := state.Load(o.St.FSID); err != nil || st.Agent == nil || st.Agent.OperatorCert != cert || st.Agent.OperatorKey != o.St.Agent.OperatorKey {
		t.Fatalf("local.json: %v", err)
	}

	if publicOperatorCert(t, o) != cert {
		t.Fatal("the public copy is not the renewed certificate")
	}
}

func TestThePublicOperatorCertificateFollowsTheCLIs(t *testing.T) {
	o, _, _ := suspendSetup(t)
	ctx := context.Background()

	// not due: kept, and its public copy written
	operatorCert(t, o, 90*24*time.Hour)
	cert := o.St.Agent.OperatorCert

	if err := o.EnsureOperatorCert(ctx); err != nil || o.St.Agent.OperatorCert != cert || publicOperatorCert(t, o) != cert {
		t.Fatalf("not due: %v", err)
	}

	// a copy a failed write left behind is corrected by the next command
	if err := o.StoreBackend.SetMany(ctx, []store.KV{{Key: OperatorCertKey, Value: []byte("stale")}}); err != nil {
		t.Fatal(err)
	}

	if err := o.EnsureOperatorCert(ctx); err != nil || publicOperatorCert(t, o) != cert {
		t.Fatalf("stale copy kept: %v", err)
	}
}
