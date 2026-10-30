package orch

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	talosfiles "github.com/siderolabs/talos/pkg/machinery/resources/files"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nberlee/cephadm-talos/internal/mgrmodule"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

func inventoryOrch(t *testing.T) *Orch {
	t.Helper()

	o := agentOrch(t)
	o.St.Image, o.St.CephVersion = "quay.io/ceph/ceph@sha256:a", "20.2.4"
	o.St.RGW = &state.RGW{KeepalivedImage: "quay.io/ceph/keepalived:2.2.4"}

	osd := 3
	o.St.AddHost(state.Host{Name: "h1", Addr: "10.5.0.2"})
	o.St.AddHost(state.Host{Name: "h2", Addr: "10.5.0.3", Maintenance: true})
	o.St.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1"})
	o.St.AddDaemon(state.Daemon{Type: state.TypeMgr, ID: "h1", Host: "h1"})
	o.St.AddDaemon(state.Daemon{Type: state.TypeOSD, ID: "h1-sda", Host: "h1", OSDID: &osd})
	o.St.AddDaemon(state.Daemon{Type: state.TypeOSD, ID: "h2-sda", Host: "h2", LocalOnly: true})
	o.St.AddDaemon(state.Daemon{Type: state.TypeVIP, ID: "h2", Host: "h2"})

	// as deployMgr does: the mgr host gets the mgr's server and client certificates
	h1, _ := o.St.Host("h1")
	if err := o.ensureMgrCerts(&h1, true); err != nil {
		t.Fatal(err)
	}

	o.St.AddHost(h1)

	return o
}

func TestInventory(t *testing.T) {
	o := inventoryOrch(t)
	inv := o.inventory()

	if inv.Schema != InventorySchema || inv.CephVersion != "20.2.4" || len(inv.Hosts) != 2 || !inv.Hosts[1].Maintenance || inv.CertExpiry == nil {
		t.Fatalf("inventory header %+v", inv)
	}

	got := map[string]invDaemon{}
	for _, d := range inv.Daemons {
		got[d.DaemonType+"."+d.DaemonID] = d
	}

	osd := got["osd.3"]
	if osd.DocName != o.St.DocName(state.Daemon{Type: state.TypeOSD, ID: "h1-sda"}) || osd.ServiceName != "osd" {
		t.Errorf("osd with id %+v", osd)
	}

	pending := got["osd.pending-"+o.St.DocName(state.Daemon{Type: state.TypeOSD, ID: "h2-sda"})]
	if !pending.LocalOnly {
		t.Errorf("osd without id %+v", pending)
	}

	if vip := got["keepalived.h2"]; vip.ServiceName != "ingress.rgw.default" || vip.DesiredImage != "quay.io/ceph/keepalived:2.2.4" {
		t.Errorf("vip %+v", vip)
	}

	b, _ := json.Marshal(inv)
	h1, _ := o.St.Host("h1")
	for _, secret := range []string{o.St.Agent.CAKey, o.St.Agent.OperatorKey, h1.MgrServerKey, h1.MgrClientKey} {
		if strings.Contains(string(b), strings.TrimSpace(secret)[30:60]) {
			t.Errorf("a key leaked into the inventory")
		}
	}
}

func TestMgrFilesOnlyOnMgrHosts(t *testing.T) {
	o := inventoryOrch(t)

	names := func(docs []any) map[string]string {
		out := map[string]string{}

		for _, d := range docs {
			b, err := spec.Render(d)
			if err != nil {
				t.Fatal(err)
			}

			s := string(b)
			for _, f := range append([]string{agentCAFile, mgrCertFile, mgrKeyFile, mgrServerCertFile, mgrServerKeyFile, inventoryFile}, mgrmodule.Names()...) {
				if strings.Contains(s, "name: "+f) || strings.Contains(s, "name: "+mgrModuleDir+"/"+f) {
					out[f] = map[bool]string{true: "delete", false: "write"}[strings.Contains(s, "$patch: delete")]
				}
			}
		}

		return out
	}

	h1, _ := o.St.Host("h1")
	h2, _ := o.St.Host("h2")

	on, off := names(o.hostDocs(h1)), names(o.hostDocs(h2))

	for _, f := range append([]string{agentCAFile, mgrCertFile, mgrKeyFile, mgrServerCertFile, mgrServerKeyFile}, mgrmodule.Names()...) {
		if on[f] != "write" || off[f] != "delete" {
			t.Errorf("%s: mgr host %q, other host %q", f, on[f], off[f])
		}
	}

	// the inventory is a record in the store (plan 03, item 4), on no host
	if on[inventoryFile] != "" || off[inventoryFile] != "" {
		t.Errorf("inventory file on a host: %q %q", on[inventoryFile], off[inventoryFile])
	}
}

func TestPublishBumpsAndRetries(t *testing.T) {
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

	if err := o.Publish(ctx); err != nil {
		t.Fatal(err)
	}

	rev := o.St.Published.Revision

	// nothing changed: no new revision, nothing pushed
	if err := o.Publish(ctx); err != nil || o.St.Published.Revision != rev {
		t.Fatalf("unchanged inventory republished (%d -> %d, %v)", rev, o.St.Published.Revision, err)
	}

	// a daemon change is a store record only: nothing to push
	o.St.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1"})

	if err := o.Publish(ctx); err != nil || o.St.Published.Revision != rev {
		t.Fatalf("a daemon change republished (%d -> %d, %v)", rev, o.St.Published.Revision, err)
	}

	// a change of the mgr's files (its certificates) whose push fails stays
	// pending, saved with the new revision
	o.St.AddDaemon(state.Daemon{Type: state.TypeMgr, ID: "h1", Host: "h1"})

	h, _ = o.St.Host("h1")
	if err := o.ensureMgrCerts(&h, true); err != nil {
		t.Fatal(err)
	}

	o.St.AddHost(h)

	f.FailAfterApply = status.Error(codes.Unavailable, "connection lost")

	if err := o.Publish(ctx); err == nil {
		t.Fatal("failed push not reported")
	}

	st := reload(t, o)

	if st.Published.Revision != rev+1 || len(st.ConfPending) != 1 {
		t.Fatalf("after reload: revision %d (want %d), pending %v", st.Published.Revision, rev+1, st.ConfPending)
	}

	o.St = st

	if err := o.RetryPendingConf(ctx); err != nil || len(o.St.ConfPending) != 0 {
		t.Fatalf("retry: %v, pending %v", err, o.St.ConfPending)
	}

	cfg, err := o.Talos.MachineConfig(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(cfg, mgrServerCertFile) {
		t.Errorf("node does not have the mgr's new files:\n%s", cfg)
	}
}

func TestModuleChangeRestartsTheMgrs(t *testing.T) {
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
	o.St.AddDaemon(state.Daemon{Type: state.TypeMgr, ID: "h1", Host: "h1"})

	// containerd knows the mgr by its instance
	mgrDoc := o.St.DocName(state.Daemon{Type: state.TypeMgr, ID: "h1"})
	for gen := range uint64(3) {
		inst := containers.NewContainerInstanceSpec(containers.NamespaceName, fmt.Sprintf("%s-%d", mgrDoc, gen))
		inst.TypedSpec().ContainerID, inst.TypedSpec().Generation = mgrDoc, gen

		if err := f.St.Create(ctx, inst); err != nil {
			t.Fatal(err)
		}
	}

	if err := o.Publish(ctx); err != nil {
		t.Fatal(err)
	}

	if len(f.Restarted) != 0 {
		t.Fatalf("first publication restarted %v", f.Restarted)
	}

	// as if the published module was older than this build's
	o.St.Published.Hash, o.St.Published.ModuleHash = "old", "old"

	if err := o.Publish(ctx); err != nil {
		t.Fatal(err)
	}

	// the config is accepted, but Talos has not written the files yet: no restart
	if len(f.Restarted) != 0 || len(o.St.Published.MgrRestart) != 1 {
		t.Fatalf("restarted %v before the files were written (still to do %v)", f.Restarted, o.St.Published.MgrRestart)
	}

	// Talos writes the files; the next command restarts the mgr
	files := mgrmodule.Files()
	for _, n := range mgrmodule.Names() {
		writeEtcFile(t, f, mgrModuleDir+"/"+n, files[n])
	}

	if err := o.Publish(ctx); err != nil {
		t.Fatal(err)
	}

	want := mgrDoc + "-2"
	if len(f.Restarted) != 1 || f.Restarted[0] != want || len(o.St.Published.MgrRestart) != 0 {
		t.Errorf("restarted %v, still to do %v", f.Restarted, o.St.Published.MgrRestart)
	}
}

// writeEtcFile makes the fake node report a file below /etc as written.
func writeEtcFile(t *testing.T, f *talostest.Node, name, contents string) {
	t.Helper()

	ctx := context.Background()

	spec := talosfiles.NewEtcFileSpec(talosfiles.NamespaceName, name)
	spec.TypedSpec().Contents = []byte(contents)

	if err := f.St.Create(ctx, spec); err != nil {
		t.Fatal(err)
	}

	cur, err := f.St.Get(ctx, spec.Metadata())
	if err != nil {
		t.Fatal(err)
	}

	st := talosfiles.NewEtcFileStatus(talosfiles.NamespaceName, name)
	st.TypedSpec().SpecVersion = cur.Metadata().Version().String()

	if err := f.St.Create(ctx, st); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalBoundaryAndEarliestExpiry(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)
	ctx := context.Background()

	if err := o.setupAgent(ctx, "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	issue := func(name string, lifetime time.Duration, usage x509.ExtKeyUsage) (string, string) {
		role, id := pki.RoleAgent, name
		if usage == x509.ExtKeyUsageClientAuth {
			role, id = pki.RoleOperator, "admin"
		}

		c, k, err := pki.Issue(o.St.Agent.CACert, o.St.Agent.CAKey, pki.Leaf{
			CommonName: name, IPs: []string{"10.5.0.2"}, Names: []string{name}, Usage: usage, Lifetime: lifetime,
			Identity: &pki.Identity{FSID: o.St.FSID, Role: role, Name: id},
		})
		if err != nil {
			t.Fatal(err)
		}

		return c, k
	}

	day := 24 * time.Hour
	keep := state.Host{Name: "keep", Addr: "10.5.0.2"}
	keep.AgentCert, keep.AgentKey = issue("keep", 31*day, x509.ExtKeyUsageServerAuth)
	due := state.Host{Name: "due", Addr: "10.5.0.2"}
	due.AgentCert, due.AgentKey = issue("due", 29*day, x509.ExtKeyUsageServerAuth)
	o.St.AddHost(keep)
	o.St.AddHost(due)
	o.St.Agent.OperatorCert, o.St.Agent.OperatorKey = issue("mgr", 20*day, x509.ExtKeyUsageClientAuth)

	// the earliest expiry is the operator's, 20 days out
	inv := o.inventory()
	if inv.CertExpiry == nil || inv.CertExpiry.Sub(time.Now()) > 21*day || inv.CertExpiry.Sub(time.Now()) < 19*day {
		t.Fatalf("earliest expiry %v, want the operator's in 20 days", inv.CertExpiry)
	}

	keepCert, dueCert, mgrCert := keep.AgentCert, due.AgentCert, o.St.Agent.OperatorCert

	if err := o.RenewAgentCerts(ctx); err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, h := range o.St.Hosts {
		got[h.Name] = h.AgentCert
	}

	if got["keep"] != keepCert || got["due"] == dueCert || o.St.Agent.OperatorCert == mgrCert {
		t.Errorf("31 days kept %t, 29 days renewed %t, operator renewed %t",
			got["keep"] == keepCert, got["due"] != dueCert, o.St.Agent.OperatorCert != mgrCert)
	}

	// after renewal the earliest expiry is the untouched 31 day certificate
	if inv := o.inventory(); inv.CertExpiry == nil || inv.CertExpiry.Sub(time.Now()) > 32*day {
		t.Errorf("earliest expiry after renewal %v", inv.CertExpiry)
	}
}

func TestPublishInterruptedBeforeThePatch(t *testing.T) {
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

	// the node never got the patch: the revision and the pending host are saved anyway
	f.FailBeforeApply = status.Error(codes.Unavailable, "connection refused")

	if err := o.Publish(ctx); err == nil {
		t.Fatal("failed push not reported")
	}

	st := reload(t, o)

	if st.Published.Revision != 1 || len(st.ConfPending) != 1 {
		t.Fatalf("after reload: revision %d, pending %v", st.Published.Revision, st.ConfPending)
	}

	o.St = st

	if err := o.RetryPendingConf(ctx); err != nil || len(o.St.ConfPending) != 0 {
		t.Fatalf("retry: %v, pending %v", err, o.St.ConfPending)
	}

	cfg, err := o.Talos.MachineConfig(ctx, "node")
	if err != nil || !strings.Contains(cfg, "ceph/ceph.conf") {
		t.Errorf("host documents not on the node after the retry (%v)", err)
	}
}
