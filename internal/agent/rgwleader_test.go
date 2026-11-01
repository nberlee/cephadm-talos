package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
)

// splitPEM splits servingPEM's output into its certificate and key.
func splitPEM(both string) (cert, key string) {
	i := strings.Index(both, "-----BEGIN EC PRIVATE KEY")

	return both[:i], both[i:]
}

// rgwSetup is a leader setup whose h1 runs an RGW with the CLI's generated
// certificate and a keepalived holding 10.5.0.200, deployed.
func rgwSetup(t *testing.T) (*leaderSetup, string, string) {
	t.Helper()

	s := newLeaderSetup(t)
	ctx := context.Background()
	now := time.Now()

	hn := network.NewHostnameStatus(network.NamespaceName, network.HostnameID)
	hn.TypedSpec().Hostname = "h1"
	must(t, s.agent.fake.St.Create(ctx, hn))

	addr := network.NewAddressStatus(network.NamespaceName, "eth0/10.5.0.3/24")
	addr.TypedSpec().Address = netip.MustParsePrefix("10.5.0.3/24")
	must(t, s.agent.fake.St.Create(ctx, addr))

	cert, key := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(24*time.Hour), "10.5.0.3", "h1", "10.5.0.200"))

	s.st.RGW = &state.RGW{Port: 443, Cert: cert, VIP: "10.5.0.200/24", VRID: 50, KeepalivedImage: testImage}
	s.st.AddDaemon(state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"})
	s.st.AddDaemon(state.Daemon{Type: state.TypeVIP, ID: "h1", Host: "h1"})
	publish(t, s.leader, s.module, s.st)

	s.module.mu.Lock()
	s.module.kv[store.SecretPrefix+state.SecretRGWServer] = key
	s.module.kv[store.SecretPrefix+state.SecretVRRP] = "abc"
	s.module.active, s.module.quorum = "h0", []string{"h0", "h1"}
	s.module.mu.Unlock()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, "r1"); op.State != "completed" {
		t.Fatalf("rgw and keepalived: %+v", op)
	}

	rgw, vip := "ceph-"+testFSID[:8]+"-rgw-h1", "ceph-"+testFSID[:8]+"-vip-h1"
	running(t, s, rgw, vip)
	keepalivedLog(s, vip, "1", "MASTER")

	return s, rgw, vip
}

func running(t *testing.T, s *leaderSetup, names ...string) {
	t.Helper()

	for _, n := range names {
		cs := containers.NewContainerStatus(containers.NamespaceName, n)
		cs.TypedSpec().State, cs.TypedSpec().Image = containers.ContainerStateRunning, "sha256:"+strings.Repeat("ab", 32)

		if err := s.agent.fake.St.Create(context.Background(), cs); err != nil {
			must(t, s.agent.fake.St.Update(context.Background(), cs))
		}
	}
}

func keepalivedLog(s *leaderSetup, name, start, state string) {
	s.agent.fake.Mu.Lock()
	defer s.agent.fake.Mu.Unlock()

	if s.agent.fake.ContainerLogs == nil {
		s.agent.fake.ContainerLogs = map[string]string{}
	}

	s.agent.fake.ContainerLogs[name] = "CEPHADM-TALOS-VIP-START " + start + "\nEntering " + state + " STATE\n"
}

func owned(t *testing.T, s *leaderSetup, name string) bool {
	t.Helper()

	rep, err := s.agent.Node.Report(context.Background())
	must(t, err)

	return rep.Owned["ContainerConfig/"+name] != ""
}

func TestAnRGWRestartMovesTheVIPFirst(t *testing.T) {
	s, rgw, vip := rgwSetup(t)
	ctx := context.Background()

	addInstance(t, s.agent.fake, rgw, 1)

	rst := s.accept(KindRestart, "rgw.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	// keepalived is off before the RGW restarts, and stays off meanwhile
	if owned(t, s, vip) {
		t.Fatal("keepalived kept its document during the RGW's restart")
	}

	for i := 0; i < 3; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
		must(t, s.agent.Reconcile(ctx))
	}

	if !owned(t, s, vip) {
		t.Fatal("keepalived did not come back")
	}

	// back once its new instance holds or backs the VIP
	s.module.mu.Lock()
	_, ended := s.module.kv[JournalPrefix(42)+"op/"+rst.Op.ID]
	s.module.mu.Unlock()

	if ended {
		t.Fatal("ended before keepalived was ready")
	}

	keepalivedLog(s, vip, "2", "BACKUP")

	for i := 0; i < 2; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, rst.Op.ID); op.State != "completed" {
		t.Fatalf("restart: %+v", op)
	}
}

func TestARollMovesAnRGWToTheOperatorsCertificate(t *testing.T) {
	s, rgw, vip := rgwSetup(t)
	ctx := context.Background()
	now := time.Now()

	addInstance(t, s.agent.fake, rgw, 1)

	// the operator's certificate, for the DNS name clients use
	cert, key := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(24*time.Hour), "s3.example.com"))
	op := LedgerOp{Version: 1, ID: "op-00000000000000be", Kind: KindAddDaemon, Daemon: "rgw.h2", Host: "h2", Port: 443, Cert: cert}
	target := "user/" + op.ID

	s.module.mu.Lock()
	s.module.kv[store.SecretPrefix+target+"/rgw-server.key"] = key
	s.module.mu.Unlock()

	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		st.RGW.Certs = append(st.RGW.Certs, state.RGWCert{ID: target, Cert: cert, User: true})

		return nil
	}))

	served := ""
	s.leader.serves = func(_ string, _ int, chain string) bool { return chain == served }

	js, err := s.leader.bridge().Store(ctx, JournalPrefix(42))
	must(t, err)

	roll := func() (bool, error) {
		done, err := s.leader.rollRGW(ctx, s.leader.bridge(), js, 42, 5, op, target, "roll")
		if errors.Is(err, errRetry) {
			return false, nil
		}

		return done, err
	}

	for i := 0; i < 3; i++ {
		if _, err := roll(); err != nil {
			t.Fatal(err)
		}
	}

	if owned(t, s, vip) {
		t.Fatal("keepalived kept its document during the roll")
	}

	// the RGW serves the new certificate from a new instance; keepalived comes back
	addInstance(t, s.agent.fake, rgw, 2)
	served = cert

	for i := 0; i < 3; i++ {
		if _, err := roll(); err != nil {
			t.Fatal(err)
		}
	}

	keepalivedLog(s, vip, "2", "MASTER")

	done, err := roll()
	if err != nil || !done || !owned(t, s, vip) {
		t.Fatalf("roll: %v %v", done, err)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, _ := st.Find("rgw.h1"); d.Cert != target {
		t.Fatalf("rgw.h1 renders %q", d.Cert)
	}
}

func TestLeaderAddsAnRGWWithAGeneratedCertificate(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()
	now := time.Now()

	hn := network.NewHostnameStatus(network.NamespaceName, network.HostnameID)
	hn.TypedSpec().Hostname = "h1"
	must(t, s.agent.fake.St.Create(ctx, hn))

	addr := network.NewAddressStatus(network.NamespaceName, "eth0/10.5.0.3/24")
	addr.TypedSpec().Address = netip.MustParsePrefix("10.5.0.3/24")
	must(t, s.agent.fake.St.Create(ctx, addr))

	add := s.accept(KindAddDaemon, "rgw.h1", "h1", 1)
	add.Op.Port = 443

	cert, key := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(24*time.Hour), "10.5.0.3", "h1"))
	out, _ := json.Marshal(map[string]string{"attempt": "0123456789abcdef", "cert": cert})
	id := "issued/" + add.Op.ID + "/0123456789abcdef"

	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = add
	s.module.active, s.module.rgwCert = "h0", string(out)
	s.module.kv[store.SecretPrefix+id+"/rgw-server.key"] = key
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))
	running(t, s, "ceph-"+testFSID[:8]+"-rgw-h1")
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add: %+v", op)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, _ := st.Find("rgw.h1"); d.Cert != id || st.RGW == nil || st.RGW.Port != 443 || len(st.RGW.Certs) != 1 {
		t.Fatalf("state: %+v %+v", d, st.RGW)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Equal(calls, []string{"rgw cert " + add.Op.ID, "rgw cert done " + add.Op.ID + " " + id}) {
		t.Fatalf("calls %v", calls)
	}
}

func TestAFirstIngressReissuesTheCertificateBeforeKeepalivedStarts(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()
	now := time.Now()

	hn := network.NewHostnameStatus(network.NamespaceName, network.HostnameID)
	hn.TypedSpec().Hostname = "h1"
	must(t, s.agent.fake.St.Create(ctx, hn))

	addr := network.NewAddressStatus(network.NamespaceName, "eth0/10.5.0.3/24")
	addr.TypedSpec().Address = netip.MustParsePrefix("10.5.0.3/24")
	must(t, s.agent.fake.St.Create(ctx, addr))

	// an RGW with the CLI's certificate, not for the VIP yet
	old, oldKey := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(24*time.Hour), "10.5.0.3", "h1"))
	s.st.RGW = &state.RGW{Port: 443, Cert: old}
	s.st.AddDaemon(state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"})
	publish(t, s.leader, s.module, s.st)

	in := s.accept(KindIngress, "", "", 1)
	in.Op.VIP, in.Op.VRID, in.Op.Hosts, in.Op.Image, in.Op.NewPassword = "10.5.0.200/24", 50, []string{"h1"}, testImage, true

	cert, key := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(24*time.Hour), "10.5.0.3", "h1", "10.5.0.200"))
	out, _ := json.Marshal(map[string]string{"attempt": "0123456789abcdef", "cert": cert})
	id := "issued/" + in.Op.ID + "/0123456789abcdef"

	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = in
	s.module.active, s.module.rgwCert = "h0", string(out)
	s.module.kv[store.SecretPrefix+state.SecretRGWServer] = oldKey
	s.module.kv[store.SecretPrefix+id+"/rgw-server.key"] = key
	s.module.kv[store.SecretPrefix+"ingress/"+in.Op.ID+"/vrrp"] = "abc"
	s.module.mu.Unlock()

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	rgw, vip := "ceph-"+testFSID[:8]+"-rgw-h1", "ceph-"+testFSID[:8]+"-vip-h1"
	running(t, s, rgw)
	addInstance(t, s.agent.fake, rgw, 1)
	s.leader.serves = func(_ string, _ int, chain string) bool { return chain == cert }

	for i := 0; i < 4; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	// the RGW serves the certificate for the VIP from a new instance; only then keepalived
	if owned(t, s, vip) {
		t.Fatal("keepalived before the RGW serves a certificate for the VIP")
	}

	addInstance(t, s.agent.fake, rgw, 2)

	for i := 0; i < 4; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if !owned(t, s, vip) {
		t.Fatal("keepalived was not granted")
	}

	running(t, s, vip)
	keepalivedLog(s, vip, "1", "BACKUP")

	for i := 0; i < 2; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, in.Op.ID); op.State != "completed" {
		t.Fatalf("ingress: %+v", op)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, _ := st.Find("rgw.h1"); d.Cert != id || st.RGW.VIP != "10.5.0.200/24" || st.RGW.VRRPSecretName() != "ingress/"+in.Op.ID+"/vrrp" {
		t.Fatalf("state: %+v %+v", d, st.RGW)
	}
}
