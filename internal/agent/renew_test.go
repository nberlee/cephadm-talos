package agent

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// mgrSetup is a leader setup whose h1 runs a mgr an add deployed.
func mgrSetup(t *testing.T) (*leaderSetup, state.Host) {
	t.Helper()

	s := newLeaderSetup(t)
	ctx := context.Background()
	s.withCA(t)

	must(t, s.leader.Tick(ctx, 42, 5)) // the takeover closes the earlier sessions

	add := s.accept(KindAddDaemon, "mgr.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add: %+v", op)
	}

	return s, s.host(t, "h1")
}

func (s *leaderSetup) host(t *testing.T, name string) state.Host {
	t.Helper()

	st, _, err := s.leader.clusterState(context.Background(), s.leader.bridge())
	must(t, err)

	h, _ := st.Host(name)

	return h
}

func (s *leaderSetup) ended(id string) bool {
	s.module.mu.Lock()
	defer s.module.mu.Unlock()

	_, ok := s.module.kv[JournalPrefix(42)+"op/"+id]

	return ok
}

func (s *leaderSetup) calls() []string {
	s.module.mu.Lock()
	defer s.module.mu.Unlock()

	return slices.Clone(s.module.retired)
}

func TestARenewalRenewsTheActiveMgrsCertificates(t *testing.T) {
	s, before := mgrSetup(t)
	ctx := context.Background()

	served := before.MgrServerCert
	s.leader.serves = func(_ string, port int, chain string) bool { return port == wire.ModulePort && chain == served }

	s.module.mu.Lock()
	s.module.active = "h1"
	s.module.mu.Unlock()

	renew := s.accept(KindRenewMgr, "mgr.h1", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	// new certificates in the state, the old ones journaled, the files granted
	h := s.host(t, "h1")
	if !strings.HasPrefix(h.MgrKeys, renew.Op.ID+"/") || h.MgrServerCert == before.MgrServerCert || h.MgrClientCert == before.MgrClientCert {
		t.Fatalf("state: %+v", h)
	}

	var rec mgrRenewal

	s.module.mu.Lock()
	err := json.Unmarshal([]byte(s.module.kv[rollKey(42, renew.Op.ID+".renew")]), &rec)
	s.module.mu.Unlock()

	if err != nil || rec.ServerCert != before.MgrServerCert || rec.ClientCert != before.MgrClientCert || rec.Keys != before.MgrKeys || rec.Retiring {
		t.Fatalf("journaled %+v %v", rec, err)
	}

	if rev := s.op(t, renew.Op.ID+".rev"); rev.State != "completed" || rev.Docs["EtcFileConfig/ceph/talos/mgr-server.key"] == "" {
		t.Fatalf("revision %+v", rev)
	}

	// the active module does not serve the new certificate yet: nothing retired
	must(t, s.leader.Tick(ctx, 42, 5))

	if s.ended(renew.Op.ID) || slices.Contains(s.calls(), "mgr cert done "+renew.Op.ID) {
		t.Fatal("retired before the active module served the new certificate")
	}

	served = h.MgrServerCert
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != "completed" {
		t.Fatalf("renewal: %+v", op)
	}

	if got := s.calls(); !slices.Equal(got, []string{"mgr cert done " + renew.Op.ID}) {
		t.Fatalf("calls %v", got)
	}
}

func TestAMgrRenewalInMaintenanceGrantsNothing(t *testing.T) {
	s, before := mgrSetup(t)
	ctx := context.Background()

	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		h, _ := st.Host("h1")
		h.Maintenance = true
		st.AddHost(h)

		return nil
	}))

	// the module does not answer mgr cert done at first: asked until it does,
	// however long that takes
	s.module.mu.Lock()
	s.module.refuse = "mgr cert done"
	s.module.mu.Unlock()

	renew := s.accept(KindRenewMgr, "mgr.h1", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	s.leader.failing = map[string]time.Time{renew.Op.ID: time.Now().Add(-stuckAfter - time.Minute)}
	must(t, s.leader.Tick(ctx, 42, 5))

	if s.ended(renew.Op.ID) {
		t.Fatal("ended before the module retired the other certificates")
	}

	s.module.mu.Lock()
	s.module.refuse = ""
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != "completed" {
		t.Fatalf("renewal: %+v", op)
	}

	// the state has the new certificates for the exit; no revision was granted
	if h := s.host(t, "h1"); !strings.HasPrefix(h.MgrKeys, renew.Op.ID+"/") || h.MgrServerCert == before.MgrServerCert {
		t.Fatalf("state: %+v", h)
	}

	if s.ended(renew.Op.ID + ".rev") {
		t.Fatal("a revision of a host in maintenance")
	}
}

func TestAFailedMgrRenewalRestoresTheInstalledCertificates(t *testing.T) {
	s, before := mgrSetup(t)
	ctx := context.Background()

	// the active module never serves the new certificate
	s.leader.serves = func(string, int, string) bool { return false }

	s.module.mu.Lock()
	s.module.active = "h1"
	s.module.mu.Unlock()

	renew := s.accept(KindRenewMgr, "mgr.h1", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	if h := s.host(t, "h1"); !strings.HasPrefix(h.MgrKeys, renew.Op.ID+"/") {
		t.Fatalf("state: %+v", h)
	}

	s.leader.failing[renew.Op.ID] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != JournalFailed {
		t.Fatalf("renewal: %+v", op)
	}

	if h := s.host(t, "h1"); h.MgrKeys != before.MgrKeys || h.MgrServerCert != before.MgrServerCert || h.MgrClientCert != before.MgrClientCert {
		t.Fatalf("not restored: %+v", h)
	}

	if slices.Contains(s.calls(), "mgr cert done "+renew.Op.ID) {
		t.Fatal("the other certificates retired by a failed renewal")
	}
}

// renewRGWSetup is rgwSetup with the module ready to issue a renewed
// certificate for the renewal it accepts.
func renewRGWSetup(t *testing.T, s *leaderSetup) (LedgerEntry, string, string) {
	t.Helper()

	now := time.Now()

	renew := s.accept(KindRenewRGW, "", "", 1)

	cert, key := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(365*24*time.Hour), "10.5.0.3", "h1", "10.5.0.200"))
	out, _ := json.Marshal(map[string]string{"attempt": "0123456789abcdef", "cert": cert})
	id := "issued/" + renew.Op.ID + "/0123456789abcdef"

	s.module.mu.Lock()
	s.module.rgwCert = string(out)
	s.module.kv[store.SecretPrefix+id+"/rgw-server.key"] = key
	s.module.mu.Unlock()

	return renew, cert, id
}

func TestARenewalRollsTheRGWCertificate(t *testing.T) {
	s, rgw, vip := rgwSetup(t)
	ctx := context.Background()

	// an RGW on a host in maintenance: not visited, its record set for the exit
	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		h, _ := st.Host("h0")
		h.Maintenance = true
		st.AddHost(h)
		st.AddDaemon(state.Daemon{Type: state.TypeRGW, ID: "h0", Host: "h0"})

		return nil
	}))

	addInstance(t, s.agent.fake, rgw, 1)

	renew, cert, id := renewRGWSetup(t, s)

	served := ""
	s.leader.serves = func(_ string, _ int, chain string) bool { return chain == served }

	for i := 0; i < 4; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	// keepalived's removal alone: the RGW's document stays as the agent holds it
	off := s.op(t, renew.Op.ID+".roll.h1.vip")
	if len(off.Docs) != 1 || off.Docs["ContainerConfig/"+vip] != "" || owned(t, s, vip) {
		t.Fatalf("keepalived off: %+v", off)
	}

	addInstance(t, s.agent.fake, rgw, 2)
	served = cert

	for i := 0; i < 3; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	keepalivedLog(s, vip, "2", "MASTER")

	for i := 0; i < 2; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, renew.Op.ID); op.State != "completed" {
		t.Fatalf("renewal: %+v", op)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	for _, name := range []string{"rgw.h0", "rgw.h1"} {
		if d, _ := st.Find(name); d.Cert != id {
			t.Fatalf("%s renders %q", name, d.Cert)
		}
	}

	if s.ended(renew.Op.ID+".roll.h0.vip") || s.ended(renew.Op.ID+".roll.h0.rev") {
		t.Fatal("the host in maintenance was visited")
	}

	if got := s.calls(); !slices.Equal(got, []string{"rgw cert " + renew.Op.ID, "rgw cert done " + renew.Op.ID + " " + id}) {
		t.Fatalf("calls %v", got)
	}
}

// unfinishedRoll records a certificate a predecessor's roll set for rgw.h1
// before it stopped, valid for the given time.
func unfinishedRoll(t *testing.T, s *leaderSetup, valid time.Duration) string {
	t.Helper()

	now := time.Now()
	prev := "op-00000000000000aa"
	id := "issued/" + prev + "/00000000000000aa"
	cert, key := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(valid), "10.5.0.3", "h1", "10.5.0.200"))

	must(t, s.leader.changeState(context.Background(), s.leader.bridge(), 42, func(st *state.State) error {
		st.RGW.Certs = append(st.RGW.Certs, state.RGWCert{ID: id, Cert: cert})

		d, _ := st.Find("rgw.h1")
		d.Cert = id
		st.AddDaemon(d)

		return nil
	}))

	s.module.mu.Lock()
	s.module.kv[store.SecretPrefix+id+"/rgw-server.key"] = key
	s.module.kv[rollKey(42, prev+".roll.h1")] = `{"instance":"x"}`
	s.module.mu.Unlock()

	return id
}

func TestARenewalSupersedesAnUnfinishedRollWhoseCertificateIsDue(t *testing.T) {
	s, rgw, _ := rgwSetup(t)
	ctx := context.Background()

	unfinishedRoll(t, s, 10*24*time.Hour)
	addInstance(t, s.agent.fake, rgw, 1)

	renew, _, id := renewRGWSetup(t, s)
	s.leader.serves = func(string, int, string) bool { return false }

	for i := 0; i < 4; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	// not finished to the due certificate: rolled to the new one
	if s.ended(renew.Op.ID + ".recover.h1.vip") {
		t.Fatal("the due certificate's roll was finished")
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, _ := st.Find("rgw.h1"); d.Cert != id {
		t.Fatalf("rgw.h1 renders %q", d.Cert)
	}

	// keepalived went off alone, not with the RGW the failed roll left named
	// in the state (the agent still holds the one before)
	if off := s.op(t, renew.Op.ID+".roll.h1.vip"); len(off.Docs) != 1 {
		t.Fatalf("keepalived off: %+v", off.Docs)
	}
}

func TestARenewalFinishesAnUnfinishedRollWhoseCertificateIsValid(t *testing.T) {
	s, rgw, _ := rgwSetup(t)
	ctx := context.Background()

	prev := unfinishedRoll(t, s, 90*24*time.Hour)
	addInstance(t, s.agent.fake, rgw, 1)

	renew, _, _ := renewRGWSetup(t, s)
	s.leader.serves = func(string, int, string) bool { return false }

	for i := 0; i < 4; i++ {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	// finished to its certificate first: nothing issued meanwhile
	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if d, _ := st.Find("rgw.h1"); d.Cert != prev || !s.ended(renew.Op.ID+".recover.h1.vip") || slices.Contains(s.calls(), "rgw cert "+renew.Op.ID) {
		t.Fatalf("rgw.h1 renders %q, calls %v", d.Cert, s.calls())
	}
}

func TestMalformedRenewalsEnd(t *testing.T) {
	s, _ := mgrSetup(t)
	ctx := context.Background()

	hosted := s.accept(KindRenewRGW, "", "h1", 2)
	bare := s.accept(KindRenewMgr, "", "h1", 3)
	other := s.accept(KindRenewMgr, "mgr.h0", "h1", 4)
	none := s.accept(KindRenewMgr, "mgr.h0", "h0", 5)

	must(t, s.leader.Tick(ctx, 42, 5))

	for _, e := range []LedgerEntry{hosted, bare} {
		if op := s.op(t, e.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "malformed") {
			t.Errorf("%s: %+v", e.Op.Kind, op)
		}
	}

	for _, e := range []LedgerEntry{other, none} {
		if op := s.op(t, e.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "is not a mgr") {
			t.Errorf("%s on %s: %+v", e.Op.Daemon, e.Op.Host, op)
		}
	}
}

func TestTheOperatorsRGWCertificateIsNotRenewed(t *testing.T) {
	s, _, _ := rgwSetup(t)
	ctx := context.Background()
	now := time.Now()

	cert, _ := splitPEM(servingPEM(t, now.Add(-time.Hour), now.Add(24*time.Hour), "s3.example.com"))

	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		st.RGW.Certs = append(st.RGW.Certs, state.RGWCert{ID: "user/op-00000000000000be", Cert: cert, User: true})

		d, _ := st.Find("rgw.h1")
		d.Cert = "user/op-00000000000000be"
		st.AddDaemon(d)

		return nil
	}))

	renew, _, _ := renewRGWSetup(t, s)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, renew.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "operator's certificate") || len(s.calls()) != 0 {
		t.Fatalf("renewal: %+v, calls %v", op, s.calls())
	}
}
