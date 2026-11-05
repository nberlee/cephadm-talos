package orch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/network"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// retiringFake is a sealed cluster with member h1 and h9, a removed host still
// retiring, with an agent of its own (a9) answering at 127.0.0.9. Both hosts
// are on the one fake Talos node. Its records jobs and ceph commands are
// recorded instead of run.
type retiringFake struct {
	o   *Orch
	h9  state.Host
	h7  state.Host
	h9b state.Host
	// caKey stays in the secrets, where only the workstation writing the state
	// would change it
	caKey string
	a1    *fakeAgent
	a9    *fakeAgent
	jobs  []string
	cmds  []string
	// handoffs are the hosts handed to their agents
	handoffs []string
	// onJob, called for each records job, may change the node; report is what
	// a job answers (a retired report by default)
	onJob  func(kind, serial string)
	report func(kind, serial string) (agent.RecordsReport, error)
}

func retiringSetup(t *testing.T) *retiringFake {
	t.Helper()

	o, _, a1 := suspendSetup(t)
	ctx := context.Background()

	h9 := state.Host{Name: "h9", Addr: "127.0.0.9"}
	if err := o.ensureAgentCert(&h9); err != nil {
		t.Fatal(err)
	}

	pair, err := tls.X509KeyPair([]byte(h9.AgentCert), []byte(h9.AgentKey))
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(o.St.Agent.CACert))

	a9 := &fakeAgent{revision: 3, node: a1.node, host: "h9"}
	a9.srv = httptest.NewUnstartedServer(a9)
	a9.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS13}
	a9.srv.StartTLS()
	t.Cleanup(a9.srv.Close)

	old := agentAddr
	agentAddr = func(h state.Host) string {
		if h.Name == "h9" {
			return a9.srv.Listener.Addr().String()
		}

		return a1.srv.Listener.Addr().String()
	}

	t.Cleanup(func() { agentAddr = old })

	f := &retiringFake{o: o, h9: h9, a1: a1, a9: a9}

	// a replacement of h9 on the node: its name, another generation
	f.h9b = state.Host{Name: "h9", Addr: h9.Addr}
	if err := o.ensureAgentCert(&f.h9b); err != nil {
		t.Fatal(err)
	}

	// a former h7's agent, for an enrollment over its node
	f.h7 = state.Host{Name: "h7", Addr: "127.0.0.7"}
	if err := o.ensureAgentCert(&f.h7); err != nil {
		t.Fatal(err)
	}

	o.nodeRecords = func(h state.Host, kind, serial string) (agent.RecordsReport, error) {
		f.jobs = append(f.jobs, kind+"/"+h.Name+"/"+serial)

		if f.onJob != nil {
			f.onJob(kind, serial)
		}

		if f.report != nil {
			return f.report(kind, serial)
		}

		return agent.RetiredReport(), nil
	}
	o.cephCommand = func(cmd string) error {
		f.cmds = append(f.cmds, cmd)

		return nil
	}
	o.handOverHook = func(h state.Host) error {
		f.handoffs = append(f.handoffs, h.Name)

		return nil
	}

	// the fake node is every host: only what a test puts there is on it
	docs, err := o.agentDocsOn(ctx, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	for _, d := range docs {
		if err := o.remove(ctx, "127.0.0.1", d); err != nil {
			t.Fatal(err)
		}
	}

	del, err := spec.Render(spec.Delete("UserVolumeConfig", spec.RecordsVolumeName))
	if err != nil {
		t.Fatal(err)
	}

	if err := o.Talos.Patch(ctx, "127.0.0.1", del); err != nil {
		t.Fatal(err)
	}

	o.St.Sealed = true
	f.caKey = o.St.Agent.CAKey
	o.St.Retiring = map[string]*state.Retiring{"h9": {Op: "op-0000000000000009", Addr: h9.Addr, AgentCert: h9.AgentCert, AgentClientCert: h9.AgentClientCert,
		Step: state.RetireStrip, Since: time.Now()}}
	f.publish(t)

	return f
}

// publish publishes the state as the leader would, then reads it back.
func (f *retiringFake) publish(t *testing.T) {
	t.Helper()

	f.o.sealed = false

	if err := f.o.save(); err != nil {
		t.Fatal(err)
	}

	if err := f.o.Open(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := f.o.StoreBackend.SetMany(context.Background(), []store.KV{{Key: store.SecretPrefix + "agent-ca.key", Value: []byte(f.caKey)}}); err != nil {
		t.Fatal(err)
	}
}

// hostname sets what the fake node calls itself.
func (f *retiringFake) hostname(t *testing.T, name string) {
	t.Helper()

	ctx := context.Background()
	r := network.NewHostnameStatus(network.NamespaceName, network.HostnameID)
	r.TypedSpec().Hostname = name

	_ = f.a1.node.St.Destroy(ctx, r.Metadata())

	if err := f.a1.node.St.Create(ctx, r); err != nil {
		t.Fatal(err)
	}
}

// docs are the cluster's agent and records-init documents on the fake node.
func (f *retiringFake) docs(t *testing.T) []string {
	t.Helper()

	d, err := f.o.agentDocsOn(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	return d
}

// agentDocs9 puts h9's agent and records-init documents on the node.
func (f *retiringFake) agentDocs9(t *testing.T) {
	t.Helper()

	if err := f.o.apply(context.Background(), f.h9.Addr, f.o.agentDocs(f.h9)...); err != nil {
		t.Fatal(err)
	}
}

// live is the report of records of h9's generation.
func (f *retiringFake) live(t *testing.T) agent.RecordsReport {
	t.Helper()

	return agent.RecordsReport{Serial: f.serial(t), Serials: []string{f.serial(t)}}
}

func (f *retiringFake) serial(t *testing.T) string {
	t.Helper()

	s, err := certSerial(f.h9.AgentCert)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func TestHostForgetTakesTheNodeOverThenTellsTheModule(t *testing.T) {
	f := retiringSetup(t)
	ctx := context.Background()
	f.agentDocs9(t)
	f.hostname(t, "h9")

	serial := f.serial(t)
	inspected := 0
	f.onJob = func(kind, s string) {
		if kind == recordsInspect {
			inspected++
		}

		// the first look validates, changing nothing
		if inspected == 1 && len(f.docs(t)) == 0 {
			t.Error("the documents went before the node was validated")
		}

		if kind == recordsInspect && inspected == 2 {
			// an earlier apply brings its documents back after this look
			if docs := f.docs(t); len(docs) != 0 {
				t.Errorf("inspected before the documents went: %v", docs)
			}

			f.agentDocs9(t)
		}

		if kind == recordsRetire && len(f.docs(t)) != 0 {
			t.Errorf("retired with documents on the node: %v", f.docs(t))
		}
	}
	f.report = func(kind, _ string) (agent.RecordsReport, error) {
		if kind == recordsInspect {
			return f.live(t), nil
		}

		return agent.RetiredReport(), nil
	}

	if err := f.o.HostForget(ctx, "h9", false); err != nil {
		t.Fatal(err)
	}

	want := []string{"inspect/h9/" + serial, "inspect/h9/" + serial, "inspect/h9/" + serial, "retire/h9/" + serial}
	if !slices.Equal(f.jobs, want) {
		t.Fatalf("records jobs %v, want %v", f.jobs, want)
	}

	if len(f.docs(t)) != 0 {
		t.Fatalf("left on the node: %v", f.docs(t))
	}

	if !slices.Equal(f.cmds, []string{"ceph orch talos host forgotten 'h9' --operation 'op-0000000000000009'"}) {
		t.Fatalf("commands %v", f.cmds)
	}
}

func TestHostForgetWaitsUntilAnApplyHasSettled(t *testing.T) {
	f := retiringSetup(t)
	f.hostname(t, "h9")

	boot, err := f.o.Talos.BootID(context.Background(), f.h9.Addr)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	// sent just now on this boot: it may still land
	f.report = func(kind, _ string) (agent.RecordsReport, error) {
		rep := f.live(t)
		rep.ApplyBoot, rep.ApplyAt = boot, time.Now().UnixNano()

		return rep, nil
	}

	if err := f.o.HostForget(ctx, "h9", false); err == nil {
		t.Fatal("retired over an apply that may still land")
	}

	if slices.ContainsFunc(f.jobs, func(j string) bool { return strings.HasPrefix(j, recordsRetire) }) || len(f.cmds) != 0 {
		t.Fatalf("jobs %v, commands %v", f.jobs, f.cmds)
	}

	// on another boot it cannot land anymore
	f.jobs = nil
	f.report = func(kind, _ string) (agent.RecordsReport, error) {
		if kind == recordsInspect {
			rep := f.live(t)
			rep.ApplyBoot, rep.ApplyAt = "another boot", time.Now().UnixNano()

			return rep, nil
		}

		return agent.RetiredReport(), nil
	}

	if err := f.o.HostForget(context.Background(), "h9", false); err != nil || len(f.cmds) != 1 {
		t.Fatalf("settled: %v, %v", err, f.cmds)
	}
}

func TestHostForgetOfANodeThatIsGoneOnlyTellsTheModule(t *testing.T) {
	f := retiringSetup(t)
	f.agentDocs9(t)

	if err := f.o.HostForget(context.Background(), "h9", true); err != nil {
		t.Fatal(err)
	}

	if len(f.jobs) != 0 || len(f.docs(t)) == 0 || !slices.Equal(f.cmds, []string{"ceph orch talos host forgotten 'h9' --operation 'op-0000000000000009'"}) {
		t.Fatalf("jobs %v, documents %v, commands %v", f.jobs, f.docs(t), f.cmds)
	}
}

func TestHostForgetRefuses(t *testing.T) {
	ctx := context.Background()

	f := retiringSetup(t)
	f.agentDocs9(t)
	f.hostname(t, "another")

	for name, c := range map[string]struct {
		host string
		want string
	}{
		"not retiring":    {"h7", "not retiring"},
		"a member":        {"h1", "a host of the cluster"},
		"another machine": {"h9", "calls itself another"},
	} {
		if err := f.o.HostForget(ctx, c.host, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	if len(f.docs(t)) == 0 || len(f.jobs) != 0 || len(f.cmds) != 0 {
		t.Fatalf("documents %v, jobs %v, commands %v", f.docs(t), f.jobs, f.cmds)
	}

	// no operator certificate
	f.hostname(t, "h9")
	cert := f.o.St.Agent.OperatorCert
	f.o.St.Agent.OperatorCert = ""

	if err := f.o.HostForget(ctx, "h9", false); err == nil || !strings.Contains(err.Error(), "operator certificate") {
		t.Errorf("without the certificate: %v", err)
	}

	f.o.St.Agent.OperatorCert = cert

	// a member now has the journaled address: its agent is not stopped
	h1, _ := f.o.St.Host("h1")
	f.o.St.Retiring["h9"].Addr = h1.Addr
	f.publish(t)

	if err := f.o.HostForget(ctx, "h9", false); err == nil || !strings.Contains(err.Error(), "now has the address") {
		t.Errorf("another member's address: %v", err)
	}

	f.o.St.Retiring["h9"].Addr = f.h9.Addr
	f.publish(t)

	// in a recovery session: the resumption finishes it
	rec := &state.Recovery{Schema: state.RecoverySchema, FSID: f.o.St.FSID, Session: "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f", Phase: state.PhaseSuspended,
		Hosts: map[string]*state.RecoveryHost{}, Jobs: map[string]*state.RecoveryJob{}}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	if err := f.o.HostForget(ctx, "h9", false); err == nil || !strings.Contains(err.Error(), "recovery session") {
		t.Errorf("in a session: %v", err)
	}
}

// enrolling is a node called h7 for `host add`, none of whose name's records
// are in the cluster.
func enrolling(t *testing.T) *retiringFake {
	t.Helper()

	f := retiringSetup(t)
	delete(f.o.St.Retiring, "h9")
	f.publish(t)
	f.hostname(t, "h7")

	return f
}

// enrollWritten reports what an enrollment of h7 has written so far.
func enrollWritten(t *testing.T, o *Orch) []string {
	t.Helper()

	ctx := context.Background()

	var got []string

	for _, k := range []string{store.SecretPrefix + state.SecretHost("h7", state.SecretAgentServer), store.SecretPrefix + state.SecretHost("h7", state.SecretAgentClient), EnrollPrefix + "h7"} {
		if _, err := o.StoreBackend.Get(ctx, k); err == nil {
			got = append(got, k)
		} else if !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
	}

	return got
}

// The name is read freshly: a workstation that read the state before the
// removal, whose copy has neither the host's retirement nor its record, must
// not write over what the retirement's end deletes.
func TestEnrollmentRefusesARetiringNameFromThePublishedRecord(t *testing.T) {
	f := retiringSetup(t)
	f.hostname(t, "h9")
	ctx := context.Background()

	// as this workstation read it before the removal
	f.o.St.Retiring = nil

	err := f.o.Enroll(ctx, "127.0.0.77")
	if err == nil || !strings.Contains(err.Error(), "being removed") {
		t.Fatalf("a retiring name: %v", err)
	}

	keys, lerr := f.o.StoreBackend.List(ctx, EnrollPrefix)
	if lerr != nil || len(keys) != 0 {
		t.Fatalf("records written: %v %v", keys, lerr)
	}

	if len(f.handoffs) != 0 || len(f.cmds) != 0 {
		t.Fatalf("handoffs %v, commands %v", f.handoffs, f.cmds)
	}
}

func TestEnrollmentRefusesTheAddressOfAMemberOrARetiringHost(t *testing.T) {
	f := retiringSetup(t)
	f.hostname(t, "h7")
	ctx := context.Background()

	for _, addr := range []string{"127.0.0.1", f.h9.Addr} {
		if err := f.o.Enroll(ctx, addr); err == nil || !strings.Contains(err.Error(), "has the address") {
			t.Errorf("%s: %v", addr, err)
		}
	}

	if got := enrollWritten(t, f.o); len(got) != 0 || len(f.jobs) != 0 {
		t.Fatalf("written %v, jobs %v", got, f.jobs)
	}
}

// A new agent never starts over an old set: the old agent's documents go and
// the records are retired before anything of the new one is written.
func TestEnrollmentOverAnOldGenerationCleansTheNodeFirst(t *testing.T) {
	f := enrolling(t)
	ctx := context.Background()

	// the old generation's documents, a former h7's
	old := f.h7
	if err := f.o.apply(ctx, old.Addr, f.o.agentDocs(old)...); err != nil {
		t.Fatal(err)
	}

	f.report = func(kind, _ string) (agent.RecordsReport, error) {
		if kind == recordsInspect {
			return agent.RecordsReport{Serial: "77"}, nil
		}

		return agent.RetiredReport(), nil
	}
	f.onJob = func(kind, serial string) {
		if docs := f.docs(t); kind == recordsRetire && len(docs) != 0 {
			t.Errorf("%s with documents on the node: %v", kind, docs)
		}

		if got := enrollWritten(t, f.o); len(got) != 0 {
			t.Errorf("%s after writing %v", kind, got)
		}
	}

	if err := f.o.Enroll(ctx, "127.0.0.7"); err != nil {
		t.Fatal(err)
	}

	back := f.docs(t)

	if !slices.Equal(f.jobs, []string{"inspect/h7/", "inspect/h7/", "retire/h7/77"}) {
		t.Fatalf("records jobs %v", f.jobs)
	}

	// the new agent: new certificates, documents on the node, added
	var rec Enrollment

	b, err := f.o.StoreBackend.Get(ctx, EnrollPrefix+"h7")
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatal(err)
	}

	if rec.AgentCert == "" || rec.AgentCert == old.AgentCert {
		t.Fatalf("the new agent has the old certificate: %+v", rec)
	}

	if !slices.Contains(back, f.o.agentDocName(old)) {
		t.Fatalf("the new agent's documents: %v", back)
	}

	if !slices.Equal(f.cmds, []string{"ceph orch host add 'h7' '127.0.0.7'"}) || !slices.Equal(f.handoffs, []string{"h7"}) {
		t.Fatalf("commands %v, handoffs %v", f.cmds, f.handoffs)
	}
}

// Enrollment's take-over refuses while the old agent's last apply may land.
func TestEnrollmentWritesNothingWhileAnOldApplyMayLand(t *testing.T) {
	f := enrolling(t)

	boot, err := f.o.Talos.BootID(context.Background(), "127.0.0.7")
	if err != nil {
		t.Fatal(err)
	}

	// the node holds the records volume, which a fresh node does not
	if err := f.o.apply(context.Background(), "127.0.0.7", spec.RecordsVolume()); err != nil {
		t.Fatal(err)
	}

	f.report = func(string, string) (agent.RecordsReport, error) {
		return agent.RecordsReport{ApplyBoot: boot, ApplyAt: time.Now().UnixNano()}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := f.o.Enroll(ctx, "127.0.0.7"); err == nil {
		t.Fatal("enrolled over an apply that may land")
	}

	if got := enrollWritten(t, f.o); len(got) != 0 {
		t.Fatalf("written %v", got)
	}
}

func TestEnrollmentOnAFreshNodeRunsNoRecordsJob(t *testing.T) {
	f := enrolling(t)

	if err := f.o.Enroll(context.Background(), "127.0.0.7"); err != nil {
		t.Fatal(err)
	}

	if len(f.jobs) != 0 || len(f.cmds) != 1 {
		t.Fatalf("jobs %v, commands %v", f.jobs, f.cmds)
	}
}

// A run after a stop goes on with its own agent: taking that over would mark
// the serial of the certificates it goes on with, and the agent would start
// retired.
func TestAnInterruptedEnrollmentGoesOnWithItsOwnAgent(t *testing.T) {
	f := enrolling(t)
	ctx := context.Background()

	if err := f.o.Enroll(ctx, "127.0.0.7"); err != nil {
		t.Fatal(err)
	}

	first, err := f.o.StoreBackend.Get(ctx, EnrollPrefix+"h7")
	if err != nil {
		t.Fatal(err)
	}

	f.cmds = nil

	if err := f.o.Enroll(ctx, "127.0.0.7"); err != nil {
		t.Fatal(err)
	}

	again, err := f.o.StoreBackend.Get(ctx, EnrollPrefix+"h7")
	if err != nil {
		t.Fatal(err)
	}

	if len(f.jobs) != 0 || string(first) != string(again) {
		t.Fatalf("jobs %v; record %s, then %s", f.jobs, first, again)
	}
}

// A late deletion erasing what was just written is found and named.
func TestAnEnrollmentErasedAfterItWasWrittenFailsLoudly(t *testing.T) {
	for _, what := range []string{EnrollPrefix + "h7", store.SecretPrefix + state.SecretHost("h7", state.SecretAgentServer), store.SecretPrefix + state.SecretHost("h7", state.SecretAgentClient)} {
		f := enrolling(t)
		ctx := context.Background()

		f.o.cephCommand = func(string) error { return f.o.StoreBackend.Remove(ctx, []string{what}) }

		err := f.o.Enroll(ctx, "127.0.0.7")
		if err == nil || !strings.Contains(err.Error(), "did not stay as written") || !strings.Contains(err.Error(), "ceph orch host rm h7") {
			t.Fatalf("%s erased: %v", what, err)
		}
	}
}

// retiringSession suspends the cluster with h9 retiring.
func retiringSession(t *testing.T, f *retiringFake) *state.Recovery {
	t.Helper()

	if _, err := f.o.Suspend(context.Background(), SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	rec, err := state.LoadRecovery(f.o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	return rec
}

func TestAReachableRetiringAgentIsSuspendedByItsJournaledIdentity(t *testing.T) {
	f := retiringSetup(t)
	ctx := context.Background()

	// its enrollment record: stale, naming another address and other certificates
	b, _ := json.Marshal(Enrollment{Version: 1, Name: "h9", Addr: "127.0.0.99", AgentCert: "stale", AgentClientCert: "stale"})
	if err := f.o.StoreBackend.SetMany(ctx, []store.KV{{Key: EnrollPrefix + "h9", Value: b}}); err != nil {
		t.Fatal(err)
	}

	rec := retiringSession(t, f)

	hr := rec.Hosts["h9"]
	if !hr.Retiring || hr.Addr != f.h9.Addr || hr.AgentCert != f.h9.AgentCert || hr.AgentClientCert != f.h9.AgentClientCert || hr.AgentSerial != f.serial(t) ||
		hr.Receipt == nil || hr.Receipt.Host != "h9" || hr.AgentRemoved {
		t.Fatalf("journal %+v", hr)
	}

	if f.a9.posts == 0 || len(f.jobs) != 0 {
		t.Fatalf("%d suspensions asked, jobs %v", f.a9.posts, f.jobs)
	}

	// never by the enrollment-record fallback; its keys by the journaled names
	if err := f.o.StoreBackend.SetMany(ctx, []store.KV{
		{Key: store.SecretPrefix + f.h9.AgentKeySecret(state.SecretAgentServer), Value: []byte(f.h9.AgentKey)},
		{Key: store.SecretPrefix + f.h9.AgentKeySecret(state.SecretAgentClient), Value: []byte(f.h9.AgentClientKey)},
	}); err != nil {
		t.Fatal(err)
	}

	ah, err := f.o.agentHost(ctx, state.Host{Name: "h9", Addr: "127.0.0.99"}, hr)
	if err != nil || ah.AgentCert != f.h9.AgentCert || ah.AgentKey != f.h9.AgentKey {
		t.Fatalf("agent host: %+v %v", ah, err)
	}
}

func TestAnUnreachableRetiringAgentIsTakenOverWithSettlement(t *testing.T) {
	f := retiringSetup(t)
	f.agentDocs9(t)
	f.hostname(t, "h9")

	f.a9.srv.Close()

	old := unreachableAfter
	unreachableAfter = 50 * time.Millisecond

	t.Cleanup(func() { unreachableAfter = old })

	var session string

	f.report = func(kind, _ string) (agent.RecordsReport, error) {
		rep := f.live(t)
		rep.Session, rep.Owned, rep.Open, rep.Intents = session, map[string]string{}, []wire.Operation{}, []wire.BridgeIntent{}

		return rep, nil
	}

	rec, err := state.LoadRecovery(f.o.St.FSID)
	if err != nil || rec != nil {
		t.Fatalf("%+v %v", rec, err)
	}

	// the session id is only known once the suspension created it
	f.onJob = func(string, string) {
		if rec, err := state.LoadRecovery(f.o.St.FSID); err == nil && rec != nil {
			session = rec.Session
		}
	}

	rec = retiringSession(t, f)

	hr := rec.Hosts["h9"]
	if !hr.AgentRemoved || hr.Receipt == nil || !slices.Equal(f.jobs, []string{"inspect/h9/" + f.serial(t), "inspect/h9/" + f.serial(t), "inspect/h9/" + f.serial(t)}) {
		t.Fatalf("journal %+v, jobs %v", hr, f.jobs)
	}

	if slices.Contains(f.docs(t), f.o.agentDocName(f.h9)) {
		t.Fatal("its agent's document stayed")
	}
}

func TestARetiringHostWhoseRecordsWereMovedAsideReadsAsRetired(t *testing.T) {
	f := retiringSetup(t)
	f.hostname(t, "h9")
	f.a9.retired = true // a retired agent answers 410: taken over, not a failure

	rec := retiringSession(t, f)

	hr := rec.Hosts["h9"]
	if hr.Receipt == nil || len(hr.Receipt.Owned) != 0 || hr.Receipt.ApplyPending || hr.Receipt.Session != rec.Session || hr.Receipt.Host != "h9" {
		t.Fatalf("receipt %+v", hr.Receipt)
	}

	if !slices.Equal(f.jobs, []string{"inspect/h9/" + f.serial(t), "inspect/h9/" + f.serial(t)}) {
		t.Fatalf("jobs %v", f.jobs)
	}
}

// A member that answers 410 is not taken over: nothing says it was removed.
func TestAMemberAnswering410IsNoReasonToTakeItsNode(t *testing.T) {
	f := retiringSetup(t)
	f.a1.retired = true

	if _, err := f.o.Suspend(context.Background(), SuspendOptions{}); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("suspended: %v", err)
	}

	if slices.ContainsFunc(f.jobs, func(j string) bool { return strings.Contains(j, "h1") }) {
		t.Fatalf("jobs %v", f.jobs)
	}
}

// A contact of the workstation that the cluster no longer knows drops out:
// its retirement ended, and asking its node would fail the suspension forever.
func TestAContactWhoseRetirementEndedIsNoMember(t *testing.T) {
	f := retiringSetup(t)

	delete(f.o.St.Retiring, "h9")
	f.publish(t)
	f.o.St.Contacts = []state.Host{{Name: "h9", Addr: f.h9.Addr}}

	hosts, err := f.o.memberHosts(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if slices.ContainsFunc(hosts, func(h state.Host) bool { return h.Name == "h9" }) {
		t.Fatalf("still a member: %+v", hosts)
	}

	// without the mons: what the workstation knows
	f.o.opened = false

	if hosts, _ = f.o.memberHosts(context.Background()); !slices.ContainsFunc(hosts, func(h state.Host) bool { return h.Name == "h9" }) {
		t.Fatalf("offline: %+v", hosts)
	}
}

func TestARetiringHostStaysKnownOffline(t *testing.T) {
	f := retiringSetup(t)

	if err := f.o.KeepLocal(); err != nil {
		t.Fatal(err)
	}

	st, err := state.Load(f.o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	if rh, _, ok := st.RetiringHost("h9"); !ok || rh.AgentCert != f.h9.AgentCert {
		t.Fatalf("offline state: %+v", st.Retiring)
	}
}

// The resumption never brings a retiring agent back: without the check, a
// taken-over agent's documents would be applied again, the retired agent would
// start from a set of records it must not touch, and the retirement would
// wait for it.
func TestTheResumptionNeverReappliesOrReadoptsARetiringAgent(t *testing.T) {
	for name, reachable := range map[string]bool{"answered": true, "taken over": false} {
		t.Run(name, func(t *testing.T) {
			f := retiringSetup(t)
			ctx := context.Background()
			f.agentDocs9(t)
			f.hostname(t, "h9")

			if !reachable {
				f.a9.srv.Close()

				old := unreachableAfter
				unreachableAfter = 50 * time.Millisecond

				t.Cleanup(func() { unreachableAfter = old })

				var session string

				f.onJob = func(string, string) {
					if rec, err := state.LoadRecovery(f.o.St.FSID); err == nil && rec != nil {
						session = rec.Session
					}
				}
				f.report = func(kind, _ string) (agent.RecordsReport, error) {
					if kind == recordsRetire {
						return agent.RetiredReport(), nil
					}

					rep := f.live(t)
					rep.Session, rep.Owned, rep.Open, rep.Intents = session, map[string]string{}, []wire.Operation{}, []wire.BridgeIntent{}

					return rep, nil
				}
			}

			if reachable {
				f.report = func(kind, _ string) (agent.RecordsReport, error) {
					if kind == recordsRetire {
						return agent.RetiredReport(), nil
					}

					return f.live(t), nil
				}
			}

			rec := retiringSession(t, f)
			if rec.Hosts["h9"].AgentRemoved == reachable {
				t.Fatalf("journal %+v", rec.Hosts["h9"])
			}

			f.jobs = nil

			before := mgrMap{Epoch: 10, ActiveGID: 100, Available: true}
			fakeMgrs(t, before, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

			if err := f.o.Resume(ctx); err != nil {
				t.Fatal(err)
			}

			if len(f.a9.readopts) != 0 || len(f.a9.activations) != 0 {
				t.Fatalf("re-adopted %v, activated %v", f.a9.readopts, f.a9.activations)
			}

			if len(f.a1.readopts) != 1 || len(f.a1.activations) != 1 {
				t.Fatalf("the member: re-adopted %v, activated %v", f.a1.readopts, f.a1.activations)
			}

			if docs := f.docs(t); len(docs) != 0 {
				t.Fatalf("on the node: %v", docs)
			}

			if !slices.Contains(f.jobs, "retire/h9/"+f.serial(t)) {
				t.Fatalf("jobs %v", f.jobs)
			}

			if !slices.Equal(f.cmds, []string{"ceph orch talos host forgotten 'h9' --operation 'op-0000000000000009'"}) {
				t.Fatalf("commands %v", f.cmds)
			}
		})
	}
}

// The module accepts nothing before the control record went: it is told only
// after the takeover, and a retry tells it again if that failed.
func TestTheResumptionTellsTheModuleLast(t *testing.T) {
	f := retiringSetup(t)
	ctx := context.Background()
	f.hostname(t, "h9")

	retiringSession(t, f)

	before := mgrMap{Epoch: 10, ActiveGID: 100, Available: true}
	fakeMgrs(t, before, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	refused := errors.New("the control record is there")
	f.o.cephCommand = func(cmd string) error {
		if _, err := f.o.StoreBackend.Get(ctx, SuspensionKey); err == nil {
			t.Error("told while the control record exists")
		}

		f.cmds = append(f.cmds, cmd)

		return refused
	}

	if err := f.o.Resume(ctx); !errors.Is(err, refused) {
		t.Fatalf("a refusal: %v", err)
	}

	rec, err := state.LoadRecovery(f.o.St.FSID)
	if err != nil || rec == nil || rec.Phase != state.PhaseResuming || !rec.Hosts["h9"].RetireFinished || rec.Hosts["h9"].RetireTold {
		t.Fatalf("journal %+v %v", rec, err)
	}

	f.o.cephCommand = func(cmd string) error {
		f.cmds = append(f.cmds, cmd)

		return nil
	}

	jobs := len(f.jobs)

	if err := f.o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(f.cmds) != 2 || len(f.jobs) != jobs {
		t.Fatalf("commands %v; jobs %v (retired once)", f.cmds, f.jobs[jobs:])
	}
}

// A retry after a stop between telling the module and saving that must not end
// a later retirement of the name, by a removal after another workstation
// enrolled it again.
func TestAResumptionsRetryDoesNotForgetALaterRetirementOfTheName(t *testing.T) {
	f := retiringSetup(t)
	ctx := context.Background()

	rec := retiringSession(t, f)
	hr := rec.Hosts["h9"]

	if hr.RetireOp != "op-0000000000000009" {
		t.Fatalf("journal %+v", hr)
	}

	hr.RetireFinished = true

	f.o.St.Retiring["h9"].Op = "op-00000000000000aa"
	f.publish(t)

	if err := f.o.retireTold(ctx, rec, state.Host{Name: "h9"}); err != nil || len(f.cmds) != 0 || !hr.RetireTold {
		t.Fatalf("%v, commands %v, journal %+v", err, f.cmds, hr)
	}
}

// A stopped enrollment's retirement job left on the node goes before anything
// is written: on the next boot it would run again over the new agent's records.
func TestALeftRetirementJobGoesBeforeAnEnrollmentProceeds(t *testing.T) {
	f := enrolling(t)
	ctx := context.Background()

	left := "ceph-" + f.o.St.Short() + "-job-abc123"
	doc := daemons.RecordsRetireJob(left, f.o.St.Agent.Image, f.o.St.FSID, "abc123", "x", "77", "")

	other := "ceph-" + f.o.St.Short() + "-job-def456"
	script := spec.Container(other, f.o.St.Agent.Image)
	script.ContainerEnvironment = []string{"CMD=ceph -s"}

	if err := f.o.apply(ctx, "127.0.0.7", doc, script); err != nil {
		t.Fatal(err)
	}

	if err := f.o.Enroll(ctx, "127.0.0.7"); err != nil {
		t.Fatal(err)
	}

	names, err := f.o.configuredContainers(ctx, "127.0.0.7", "ceph-"+f.o.St.Short()+"-job-")
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(names, []string{other}) {
		t.Fatalf("jobs on the node: %v", names)
	}
}

// Records whose generation the inspection cannot read are not retired blindly.
func TestATakeoverNeedsTheGenerationItInspected(t *testing.T) {
	f := enrolling(t)
	ctx := context.Background()

	if err := f.o.apply(ctx, "127.0.0.7", spec.RecordsVolume()); err != nil {
		t.Fatal(err)
	}

	f.report = func(string, string) (agent.RecordsReport, error) { return agent.RecordsReport{}, nil }

	if err := f.o.Enroll(ctx, "127.0.0.7"); err == nil || !strings.Contains(err.Error(), "no identity record") {
		t.Fatalf("enrolled: %v", err)
	}

	if slices.ContainsFunc(f.jobs, func(j string) bool { return strings.HasPrefix(j, recordsRetire) }) {
		t.Fatalf("jobs %v", f.jobs)
	}

	if got := enrollWritten(t, f.o); len(got) != 0 {
		t.Fatalf("written %v", got)
	}
}

// removedMeanwhile is h9 as a member, its agent no longer answering, its records
// moved aside under its serial and missing otherwise; retired tells which.
func removedMeanwhile(t *testing.T, retired bool) *retiringFake {
	t.Helper()

	f := retiringSetup(t)
	f.a9.srv.Close()

	old := unreachableAfter
	unreachableAfter = 50 * time.Millisecond

	t.Cleanup(func() { unreachableAfter = old })

	f.report = func(_, serial string) (agent.RecordsReport, error) {
		if retired && serial == f.serial(t) {
			return agent.RetiredReport(), nil
		}

		return agent.RecordsReport{}, errors.New("no records of the cluster on the node")
	}

	return f
}

// A removal finishing after its host was journaled as a member, before the
// suspension reaches it: without the serial journaled at the start, its retired
// records read as missing and the session never ends.
func TestAMemberRemovedDuringTheSuspensionReadsAsRetired(t *testing.T) {
	f := removedMeanwhile(t, true)
	ctx := context.Background()
	f.hostname(t, "h9")

	delete(f.o.St.Retiring, "h9")
	f.o.St.AddHost(f.h9)
	f.publish(t)

	rec := retiringSession(t, f)

	hr := rec.Hosts["h9"]
	if hr.AgentSerial != f.serial(t) || !hr.Retiring || hr.Receipt == nil || len(hr.Receipt.Owned) != 0 || hr.Receipt.ApplyPending {
		t.Fatalf("journal %+v", hr)
	}

	// its resumption does not bring it back, and tells the module nothing:
	// no removal is journaled
	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	if err := f.o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(f.a9.readopts) != 0 || len(f.a1.activations) != 1 || len(f.cmds) != 0 {
		t.Fatalf("re-adopted %v, member activated %v, commands %v", f.a9.readopts, f.a1.activations, f.cmds)
	}
}

// An interrupted suspension retried once the removal ended: the published state
// says it left, whatever its node says.
func TestAJournaledHostThatLeftMeanwhileLeavesTheSession(t *testing.T) {
	for name, journal := range map[string]*state.RecoveryHost{
		"as a member":    {Addr: "127.0.0.9"},
		"while retiring": {Addr: "127.0.0.9", Retiring: true, RetireOp: "op-0000000000000009"},
	} {
		t.Run(name, func(t *testing.T) {
			f := removedMeanwhile(t, false)

			delete(f.o.St.Retiring, "h9")
			f.publish(t)

			rec := &state.Recovery{Schema: state.RecoverySchema, FSID: f.o.St.FSID, Session: "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f", Phase: state.PhaseSuspending,
				Hosts: map[string]*state.RecoveryHost{"h9": journal}, Jobs: map[string]*state.RecoveryJob{}}
			if err := rec.Save(); err != nil {
				t.Fatal(err)
			}

			got, err := f.o.Suspend(context.Background(), SuspendOptions{})
			if err != nil || got.Phase != state.PhaseSuspended || got.Hosts["h9"] != nil || len(f.jobs) != 0 {
				t.Fatalf("%v, journal %+v, jobs %v", err, got, f.jobs)
			}
		})
	}
}

// Without the mons the journal stands: its serial recognizes the retired set,
// and a set missing without a mark still fails.
func TestAnOfflineRetryRecognizesARetiredGeneration(t *testing.T) {
	for name, retired := range map[string]bool{"retired": true, "missing": false} {
		t.Run(name, func(t *testing.T) {
			f := removedMeanwhile(t, retired)
			f.hostname(t, "h9")

			rec := &state.Recovery{Schema: state.RecoverySchema, FSID: f.o.St.FSID, Session: "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f", Phase: state.PhaseSuspending,
				Hosts: map[string]*state.RecoveryHost{"h9": {Addr: "127.0.0.9", AgentSerial: f.serial(t)}}, Jobs: map[string]*state.RecoveryJob{}}
			if err := rec.Save(); err != nil {
				t.Fatal(err)
			}

			f.o.opened = false
			f.o.St.Retiring = nil

			got, err := f.o.Suspend(context.Background(), SuspendOptions{})
			if retired && (err != nil || got.Hosts["h9"].Receipt == nil || !got.Hosts["h9"].Retiring) {
				t.Fatalf("%v, %+v", err, got)
			}

			if !retired && (err == nil || !strings.Contains(err.Error(), "no records") || got.Hosts["h9"].Receipt != nil) {
				t.Fatalf("a missing set: %v, %+v", err, got)
			}
		})
	}
}

// A host with its receipt whose removal ended before the suspension reached the
// leader's own agent is no host to re-adopt.
func TestAResumptionDoesNotBringBackAHostThatLeft(t *testing.T) {
	f := retiringSetup(t)
	ctx := context.Background()
	f.hostname(t, "h9")

	delete(f.o.St.Retiring, "h9")
	f.o.St.AddHost(f.h9)
	f.publish(t)

	rec := retiringSession(t, f)
	if rec.Hosts["h9"].Retiring {
		t.Fatalf("journal %+v", rec.Hosts["h9"])
	}

	f.o.St.RemoveHost("h9")
	f.publish(t)

	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	if err := f.o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(f.a9.readopts) != 0 || len(f.a9.activations) != 0 || len(f.a1.readopts) != 1 {
		t.Fatalf("re-adopted %v, activated %v", f.a9.readopts, f.a9.activations)
	}
}

// The generation is checked before anything changes: a reused node keeps its
// replacement agent, and the retirement refuses with nothing changed.
func TestATakeoverOfAnotherGenerationChangesNothing(t *testing.T) {
	for name, c := range map[string]struct {
		docs   func(f *retiringFake) state.Host
		report func(f *retiringFake, t *testing.T) (agent.RecordsReport, error)
	}{
		"records of another generation": {
			func(f *retiringFake) state.Host { return f.h9 },
			func(*retiringFake, *testing.T) (agent.RecordsReport, error) {
				return agent.RecordsReport{Serial: "5", Serials: []string{"5"}}, nil
			},
		},
		"an agent of another generation": {
			func(f *retiringFake) state.Host { return f.h9b },
			func(f *retiringFake, t *testing.T) (agent.RecordsReport, error) { return f.live(t), nil },
		},
		"an agent of another host": {
			func(f *retiringFake) state.Host { return f.h7 },
			func(f *retiringFake, t *testing.T) (agent.RecordsReport, error) { return f.live(t), nil },
		},
		"an agent beside retired records of no such mark": {
			func(f *retiringFake) state.Host { return f.h9b },
			func(f *retiringFake, _ *testing.T) (agent.RecordsReport, error) { return agent.RetiredReport(), nil },
		},
		"no records and no mark": {
			func(f *retiringFake) state.Host { return f.h9 },
			func(*retiringFake, *testing.T) (agent.RecordsReport, error) {
				return agent.RecordsReport{}, errors.New("no records of cluster f on the node")
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := retiringSetup(t)
			ctx := context.Background()
			f.hostname(t, "h9")

			if err := f.o.apply(ctx, f.h9.Addr, f.o.agentDocs(c.docs(f))...); err != nil {
				t.Fatal(err)
			}

			before := f.docs(t)
			f.report = func(_, serial string) (agent.RecordsReport, error) {
				rep, err := c.report(f, t)
				if rep.Retired && serial != f.serial(t) {
					return agent.RecordsReport{}, errors.New("no records of cluster f on the node")
				}

				return rep, err
			}

			err := f.o.HostForget(ctx, "h9", false)
			if !errors.Is(err, errNotThatNode) {
				t.Fatalf("taken over: %v", err)
			}

			if !slices.Equal(f.docs(t), before) || len(f.cmds) != 0 || slices.ContainsFunc(f.jobs, func(j string) bool { return strings.HasPrefix(j, recordsRetire) }) {
				t.Fatalf("documents %v, commands %v, jobs %v", f.docs(t), f.cmds, f.jobs)
			}
		})
	}
}

// An older serial of the same generation is that generation: a certificate
// renewed since the document was written is no reason to refuse.
func TestATakeoverAcceptsAnotherSerialOfTheGeneration(t *testing.T) {
	f := retiringSetup(t)
	f.hostname(t, "h9")

	if err := f.o.apply(context.Background(), f.h9.Addr, f.o.agentDocs(f.h9b)...); err != nil {
		t.Fatal(err)
	}

	other, err := certSerial(f.h9b.AgentCert)
	if err != nil {
		t.Fatal(err)
	}

	f.report = func(kind, _ string) (agent.RecordsReport, error) {
		if kind == recordsRetire {
			return agent.RetiredReport(), nil
		}

		return agent.RecordsReport{Serial: f.serial(t), Serials: []string{other, f.serial(t)}}, nil
	}

	if err := f.o.HostForget(context.Background(), "h9", false); err != nil {
		t.Fatal(err)
	}
}

// A reused node does not block the resumption, and keeps its agent.
func TestAResumptionLeavesAReusedNodeAlone(t *testing.T) {
	for name, reuse := range map[string]func(*retiringFake){
		"another hostname": func(f *retiringFake) { f.hostname(t, "another") },
		"another records generation": func(f *retiringFake) {
			f.hostname(t, "h9")
			f.report = func(string, string) (agent.RecordsReport, error) {
				return agent.RecordsReport{Serial: "5", Serials: []string{"5"}}, nil
			}
		},
		"no serial journaled": func(f *retiringFake) { f.hostname(t, "h9") },
	} {
		t.Run(name, func(t *testing.T) {
			f := retiringSetup(t)
			ctx := context.Background()

			if err := f.o.apply(ctx, f.h9.Addr, f.o.agentDocs(f.h9b)...); err != nil {
				t.Fatal(err)
			}

			rec := retiringSession(t, f)
			if name == "no serial journaled" {
				rec.Hosts["h9"].AgentSerial = ""

				if err := rec.Save(); err != nil {
					t.Fatal(err)
				}
			}

			reuse(f)

			before := f.docs(t)

			fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

			if err := f.o.Resume(ctx); err != nil {
				t.Fatal(err)
			}

			if !slices.Equal(f.docs(t), before) || len(f.cmds) != 0 || len(f.a1.activations) != 1 {
				t.Fatalf("documents %v, commands %v, activations %v", f.docs(t), f.cmds, f.a1.activations)
			}
		})
	}
}

// Offline, without a journaled serial, the agent's document still on the node
// names the certificate that recognizes its retired records.
func TestAnOfflineSuspensionTakesTheSerialFromTheAgentsDocument(t *testing.T) {
	f := removedMeanwhile(t, true)
	f.hostname(t, "h9")

	f.agentDocs9(t)

	rec := &state.Recovery{Schema: state.RecoverySchema, FSID: f.o.St.FSID, Session: "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f", Phase: state.PhaseSuspending,
		Hosts: map[string]*state.RecoveryHost{"h9": {Addr: "127.0.0.9"}}, Jobs: map[string]*state.RecoveryJob{}}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	f.o.opened = false
	f.o.St.Retiring = nil

	got, err := f.o.Suspend(context.Background(), SuspendOptions{})
	if err != nil || got.Hosts["h9"].AgentSerial != f.serial(t) || got.Hosts["h9"].Receipt == nil {
		t.Fatalf("%v, %+v", err, got)
	}

	saved, err := state.LoadRecovery(f.o.St.FSID)
	if err != nil || saved.Hosts["h9"].AgentSerial != f.serial(t) {
		t.Fatalf("not journaled: %+v %v", saved, err)
	}
}

// staleRetirement is a workstation offline with an old retirement of h9, whose
// name and address were enrolled again: a replacement agent on the node, of
// another generation, at first not answering.
func staleRetirement(t *testing.T) (*retiringFake, func()) {
	t.Helper()

	f := retiringSetup(t)
	f.hostname(t, "h9")

	if err := f.o.apply(context.Background(), f.h9.Addr, f.o.agentDocs(f.h9b)...); err != nil {
		t.Fatal(err)
	}

	other, err := certSerial(f.h9b.AgentCert)
	if err != nil {
		t.Fatal(err)
	}

	f.report = func(string, string) (agent.RecordsReport, error) {
		return agent.RecordsReport{Serial: other, Serials: []string{other}}, nil
	}

	f.o.opened = false

	serving := agentAddr
	agentAddr = func(h state.Host) string {
		if h.Name == "h9" {
			return "127.0.0.1:1"
		}

		return serving(h)
	}

	old := unreachableAfter
	unreachableAfter = 50 * time.Millisecond

	t.Cleanup(func() { unreachableAfter = old })

	return f, func() { agentAddr = serving }
}

// The replacement published as the member it is, the state read again.
func (f *retiringFake) republished(t *testing.T) {
	t.Helper()

	f.o.opened = true
	delete(f.o.St.Retiring, "h9")
	f.o.St.AddHost(f.h9b)
	f.publish(t)
}

// Suspending over an old retirement would remove the replacement's document and
// suspend its records, and the resumption would then leave it disabled.
func TestASuspensionOverAnOldRetirementLeavesTheReplacementAlone(t *testing.T) {
	f, answers := staleRetirement(t)
	ctx := context.Background()

	before := f.docs(t)

	rec, err := f.o.Suspend(ctx, SuspendOptions{})
	if err != nil {
		t.Fatal(err)
	}

	hr := rec.Hosts["h9"]
	if !hr.LeftOut || hr.AgentRemoved || hr.RemovingAgent || !slices.Equal(f.docs(t), before) {
		t.Fatalf("journal %+v, documents %v", hr, f.docs(t))
	}

	// the rest of the cluster is suspended
	if rec.Phase != state.PhaseSuspended || rec.Hosts["h1"].Receipt == nil {
		t.Fatalf("session %+v", rec)
	}

	// the mons answer: the replacement is a member, suspended and brought back
	answers()
	f.republished(t)
	f.report = nil

	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	if err := f.o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if f.a9.posts == 0 || len(f.a9.readopts) != 1 || len(f.a9.activations) != 1 || len(f.cmds) != 0 || !slices.Equal(f.docs(t), before) {
		t.Fatalf("suspended %d, re-adopted %v, activated %v, commands %v, documents %v", f.a9.posts, f.a9.readopts, f.a9.activations, f.cmds, f.docs(t))
	}
}

// One that answered the suspension gave a real receipt: it comes back too.
func TestAReplacementThatAnsweredAnOldRetirementIsReadopted(t *testing.T) {
	f, answers := staleRetirement(t)
	ctx := context.Background()

	answers()

	rec, err := f.o.Suspend(ctx, SuspendOptions{})
	if err != nil || !rec.Hosts["h9"].Retiring || rec.Hosts["h9"].Receipt == nil {
		t.Fatalf("%v, %+v", err, rec)
	}

	f.republished(t)
	f.report = nil

	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	if err := f.o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(f.a9.readopts) != 1 || len(f.a9.activations) != 1 || len(f.cmds) != 0 || len(f.jobs) != 0 {
		t.Fatalf("re-adopted %v, activated %v, commands %v, jobs %v", f.a9.readopts, f.a9.activations, f.cmds, f.jobs)
	}
}

// A late suspension that fails is asked again by the next resume: suspend refuses
// once recovery began, and its flags are cleared by then.
func TestAFailedLateSuspensionIsRetriedByResume(t *testing.T) {
	f, answers := staleRetirement(t)
	ctx := context.Background()

	rec, err := f.o.Suspend(ctx, SuspendOptions{})
	if err != nil || !rec.Hosts["h9"].LeftOut {
		t.Fatalf("%v, %+v", err, rec)
	}

	rec.Phase = state.PhaseRecovering
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	answers()
	f.republished(t)
	f.report = nil

	// suspended for another session: a refusal, the journal keeps it pending
	f.a9.session = "someone else's"

	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	if err := f.o.Resume(ctx); err == nil || !strings.Contains(err.Error(), "h9") {
		t.Fatalf("a refused suspension: %v", err)
	}

	f.a9.session = ""

	if err := f.o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(f.a9.readopts) != 1 || len(f.a9.activations) != 1 {
		t.Fatalf("re-adopted %v, activated %v", f.a9.readopts, f.a9.activations)
	}
}

// leftOutWithMon is a suspended session with h9 left out over an old retirement,
// its stopped mon's document on the node.
func leftOutWithMon(t *testing.T, f *retiringFake) (*state.Recovery, string) {
	t.Helper()

	ctx := context.Background()

	old := quorumTimeout
	quorumTimeout = 10 * time.Millisecond

	t.Cleanup(func() { quorumTimeout = old })

	rec, err := f.o.Suspend(ctx, SuspendOptions{})
	if err != nil || !rec.Hosts["h9"].LeftOut {
		t.Fatalf("%v, %+v", err, rec)
	}

	doc := f.o.St.DocName(state.Daemon{Type: state.TypeMon, ID: "h9", Host: "h9"})
	mon := daemons.Mon(daemons.Params{Name: doc, Image: "quay.io/ceph/ceph@sha256:" + strings.Repeat("ab", 32), FSID: f.o.St.FSID, ID: "h9", Addr: f.h9.Addr, DeployID: "d9", Mode: "join", Addrv: daemons.MonAddrv(f.h9.Addr)})

	if err := f.o.apply(ctx, f.h9.Addr, mon); err != nil {
		t.Fatal(err)
	}

	return rec, doc
}

// The operator's assertion: suspended as a member first, then recovered.
func TestRecoverMemberSuspendsAHostLeftOutFirst(t *testing.T) {
	f, answers := staleRetirement(t)
	ctx := context.Background()

	_, doc := leftOutWithMon(t, f)

	answers()

	f.o.inspectMon = func(h state.Host) (string, error) {
		if h.Name == "h9" && f.a9.posts == 0 {
			t.Error("inspected before it was suspended")
		}

		return "d9", nil
	}

	_ = f.o.RecoverMons(ctx, "", []string{"h9"}) // no quorum in the fake

	got, err := state.LoadRecovery(f.o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	hr := got.Hosts["h9"]
	if f.a9.posts == 0 || hr.LeftOut || hr.Retiring || hr.Receipt == nil || hr.Receipt.Session != got.Session || !slices.Contains(hr.Restarted, doc) {
		t.Fatalf("%d suspensions, journal %+v", f.a9.posts, hr)
	}
}

// An agent that does not answer is taken over by the member path, by the
// certificate on the node and not the old retirement's.
func TestRecoverMemberTakesOverAnUnreachableAgentAsAMember(t *testing.T) {
	f, _ := staleRetirement(t)
	ctx := context.Background()

	rec, doc := leftOutWithMon(t, f)

	other, err := certSerial(f.h9b.AgentCert)
	if err != nil {
		t.Fatal(err)
	}

	f.onJob = func(_, serial string) {
		if serial != other {
			t.Errorf("a job with serial %s, want the node's %s", serial, other)
		}
	}
	f.report = func(string, string) (agent.RecordsReport, error) {
		return agent.RecordsReport{Session: rec.Session, Serial: other, Serials: []string{other}, Owned: map[string]string{}, Open: []wire.Operation{}, Intents: []wire.BridgeIntent{}}, nil
	}
	f.o.inspectMon = func(state.Host) (string, error) { return "d9", nil }

	_ = f.o.RecoverMons(ctx, "", []string{"h9"})

	got, err := state.LoadRecovery(f.o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	hr := got.Hosts["h9"]
	if !hr.AgentRemoved || hr.LeftOut || hr.Retiring || hr.Receipt == nil || hr.AgentSerial != other || !slices.Contains(hr.Restarted, doc) {
		t.Fatalf("journal %+v", hr)
	}
}

// A suspension that fails: the host is not touched further, the error says so,
// and a retry continues.
func TestRecoverMemberStopsWhenItsSuspensionFails(t *testing.T) {
	f, answers := staleRetirement(t)
	ctx := context.Background()

	_, doc := leftOutWithMon(t, f)

	answers()

	f.a9.session = "someone else's"
	f.o.inspectMon = func(state.Host) (string, error) { t.Error("inspected a host not suspended"); return "", nil }

	err := f.o.RecoverMons(ctx, "", []string{"h9"})
	if err == nil || !strings.Contains(err.Error(), "--member h9") {
		t.Fatalf("a refused suspension: %v", err)
	}

	got, lerr := state.LoadRecovery(f.o.St.FSID)
	if lerr != nil || got.Hosts["h9"].Receipt != nil || len(got.Hosts["h9"].Restarted) != 0 {
		t.Fatalf("journal %+v %v", got.Hosts["h9"], lerr)
	}

	f.a9.session = ""
	f.o.inspectMon = func(state.Host) (string, error) { return "d9", nil }

	_ = f.o.RecoverMons(ctx, "", []string{"h9"})

	if got, _ := state.LoadRecovery(f.o.St.FSID); got.Hosts["h9"].Receipt == nil || !slices.Contains(got.Hosts["h9"].Restarted, doc) {
		t.Fatalf("after the retry: %+v", got.Hosts["h9"])
	}
}

// An online retry corrects an offline attempt's journal the same way.
func TestAnOnlineRetryCorrectsAnOfflineLeftOut(t *testing.T) {
	f, answers := staleRetirement(t)
	ctx := context.Background()

	rec := &state.Recovery{Schema: state.RecoverySchema, FSID: f.o.St.FSID, Session: "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f", Phase: state.PhaseSuspending,
		Hosts: map[string]*state.RecoveryHost{"h9": {Addr: f.h9.Addr, Retiring: true, LeftOut: true, Receipt: &wire.SuspendReceipt{}}}, Jobs: map[string]*state.RecoveryJob{}}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	answers()
	f.republished(t)

	got, err := f.o.Suspend(ctx, SuspendOptions{})
	if err != nil || got.Hosts["h9"].LeftOut || got.Hosts["h9"].Retiring || f.a9.posts == 0 {
		t.Fatalf("%v, %+v, %d suspensions", err, got.Hosts["h9"], f.a9.posts)
	}
}

// A cached host on a node that calls itself something else is not suspended
// through Talos offline; with the published state it is a member as before.
// Round 10: a member left out of an offline suspension, published again once
// the mons answer. Its receipt is a placeholder, its agent was never suspended.
func TestAgentRestoreRefusesAHostLeftOut(t *testing.T) {
	f, answers := staleRetirement(t)
	ctx := context.Background()

	rec := &state.Recovery{Schema: state.RecoverySchema, FSID: f.o.St.FSID, Session: "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f", Phase: state.PhaseRecovering,
		Hosts: map[string]*state.RecoveryHost{"h9": {Addr: f.h9.Addr, LeftOut: true, Receipt: &wire.SuspendReceipt{}}}, Jobs: map[string]*state.RecoveryJob{}}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	answers()
	f.republished(t)

	before := f.docs(t)

	settled := 0
	f.o.settleSelf = func(state.Host) (agent.RecordsReport, error) {
		settled++

		return agent.RecordsReport{}, nil
	}

	if err := f.o.RestoreAgent(ctx, "h9", true); err == nil || !strings.Contains(err.Error(), "left out") {
		t.Fatalf("restored: %v", err)
	}

	if settled != 0 || !slices.Equal(f.docs(t), before) {
		t.Fatalf("settled %d, documents %v", settled, f.docs(t))
	}
}

func TestAnOfflineCachedHostOnAnotherNodeIsLeftOut(t *testing.T) {
	f, _ := staleRetirement(t)
	ctx := context.Background()

	f.o.St.Retiring = nil
	f.o.St.Hosts = append(f.o.St.Hosts, state.Host{Name: "h9", Addr: f.h9.Addr})
	f.hostname(t, "another")

	before := f.docs(t)

	rec, err := f.o.Suspend(ctx, SuspendOptions{})
	if err != nil {
		t.Fatal(err)
	}

	// journaled from the workstation's cache, as a member
	if hr := rec.Hosts["h9"]; hr == nil || !hr.LeftOut || hr.AgentRemoved || hr.Retiring {
		t.Fatalf("journal %+v", hr)
	}

	if !slices.Equal(f.docs(t), before) {
		t.Fatalf("documents %v", f.docs(t))
	}
}

func TestARetirementThatEndedMeanwhileIsNotTold(t *testing.T) {
	f := retiringSetup(t)
	ctx := context.Background()

	rec := retiringSession(t, f)
	hr := rec.Hosts["h9"]
	hr.RetireFinished = true

	delete(f.o.St.Retiring, "h9")
	f.publish(t)

	if err := f.o.retireTold(ctx, rec, state.Host{Name: "h9"}); err != nil || len(f.cmds) != 0 || !hr.RetireTold {
		t.Fatalf("%v, commands %v, journal %+v", err, f.cmds, hr)
	}
}

// `agent restore` would apply a removed agent again and settle its retirement's
// intent as failed.
func TestAgentRestoreRefusesARetiringHost(t *testing.T) {
	f := retiringSetup(t)
	ctx := context.Background()

	retiringSession(t, f)

	settled := 0
	f.o.settleSelf = func(state.Host) (agent.RecordsReport, error) {
		settled++

		return agent.RecordsReport{}, nil
	}

	if err := f.o.RestoreAgent(ctx, "h9", false); err == nil || !strings.Contains(err.Error(), "retiring") {
		t.Fatalf("restored: %v", err)
	}

	if settled != 0 || len(f.docs(t)) != 0 {
		t.Fatalf("settled %d, documents %v", settled, f.docs(t))
	}

	// also once the published state no longer has it: the journal does
	delete(f.o.St.Retiring, "h9")
	f.publish(t)

	if err := f.o.RestoreAgent(ctx, "h9", false); err == nil || !strings.Contains(err.Error(), "retiring") {
		t.Fatalf("restored: %v", err)
	}
}
