package orch

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// fakeMgrs replaces the mgr map: the maps in order (the last one stays), and
// counts the mgr fails.
func fakeMgrs(t *testing.T, maps ...mgrMap) (dumps, fails *int) {
	t.Helper()

	dumps, fails = new(int), new(int)
	oldDump, oldFail, oldWait := mgrDump, mgrFail, waitTakeover

	mgrDump = func(context.Context, *Orch) (mgrMap, error) {
		m := maps[min(*dumps, len(maps)-1)]
		*dumps++

		return m, nil
	}
	mgrFail = func(_ context.Context, _ *Orch, gid int64) error {
		if gid != 100 {
			t.Errorf("failed gid %d, want the one of before", gid)
		}

		*fails++

		return nil
	}
	waitTakeover = func(context.Context, *Orch, []int64) (string, error) { return "200", nil }

	t.Cleanup(func() { mgrDump, mgrFail, waitTakeover = oldDump, oldFail, oldWait })

	return dumps, fails
}

func TestResumeReadoptsReplacesTheMgrsAndActivates(t *testing.T) {
	o, _, a := suspendSetup(t)
	ctx := context.Background()

	if _, err := o.Suspend(ctx, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	// before: gid 100 active, 101 standby; it stays active until failed
	before := mgrMap{Epoch: 10, ActiveGID: 100, Available: true}
	before.Standbys = append(before.Standbys, struct {
		GID int64 `json:"gid"`
	}{101})

	_, fails := fakeMgrs(t, before, before, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	// the first activation is refused: a retry continues with the activation
	a.refuseAct = 1

	if err := o.Resume(ctx); err == nil {
		t.Fatal("a refused activation went unnoticed")
	}

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil || rec == nil || rec.Phase != state.PhaseResuming || rec.Boundary == nil || rec.Boundary.GID != 200 || rec.Boundary.Epoch != 10 {
		t.Fatalf("journal after the refusal: %+v %v", rec, err)
	}

	if err := o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(a.readopts) != 1 || len(a.readopts[0]) != 0 {
		t.Fatalf("re-adoptions: %+v", a.readopts)
	}

	if len(a.activations) != 1 || a.activations[0].Epoch != 10 || a.activations[0].Revision != a.revision+1 || a.activations[0].Session != rec.Session {
		t.Fatalf("activations: %+v", a.activations)
	}

	if *fails != 1 {
		t.Fatalf("%d mgr fails, want 1", *fails)
	}

	if rec, err := state.LoadRecovery(o.St.FSID); err != nil || rec != nil {
		t.Fatalf("the journal stays after the resumption: %+v %v", rec, err)
	}

	if _, err := o.StoreBackend.Get(ctx, SuspensionKey); err != store.ErrNotFound {
		t.Fatalf("the control record stays: %v", err)
	}
}

func TestResumeRefusesAChangeTheStateDoesNotName(t *testing.T) {
	o, h, a := suspendSetup(t)
	ctx := context.Background()

	if _, err := o.Suspend(ctx, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	mon := o.St.DaemonsOf(state.TypeMon, "")[0]
	mon.DeployID = "d1"
	o.St.AddDaemon(mon)

	// the recovery applied the mon with another deployment id
	doc := o.St.DocName(mon)
	if err := o.apply(ctx, h.Addr, daemons.Mon(daemons.Params{Name: doc, Image: o.St.Image, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr, DeployID: "d2", Mode: "join"})); err != nil {
		t.Fatal(err)
	}

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	rec.Host(h.Name).Changes = map[string]string{"ContainerConfig/" + doc: "x"}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 200, Available: true})

	if err := o.Resume(ctx); err == nil || !strings.Contains(err.Error(), "deployment d2") || len(a.readopts) != 0 {
		t.Fatalf("a mon of another deployment: %v, %d re-adoptions", err, len(a.readopts))
	}

	// a document still being applied refuses too
	rec.Host(h.Name).Applying = map[string]state.Applying{"ContainerConfig/" + doc: {Hash: "y"}}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	if err := o.Resume(ctx); err == nil || !strings.Contains(err.Error(), "recover mons") {
		t.Fatalf("an unconfirmed apply: %v", err)
	}

	// neither refusal moved the session on: `recover mons` still runs
	if rec, err := state.LoadRecovery(o.St.FSID); err != nil || rec.Phase != state.PhaseSuspended {
		t.Fatalf("phase after the refusals: %+v %v", rec, err)
	}
}

func TestAForcedJobRemovalIsAJournaledChange(t *testing.T) {
	o, h, a := suspendSetup(t)
	ctx := context.Background()

	if _, err := o.Suspend(ctx, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	job := "ceph-" + o.St.Short() + "-job-abcdef"
	if err := o.apply(ctx, h.Addr, daemons.Probe(job, o.St.Image)); err != nil {
		t.Fatal(err)
	}

	rep := agent.RecordsReport{Open: []wire.Operation{{Operation: "op-2", State: wire.OpStarted, Job: &wire.JobRef{ID: "abcdef", Doc: job}}}}
	if err := o.awaitStarted(ctx, h, rec, rep, SuspendOptions{Force: true}); err != nil {
		t.Fatal(err)
	}

	if v, ok := rec.Hosts[h.Name].Changes["ContainerConfig/"+job]; !ok || v != "" {
		t.Fatalf("changes: %+v", rec.Hosts[h.Name].Changes)
	}

	// the resumption takes it to the re-adoption
	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	if err := o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(a.readopts) != 1 || len(a.readopts[0]) != 1 {
		t.Fatalf("re-adoptions: %+v", a.readopts)
	}
}

func TestTheBoundaryRestartsEachMgrOnce(t *testing.T) {
	o, h, a := suspendSetup(t)
	ctx := context.Background()

	if _, err := o.Suspend(ctx, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	f := a.node
	mgr := o.St.DocName(state.Daemon{Type: state.TypeMgr, ID: h.Name, Host: h.Name})

	inst := containers.NewContainerInstanceSpec(containers.NamespaceName, mgr+"-1")
	inst.TypedSpec().ContainerID, inst.TypedSpec().Generation = mgr, 1

	if err := f.St.Create(ctx, inst); err != nil {
		t.Fatal(err)
	}

	before := mgrMap{Epoch: 10, ActiveGID: 100, Available: true}
	after := mgrMap{Epoch: 12, ActiveGID: 200, Available: true}

	// Talos still stopping the instance: one restart, not one per poll
	f.HoldRestarts = true
	oldTimeout := mgrTimeout
	mgrTimeout = 200 * time.Millisecond

	t.Cleanup(func() { mgrTimeout = oldTimeout })

	fakeMgrs(t, before, after)

	if err := o.Resume(ctx); err == nil {
		t.Fatal("a mgr without a newer instance went unnoticed")
	}

	if len(f.Restarted) != 1 || f.Restarted[0] != mgr+"-1" {
		t.Fatalf("restarts: %v", f.Restarted)
	}

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil || rec.Boundary == nil || rec.Boundary.Instances[h.Name+"/"+mgr] != mgr+"-1" || rec.Boundary.GID != 0 {
		t.Fatalf("boundary: %+v %v", rec.Boundary, err)
	}

	// the retry: the instance of before is still current, so it restarts it
	// again; the journaled instances and epoch stay those of before
	f.HoldRestarts = false
	mgrTimeout = oldTimeout

	if err := o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(f.Restarted) != 2 {
		t.Fatalf("restarts after the retry: %v", f.Restarted)
	}

	if len(a.activations) != 1 || a.activations[0].Epoch != 10 {
		t.Fatalf("activations: %+v", a.activations)
	}
}

func TestARetryAfterTheActivationsSkipsTheChecks(t *testing.T) {
	o, h, a := suspendSetup(t)
	ctx := context.Background()

	if _, err := o.Suspend(ctx, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	// the takeover is not seen: the session stays resuming, every agent active
	waitTakeover = func(context.Context, *Orch, []int64) (string, error) { return "", context.DeadlineExceeded }

	if err := o.Resume(ctx); err == nil {
		t.Fatal("a takeover not seen")
	}

	// meanwhile the leader took the host's mon out of the state: the
	// recovery's change on it is not checked again
	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil || len(a.activations) != 1 {
		t.Fatalf("after the first run: %+v %v, %d activations", rec, err, len(a.activations))
	}

	rec.Host(h.Name).Changes = map[string]string{"ContainerConfig/" + o.St.DocName(state.Daemon{Type: state.TypeMon, ID: "gone", Host: h.Name}): "x"}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	// and added a host, which the session never had
	o.St.AddHost(state.Host{Name: "h2", Addr: "127.0.0.2"})

	waitTakeover = func(context.Context, *Orch, []int64) (string, error) { return "200", nil }

	if err := o.Resume(ctx); err != nil {
		t.Fatal(err)
	}

	if len(a.readopts) != 1 || len(a.activations) != 1 {
		t.Fatalf("the retry repeated calls: %d re-adoptions, %d activations", len(a.readopts), len(a.activations))
	}
}

func TestAResumedJournalLeftBehindHasEnded(t *testing.T) {
	o, _, a := suspendSetup(t)

	rec, err := o.Suspend(context.Background(), SuspendOptions{})
	if err != nil {
		t.Fatal(err)
	}

	rec.Phase = state.PhaseResumed
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	if rec, err := state.LoadRecovery(o.St.FSID); err != nil || rec != nil {
		t.Fatalf("a resumed journal: %+v %v", rec, err)
	}

	// a new suspension starts a new session (the agent was activated)
	a.session = ""

	next, err := o.Suspend(context.Background(), SuspendOptions{})
	if err != nil || next.Session == rec.Session {
		t.Fatalf("after a resumed journal: %+v %v", next, err)
	}
}

func TestARemovedHostsAgentComesBackWithTheJournaledCertificates(t *testing.T) {
	o, h, _ := suspendSetup(t)
	ctx := context.Background()

	// a host the leader removed: no state entry, no enrollment record, its
	// keys still in the secrets
	if err := o.StoreBackend.SetMany(ctx, []store.KV{
		{Key: store.SecretPrefix + state.SecretHost("h9", state.SecretAgentServer), Value: []byte(h.AgentKey)},
		{Key: store.SecretPrefix + state.SecretHost("h9", state.SecretAgentClient), Value: []byte(h.AgentClientKey)},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := o.agentHost(ctx, state.Host{Name: "h9", Addr: "127.0.0.9"}, &state.RecoveryHost{}); err == nil {
		t.Fatal("an agent without certificates")
	}

	ah, err := o.agentHost(ctx, state.Host{Name: "h9", Addr: "127.0.0.9"}, &state.RecoveryHost{AgentCert: h.AgentCert, AgentClientCert: h.AgentClientCert})
	if err != nil || ah.AgentCert != h.AgentCert || ah.AgentKey != h.AgentKey || ah.Addr != "127.0.0.9" {
		t.Fatalf("agent host: %v", err)
	}
}

func TestARestoredAgentMayHaveReconciledAnOpenApply(t *testing.T) {
	r := &wire.SuspendReceipt{Revision: 7, Unresolved: []wire.Operation{{Operation: "op-8", Revision: 8}}}

	if !advanced(r, 8) || advanced(r, 9) {
		t.Fatal("advanced")
	}
}

func TestAForcedRemovalLeavesAJobWhoseApplyIsNotRecorded(t *testing.T) {
	o, h, _ := suspendSetup(t)
	ctx := context.Background()

	rec, err := o.Suspend(ctx, SuspendOptions{})
	if err != nil {
		t.Fatal(err)
	}

	job := "ceph-" + o.St.Short() + "-job-abcdef"
	if err := o.apply(ctx, h.Addr, daemons.Probe(job, o.St.Image)); err != nil {
		t.Fatal(err)
	}

	old := suspendTimeout
	suspendTimeout = 100 * time.Millisecond

	t.Cleanup(func() { suspendTimeout = old })

	// its revision is above the ownership's: waited for, not removed
	rep := agent.RecordsReport{Revision: 3, Open: []wire.Operation{{Operation: "op-2", Revision: 4, State: wire.OpStarted, Job: &wire.JobRef{ID: "abcdef", Doc: job}}}}
	if err := o.awaitStarted(ctx, h, rec, rep, SuspendOptions{Force: true}); err == nil {
		t.Fatal("a job whose apply is not recorded was not waited for")
	}

	if _, ok := rec.Hosts[h.Name].Changes["ContainerConfig/"+job]; ok {
		t.Fatal("its removal was journaled")
	}

	docs, err := o.configuredContainers(ctx, h.Addr, job)
	if err != nil || len(docs) != 1 {
		t.Fatalf("the job's document: %v %v", docs, err)
	}
}

func TestResumeChecksARestartedMonToo(t *testing.T) {
	o, h, a := suspendSetup(t)
	ctx := context.Background()

	if _, err := o.Suspend(ctx, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	mon := o.St.DaemonsOf(state.TypeMon, "")[0]
	mon.DeployID = "d1"
	o.St.AddDaemon(mon)

	doc := o.St.DocName(mon)
	if err := o.apply(ctx, h.Addr, daemons.Mon(daemons.Params{Name: doc, Image: o.St.Image, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr, DeployID: "d1", Mode: "join"})); err != nil {
		t.Fatal(err)
	}

	// the state has the host in maintenance: its restarted mon is not the state's
	sh, _ := o.St.Host(h.Name)
	sh.Maintenance = true
	o.St.AddHost(sh)

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	rec.Host(h.Name).Restarted = []string{doc}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	fakeMgrs(t, mgrMap{Epoch: 10, ActiveGID: 100, Available: true}, mgrMap{Epoch: 12, ActiveGID: 200, Available: true})

	if err := o.Resume(ctx); err == nil || !strings.Contains(err.Error(), "maintenance") || len(a.readopts) != 0 {
		t.Fatalf("a restarted mon on a host in maintenance: %v", err)
	}
}
