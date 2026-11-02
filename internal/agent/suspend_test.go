package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

const testSession = "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f"

func TestSuspensionClosesAdmission(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	must(t, g.Suspend(ctx, testSession))

	var se errSuspended

	if _, err := g.Grant(ctx, probeGrant(2, "op-1", "aaaaaa")); !errors.As(err, &se) || g.patches.n != 0 {
		t.Fatalf("a grant while suspended: %v, %d patches", err, g.patches.n)
	}

	if _, err := g.Close(ctx, wire.Close{FSID: testFSID, Host: "h1", Mgr: "h0", GID: 43, Epoch: 6}); !errors.As(err, &se) {
		t.Fatalf("a close while suspended: %v", err)
	}

	if _, err := g.Abandon(ctx, wire.Abandon{FSID: testFSID, Host: "h1", Revision: 9, Operation: "op-9", Epoch: 5}); !errors.As(err, &se) {
		t.Fatalf("an abandon while suspended: %v", err)
	}

	// another session is refused; the same one again is fine
	if err := g.Suspend(ctx, "11111111-2222-4333-8444-555555555555"); err == nil {
		t.Fatal("a second session while suspended")
	}

	must(t, g.Suspend(ctx, testSession))

	// a restarted agent is still suspended
	g2 := NewGranter(g.Node, g.Channel, nil, g.Records)
	if !g2.Suspended() {
		t.Fatal("the suspension did not survive a restart")
	}

	st, err := g2.SuspendState(ctx)
	if err != nil || st.Receipt == nil || st.Receipt.Session != testSession || st.Receipt.Revision != 1 || len(st.Receipt.Owned) == 0 {
		t.Fatalf("receipt: %+v %v", st, err)
	}
}

func TestADamagedSuspensionRecordCountsAsSuspended(t *testing.T) {
	g := newTestGranter(t)
	must(t, g.Records.Write(suspensionRecord, []byte("{")))

	if !g.Suspended() {
		t.Fatal("an unreadable suspension record admits grants")
	}

	if _, err := g.Grant(context.Background(), probeGrant(2, "op-1", "aaaaaa")); err == nil {
		t.Fatal("a grant with a damaged suspension record")
	}
}

func TestSuspensionWaitsForWhatTheAgentStarted(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	// a job still running, a reboot and a restart still being decided, and an
	// uncertain apply that only gets listed
	job := wire.Operation{Version: wire.Version, Operation: "op-2", Revision: 1, State: wire.OpStarted, GID: 42, InputsHash: "h",
		Job: &wire.JobRef{ID: "abcdef", Doc: "ceph-" + testFSID[:8] + "-job-abcdef", Inputs: "x"}}
	must(t, g.writeOp(job))

	reboot := wire.Operation{Version: wire.Version, Operation: "op-3", Revision: 3, State: wire.OpStarted, GID: 42, InputsHash: "h", Reboot: true, BootID: "other", At: time.Now().UnixNano()}
	must(t, g.writeOp(reboot))

	cs := containers.NewContainerStatus(containers.NamespaceName, job.Job.Doc)
	cs.TypedSpec().State = containers.ContainerStateRunning
	must(t, g.fake.St.Create(ctx, cs))

	must(t, g.Suspend(ctx, testSession))

	st, err := g.SuspendState(ctx)
	if err != nil || st.Receipt != nil || len(st.Waiting) != 1 {
		t.Fatalf("while a job runs: %+v %v", st, err)
	}

	// the reboot was decided by the reconcile (the boot id changed); the job ends
	cs.TypedSpec().State = containers.ContainerStateFailed
	must(t, g.fake.St.Update(ctx, cs))

	st, err = g.SuspendState(ctx)
	if err != nil || st.Receipt == nil {
		t.Fatalf("after the job ended: %+v %v", st, err)
	}

	if op, _, _ := g.readOp("op-3"); op.State != wire.OpCompleted {
		t.Errorf("the reboot: %+v", op)
	}
}

func TestBridgeIntents(t *testing.T) {
	b, m := testBridge(t, "h1")
	ctx := context.Background()

	recs := &records.Store{Dir: t.TempDir()}
	b.Intents, b.GID, b.Epoch = recs, 42, 5
	b.ops = map[string][2]string{"op-7": {"mon.h2", "h2"}}

	open := func() []wire.BridgeIntent {
		t.Helper()

		in, err := OpenIntents(recs)
		must(t, err)

		return in
	}

	// a read records nothing; an answered mutation leaves nothing
	_, _ = b.Quorum(ctx)

	if in := open(); len(in) != 0 {
		t.Fatalf("a read left an intent: %+v", in)
	}

	must(t, b.Retire(ctx, "retire", "op-7"))

	if in := open(); len(in) != 0 {
		t.Fatalf("an answered call left an intent: %+v", in)
	}

	// a call without an answer keeps its intent, with what it reserves
	m.hang = "mon rm"

	if err := b.Retire(ctx, "mon rm", "op-7"); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("hung call: %v", err)
	}

	in := open()
	if len(in) != 1 || in[0].Call != "mon rm" || in[0].Daemon != "mon.h2" || in[0].Host != "h2" || in[0].GID != 42 || in[0].Epoch != 5 {
		t.Fatalf("intent: %+v", in)
	}

	// its outcome settles it
	if _, err := b.Outcome(ctx, in[0].Dispatch); err != nil {
		t.Fatal(err)
	}

	if in := open(); len(in) != 0 {
		t.Fatalf("a fetched outcome left the intent: %+v", in)
	}

	// a refusal sent nothing: settled too
	m.hang, m.refuse = "", "retire"

	if err := b.Retire(ctx, "retire", "op-7"); err == nil {
		t.Fatal("the refusal")
	}

	if in := open(); len(in) != 0 {
		t.Fatalf("a refused call left an intent: %+v", in)
	}
}

func TestOutcomeUnknownToTheModuleKeepsTheIntent(t *testing.T) {
	b, _ := testBridge(t, "h1")
	recs := &records.Store{Dir: t.TempDir()}
	b.Intents = recs

	must(t, b.intend("d1", "mon rm", map[string]any{"operation": "op-7"}))

	if _, err := b.Outcome(context.Background(), "d1"); !errors.Is(err, ErrDispatchUnknown) {
		t.Fatalf("outcome: %v", err)
	}

	if in, err := OpenIntents(recs); err != nil || len(in) != 1 {
		t.Fatalf("an intent the module does not know was dropped: %+v %v", in, err)
	}
}

func TestPauseWaitsForTheTick(t *testing.T) {
	suspended := false
	l := &LeaderLoop{Suspended: func() bool { return suspended }}

	started, release := make(chan struct{}), make(chan struct{})

	l.tickMu.Lock()
	tctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	l.cancelTick, l.ticking = cancel, done
	l.tickMu.Unlock()

	go func() {
		close(started)
		<-tctx.Done()
		<-release
		l.tickMu.Lock()
		l.cancelTick, l.ticking = nil, nil
		l.tickMu.Unlock()
		close(done)
	}()

	<-started

	suspended = true

	ctx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()

	if err := l.Pause(ctx); err == nil {
		t.Fatal("Pause returned while the tick ran")
	}

	close(release)
	must(t, l.Pause(context.Background()))

	// no new tick while suspended
	l.tick(context.Background(), &Leader{GID: 1, Epoch: 1})

	if l.cancelTick != nil {
		t.Fatal("a tick started while suspended")
	}
}

func TestSuspensionWaitsForAnUncertainRebootAndAConfiguredJob(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	boot, err := g.Node.Talos.BootID(ctx, "")
	must(t, err)

	// a reboot whose call had no answer, on the same boot: it may still happen
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-3", Revision: 1, State: wire.OpUncertain, GID: 42, InputsHash: "h",
		Reboot: true, BootID: boot, At: time.Now().UnixNano()}))

	// a job whose document is configured but has no status yet
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-2", Revision: 1, State: wire.OpStarted, GID: 42, InputsHash: "h",
		Job: &wire.JobRef{ID: "abcdef", Doc: "app", Inputs: "x"}}))

	must(t, g.Suspend(ctx, testSession))

	st, err := g.SuspendState(ctx)
	if err != nil || st.Receipt != nil || len(st.Waiting) != 2 {
		t.Fatalf("an uncertain reboot and a configured job: %+v %v", st, err)
	}
}

func TestOneOfTwoSessionsWins(t *testing.T) {
	g := newTestGranter(t)

	errs := make(chan error, 2)
	for _, s := range []string{testSession, "11111111-2222-4333-8444-555555555555"} {
		go func() { errs <- g.Suspend(context.Background(), s) }()
	}

	if a, b := <-errs, <-errs; (a == nil) == (b == nil) {
		t.Fatalf("two sessions at once: %v, %v", a, b)
	}
}

func TestAMgrFailIntentNamesTheMgr(t *testing.T) {
	b, m := testBridge(t, "h1")
	recs := &records.Store{Dir: t.TempDir()}
	b.Intents = recs
	m.hang = "mgr fail"

	// an upgrade's start names no daemon: the intent names the mgr it fails
	if err := b.MgrFail(context.Background(), "op-5", 4122, "h2", "h2"); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("hung mgr fail: %v", err)
	}

	in, err := OpenIntents(recs)
	if err != nil || len(in) != 1 || in[0].Daemon != "mgr.h2" || in[0].Host != "h2" {
		t.Fatalf("intent: %+v %v", in, err)
	}
}

func TestARestartWithoutAReplacementIsListedAfterItsLimit(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	boot, err := g.Node.Talos.BootID(ctx, "")
	must(t, err)

	// the old instance is gone and no newer one exists
	for _, at := range []time.Time{time.Now(), time.Now().Add(-11 * time.Minute)} {
		must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-4", Revision: 1, State: wire.OpStarted, GID: 42, InputsHash: "h",
			Instance: "ceph-" + testFSID[:8] + "-mon-h1-3", BootID: boot, At: at.UnixNano()}))

		_ = g.Records.Remove(suspensionRecord)
		must(t, g.Suspend(ctx, testSession))

		st, err := g.SuspendState(ctx)
		must(t, err)

		if fresh := time.Since(at) < time.Minute; fresh != (st.Receipt == nil) {
			t.Fatalf("restart at %s: %+v", at, st)
		}

		if st.Receipt != nil && (len(st.Receipt.Unresolved) != 1 || st.Receipt.Unresolved[0].State != wire.OpUncertain) {
			t.Fatalf("after the limit: %+v", st.Receipt)
		}
	}
}
