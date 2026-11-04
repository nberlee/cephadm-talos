package agent

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/block"

	"github.com/nberlee/cephadm-talos/internal/state"
)

// drainSetup is a leader whose h1 has an OSD, the mgr (added through the
// ledger) and a mon; h0, the leader's host, is in maintenance so ceph.conf
// goes to h1 alone (this test serves h1's agent only).
func drainSetup(t *testing.T) (*leaderSetup, string) {
	t.Helper()

	s := newLeaderSetup(t)
	ctx := context.Background()
	s.withCA(t)

	disk := block.NewDisk(block.NamespaceName, "sdb")
	disk.TypedSpec().Serial, disk.TypedSpec().DevPath = "QM00003", "/dev/sdb"
	disk.TypedSpec().Symlinks = []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"}
	must(t, s.agent.fake.St.Create(ctx, disk))

	id, uuid := 3, "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f"
	s.st.AddDaemon(state.Daemon{Type: state.TypeOSD, ID: "h1-sdb", Host: "h1", OSDID: &id, OSDUUID: uuid, DeployID: "0123456789abcdef",
		DiskSerial: "QM00003", DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003"})
	s.st.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h0", Host: "h0", DeployID: "0123456789abcdef"})

	h0, _ := s.st.Host("h0")
	h0.Maintenance = true
	s.st.AddHost(h0)
	publish(t, s.leader, s.module, s.st)

	s.module.mu.Lock()
	s.module.active, s.module.standbys, s.module.quorum = "h0", []string{"h1"}, []string{"h0", "h1"}
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	add := s.accept(KindAddDaemon, "mgr.h1", "h1", 1)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, add.Op.ID); op.State != "completed" {
		t.Fatalf("add: %+v", op)
	}

	return s, uuid
}

func (s *leaderSetup) drain(t *testing.T) *state.Drain {
	t.Helper()

	st, _, err := s.leader.clusterState(context.Background(), s.leader.bridge())
	must(t, err)

	h, _ := st.Host("h1")

	return h.Drain
}

func TestADrainRemovesAHostsDaemonsInOrder(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	s.module.mu.Lock()
	s.module.active = "h1" // the mgr on h1 is the active one: failed over first
	s.module.retired = nil
	s.module.mu.Unlock()

	drain := s.accept(KindDrain, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))

	// recorded, and its first step run: every OSD out at once
	if op := s.op(t, drain.Op.ID); op.State != "completed" {
		t.Fatalf("drain: %+v", op)
	}

	if d := s.drain(t); d == nil || d.Op != drain.Op.ID || !slices.Equal(d.Done, []string{drainStepOut}) || d.Step != "" {
		t.Fatalf("record: %+v", d)
	}

	// the OSD's removal, the mgr failed over, then removed once a standby took over
	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if d := s.drain(t); d == nil || d.Step != "mgr.h1" {
		t.Fatalf("record: %+v", d)
	}

	s.module.mu.Lock()
	s.module.active = "h0"
	s.module.mu.Unlock()

	for range 3 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	op := drain.Op.ID
	want := []string{
		"osd out " + op,
		"osd out " + op + " osd.3", "drain " + op + " osd.3", "retire " + op + " osd.3",
		"mgr fail " + op + " 42", "retire " + op + " mgr.h1",
		"mon rm " + op + " mon.h1", "retire " + op + " mon.h1",
		"drain done " + op,
	}

	if got := s.calls(); !slices.Equal(got, want) {
		t.Fatalf("module calls\n%v\nwant\n%v", got, want)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	h, _ := st.Host("h1")
	if h.Drain != nil || len(st.DaemonsOf("", "h1")) != 0 {
		t.Fatalf("after the drain: %+v, daemons %v", h.Drain, st.DaemonsOf("", "h1"))
	}

	// each step under the drain's journal id; the host stays
	for i := 1; i <= 4; i++ {
		if r := s.op(t, op+".d"+string(rune('0'+i))); r.State != "completed" {
			t.Fatalf("step %d: %+v", i, r)
		}
	}

	if inv := s.inventory(t); !strings.Contains(inv, `"name":"h1"`) || strings.Contains(inv, `"drain"`) {
		t.Fatalf("inventory %s", inv)
	}
}

func TestADrainStopsPausesAndResumes(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	// the OSD's drain waits as long as recovery takes: no pause
	s.module.mu.Lock()
	s.module.refuse = "drain"
	s.module.mu.Unlock()

	drain := s.accept(KindDrain, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))
	must(t, s.leader.Tick(ctx, 42, 5))

	if d := s.drain(t); d == nil || d.Step != "osd.3" || d.Paused {
		t.Fatalf("record: %+v", d)
	}

	// a step waiting does not hold the ledger: another operation runs beside it
	restart := s.accept(KindRestart, "mon.h1", "h1", 3)
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, restart.Op.ID); op.State == JournalGranting {
		t.Fatalf("restart: %+v", op)
	}

	// a step failing too long pauses the drain with its reason
	s.module.mu.Lock()
	s.module.refuse = "retire"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))
	s.leader.failing[drain.Op.ID+".d2"] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	d := s.drain(t)
	if d == nil || !d.Paused || d.Step != "osd.3" || !strings.Contains(d.Error, "osd.3") {
		t.Fatalf("record: %+v", d)
	}

	if inv := s.inventory(t); !strings.Contains(inv, `"paused":true`) {
		t.Fatalf("inventory %s", inv)
	}

	// paused: nothing runs; resumed, the step again under a new attempt
	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	s.module.refuse = ""
	s.module.mu.Unlock()

	resume := s.accept(KindDrainResume, "", "h1", 4)
	resume.Op.Drain = drain.Op.ID
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = resume
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.op(t, drain.Op.ID+".d3"); r.State != "completed" {
		t.Fatalf("resumed step: %+v", r)
	}

	// a stop with a takeover between: the successor reads the record and ends
	// the drain without starting the next step
	stop := s.accept(KindDrainStop, "", "h1", 5)
	stop.Op.Drain = drain.Op.ID
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = stop
	s.module.retired = nil
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if got := s.calls(); !slices.Equal(got, []string{"drain done " + drain.Op.ID}) {
		t.Fatalf("calls after the stop: %v", got)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if h, _ := st.Host("h1"); h.Drain != nil {
		t.Fatalf("record after the stop: %+v", h.Drain)
	}

	if _, ok := st.Find("mgr.h1"); !ok {
		t.Fatal("the mgr went after the stop")
	}
}

func TestADrainOfAnotherHostOrMalformedEnds(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	gone := s.accept(KindDrain, "", "h9", 1)
	bad := s.accept(KindDrainStop, "", "h1", 2) // names no drain
	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, gone.Op.ID); op.State != JournalFailed {
		t.Fatalf("drain of an unknown host: %+v", op)
	}

	if op := s.op(t, bad.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "malformed") {
		t.Fatalf("malformed stop: %+v", op)
	}

	// closed in the fold: the module stops counting it as draining
	if got := s.calls(); !slices.Contains(got, "drain done "+gone.Op.ID) {
		t.Fatalf("calls %v", got)
	}
}

func TestADrainContinuesAfterATakeover(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	s.module.mu.Lock()
	s.module.refuse = "drain"
	s.module.mu.Unlock()

	drain := s.accept(KindDrain, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5))
	must(t, s.leader.Tick(ctx, 42, 5))

	if d := s.drain(t); d == nil || d.Step != "osd.3" {
		t.Fatalf("record: %+v", d)
	}

	// a successor incarnation (43) takes over from the published state: the
	// step in progress goes on under its journal id, then the next ones
	l := s.successor(t, "h0", 43, 6)

	s.module.mu.Lock()
	s.module.refuse, s.module.retired = "", nil
	s.module.mu.Unlock()

	for range 5 {
		must(t, l.Tick(ctx, 43, 6))
	}

	op := drain.Op.ID
	want := []string{
		"osd out " + op + " osd.3", "drain " + op + " osd.3", "retire " + op + " osd.3",
		"retire " + op + " mgr.h1", "mon rm " + op + " mon.h1", "retire " + op + " mon.h1", "drain done " + op,
	}

	if got := s.calls(); !slices.Equal(got, want) {
		t.Fatalf("module calls\n%v\nwant\n%v", got, want)
	}

	s.module.mu.Lock()
	_, d2 := s.module.kv[JournalPrefix(43)+"op/"+op+".d2"]
	s.module.mu.Unlock()

	if !d2 {
		t.Fatal("the step in progress did not end under the successor")
	}
}

func TestADrainStepContinuesARemovalPastTheStateChange(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	drain := s.accept(KindDrain, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSDs out
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSD removed

	// the mgr's removal takes it out of the state, then its retirement is refused
	s.module.mu.Lock()
	s.module.refuse = "retire"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))
	must(t, s.leader.Tick(ctx, 42, 5))

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if _, ok := st.Find("mgr.h1"); ok {
		t.Fatal("the mgr is still in the state")
	}

	// absent from the state, its step is not done: the removal goes on
	if d := s.drain(t); d == nil || d.Step != "mgr.h1" {
		t.Fatalf("record: %+v", d)
	}

	s.module.mu.Lock()
	_, ended := s.module.kv[JournalPrefix(42)+"op/"+drain.Op.ID+".d3"]
	s.module.refuse, s.module.retired = "", nil
	s.module.mu.Unlock()

	if ended {
		t.Fatal("the step ended before its removal's retirement")
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	if r := s.op(t, drain.Op.ID+".d3"); r.State != "completed" || !slices.Contains(s.calls(), "retire "+drain.Op.ID+" mgr.h1") {
		t.Fatalf("step %+v, calls %v", r, s.calls())
	}
}

func TestAResumedDrainFinishesTheRemovalItPausedIn(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	drain := s.accept(KindDrain, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSDs out
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSD removed

	// the mgr leaves the state, its retirement keeps failing: the drain pauses
	s.module.mu.Lock()
	s.module.refuse = "retire"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))
	s.leader.failing[drain.Op.ID+".d3"] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	if d := s.drain(t); d == nil || !d.Paused || d.Step != "mgr.h1" || d.First != 3 {
		t.Fatalf("record: %+v", d)
	}

	// resumed: the mgr's removal is finished first, under a new attempt, its
	// certificates (journaled by the first) revoked with its retirement
	resume := s.accept(KindDrainResume, "", "h1", 3)
	resume.Op.Drain = drain.Op.ID
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = resume
	s.module.refuse = ""
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	revoked := s.module.certs["retire "+drain.Op.ID]
	s.module.mu.Unlock()

	if r := s.op(t, drain.Op.ID+".d4"); r.State != "completed" || len(revoked) != 2 {
		t.Fatalf("step %+v, %d certificates revoked", r, len(revoked))
	}

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if got := s.calls(); !slices.Contains(got, "retire "+drain.Op.ID+" mgr.h1") || !slices.Contains(got, "drain done "+drain.Op.ID) {
		t.Fatalf("calls %v", got)
	}
}

func TestAStopFinishesARemovalWhoseDaemonLeftTheState(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	drain := s.accept(KindDrain, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSDs out
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSD removed

	// the mgr leaves the state, its retirement keeps failing: paused
	s.module.mu.Lock()
	s.module.refuse = "retire"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))
	s.leader.failing[drain.Op.ID+".d3"] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	// stopped: the record stays, stopping with that removal, retried
	stop := s.accept(KindDrainStop, "", "h1", 3)
	stop.Op.Drain = drain.Op.ID
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = stop
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if d := s.drain(t); d == nil || !d.Stopped || d.Paused || d.Step != "mgr.h1" || d.Attempt != 4 {
		t.Fatalf("record after the stop: %+v", d)
	}

	// failing again, it pauses again, not given up
	s.leader.failing[drain.Op.ID+".d4"] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	if d := s.drain(t); d == nil || !d.Stopped || !d.Paused || d.Step != "mgr.h1" {
		t.Fatalf("record after the second failure: %+v", d)
	}

	// resumed (host drain again): the retirement goes through, then the drain
	// ends without another step (the mon stays)
	resume := s.accept(KindDrainResume, "", "h1", 4)
	resume.Op.Drain = drain.Op.ID
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = resume
	s.module.refuse, s.module.retired = "", nil
	s.module.mu.Unlock()

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if got := s.calls(); !slices.Equal(got, []string{"retire " + drain.Op.ID + " mgr.h1", "drain done " + drain.Op.ID}) {
		t.Fatalf("calls %v", got)
	}

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if h, _ := st.Host("h1"); h.Drain != nil {
		t.Fatalf("record: %+v", h.Drain)
	}

	if _, ok := st.Find("mon.h1"); !ok {
		t.Fatal("the stopped drain removed the mon")
	}
}

func TestAStopGivesUpAFailedStepWhoseDaemonStays(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	drain := s.accept(KindDrain, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSDs out

	// osd.3's own out is refused: nothing of its removal past its retirement
	s.module.mu.Lock()
	s.module.refuse = "osd out"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))
	s.leader.failing[drain.Op.ID+".d2"] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	if d := s.drain(t); d == nil || !d.Paused || d.Step != "osd.3" {
		t.Fatalf("record: %+v", d)
	}

	stop := s.accept(KindDrainStop, "", "h1", 3)
	stop.Op.Drain = drain.Op.ID
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = stop
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if d := s.drain(t); d != nil {
		t.Fatalf("record after the stop: %+v", d)
	}
}

func TestAStopFinishesAPurgedOSDsRemoval(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	drain := s.accept(KindDrain, "", "h1", 2)
	drain.Op.Zap = true
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = drain
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5)) // the OSDs out
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSD retired, its zap running

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if x, ok := st.Find("osd.3"); !ok || !x.Purged {
		t.Fatalf("the retired OSD is not marked purged: %+v", x)
	}

	// paused in the zap (its host unreachable, say), then stopped: the record
	// keeps that removal, retried under a new attempt
	must(t, s.leader.changeState(ctx, s.leader.bridge(), 42, func(st *state.State) error {
		h, _ := st.Host("h1")
		h.Drain.Paused, h.Drain.Error = true, "osd.3: the zap did not end"
		st.AddHost(h)

		return nil
	}))

	stop := s.accept(KindDrainStop, "", "h1", 3)
	stop.Op.Drain = drain.Op.ID
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = stop
	s.module.retired = nil
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	if d := s.drain(t); d == nil || !d.Stopped || d.Paused || d.Step != "osd.3" || d.Attempt != 3 {
		t.Fatalf("record after the stop: %+v", d)
	}

	// the first attempt's zap job ends: the removal finishes (no second zap),
	// the OSD leaves the state, then the stopped drain ends; the mgr stays
	finishJob(t, s.agent, drain.Op.ID+".d2.zap", 0, "zapped")

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if r := s.op(t, drain.Op.ID+".d3"); r.State != "completed" {
		t.Fatalf("resumed step: %+v", r)
	}

	s.module.mu.Lock()
	_, second := s.module.kv[JournalPrefix(42)+"op/"+drain.Op.ID+".d3.zap"]
	s.module.mu.Unlock()

	if second {
		t.Fatal("a second zap was started")
	}

	st, _, err = s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	h, _ := st.Host("h1")
	_, osd := st.Find("osd.3")
	_, mgr := st.Find("mgr.h1")

	if h.Drain != nil || osd || !mgr || !slices.Contains(s.calls(), "drain done "+drain.Op.ID) {
		t.Fatalf("after: record %+v, osd %t, mgr %t, calls %v", h.Drain, osd, mgr, s.calls())
	}
}

func TestAStopFinishesAnOSDRemovalWhoseRetirementWasAsked(t *testing.T) {
	s, _ := drainSetup(t)
	ctx := context.Background()

	drain := s.accept(KindDrain, "", "h1", 2)
	must(t, s.leader.Tick(ctx, 42, 5)) // the OSDs out

	// the retirement's answer is lost (refused here): the intent is in the
	// state before the call, so the module may have purged it
	s.module.mu.Lock()
	s.module.refuse = "retire"
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))

	st, _, err := s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	if x, ok := st.Find("osd.3"); !ok || !x.Retiring || x.Purged {
		t.Fatalf("the OSD before its retirement's answer: %+v", x)
	}

	s.leader.failing[drain.Op.ID+".d2"] = time.Now().Add(-stuckAfter - time.Minute)
	must(t, s.leader.Tick(ctx, 42, 5))

	// paused, then stopped: the removal is kept and retried, not given up
	stop := s.accept(KindDrainStop, "", "h1", 3)
	stop.Op.Drain = drain.Op.ID
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = stop
	s.module.refuse, s.module.retired = "", nil
	s.module.mu.Unlock()

	for range 3 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	st, _, err = s.leader.clusterState(ctx, s.leader.bridge())
	must(t, err)

	h, _ := st.Host("h1")
	_, osd := st.Find("osd.3")

	if h.Drain != nil || osd || !slices.Contains(s.calls(), "retire "+drain.Op.ID+" osd.3") || !slices.Contains(s.calls(), "drain done "+drain.Op.ID) {
		t.Fatalf("after: record %+v, osd %t, calls %v", h.Drain, osd, s.calls())
	}
}
