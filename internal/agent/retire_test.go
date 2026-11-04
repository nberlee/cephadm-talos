package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

func retireGrant(rev int64, op string) wire.Grant {
	return wire.Grant{
		Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5,
		Revision: rev, Operation: op, Retire: true,
	}
}

// stripGrant removes the documents the test node starts with, as the
// leader's strip does before a retirement.
func stripGrant(rev int64, op string) wire.Grant {
	return wire.Grant{
		Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5,
		Revision: rev, Operation: op, Docs: []wire.GrantDoc{{Kind: "EtcFileConfig", Name: "ceph/ceph.conf"}},
	}
}

// retireSetup is selfSetup stripped at revision 2, whose records list two
// serials, the latest 12.
func retireSetup(t *testing.T) *testGranter {
	t.Helper()

	g, _, _ := selfSetup(t)
	must(t, RecordIdentity(g.Records, "11"))
	must(t, RecordIdentity(g.Records, "12"))

	if op, err := g.Grant(context.Background(), stripGrant(2, "op-strip")); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("strip: %+v %v", op, err)
	}

	g.patches.n = 0

	return g
}

// ownDocsOnNode reports which of the agent's own documents the node holds.
func ownDocsOnNode(t *testing.T, n *Node) (agent, init bool) {
	t.Helper()

	cfg, err := n.Talos.MachineConfig(context.Background(), "")
	must(t, err)

	cur, err := parseDocs(cfg)
	must(t, err)

	ak, ik := n.selfKeys()

	return cur[ak] != "", cur[ik] != ""
}

// checkRetired checks the records were moved aside under 12 and both serials marked.
func checkRetired(t *testing.T, dir string) {
	t.Helper()

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the records stayed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), records.RetiredName(filepath.Base(dir), "12"), identityRecord)); err != nil {
		t.Fatalf("the records moved aside: %v", err)
	}

	for _, s := range []string{"11", "12"} {
		if ok, err := records.Marked(dir, s); err != nil || !ok {
			t.Fatalf("serial %s not marked: %v", s, err)
		}
	}
}

func TestTheIdentityRecordListsEverySerialOnce(t *testing.T) {
	recs := &records.Store{Dir: t.TempDir()}

	for _, s := range []string{"5", "5", "6", "5"} {
		must(t, RecordIdentity(recs, s))
	}

	id, found, err := readIdentity(recs)
	if err != nil || !found || strings.Join(id.Serials, ",") != "5,6" {
		t.Fatalf("identity %+v %v %v", id, found, err)
	}

	if err := RecordIdentity(recs, "x1"); err == nil {
		t.Fatal("a malformed serial")
	}
}

func TestARetireGrantRemovesTheAgentsDocumentsThenRetiresItsRecords(t *testing.T) {
	g := retireSetup(t)
	ctx := context.Background()
	dir := g.Records.Dir

	op, err := g.Grant(ctx, retireGrant(3, "op-r1"))
	if err != nil || op.State != wire.OpCompleted || !op.Retire || !op.Self || g.patches.n != 1 {
		t.Fatalf("retire: %+v %v, %d patches", op, err, g.patches.n)
	}

	if a, i := ownDocsOnNode(t, g.Node); a || i {
		t.Fatalf("the agent's documents stayed: %v %v", a, i)
	}

	checkRetired(t, dir)

	// the operation's record went with the records, completed
	moved := &records.Store{Dir: filepath.Join(filepath.Dir(dir), records.RetiredName(filepath.Base(dir), "12"))}
	if op, found, err := (&Granter{Records: moved}).readOp("op-r1"); err != nil || !found || op.State != wire.OpCompleted {
		t.Fatalf("the moved operation: %+v %v %v", op, found, err)
	}

	// retired: every grant, abandon, close and handoff is refused
	if !g.Retired() {
		t.Fatal("not retired")
	}

	if _, err := g.Grant(ctx, probeGrant(4, "op-r2", "aaaaaa")); !errors.Is(err, errRetired) {
		t.Fatalf("a grant: %v", err)
	}

	if _, err := g.Abandon(ctx, wire.Abandon{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 5, Revision: 5, Operation: "op-r3"}); !errors.Is(err, errRetired) {
		t.Fatalf("an abandon: %v", err)
	}

	if _, err := g.Close(ctx, wire.Close{Version: wire.Version, FSID: testFSID, Host: "h1", Mgr: "h0", MgrAddr: "10.5.0.2", GID: 42, Epoch: 6}); !errors.Is(err, errRetired) {
		t.Fatalf("a close: %v", err)
	}

	if !g.Suspended() {
		t.Fatal("the leader's loop would tick")
	}

	h := (&Agent{Granter: g.Granter}).Handler()

	for _, path := range []string{"/v1/handoff", "/v1/grant", "/v1/suspend", "/v1/readopt", "/v1/activate", "/v1/resolve"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))

		if w.Code != http.StatusGone {
			t.Errorf("%s: %d %s", path, w.Code, w.Body)
		}
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/node", nil))

	if w.Code != http.StatusGone {
		t.Errorf("node report: %d", w.Code)
	}
}

func TestARetireGrantIsRefusedWhileTheAgentOwnsDocuments(t *testing.T) {
	g := retireSetup(t)
	ctx := context.Background()

	if op, err := g.Grant(ctx, probeGrant(3, "op-p1", "aaaaaa")); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("probe: %+v %v", op, err)
	}

	n := g.patches.n

	op, err := g.Grant(ctx, retireGrant(4, "op-r1"))
	if err != nil || op.State != wire.OpRefused || !strings.Contains(op.Error, "owns 1 documents") || g.patches.n != n {
		t.Fatalf("retire: %+v %v", op, err)
	}

	if a, i := ownDocsOnNode(t, g.Node); !a || !i || g.Retired() {
		t.Fatal("refused, yet retired")
	}

	if _, err := os.Stat(g.Records.Dir); err != nil {
		t.Fatalf("the records: %v", err)
	}

	// with anything else it is malformed
	gr := retireGrant(5, "op-r2")
	gr.Reboot = true

	if err := g.checkGrant(gr, "h0"); err == nil {
		t.Fatal("a retirement with a reboot")
	}

	gr = retireGrant(5, "op-r2")
	gr.Pull = agentImage2

	if err := g.checkGrant(gr, "h0"); err == nil {
		t.Fatal("a retirement with a pull")
	}
}

func TestARetireGrantNeedsAnIdentityRecord(t *testing.T) {
	g, _, _ := selfSetup(t)

	if op, err := g.Grant(context.Background(), stripGrant(2, "op-strip")); err != nil || op.State != wire.OpCompleted {
		t.Fatalf("strip: %+v %v", op, err)
	}

	op, err := g.Grant(context.Background(), retireGrant(3, "op-r1"))
	if err != nil || op.State != wire.OpRefused || !strings.Contains(op.Error, "identity") || g.patches.n != 1 || g.Retired() {
		t.Fatalf("retire: %+v %v", op, err)
	}
}

func TestAnInterruptedRetirementIsDecidedOnALaterStart(t *testing.T) {
	g := retireSetup(t)
	ctx := context.Background()
	dir := g.Records.Dir

	// Talos took the config, the answer was lost
	g.fake.FailAfterApply = errors.New("connection reset")

	op, err := g.Grant(ctx, retireGrant(3, "op-r1"))
	if err != nil || op.State != wire.OpUncertain || g.Retired() {
		t.Fatalf("interrupted: %+v %v", op, err)
	}

	rep, err := InspectRecords(g.Records, "")
	if err != nil || !rep.ApplyRetire || rep.ApplySelf != "op-r1" {
		t.Fatalf("inspection %+v %v", rep, err)
	}

	// decided completed from the node's config: retired
	if err := g.Reconcile(ctx); err != nil || !g.Retired() {
		t.Fatalf("reconciled: %v %v", err, g.Retired())
	}

	checkRetired(t, dir)
}

func TestARetirementLostBeforeTalosLeavesTheAgentUnretired(t *testing.T) {
	g := retireSetup(t)
	ctx := context.Background()

	g.fake.FailBeforeApply = errors.New("connection reset")

	if op, err := g.Grant(ctx, retireGrant(3, "op-r1")); err != nil || op.State != wire.OpUncertain {
		t.Fatalf("lost: %+v %v", op, err)
	}

	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-r1"); op.State != wire.OpUncertain || g.Retired() {
		t.Fatalf("decided before the apply settled: %+v", op)
	}

	var intent applyIntent

	_, err := g.Node.readJSON(applyRecord, &intent)
	must(t, err)

	intent.At = intent.At.Add(-ApplySettle)
	must(t, g.Node.writeJSON(applyRecord, intent))
	must(t, g.Reconcile(ctx))

	if op, _, _ := g.readOp("op-r1"); op.State != wire.OpRefused || g.Retired() {
		t.Fatalf("after it settled: %+v", op)
	}

	if a, i := ownDocsOnNode(t, g.Node); !a || !i {
		t.Fatal("the agent's documents went")
	}

	// granted again with a new attempt
	g.fake.FailBeforeApply = nil

	if op, err := g.Grant(ctx, retireGrant(4, "op-r2")); err != nil || op.State != wire.OpCompleted || !g.Retired() {
		t.Fatalf("again: %+v %v", op, err)
	}
}

func TestAStopBeforeTheMoveIsFinishedOnTheNextStart(t *testing.T) {
	g := retireSetup(t)
	ctx := context.Background()
	dir := g.Records.Dir

	// decided completed, stopped before the records moved
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-r1", Revision: 3, InputsHash: "h", GID: 42, State: wire.OpCompleted, Self: true, Retire: true}))

	if err := g.Reconcile(ctx); err != nil || !g.Retired() {
		t.Fatalf("reconciled: %v", err)
	}

	checkRetired(t, dir)
}

func TestTheRecordsJobRetiresTheRecords(t *testing.T) {
	g := retireSetup(t)
	ctx := context.Background()
	dir := g.Records.Dir
	now := time.Now()

	if _, err := RetireRecords(g.Records, "13", "", now); err == nil || !strings.Contains(err.Error(), "another generation") {
		t.Fatalf("an unlisted serial: %v", err)
	}

	// an agent stopped by its own retirement before it decided it
	g.fake.FailAfterApply = errors.New("connection reset")

	if op, _ := g.Grant(ctx, retireGrant(3, "op-r1")); op.State != wire.OpUncertain {
		t.Fatalf("interrupted: %+v", op)
	}

	var intent applyIntent

	_, err := g.Node.readJSON(applyRecord, &intent)
	must(t, err)

	// not settled: on the same boot within ApplySettle
	if _, err := RetireRecords(g.Records, "11", intent.BootID, now); err == nil {
		t.Fatal("retired over an apply that may still land")
	}

	if _, err := RetireRecords(g.Records, "11", "", now); err == nil {
		t.Fatal("retired over an apply that may still land, boot unknown")
	}

	// another boot: settled, the retirement decided completed, then moved
	rep, err := RetireRecords(g.Records, "11", "another-boot", now)
	if err != nil || !rep.Retired || len(rep.Owned) != 0 || rep.ApplyBoot != "" {
		t.Fatalf("retired: %+v %v", rep, err)
	}

	checkRetired(t, dir)

	moved := &records.Store{Dir: filepath.Join(filepath.Dir(dir), records.RetiredName(filepath.Base(dir), "12"))}
	if op, _, _ := (&Granter{Records: moved}).readOp("op-r1"); op.State != wire.OpCompleted {
		t.Fatalf("its operation: %+v", op)
	}

	if rep, err := InspectRecords(moved, ""); err != nil || rep.ApplyBoot != "" {
		t.Fatalf("its intent: %+v %v", rep, err)
	}

	// a retry: retired already
	if rep, err := RetireRecords(g.Records, "12", "", now); err != nil || !rep.Retired {
		t.Fatalf("a retry: %+v %v", rep, err)
	}

	// read for the host's serial: retired; another serial: missing
	if rep, found, err := RetiredRecords(dir, "11"); err != nil || !found || !rep.Retired {
		t.Fatalf("read retired: %+v %v %v", rep, found, err)
	}

	if _, found, err := RetiredRecords(dir, "13"); err != nil || found {
		t.Fatalf("read an unmarked serial: %v %v", found, err)
	}

	if _, found, err := RetiredRecords(dir, ""); err != nil || found {
		t.Fatalf("read without a serial: %v %v", found, err)
	}
}

func TestTheRecordsJobRefusesRecordsWithoutAnIdentity(t *testing.T) {
	g, _, _ := selfSetup(t)

	if _, err := RetireRecords(g.Records, "", "", time.Now()); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("no identity record: %v", err)
	}

	if _, err := os.Stat(g.Records.Dir); err != nil {
		t.Fatalf("the records: %v", err)
	}

	// none at all, nor a mark: missing
	if _, err := RetireRecords(&records.Store{Dir: filepath.Join(t.TempDir(), testFSID)}, "1", "", time.Now()); err == nil {
		t.Fatal("retired missing records")
	}
}

func TestAPartlyMarkedRetirementIsFinishedAtStart(t *testing.T) {
	g := retireSetup(t)
	dir := g.Records.Dir

	// unmarked: nothing to resume
	if resumed, err := ResumeRetirement(g.Records); err != nil || resumed {
		t.Fatalf("unmarked: %v %v", resumed, err)
	}

	// a records job stopped after marking 11, before 12 and the move
	must(t, (&records.Store{Dir: filepath.Dir(dir)}).Write(records.MarkName(filepath.Base(dir), "11"), []byte("x\n")))

	if resumed, err := ResumeRetirement(g.Records); err != nil || !resumed {
		t.Fatalf("resumed: %v %v", resumed, err)
	}

	checkRetired(t, dir)

	// missing records: nothing to resume
	if resumed, err := ResumeRetirement(g.Records); err != nil || resumed {
		t.Fatalf("after the move: %v %v", resumed, err)
	}
}

func TestARetireWithoutASerialIsDoneOnceTheRecordsAreGone(t *testing.T) {
	g := retireSetup(t)
	dir := g.Records.Dir

	if rep, err := RetireRecords(g.Records, "", "", time.Now()); err != nil || !rep.Retired {
		t.Fatalf("retire: %+v %v", rep, err)
	}

	checkRetired(t, dir)

	// the result was lost: a retry finds nothing left to retire
	if rep, err := RetireRecords(g.Records, "", "", time.Now()); err != nil || !rep.Retired {
		t.Fatalf("a retry: %+v %v", rep, err)
	}

	// with an unmarked serial, missing records still fail
	if _, err := RetireRecords(g.Records, "13", "", time.Now()); err == nil {
		t.Fatal("an unmarked serial")
	}
}
