package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// Plan 04, step 4: the leader skips module entries, a takeover's import skips
// what the ledger's snapshot covers, and the operator resolves an uncertain job.

func TestModuleEntriesAreSkippedAndCheckpointedPast(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	must(t, s.leader.Tick(ctx, 42, 5))

	restart := s.accept(KindRestart, "mon.h1", "h1", 1)
	close1 := LedgerEntry{Key: "cephadm-talos/ledger/00000000000000000005-0000000002-m-00000000000000aa",
		Op: LedgerOp{Version: 1, ID: "m-00000000000000aa", Kind: "close", Daemon: "mon.h1", Host: "h1", GID: 42, Epoch: 5, Seq: 2}}
	s.module.mu.Lock()
	s.module.ledger = append(s.module.ledger, close1)
	s.module.mu.Unlock()

	for range 3 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, restart.Op.ID); !terminal(op.State) {
		t.Fatalf("restart %+v", op)
	}

	s.module.mu.Lock()
	_, recorded := s.module.kv[JournalPrefix(42)+"op/"+close1.Op.ID]
	s.module.mu.Unlock()

	if recorded {
		t.Fatal("a module entry left a journal record")
	}

	// the trailing module entry is checkpointed past
	if got := s.applied(t); got != close1.Key {
		t.Fatalf("checkpoint %q", got)
	}
}

func TestImportSkipsWhatTheSnapshotCovers(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	// incarnation 41 left grants of two operations without their outcome: one
	// at or below the ledger's snapshot (finished), one above it
	covered, above := "op-00000000000000c1", "op-00000000000000c2"

	s.module.mu.Lock()
	s.module.kv[JournalPrefix(41)+"takeover"] = `{"version":1,"epoch":3,"closed":[],"imported":true}`
	s.module.kv[JournalPrefix(41)+"op/"+covered+".rev"] = `{"version":1,"kind":"revision","host":"h1","state":"granting","revision":7}`
	s.module.kv[JournalPrefix(41)+"op/"+above+".rev"] = `{"version":1,"kind":"revision","host":"h1","state":"granting","revision":8}`
	s.module.snapshot = "00000000000000000003-0000000009-" + covered
	s.module.mu.Unlock()

	// the operation above the snapshot stays queued: held by an unfinished one before it
	s.accept(KindRestart, "mon.h9", "h9", 1)
	e := s.module.ledger[0]
	e.Op.ID = above
	s.module.ledger[0] = e

	must(t, s.leader.Tick(ctx, 42, 5))

	s.module.mu.Lock()
	_, gotCovered := s.module.kv[JournalPrefix(42)+"op/"+covered+".rev"]
	_, gotAbove := s.module.kv[JournalPrefix(42)+"op/"+above+".rev"]
	s.module.mu.Unlock()

	if gotCovered || !gotAbove {
		t.Fatalf("imported: covered %v, above %v", gotCovered, gotAbove)
	}
}

// uncertainJob makes a job's container end without a result, as a kill
// between its start and its result does: the agent records it uncertain.
func uncertainJob(t *testing.T, g *testGranter, opID string) wire.Operation {
	t.Helper()

	op, found, err := g.readOp(opID)
	if err != nil || !found || op.Job == nil {
		t.Fatalf("no job operation %s: %v", opID, err)
	}

	must(t, os.WriteFile(g.Node.jobFile(op.Job.ID, "started"), []byte("started\n"), 0o644))

	cs := containers.NewContainerStatus(containers.NamespaceName, op.Job.Doc)
	cs.TypedSpec().State = containers.ContainerStateFailed
	must(t, g.fake.St.Create(context.Background(), cs))
	must(t, g.Reconcile(context.Background()))

	op, _, err = g.readOp(opID)
	must(t, err)

	if op.State != wire.OpUncertain {
		t.Fatalf("not uncertain: %+v", op)
	}

	return op
}

func TestResolveOnlyWhenTheJobCannotRun(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	doc := "ceph-" + testFSID[:8] + "-job-abcdef"
	job := wire.Operation{Version: wire.Version, Operation: "op-2.prep", Revision: 1, State: wire.OpUncertain, GID: 42, InputsHash: "h",
		Job: &wire.JobRef{ID: "abcdef", Doc: doc, Inputs: "x"}}
	must(t, g.writeOp(job))
	must(t, os.WriteFile(g.Node.jobFile("abcdef", "started"), []byte("started\n"), 0o644))

	plain := wire.Operation{Version: wire.Version, Operation: "op-3.rev", Revision: 1, State: wire.OpUncertain, GID: 42, InputsHash: "h"}
	must(t, g.writeOp(plain))

	done := job
	done.Operation, done.State, done.Job = "op-4.prep", wire.OpCompleted, &wire.JobRef{ID: "bbbbbb", Doc: doc + "b", Inputs: "y"}
	must(t, g.writeOp(done))

	for id, want := range map[string]string{"op-9": "no operation", "op-3.rev": "not a job's", "op-4.prep": "not uncertain"} {
		if _, err := g.Resolve(ctx, id); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", id, err)
		}
	}

	// its container still runs
	cs := containers.NewContainerStatus(containers.NamespaceName, doc)
	cs.TypedSpec().State = containers.ContainerStateRunning
	must(t, g.fake.St.Create(ctx, cs))

	if _, err := g.Resolve(ctx, job.Operation); err == nil || !strings.Contains(err.Error(), "runs") {
		t.Fatalf("resolved a running job: %v", err)
	}

	cs.TypedSpec().State = containers.ContainerStateFailed
	must(t, g.fake.St.Update(ctx, cs))

	// an apply whose outcome is still open
	must(t, g.Node.writeJSON(applyRecord, applyIntent{Schema: ownershipSchema, Revision: 2, BootID: "other"}))

	if _, err := g.Resolve(ctx, job.Operation); err == nil || !strings.Contains(err.Error(), "apply") {
		t.Fatalf("resolved beside an open apply: %v", err)
	}

	must(t, g.Node.Records.Remove(applyRecord))

	// suspended, it is still served: failed, rc -1, and tombstoned
	must(t, g.Suspend(ctx, testSession))

	op, err := g.Resolve(ctx, job.Operation)
	if err != nil || op.State != wire.OpFailed || op.Result == nil || op.Result.RC != -1 || op.Error != resolvedByOperator {
		t.Fatalf("resolve: %+v %v", op, err)
	}

	if _, err := g.Records.Read(tombRecord + "abcdef"); err != nil {
		t.Fatalf("no tombstone: %v", err)
	}

	if _, err := os.Stat(g.Node.jobFile("abcdef", "tombstone")); err != nil {
		t.Fatalf("no tombstone for the job script: %v", err)
	}

	if ops, err := g.Unresolved(); err != nil || len(ops) != 0 {
		t.Fatalf("still unresolved: %+v %v", ops, err)
	}

	if !failClosedOpen["POST /v1/resolve"] || !failClosedOpen["GET /v1/resolve"] {
		t.Fatal("a fail-closed agent does not serve the operator's resolve")
	}
}

func TestResolveRecordsAResultThatAppeared(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	doc := "ceph-" + testFSID[:8] + "-job-abcdef"
	job := wire.Operation{Version: wire.Version, Operation: "op-2.prep", Revision: 1, State: wire.OpUncertain, GID: 42, InputsHash: "h",
		Job: &wire.JobRef{ID: "abcdef", Doc: doc, Inputs: "x"}}
	must(t, g.writeOp(job))

	// the job wrote its result and exited after the last reconcile
	must(t, os.WriteFile(g.Node.jobFile("abcdef", "result"), []byte("rc 0\ninputs x\nosd_id 5"), 0o644))

	op, err := g.Resolve(ctx, job.Operation)
	if err != nil || op.State != wire.OpCompleted || op.Result == nil || op.Result.RC != 0 {
		t.Fatalf("resolve: %+v %v", op, err)
	}

	if _, err := g.Records.Read(tombRecord + "abcdef"); err == nil {
		t.Fatal("a job with its result tombstoned before its acknowledgement")
	}
}

// operatorResolve posts a resolve to the leader setup's agent with the
// operator's certificate.
func operatorResolve(t *testing.T, s *leaderSetup, role pki.Role, id string) (int, wire.Operation) {
	t.Helper()

	cert, key := s.ca.pair(role, "admin", x509.ExtKeyUsageClientAuth, testFSID)
	body, _ := json.Marshal(wire.Resolve{Version: wire.Version, FSID: testFSID, Host: "h1", Operation: id})

	resp, err := s.ca.client(cert, key).Post(s.leader.agentURL(state.Host{})+"/v1/resolve", "application/json", bytes.NewReader(body))
	must(t, err)

	defer resp.Body.Close() //nolint:errcheck

	var op wire.Operation
	_ = json.NewDecoder(resp.Body).Decode(&op)

	return resp.StatusCode, op
}

func TestAResolvedPreparationFailsTheCreation(t *testing.T) {
	s, create := creationSetup(t)
	ctx := context.Background()

	uncertainJob(t, s.agent, create.Op.ID+".prep")

	// the leader asks again and again: the ledger waits behind it
	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, create.Op.ID+".prep"); op.State != wire.OpUncertain {
		t.Fatalf("preparation %+v", op)
	}

	if code, _ := operatorResolve(t, s, pki.RoleMgr, create.Op.ID+".prep"); code != http.StatusForbidden {
		t.Fatalf("a mgr resolved: %d", code)
	}

	if code, op := operatorResolve(t, s, pki.RoleOperator, create.Op.ID+".prep"); code != http.StatusOK || op.State != wire.OpFailed {
		t.Fatalf("resolve: %d %+v", code, op)
	}

	must(t, s.leader.Tick(ctx, 42, 5))

	if op := s.op(t, create.Op.ID); op.State != JournalFailed {
		t.Fatalf("creation %+v", op)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Contains(calls, "close create "+create.Op.ID) {
		t.Fatalf("not closed: %v", calls)
	}

	// acknowledged with its document's removal, and the next operation runs
	if op, _, _ := s.agent.readOp(create.Op.ID + ".prep"); !op.Acked {
		t.Fatalf("the resolved job is not acknowledged: %+v", op)
	}

	next := s.accept(KindRestart, "mon.h1", "h1", 2)
	addInstance(t, s.agent.fake, "ceph-"+testFSID[:8]+"-mon-h1", 1)

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, next.Op.ID); op.State != wire.OpCompleted {
		t.Fatalf("the next operation: %+v", op)
	}
}

func TestAResolvedProbeRefusesTheUpgrade(t *testing.T) {
	s := newLeaderSetup(t)
	ctx := context.Background()

	target := "quay.io/ceph/ceph@sha256:" + strings.Repeat("cd", 32)

	appr, err := approval.Sign(testApprovalPriv, approval.Approval{Version: approval.Version, FSID: testFSID, Serial: 2, Images: []string{testImage, target}})
	must(t, err)

	b, _ := json.Marshal(appr)

	s.module.mu.Lock()
	s.module.approval, s.module.active, s.module.quorum = string(b), "h0", []string{"h1"}
	s.module.mu.Unlock()

	s.st.CephVersion, s.st.Arch = "20.2.4", "x86_64"
	publish(t, s.leader, s.module, s.st)

	s.request("r1", `{"version":1,"kind":"revision","host":"h1"}`)
	must(t, s.leader.Tick(ctx, 42, 5))

	up := s.accept(KindUpgrade, "", "", 1)
	up.Op.Image = target
	s.module.mu.Lock()
	s.module.ledger[len(s.module.ledger)-1] = up
	s.module.mu.Unlock()

	must(t, s.leader.Tick(ctx, 42, 5))
	uncertainJob(t, s.agent, up.Op.ID+".probe")
	must(t, s.leader.Tick(ctx, 42, 5))

	if _, err := s.agent.Resolve(ctx, up.Op.ID+".probe"); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		must(t, s.leader.Tick(ctx, 42, 5))
	}

	if op := s.op(t, up.Op.ID); op.State != JournalFailed || !strings.Contains(op.Error, "probe") {
		t.Fatalf("start %+v", op)
	}

	s.module.mu.Lock()
	calls := slices.Clone(s.module.retired)
	s.module.mu.Unlock()

	if !slices.Contains(calls, "upgrade refused "+up.Op.ID) {
		t.Fatalf("not refused: %v", calls)
	}

	if op, _, _ := s.agent.readOp(up.Op.ID + ".probe"); !op.Acked {
		t.Fatalf("the resolved probe is not acknowledged: %+v", op)
	}
}
