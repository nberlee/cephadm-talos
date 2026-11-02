package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// recoveryChange applies a document behind the agent's back, as a recovery
// does, and returns its key and hash.
func recoveryChange(t *testing.T, g *testGranter, id string) (string, string) {
	t.Helper()

	ctx := context.Background()
	name := "ceph-" + testFSID[:8] + "-probe-" + id
	must(t, g.patches.Client.Patch(ctx, "", mustRender(daemons.Probe(name, testImage))))

	cfg, err := g.patches.Client.MachineConfig(ctx, "")
	must(t, err)

	hashes, err := DocHashes(cfg)
	must(t, err)

	key := "ContainerConfig/" + name

	return key, hashes[key]
}

func TestReadoptionTakesOnlyTheJournaledChanges(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	if _, err := g.Readopt(ctx, testSession, nil); err == nil {
		t.Fatal("a re-adoption without a suspension")
	}

	must(t, g.Suspend(ctx, testSession))

	key, hash := recoveryChange(t, g, "aaaaaa")

	// a change the CLI did not journal is not adopted
	if _, err := g.Readopt(ctx, testSession, nil); err == nil {
		t.Fatal("an unjournaled document was adopted")
	}

	if _, err := g.Readopt(ctx, testSession, map[string]string{key: "0000"}); err == nil {
		t.Fatal("a document other than the journaled one was adopted")
	}

	// an operation of a higher revision than the ownership: the new revision is above it
	must(t, g.writeOp(wire.Operation{Version: wire.Version, Operation: "op-7", Revision: 7, State: wire.OpUncertain, GID: 42, InputsHash: "h"}))

	changes := map[string]string{key: hash}

	r, err := g.Readopt(ctx, testSession, changes)
	if err != nil || r.Revision != 8 || r.Docs[key] != hash {
		t.Fatalf("re-adoption: %+v %v", r, err)
	}

	own, _, err := g.Node.ownership()
	if err != nil || own.Revision != 8 || own.Docs[key] != hash || own.ApprovalSerial != 1 {
		t.Fatalf("ownership: %+v %v", own, err)
	}

	// the same request again: the same receipt; other changes are refused
	if r2, err := g.Readopt(ctx, testSession, changes); err != nil || r2.Revision != r.Revision {
		t.Fatalf("the same re-adoption again: %+v %v", r2, err)
	}

	if _, err := g.Readopt(ctx, testSession, map[string]string{}); err == nil {
		t.Fatal("a re-adoption with other changes")
	}

	// the agent stays suspended, the records stay
	if !g.Suspended() {
		t.Fatal("the re-adoption ended the suspension")
	}

	if op, found, _ := g.readOp("op-7"); !found || op.Revision != 7 {
		t.Fatalf("the operation record: %+v", op)
	}
}

func TestActivationChecksTheBoundaryEpoch(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	must(t, g.Suspend(ctx, testSession))

	act := wire.Activate{Version: wire.Version, FSID: testFSID, Host: "h1", Session: testSession, Revision: 2, Epoch: 9}

	if err := g.Activate(ctx, act); err == nil {
		t.Fatal("an activation without a re-adoption")
	}

	r, err := g.Readopt(ctx, testSession, nil)
	if err != nil || r.Revision != 2 {
		t.Fatalf("re-adoption: %+v %v", r, err)
	}

	b, _ := testBridge(t, "h1")
	b.Intents = g.Records

	// an intent of an epoch after the boundary refuses the activation
	must(t, b.intend("d1", "mon rm", map[string]any{"operation": "op-7"}))
	must(t, b.intend("d2", "mon rm", map[string]any{"operation": "op-8"}))

	in, err := OpenIntents(g.Records)
	must(t, err)

	for _, i := range in {
		i.Epoch = 9
		if i.Dispatch == "d2" {
			i.Epoch = 10
		}

		raw := mustJSON(t, i)
		must(t, g.Records.Write(intentRecord+i.Dispatch, raw))
	}

	if err := g.Activate(ctx, act); err == nil || !g.Suspended() {
		t.Fatalf("an intent after the boundary: %v", err)
	}

	must(t, g.Records.Remove(intentRecord+"d2"))

	if err := g.Activate(ctx, wire.Activate{Version: wire.Version, FSID: testFSID, Host: "h1", Session: testSession, Revision: 3, Epoch: 9}); err == nil {
		t.Fatal("an activation of another revision")
	}

	must(t, g.Activate(ctx, act))

	if g.Suspended() {
		t.Fatal("still suspended after the activation")
	}

	if in, err := OpenIntents(g.Records); err != nil || len(in) != 0 {
		t.Fatalf("intents left after the activation: %+v %v", in, err)
	}

	// again: fine, and the agent grants again
	must(t, g.Activate(ctx, act))

	if _, err := g.Grant(ctx, probeGrant(3, "op-1", "bbbbbb")); err != nil {
		t.Fatalf("a grant after the activation: %v", err)
	}
}

func TestReadoptionRefusesAnUncertainApply(t *testing.T) {
	g := newTestGranter(t)
	ctx := context.Background()

	must(t, g.Suspend(ctx, testSession))
	must(t, g.Node.writeJSON(applyRecord, applyIntent{Schema: ownershipSchema, Revision: 2, BootID: "other"}))

	if _, err := g.Node.readopt(ctx, testSession, nil, 0); err == nil {
		t.Fatal("a re-adoption with an uncertain apply")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()

	b, err := json.Marshal(v)
	must(t, err)

	return b
}
