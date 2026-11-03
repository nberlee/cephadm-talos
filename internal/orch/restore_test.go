package orch

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
)

// restoreSetup is a suspended session of h1, whose agent answered, its
// documents on the node and running the agents' image; h1's keys are the
// module's (AgentKeys), not the CLI's.
func restoreSetup(t *testing.T) (*Orch, state.Host, *fakeAgent) {
	t.Helper()

	o, h, a := suspendSetup(t)
	ctx := context.Background()

	if err := o.apply(ctx, h.Addr, o.agentDocs(h)...); err != nil {
		t.Fatal(err)
	}

	cs := containers.NewContainerStatus(containers.NamespaceName, o.agentDocName(h))
	cs.TypedSpec().State, cs.TypedSpec().Image = containers.ContainerStateRunning, strings.SplitN(o.St.Agent.Image, "@", 2)[1]

	if err := a.node.St.Create(ctx, cs); err != nil {
		t.Fatal(err)
	}

	// renewed by the module: the keys are an attempt's secrets
	h.AgentKeys = "op-0000000000000001/0000000000000001"
	o.St.AddHost(h)

	if err := o.save(); err != nil {
		t.Fatal(err)
	}

	if err := o.StoreBackend.SetMany(ctx, []store.KV{
		{Key: store.SecretPrefix + h.AgentKeySecret(state.SecretAgentServer), Value: []byte(h.AgentKey)},
		{Key: store.SecretPrefix + h.AgentKeySecret(state.SecretAgentClient), Value: []byte(h.AgentClientKey)},
	}); err != nil {
		t.Fatal(err)
	}

	if err := o.StoreBackend.Remove(ctx, []string{
		store.SecretPrefix + state.SecretHost("h1", state.SecretAgentServer), store.SecretPrefix + state.SecretHost("h1", state.SecretAgentClient),
	}); err != nil {
		t.Fatal(err)
	}

	return o, h, a
}

func TestAgentRestoreRunsInASuspension(t *testing.T) {
	o, _, _ := restoreSetup(t)

	if err := o.RestoreAgent(context.Background(), "h1", false); err == nil || !strings.Contains(err.Error(), "recovery session") {
		t.Fatalf("outside a session: %v", err)
	}
}

func TestAgentRestoreAppliesTheStatesAgent(t *testing.T) {
	o, h, a := restoreSetup(t)
	ctx := context.Background()

	if _, err := o.Suspend(ctx, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	posts := a.posts

	if err := o.RestoreAgent(ctx, "h1", false); err != nil {
		t.Fatal(err)
	}

	// it answered suspended again, and keeps its receipt
	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil || rec.Hosts["h1"].Receipt == nil || a.posts != posts+1 || rec.Hosts["h1"].AgentRestored {
		t.Fatalf("journal %+v %v, %d posts", rec, err, a.posts)
	}

	docs, err := o.configuredDocs(ctx, h.Addr, o.agentDocName(h))
	if err != nil {
		t.Fatal(err)
	}

	if d := docs[o.agentDocName(h)]; d.image != o.St.Agent.Image || d.env["CEPHADM_TALOS_APPROVAL_KEY"] != o.St.Agent.ApprovalKey {
		t.Fatalf("restored %+v", d)
	}
}

func TestAgentRestorePreviousTakesTheKnownGood(t *testing.T) {
	o, h, _ := restoreSetup(t)
	ctx := context.Background()

	if _, err := o.Suspend(ctx, SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	if err := o.RestoreAgent(ctx, "h1", true); err == nil || !strings.Contains(err.Error(), "no earlier agent image") {
		t.Fatalf("without an upgrade: %v", err)
	}

	// an unfinished upgrade's from-image before the last one's
	from := "docker.io/registry/agent@sha256:" + strings.Repeat("bb", 32)
	o.St.Agent.PreviousImage = "docker.io/registry/agent@sha256:" + strings.Repeat("cc", 32)
	o.St.AgentUpgrade = &state.AgentUpgrade{Op: "op-0000000000000002", From: from, Image: o.St.Agent.Image}

	// applied, but its agent does not run it: the restore says so
	if err := o.RestoreAgent(ctx, "h1", true); err == nil || !strings.Contains(err.Error(), "does not run") {
		t.Fatalf("the check of its image: %v", err)
	}

	docs, err := o.configuredDocs(ctx, h.Addr, o.agentDocName(h))
	if err != nil {
		t.Fatal(err)
	}

	if d := docs[o.agentDocName(h)]; d.image != from {
		t.Fatalf("restored %s", d.image)
	}
}

func TestASuspensionJournalsTheRemovedAgentsInputs(t *testing.T) {
	o, h, a := restoreSetup(t)

	// expired: the node's agent is removed through Talos
	operatorCert(t, o, time.Millisecond)
	time.Sleep(5 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rec, _ := o.Suspend(ctx, SuspendOptions{})
	if a.posts != 0 || rec == nil {
		t.Fatalf("journal %+v", rec)
	}

	hr := rec.Hosts["h1"]
	if !hr.AgentPinned || !slices.Equal(hr.AgentRepos, o.imageRepos()) || hr.AgentApprovalKey != o.St.Agent.ApprovalKey || hr.AgentCert != h.AgentCert {
		t.Fatalf("pinned inputs %+v", hr)
	}

	if hr.AgentServerKey != h.AgentKeySecret(state.SecretAgentServer) || hr.AgentClientKey != h.AgentKeySecret(state.SecretAgentClient) {
		t.Fatalf("key names %q %q", hr.AgentServerKey, hr.AgentClientKey)
	}

	// for a host the state no longer has, the journal's certificates and key
	// names come before an enrollment record
	enrolled, _ := json.Marshal(Enrollment{Version: 1, Name: "h9", Addr: "127.0.0.9", AgentCert: "other", AgentClientCert: "other"})
	if err := o.StoreBackend.SetMany(context.Background(), []store.KV{{Key: EnrollPrefix + "h9", Value: enrolled}}); err != nil {
		t.Fatal(err)
	}

	ah, err := o.agentHost(context.Background(), state.Host{Name: "h9", Addr: "127.0.0.9"}, hr)
	if err != nil || ah.AgentKey != h.AgentKey || ah.AgentCert != h.AgentCert {
		t.Fatalf("agent host: %v", err)
	}
}

func TestARemovedRenewedHostsKeysAreFoundByItsCertificate(t *testing.T) {
	o, h, _ := suspendSetup(t)
	ctx := context.Background()

	// h9 left the state after a module renewal: its keys are the renewal's,
	// its certificate beside them; the CLI's were deleted
	renewed := state.Host{Name: "h9", Addr: "127.0.0.9"}
	if err := o.ensureAgentCert(&renewed); err != nil {
		t.Fatal(err)
	}

	ref := "op-0000000000000003/0000000000000007"
	if err := o.StoreBackend.SetMany(ctx, []store.KV{
		{Key: store.SecretPrefix + state.SecretIssued(ref, "agent-server.crt"), Value: []byte(renewed.AgentCert)},
		{Key: store.SecretPrefix + state.SecretIssued(ref, state.SecretAgentServer), Value: []byte(renewed.AgentKey)},
		{Key: store.SecretPrefix + state.SecretIssued(ref, state.SecretAgentClient), Value: []byte(renewed.AgentClientKey)},
	}); err != nil {
		t.Fatal(err)
	}

	server, client, err := o.agentKeyNames(ctx, "h9", renewed.AgentCert)
	if err != nil || server != state.SecretIssued(ref, state.SecretAgentServer) || client != state.SecretIssued(ref, state.SecretAgentClient) {
		t.Fatalf("by the renewed certificate: %q %q %v", server, client, err)
	}

	// another certificate: the CLI's names
	if server, _, err := o.agentKeyNames(ctx, "h9", h.AgentCert); err != nil || server != state.SecretHost("h9", state.SecretAgentServer) {
		t.Fatalf("by another certificate: %q %v", server, err)
	}

	// a journal without the names (the secrets were not readable at the
	// suspension): the resumption finds them by the certificate
	ah, err := o.agentHost(ctx, renewed, &state.RecoveryHost{AgentCert: renewed.AgentCert, AgentClientCert: renewed.AgentClientCert})
	if err != nil || ah.AgentKey != renewed.AgentKey || ah.AgentClientKey != renewed.AgentClientKey {
		t.Fatalf("agent host: %v", err)
	}
}

// suspended suspends restoreSetup's session and returns its journal.
func suspended(t *testing.T, o *Orch) *state.Recovery {
	t.Helper()

	if _, err := o.Suspend(context.Background(), SuspendOptions{}); err != nil {
		t.Fatal(err)
	}

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil {
		t.Fatal(err)
	}

	return rec
}

func TestAnAgentApplyThatMayStillLandRefusesRestoreAndResume(t *testing.T) {
	o, h, _ := restoreSetup(t)
	ctx := context.Background()

	rec := suspended(t, o)

	// a restore stopped after journaling its apply: not on the node, not settled
	boot, err := o.Talos.BootID(ctx, h.Addr)
	if err != nil {
		t.Fatal(err)
	}

	rec.Hosts["h1"].AgentApply = &state.AgentApply{Hashes: map[string]string{"ContainerConfig/" + o.agentDocName(h): "elsewhere"}, BootID: boot, At: time.Now()}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	if err := o.RestoreAgent(ctx, "h1", false); err == nil || !strings.Contains(err.Error(), "may still land") {
		t.Fatalf("restore: %v", err)
	}

	if err := o.Resume(ctx); err == nil || !strings.Contains(err.Error(), "may still land") {
		t.Fatalf("resume: %v", err)
	}

	if rec, _ := state.LoadRecovery(o.St.FSID); rec.Phase != state.PhaseSuspended {
		t.Fatalf("the refusal moved the session on: %s", rec.Phase)
	}

	// once it settled it did not happen: the restore applies, decides and clears it
	rec, _ = state.LoadRecovery(o.St.FSID)
	rec.Hosts["h1"].AgentApply.At = time.Now().Add(-agent.ApplySettle)
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	if err := o.RestoreAgent(ctx, "h1", false); err != nil {
		t.Fatal(err)
	}

	if rec, _ := state.LoadRecovery(o.St.FSID); rec.Hosts["h1"].AgentApply != nil {
		t.Fatalf("the apply stayed journaled: %+v", rec.Hosts["h1"].AgentApply)
	}
}

func TestAResumptionFinishesALandedRestoreAsRendered(t *testing.T) {
	o, h, _ := restoreSetup(t)
	ctx := context.Background()

	rec := suspended(t, o)
	hr := rec.Hosts["h1"]
	hr.RemovingAgent, hr.AgentRemoved = true, true

	// `agent restore --previous` applied its documents and stopped
	ah, err := o.agentHost(ctx, h, hr)
	if err != nil {
		t.Fatal(err)
	}

	previous := "docker.io/registry/agent@sha256:" + strings.Repeat("bb", 32)
	docs := o.agentDocsWith(ah, previous, o.imageRepos(), o.St.Agent.ApprovalKey)

	hashes, err := docHashes(docs)
	if err != nil {
		t.Fatal(err)
	}

	hr.AgentApply = &state.AgentApply{Hashes: hashes, BootID: "boot-1", At: time.Now()}
	if err := o.apply(ctx, h.Addr, docs...); err != nil {
		t.Fatal(err)
	}

	// what the resumption does first: finished, not rendered with the state's image
	if err := o.agentReturn(ctx, rec, h, nil); err != nil {
		t.Fatal(err)
	}

	if hr.AgentApply != nil || !hr.AgentRestored {
		t.Fatalf("journal %+v", hr)
	}

	cur, err := o.configuredDocs(ctx, h.Addr, o.agentDocName(h))
	if err != nil {
		t.Fatal(err)
	}

	if d := cur[o.agentDocName(h)]; d.image != previous {
		t.Fatalf("rendered again: %s", d.image)
	}
}

func TestTheResumptionsRestoreSettlesASelfUpdate(t *testing.T) {
	o, h, _ := restoreSetup(t)
	ctx := context.Background()

	rec := suspended(t, o)
	hr := rec.Hosts["h1"]
	hr.RemovingAgent, hr.AgentRemoved = true, true
	hr.Receipt.ApplyPending = true // an interrupted renewal's self-update intent

	settled := 0
	o.settleSelf = func(state.Host) (agent.RecordsReport, error) {
		settled++

		// once the restored documents are in the node's config
		if a := rec.Hosts["h1"].AgentApply; a == nil || !a.Applied {
			t.Error("settled before the documents were in the node's config")
		}

		return agent.RecordsReport{Settled: "op-1.self"}, nil
	}

	if err := o.restoreAgent(ctx, rec, h); err != nil {
		t.Fatal(err)
	}

	if settled != 1 || !hr.AgentRestored || hr.AgentApply != nil {
		t.Fatalf("settled %d times, journal %+v", settled, hr)
	}
}
