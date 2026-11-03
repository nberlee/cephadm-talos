package orch

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

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
