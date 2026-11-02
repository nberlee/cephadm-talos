package orch

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

func TestReservedMon(t *testing.T) {
	doc := "ceph-x-mon-h1"

	for _, c := range []struct {
		receipt *wire.SuspendReceipt
		ok      bool
	}{
		{&wire.SuspendReceipt{}, true},
		{&wire.SuspendReceipt{Unresolved: []wire.Operation{{Operation: "op-1", Job: &wire.JobRef{ID: "a"}}}}, true},
		{&wire.SuspendReceipt{Unresolved: []wire.Operation{{Operation: "op-1", Instance: "ceph-x-osd-0-2"}}}, true},
		{&wire.SuspendReceipt{Unresolved: []wire.Operation{{Operation: "op-1", Instance: doc + "-2"}}}, false},
		{&wire.SuspendReceipt{Unresolved: []wire.Operation{{Operation: "op-1"}}}, false}, // an apply: the node
		{&wire.SuspendReceipt{Intents: []wire.BridgeIntent{{Call: "mon rm", Daemon: "mon.h1"}}}, false},
		{&wire.SuspendReceipt{Intents: []wire.BridgeIntent{{Call: "retire", Daemon: "mgr.h1"}}}, true},
	} {
		rec := &state.Recovery{Hosts: map[string]*state.RecoveryHost{"h1": {Receipt: c.receipt}}}
		if err := reservedMon(rec, "h1", doc); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.receipt, err)
		}
	}

	// a bridge intent the leader recorded on another host
	rec := &state.Recovery{Hosts: map[string]*state.RecoveryHost{
		"h1": {Receipt: &wire.SuspendReceipt{}},
		"h2": {Receipt: &wire.SuspendReceipt{Intents: []wire.BridgeIntent{{Call: "mon rm", Daemon: "mon.h1", Host: "h1"}}}},
	}}
	if err := reservedMon(rec, "h1", doc); err == nil {
		t.Error("an intent on the leader's host did not reserve the mon")
	}
}

func TestParseMarker(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	for out, want := range map[string]string{
		"marker\n":                         "",
		"marker " + b64("0123abcd") + "\n": "0123abcd",
	} {
		if got, err := parseMarker(out); err != nil || got != want {
			t.Errorf("%q: %q %v", out, got, err)
		}
	}

	// a marker mon.sh would not compare as the recovery reads it
	for _, out := range []string{"marker " + b64("abc ") + "\n", "marker " + b64("a\nb") + "\n", "marker !!\n", "nothing\n"} {
		if _, err := parseMarker(out); err == nil {
			t.Errorf("%q accepted", out)
		}
	}
}

func recoverSetup(t *testing.T, owned bool) (*Orch, state.Host, *state.Recovery) {
	o, h, rec, _ := recoverSetupNode(t, owned)

	return o, h, rec
}

func recoverSetupNode(t *testing.T, owned bool) (*Orch, state.Host, *state.Recovery, *talostest.Node) {
	t.Helper()

	o, h, a := suspendSetup(t)
	o.opened = false

	// the mon is not running
	doc := o.St.DocName(state.Daemon{Type: state.TypeMon, ID: h.Name, Host: h.Name})
	if err := a.node.St.Destroy(context.Background(), containers.NewContainerStatus(containers.NamespaceName, doc).Metadata()); err != nil {
		t.Fatal(err)
	}
	receipt := &wire.SuspendReceipt{Owned: map[string]string{}}

	if owned {
		receipt.Owned["ContainerConfig/"+doc] = "hash"
	}

	rec := &state.Recovery{Schema: state.RecoverySchema, FSID: o.St.FSID, Session: "0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f", Phase: state.PhaseSuspended,
		Hosts: map[string]*state.RecoveryHost{h.Name: {Addr: h.Addr, Receipt: receipt}}, Jobs: map[string]*state.RecoveryJob{}}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	// the node's ceph.conf names the cluster
	if err := o.apply(context.Background(), h.Addr, spec.EtcFile("ceph/ceph.conf", 0o644, daemons.CephConf(o.St.FSID, []string{h.Addr}))); err != nil {
		t.Fatal(err)
	}

	old := quorumTimeout
	quorumTimeout = 10 * time.Millisecond

	t.Cleanup(func() { quorumTimeout = old })

	return o, h, rec, a.node
}

func TestAMissingMonDocumentIsAppliedOnItsStore(t *testing.T) {
	o, h, _ := recoverSetup(t, true)
	ctx := context.Background()
	o.inspectMon = func(state.Host) (string, error) { return "d3p10y", nil }

	_ = o.RecoverMons(ctx, "quay.io/ceph/ceph@sha256:"+strings.Repeat("ab", 32)) // no quorum in the fake

	doc := o.St.DocName(state.Daemon{Type: state.TypeMon, ID: h.Name, Host: h.Name})

	docs, err := o.configuredDocs(ctx, h.Addr, doc)
	if err != nil || docs[doc].env["DEPLOY_ID"] != "d3p10y" || docs[doc].env["MODE"] != "join" || docs[doc].env["CEPHADM_TALOS_KEYRING"] != "" {
		t.Fatalf("the mon's document: %+v %v", docs[doc], err)
	}

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil || rec.Phase != state.PhaseRecovering {
		t.Fatalf("journal: %+v %v", rec, err)
	}

	if hash := rec.Hosts[h.Name].Changes["ContainerConfig/"+doc]; hash == "" || len(rec.Hosts[h.Name].Applying) != 0 {
		t.Fatalf("the change's hash: %q, applying %+v", hash, rec.Hosts[h.Name].Applying)
	}
}

func TestAMonIsNotStartedOnAStoreThatDoesNotMatch(t *testing.T) {
	ctx := context.Background()

	// configured with another deployment id than its store's marker
	o, h, _ := recoverSetup(t, true)
	o.inspectMon = func(state.Host) (string, error) { return "other", nil }

	doc := o.St.DocName(state.Daemon{Type: state.TypeMon, ID: h.Name, Host: h.Name})
	if err := o.apply(ctx, h.Addr, daemons.Mon(daemons.Params{Name: doc, Image: o.St.Image, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr, DeployID: "d3p10y", Mode: "join"})); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	o.Out = &out

	if err := o.RecoverMons(ctx, ""); err == nil || !strings.Contains(err.Error(), "were not recovered") || !strings.Contains(out.String(), "is not the document's deployment id") {
		t.Fatalf("a marker that differs: %v\n%s", err, out.String())
	}

	// neither configured nor owned: no mon here, no inspection
	o2, _, _ := recoverSetup(t, false)
	o2.inspectMon = func(state.Host) (string, error) { t.Fatal("inspected a host without a mon"); return "", nil }

	_ = o2.RecoverMons(ctx, "")
}

func TestEachInspectionAfterAResultIsANewJob(t *testing.T) {
	o, h, rec := recoverSetup(t, true)
	_ = o

	a, err := inspectionJob(rec, h)
	if err != nil {
		t.Fatal(err)
	}

	again, _ := inspectionJob(rec, h)
	if again.ID != a.ID {
		t.Fatal("an inspection without a result got a new id")
	}

	a.Done = true

	b, _ := inspectionJob(rec, h)
	if b.ID == a.ID || b.Inputs == a.Inputs {
		t.Fatalf("an inspection after a result replays it: %+v %+v", a, b)
	}
}

func TestAMonDocumentMustRunItsOwnStore(t *testing.T) {
	o, h, _ := recoverSetup(t, true)

	good := configuredDoc{image: o.St.Image, env: map[string]string{"FSID": o.St.FSID, "ID": h.Name}, volumes: map[string]string{"/var/lib/ceph": spec.VolumeName}, mounts: []string{"/var/lib/ceph", "/etc/ceph"}}
	if err := o.checkMonDoc(h, good); err != nil {
		t.Fatal(err)
	}

	shadowed := good
	shadowed.mounts = append(slices.Clone(good.mounts), "/var/lib/ceph/"+o.St.FSID+"/mon."+h.Name)

	other := good
	other.env = map[string]string{"FSID": o.St.FSID, "ID": "h2"}

	unclean := good
	unclean.mounts = append(slices.Clone(good.mounts), "/var//lib/ceph/"+o.St.FSID+"/mon."+h.Name)

	parent := good
	parent.mounts = append(slices.Clone(good.mounts), "/var/lib")

	twice := good
	twice.mounts = append(slices.Clone(good.mounts), "/var/lib/ceph")

	for name, d := range map[string]configuredDoc{"a mount over the store": shadowed, "another mon": other, "an unclean path": unclean,
		"a parent mount": parent, "the store mounted twice": twice} {
		if err := o.checkMonDoc(h, d); err == nil {
			t.Errorf("%s passed", name)
		}
	}
}

func TestRecoveryNeedsEveryHostSuspended(t *testing.T) {
	o, _, rec := recoverSetup(t, true)

	// a host found since the suspension, without a receipt
	rec.Hosts["h9"] = &state.RecoveryHost{Addr: "127.0.0.9"}
	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	o.inspectMon = func(state.Host) (string, error) { t.Fatal("an effect before every host was checked"); return "", nil }

	if err := o.RecoverMons(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "h9") {
		t.Fatalf("a host without a receipt: %v", err)
	}
}

func TestAnInspectionWhoseCleanupFailedIsRemovedNextTime(t *testing.T) {
	o, h, rec := recoverSetup(t, true)
	ctx := context.Background()

	// an earlier run's inspection: its result read, its document left behind
	j, err := inspectionJob(rec, h)
	if err != nil {
		t.Fatal(err)
	}

	j.Done = true
	name := fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), j.ID)

	if err := o.apply(ctx, h.Addr, daemons.HostJob(daemons.Params{Name: name, Image: o.St.Image, FSID: o.St.FSID, ID: "job"}, j.ID, j.Inputs, "true")); err != nil {
		t.Fatal(err)
	}

	// the next inspection (cut short: the fake node runs no job) removes it first
	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()

	_, _ = o.monMarker(cctx, rec, h, o.St.Image)

	docs, err := o.configuredContainers(ctx, h.Addr, name)
	if err != nil || slices.Contains(docs, name) || !rec.Jobs["inspect-mon/"+h.Name+"/1"].Cleaned {
		t.Fatalf("the earlier inspection is left: %v %v", docs, err)
	}
}

func TestALeftInspectionGoesAlsoWhenTheMonRuns(t *testing.T) {
	o, h, rec, node := recoverSetupNode(t, true)
	ctx := context.Background()

	j, err := inspectionJob(rec, h)
	if err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), j.ID)
	if err := o.apply(ctx, h.Addr, daemons.HostJob(daemons.Params{Name: name, Image: o.St.Image, FSID: o.St.FSID, ID: "job"}, j.ID, j.Inputs, "true")); err != nil {
		t.Fatal(err)
	}

	// the mon runs again by now
	doc := o.St.DocName(state.Daemon{Type: state.TypeMon, ID: h.Name, Host: h.Name})
	if err := o.apply(ctx, h.Addr, daemons.Mon(daemons.Params{Name: doc, Image: o.St.Image, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr, DeployID: "d3p10y", Mode: "join"})); err != nil {
		t.Fatal(err)
	}

	cs := containers.NewContainerStatus(containers.NamespaceName, doc)
	cs.TypedSpec().State = containers.ContainerStateRunning

	if err := node.St.Create(ctx, cs); err != nil {
		t.Fatal(err)
	}

	_ = o.RecoverMons(ctx, "")

	docs, err := o.configuredContainers(ctx, h.Addr, name)
	if err != nil || slices.Contains(docs, name) {
		t.Fatalf("the left inspection stayed: %v %v", docs, err)
	}
}
