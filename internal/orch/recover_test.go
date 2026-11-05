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
	"github.com/nberlee/cephadm-talos/internal/talos"
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
		// a job whose document the ownership shows applied; one whose apply is uncertain reserves the node
		{&wire.SuspendReceipt{Revision: 3, Unresolved: []wire.Operation{{Operation: "op-1", Revision: 3, Job: &wire.JobRef{ID: "a"}}}}, true},
		{&wire.SuspendReceipt{Revision: 3, Unresolved: []wire.Operation{{Operation: "op-1", Revision: 4, Job: &wire.JobRef{ID: "a"}}}}, false},
		{&wire.SuspendReceipt{Unresolved: []wire.Operation{{Operation: "op-1", Instance: "ceph-x-osd-0-2"}}}, true},
		{&wire.SuspendReceipt{Unresolved: []wire.Operation{{Operation: "op-1", Instance: doc + "-2"}}}, false},
		{&wire.SuspendReceipt{Unresolved: []wire.Operation{{Operation: "op-1"}}}, false}, // an apply: the node
		{&wire.SuspendReceipt{Revision: 3, ApplyPending: true, Unresolved: []wire.Operation{{Operation: "op-1", Revision: 3, Job: &wire.JobRef{ID: "a"}}}}, false},
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

	_ = o.RecoverMons(ctx, "quay.io/ceph/ceph@sha256:"+strings.Repeat("ab", 32), nil) // no quorum in the fake

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

	if err := o.RecoverMons(ctx, "", nil); err == nil || !strings.Contains(err.Error(), "were not recovered") || !strings.Contains(out.String(), "is not the document's deployment id") {
		t.Fatalf("a marker that differs: %v\n%s", err, out.String())
	}

	// neither configured nor owned: no mon here, no inspection
	o2, _, _ := recoverSetup(t, false)
	o2.inspectMon = func(state.Host) (string, error) { t.Fatal("inspected a host without a mon"); return "", nil }

	_ = o2.RecoverMons(ctx, "", nil)
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

	if err := o.RecoverMons(context.Background(), "", nil); err == nil || !strings.Contains(err.Error(), "h9") {
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

	_ = o.RecoverMons(ctx, "", nil)

	docs, err := o.configuredContainers(ctx, h.Addr, name)
	if err != nil || slices.Contains(docs, name) {
		t.Fatalf("the left inspection stayed: %v %v", docs, err)
	}
}

// Offline, the workstation's cached hosts include contacts the suspension did
// not count, as state.Load gives them: the journal is the authority, or a
// removed host's contact fails `recover mons` before any mon is recovered.
func TestAnOfflineRecoveryKeepsTheSessionsExclusions(t *testing.T) {
	o, h, rec := recoverSetup(t, true)

	// h8's retirement ended before the suspension; h7's node was left out of it
	o.St.Hosts = append(o.St.Hosts, state.Host{Name: "h8", Addr: "127.0.0.8"}, state.Host{Name: "h7", Addr: "127.0.0.7"})
	rec.Hosts["h7"] = &state.RecoveryHost{Addr: "127.0.0.7", Retiring: true, LeftOut: true, Receipt: &wire.SuspendReceipt{}}

	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	names := func() []string {
		var out []string
		for _, x := range o.removalHosts(rec) {
			out = append(out, x.Name)
		}

		return out
	}

	if got := names(); !slices.Equal(got, []string{h.Name}) {
		t.Fatalf("offline: %v", got)
	}

	if err := o.RecoverMons(context.Background(), "", nil); err != nil && strings.Contains(err.Error(), "not suspended") {
		t.Fatalf("recover mons: %v", err)
	}

	// with the published state, a member the session has not found still counts
	o.opened = true

	if got := names(); !slices.Equal(got, []string{h.Name, "h8"}) {
		t.Fatalf("online: %v", got)
	}

	// without a session nothing is excluded: a removal's cleanup reaches the contacts
	o.opened = false

	if got := o.removalHosts(nil); len(got) != 3 {
		t.Fatalf("no session: %v", got)
	}
}

// Offline, a host's address is the journal's: the cached one may be from before
// a move, and the session suspended the host at the journaled one.
func TestAnOfflineSessionReachesAHostAtItsJournaledAddress(t *testing.T) {
	o, h, rec := recoverSetup(t, true)

	// a member moved and a retiring host moved, between this workstation's
	// refreshes, its cache as state.Load gives it
	o.St.Hosts = []state.Host{{Name: h.Name, Addr: "127.0.0.66", Talosconfig: "/other", Context: "c"}, {Name: "h9", Addr: "127.0.0.67"}}
	rec.Hosts["h9"] = &state.RecoveryHost{Addr: "127.0.0.9", Retiring: true, Receipt: &wire.SuspendReceipt{}}
	o.Talos.Hosts = map[string]talos.Conn{"127.0.0.66": {Talosconfig: "/other", Context: "c"}}

	addrs := map[string]string{}
	for _, x := range o.removalHosts(rec) {
		addrs[x.Name] = x.Addr
	}

	if addrs[h.Name] != h.Addr || addrs["h9"] != "127.0.0.9" || len(addrs) != 2 {
		t.Fatalf("offline: %v", addrs)
	}

	if c := o.Talos.Hosts[h.Addr]; c.Talosconfig != "/other" || c.Context != "c" {
		t.Fatalf("its connection at the journaled address: %+v", c)
	}

	// the cache itself stays as it was, and the published state wins online
	o.opened = true

	if o.St.Hosts[0].Addr != "127.0.0.66" || o.removalHosts(rec)[0].Addr != "127.0.0.66" {
		t.Fatalf("online: %+v", o.removalHosts(rec))
	}
}

// A host left out may have a running agent, whose changes a write would race:
// nothing is written to it without the operator's assertion.
func TestRecoveryWritesNothingToAHostLeftOut(t *testing.T) {
	o, _, rec := recoverSetup(t, false)
	ctx := context.Background()

	rec.Hosts["h9"] = &state.RecoveryHost{Addr: "127.0.0.9", Retiring: true, LeftOut: true, Receipt: retiredReceipt(rec.Session, "h9")}

	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	doc := o.St.DocName(state.Daemon{Type: state.TypeMon, ID: "h9", Host: "h9"})
	mon := daemons.Mon(daemons.Params{Name: doc, Image: "quay.io/ceph/ceph@sha256:" + strings.Repeat("ab", 32), FSID: o.St.FSID, ID: "h9", Addr: "127.0.0.9", DeployID: "d9", Mode: "join", Addrv: daemons.MonAddrv("127.0.0.9")})

	if err := o.apply(ctx, "127.0.0.9", mon); err != nil {
		t.Fatal(err)
	}

	before, err := o.Talos.MachineConfig(ctx, "127.0.0.9")
	if err != nil {
		t.Fatal(err)
	}

	o.inspectMon = func(h state.Host) (string, error) {
		if h.Name == "h9" {
			t.Error("inspected a host left out")
		}

		return "", nil
	}

	err = o.RecoverMons(ctx, "", nil)
	if err == nil || !strings.Contains(err.Error(), "--member") {
		t.Fatalf("without a quorum: %v", err)
	}

	after, err := o.Talos.MachineConfig(ctx, "127.0.0.9")
	if err != nil || after != before {
		t.Fatalf("the node's config changed: %v", err)
	}

	got, err := state.LoadRecovery(o.St.FSID)
	if err != nil || !got.Hosts["h9"].LeftOut || len(got.Hosts["h9"].Restarted) != 0 {
		t.Fatalf("journal %+v %v", got.Hosts["h9"], err)
	}
}

// A host without a receipt is not suspended: it is not written to either.
func TestRecoveryWritesNothingToAHostWithoutAReceipt(t *testing.T) {
	o, _, rec := recoverSetup(t, false)
	ctx := context.Background()

	rec.Phase = state.PhaseRecovering
	rec.Hosts["h9"] = &state.RecoveryHost{Addr: "127.0.0.9"}

	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	doc := o.St.DocName(state.Daemon{Type: state.TypeMon, ID: "h9", Host: "h9"})
	mon := daemons.Mon(daemons.Params{Name: doc, Image: "quay.io/ceph/ceph@sha256:" + strings.Repeat("ab", 32), FSID: o.St.FSID, ID: "h9", Addr: "127.0.0.9", DeployID: "d9", Mode: "join", Addrv: daemons.MonAddrv("127.0.0.9")})

	if err := o.apply(ctx, "127.0.0.9", mon); err != nil {
		t.Fatal(err)
	}

	o.inspectMon = func(h state.Host) (string, error) {
		if h.Name == "h9" {
			t.Error("inspected a host that is not suspended")
		}

		return "", nil
	}

	_ = o.RecoverMons(ctx, "", nil)
}

// --member names only hosts the session left out.
func TestRecoverMemberNeedsAHostLeftOut(t *testing.T) {
	o, h, _ := recoverSetup(t, false)

	for _, name := range []string{"unknown", h.Name} {
		if err := o.RecoverMons(context.Background(), "", []string{name}); err == nil || !strings.Contains(err.Error(), "not a host this session left out") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Without a quorum the error says which hosts it may depend on.
func TestRecoveryNamesTheHostsLeftOutWithoutAQuorum(t *testing.T) {
	o, _, rec := recoverSetup(t, false)

	rec.Hosts["h9"] = &state.RecoveryHost{Addr: "127.0.0.9", LeftOut: true, Receipt: retiredReceipt(rec.Session, "h9")}

	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	err := o.RecoverMons(context.Background(), "", nil)
	if err == nil || !strings.Contains(err.Error(), "h9 (127.0.0.9)") || !strings.Contains(err.Error(), "--member") {
		t.Fatalf("without a quorum: %v", err)
	}
}

// Once recovery began suspend refuses: a host without a receipt warns, it does
// not keep the mons from being recovered.
func TestAResumedRecoveryIsNotHeldByAHostWithoutAReceipt(t *testing.T) {
	o, _, rec := recoverSetup(t, false)

	rec.Phase = state.PhaseRecovering
	rec.Hosts["h9"] = &state.RecoveryHost{Addr: "127.0.0.9"}

	if err := rec.Save(); err != nil {
		t.Fatal(err)
	}

	if err := o.RecoverMons(context.Background(), "", nil); err != nil && strings.Contains(err.Error(), "not suspended") {
		t.Fatalf("held: %v", err)
	}
}
