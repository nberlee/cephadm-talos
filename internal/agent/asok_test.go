package agent

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

func TestAsokEntity(t *testing.T) {
	st := &state.State{FSID: testFSID}
	p := func(typ, id string) daemons.Params {
		return daemons.Params{Name: st.DocName(state.Daemon{Type: typ, ID: id}), Image: testImage, FSID: testFSID, ID: id, Addr: "10.5.0.2"}
	}

	osd := p(state.TypeOSD, "h1-sda")
	osd.OSDID, osd.OSDUUID, osd.Device = 3, "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f", "/dev/disk/by-id/x"

	for want, c := range map[string]any{
		"mon.h1":        daemons.Mon(p(state.TypeMon, "h1")),
		"mgr.h1":        daemons.Mgr(p(state.TypeMgr, "h1")),
		"osd.3":         daemons.OSD(osd),
		"client.rgw.h1": daemons.RGW(p(state.TypeRGW, "h1")),
		"":              daemons.VIP(p(state.TypeVIP, "h1"), testImage),
	} {
		if got := asokEntity(testFSID, c.(*spec.ContainerConfig)); got != want {
			t.Errorf("%s: %q", want, got)
		}
	}

	// a name that is not its id's document has no socket
	m := daemons.Mon(p(state.TypeMon, "h1"))
	m.MetaName = st.DocName(state.Daemon{Type: state.TypeMon, ID: "h2"})

	if got := asokEntity(testFSID, m); got != "" {
		t.Errorf("mismatched name: %q", got)
	}
}

func TestAsokQueries(t *testing.T) {
	ctx := context.Background()

	var args []string

	exec := func(out string, rc int) Execer {
		return func(_ context.Context, _ string, a []string, stdout, _ io.Writer) (int, error) {
			args = a
			_, _ = io.WriteString(stdout, out)

			return rc, nil
		}
	}

	if v, err := daemonVersion(ctx, exec(`{"version":"20.2.4","release":"tentacle"}`, 0), "c", "mon.h1"); err != nil || v != "20.2.4" {
		t.Fatalf("version: %q %v", v, err)
	}

	if strings.Join(args, " ") != "ceph --admin-daemon /var/run/ceph/ceph-mon.h1.asok version" {
		t.Fatalf("command %v", args)
	}

	for name, e := range map[string]Execer{
		"a failing query": exec(`{}`, 1),
		"no version":      exec(`{"release":"x"}`, 0),
		"too much output": exec(strings.Repeat("x", asokOutput+1), 0),
	} {
		if _, err := daemonVersion(ctx, e, "c", "mon.h1"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	if _, err := asok(ctx, exec("", 0), "c", "mon.h1", "config set debug_ms 20"); err == nil {
		t.Fatal("a command outside the allowlist")
	}
}

func TestVersionsOncePerInstance(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	st := &state.State{FSID: testFSID}
	mon := daemons.Mon(daemons.Params{Name: st.DocName(state.Daemon{Type: state.TypeMon, ID: "h1"}), Image: testImage, FSID: testFSID, ID: "h1", Addr: "10.5.0.2", Mode: "join", Addrv: daemons.MonAddrv("10.5.0.2"), Keyring: daemons.MonKeyring(fakeKey)})
	must(t, tc.Patch(ctx, "", yamlOf(t, mon)))

	calls := 0
	a := &Agent{Talos: tc, Node: n}

	a.Exec = func(_ context.Context, _ string, _ []string, stdout, _ io.Writer) (int, error) {
		calls++
		_, _ = fmt.Fprintf(stdout, `{"version":"20.2.%d"}`, calls)

		return 0, nil
	}

	statuses := map[string]containers.ContainerStatusSpec{mon.MetaName: {State: containers.ContainerStateRunning, Generation: 1}}

	for range 5 {
		rec := &Record{Containers: map[string]Container{}}
		a.daemonVersions(ctx, rec, statuses)

		if rec.Containers[mon.MetaName].Version != "20.2.1" {
			t.Fatalf("version %+v", rec.Containers[mon.MetaName])
		}
	}

	if calls != 1 {
		t.Fatalf("%d execs for one instance", calls)
	}

	// a new instance is asked again
	statuses[mon.MetaName] = containers.ContainerStatusSpec{State: containers.ContainerStateRunning, Generation: 2}
	rec := &Record{Containers: map[string]Container{}}
	a.daemonVersions(ctx, rec, statuses)

	if calls != 2 || rec.Containers[mon.MetaName].Version != "20.2.2" {
		t.Fatalf("new instance: %d execs, %+v", calls, rec.Containers[mon.MetaName])
	}

	// removed and created again: the counters start over, the PID tells it apart
	statuses[mon.MetaName] = containers.ContainerStatusSpec{State: containers.ContainerStateRunning, Generation: 2, PID: 4242}
	rec = &Record{Containers: map[string]Container{}}
	a.daemonVersions(ctx, rec, statuses)

	if calls != 3 {
		t.Fatalf("recreated container not asked: %d execs", calls)
	}
}

func TestVersionsOnlyForAdmittedDocumentsAndBounded(t *testing.T) {
	n, tc := testNode(t)
	ctx := context.Background()

	st := &state.State{FSID: testFSID}
	mon := daemons.Mon(daemons.Params{Name: st.DocName(state.Daemon{Type: state.TypeMon, ID: "h1"}), Image: testImage, FSID: testFSID, ID: "h1", Addr: "10.5.0.2", Mode: "join", Addrv: daemons.MonAddrv("10.5.0.2"), Keyring: daemons.MonKeyring(fakeKey)})

	// a document that steers the ceph CLI is never queried
	steered := daemons.Mon(daemons.Params{Name: mon.MetaName, Image: testImage, FSID: testFSID, ID: "h1", Addr: "10.5.0.2", Mode: "join", Addrv: daemons.MonAddrv("10.5.0.2"), Keyring: daemons.MonKeyring(fakeKey)})
	steered.ContainerEnvironment = append(steered.ContainerEnvironment, "CEPH_ARGS=--admin-daemon=/tmp/other.asok")
	must(t, tc.Patch(ctx, "", yamlOf(t, steered)))

	calls := 0
	a := &Agent{Talos: tc, Node: n, Exec: func(context.Context, string, []string, io.Writer, io.Writer) (int, error) {
		calls++

		return 1, nil // no socket yet
	}}

	statuses := map[string]containers.ContainerStatusSpec{mon.MetaName: {State: containers.ContainerStateRunning, Generation: 1}}

	a.daemonVersions(ctx, &Record{Containers: map[string]Container{}}, statuses)

	if calls != 0 {
		t.Fatalf("queried a document outside the policy: %d execs", calls)
	}

	// an admitted one is asked at most versionAttempts times per instance
	must(t, tc.Patch(ctx, "", []byte("apiVersion: v1alpha1\nkind: ContainerConfig\nname: "+mon.MetaName+"\n$patch: delete\n"), yamlOf(t, mon)))

	for range 10 {
		a.daemonVersions(ctx, &Record{Containers: map[string]Container{}}, statuses)
	}

	if calls != versionAttempts {
		t.Fatalf("%d execs for one instance without an answer", calls)
	}

	statuses[mon.MetaName] = containers.ContainerStatusSpec{State: containers.ContainerStateRunning, Generation: 1, RestartCount: 1}
	a.daemonVersions(ctx, &Record{Containers: map[string]Container{}}, statuses)

	if calls != versionAttempts+1 {
		t.Fatalf("a restarted instance was not asked: %d execs", calls)
	}
}

func TestVersionsKeepAttemptsWhenTheRefreshRunsOut(t *testing.T) {
	n, tc := testNode(t)

	st := &state.State{FSID: testFSID}
	mon := daemons.Mon(daemons.Params{Name: st.DocName(state.Daemon{Type: state.TypeMon, ID: "h1"}), Image: testImage, FSID: testFSID, ID: "h1", Addr: "10.5.0.2", Mode: "join", Addrv: daemons.MonAddrv("10.5.0.2"), Keyring: daemons.MonKeyring(fakeKey)})
	must(t, tc.Patch(context.Background(), "", yamlOf(t, mon)))

	calls := 0
	a := &Agent{Talos: tc, Node: n, Exec: func(context.Context, string, []string, io.Writer, io.Writer) (int, error) {
		calls++

		return 1, nil
	}}

	statuses := map[string]containers.ContainerStatusSpec{mon.MetaName: {State: containers.ContainerStateRunning, Generation: 1}}

	// the config is read with a live context; the deadline passes before the query
	a.daemonVersions(context.Background(), &Record{Containers: map[string]Container{}}, statuses)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	a.daemonVersions(ctx, &Record{Containers: map[string]Container{}}, statuses)

	if calls != 1 || a.versions[mon.MetaName].attempts != 1 {
		t.Fatalf("%d execs, %+v", calls, a.versions[mon.MetaName])
	}
}
