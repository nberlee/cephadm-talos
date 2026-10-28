//go:build integration

// Package integration runs cephadm-talos against a live Talos QEMU cluster.
//
//	CEPHADM_TALOS_TALOSCONFIG  talosconfig of the cluster (required)
//	CEPHADM_TALOS_NODES        comma-separated node IPs, at least 3 (required)
//	CEPHADM_TALOS_DEVICE       spare disk on every node for an OSD (default /dev/sda)
//	CEPHADM_TALOS_IMAGE        supported Ceph image (default quay.io/ceph/ceph:v20.2.4)
//	CEPHADM_TALOS_OLD_IMAGE    an unsupported Ceph image for the gate test (default quay.io/ceph/ceph:v20.2.3)
//	CEPHADM_TALOS_AGENT_IMAGE  the agent image, pinned by digest (required; hack/agent-image.sh)
//
// The upgrade tests need two images of the supported release that differ only
// in a label, in a registry every node can reach, plus a mutable tag in it
// (see hack/fixtures.sh); without them they are skipped:
//
//	CEPHADM_TALOS_FIXTURE_A, CEPHADM_TALOS_FIXTURE_B   digest references
//	CEPHADM_TALOS_FIXTURE_TAG                          a tag the test moves with crane
//
// The cluster must be empty: the suite bootstraps, exercises and removes a Ceph
// cluster (rm-cluster --zap wipes the device on every node).
//
//	go test -tags integration -timeout 3h -v ./internal/integration/
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

type env struct {
	bin, home, talosconfig string
	nodes                  []string
	device                 string
	tc                     *talos.Client
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}

	return def
}

func setup(t *testing.T) *env {
	t.Helper()

	e := &env{
		talosconfig: os.Getenv("CEPHADM_TALOS_TALOSCONFIG"),
		nodes:       strings.Split(os.Getenv("CEPHADM_TALOS_NODES"), ","),
		device:      getenv("CEPHADM_TALOS_DEVICE", "/dev/sda"),
		home:        t.TempDir(),
	}

	if e.talosconfig == "" || len(e.nodes) < 3 {
		t.Skip("set CEPHADM_TALOS_TALOSCONFIG and CEPHADM_TALOS_NODES (3 nodes)")
	}

	e.bin = filepath.Join(t.TempDir(), "cephadm-talos")

	build := exec.Command("go", "build", "-o", e.bin, "../../cmd/cephadm-talos")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	t.Setenv("CEPHADM_TALOS_HOME", e.home)

	e.tc = &talos.Client{Default: talos.Conn{Talosconfig: e.talosconfig}}
	t.Cleanup(func() { e.tc.Close() }) //nolint:errcheck

	return e
}

// run runs the CLI and returns its combined output.
func (e *env) run(t *testing.T, args ...string) (string, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, e.bin, append([]string{"--talosconfig", e.talosconfig}, args...)...)

	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out

	err := cmd.Run()
	t.Logf("$ cephadm-talos %s\n%s", strings.Join(args, " "), out.String())

	return out.String(), err
}

func (e *env) ok(t *testing.T, args ...string) string {
	t.Helper()

	out, err := e.run(t, args...)
	if err != nil {
		t.Fatalf("cephadm-talos %s: %v", strings.Join(args, " "), err)
	}

	return out
}

func (e *env) state(t *testing.T) *state.State {
	t.Helper()

	st, err := state.Load("")
	if err != nil {
		t.Fatal(err)
	}

	return st
}

// containers returns the ContainerConfig names on a node that start with prefix.
func (e *env) containers(t *testing.T, node, prefix string) []string {
	t.Helper()

	st, err := e.tc.ContainerStatuses(context.Background(), node)
	if err != nil {
		t.Fatal(err)
	}

	var out []string

	for name := range st {
		if strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}

	return out
}

func TestCluster(t *testing.T) {
	e := setup(t)
	n1, n2, n3 := e.nodes[0], e.nodes[1], e.nodes[2]

	image := getenv("CEPHADM_TALOS_IMAGE", "quay.io/ceph/ceph:v20.2.4")

	agentImage := os.Getenv("CEPHADM_TALOS_AGENT_IMAGE")
	if agentImage == "" {
		t.Skip("set CEPHADM_TALOS_AGENT_IMAGE (hack/agent-image.sh)")
	}
	fixA, fixB, fixTag := os.Getenv("CEPHADM_TALOS_FIXTURE_A"), os.Getenv("CEPHADM_TALOS_FIXTURE_B"), os.Getenv("CEPHADM_TALOS_FIXTURE_TAG")

	if fixA != "" {
		image = fixA
	}

	for _, n := range e.nodes {
		if left := e.containers(t, n, "ceph-"); len(left) > 0 {
			t.Fatalf("node %s is not empty: %v", n, left)
		}
	}

	t.Run("dry-run stays offline", func(t *testing.T) {
		out := e.ok(t, "--dry-run", "bootstrap", "--mon-node", n1, "--image", image, "--agent-image", agentImage)
		if !strings.Contains(out, "# pull "+image) {
			t.Errorf("dry-run does not show the planned pull")
		}

		if _, err := os.Stat(filepath.Join(e.home, "current")); err == nil {
			t.Errorf("dry-run wrote state")
		}

		if left := e.containers(t, n1, "ceph-"); len(left) > 0 {
			t.Errorf("dry-run created containers: %v", left)
		}
	})

	t.Run("unsupported image refused", func(t *testing.T) {
		out, err := e.run(t, "bootstrap", "--mon-node", n1, "--image", getenv("CEPHADM_TALOS_OLD_IMAGE", "quay.io/ceph/ceph:v20.2.3"), "--agent-image", agentImage)
		if err == nil || !strings.Contains(out, "supports only Ceph") {
			t.Fatalf("want a version gate error, got %v", err)
		}

		if left := e.containers(t, n1, "ceph-"); len(left) > 0 {
			t.Errorf("refused bootstrap left containers: %v", left)
		}
	})

	if t.Failed() {
		t.FailNow()
	}

	t.Run("bootstrap", func(t *testing.T) {
		e.ok(t, "bootstrap", "--mon-node", n1, "--image", image, "--agent-image", agentImage)

		st := e.state(t)
		if !strings.Contains(st.Image, "@sha256:") || st.CephVersion == "" || st.Arch != "x86_64" {
			t.Errorf("image not pinned and probed: %q %q %q", st.Image, st.CephVersion, st.Arch)
		}
	})

	if t.Failed() {
		t.FailNow()
	}

	t.Run("deploy", func(t *testing.T) {
		e.ok(t, "host", "add", n2)
		e.ok(t, "host", "add", n3)
		e.ok(t, "deploy", "mon", n2)
		e.ok(t, "deploy", "mon", n3)
		e.ok(t, "deploy", "mgr", n2)

		for _, n := range e.nodes {
			e.ok(t, "deploy", "osd", n, e.device)
		}

		out := e.ok(t, "shell", "--", "ceph", "-s")
		if !strings.Contains(out, "3 osds: 3 up") {
			t.Errorf("not all OSDs up")
		}
	})

	if t.Failed() {
		t.FailNow()
	}

	t.Run("orch read path", func(t *testing.T) {
		cluster := e.state(t)

		var st struct {
			Available  bool   `json:"available"`
			Backend    string `json:"backend"`
			Revision   int    `json:"inventory_revision"`
			CertExpiry string `json:"agent_cert_expiry"`
		}

		e.cephJSON(t, &st, "orch", "status")

		if !st.Available || st.Backend != "cephadm" || st.Revision != cluster.Published.Revision {
			t.Errorf("orch status %+v, want revision %d", st, cluster.Published.Revision)
		}

		// the earliest of the mgr's and the agents' certificates
		want, _ := pki.NotAfter(cluster.Agent.MgrCert)
		for _, h := range cluster.Hosts {
			if na, err := pki.NotAfter(h.AgentCert); err == nil && na.Before(want) {
				want = na
			}
		}

		if got, err := time.Parse(time.RFC3339, st.CertExpiry); err != nil || !got.Equal(want.UTC().Truncate(time.Second)) {
			t.Errorf("agent_cert_expiry %q, want %s", st.CertExpiry, want.UTC().Format(time.RFC3339))
		}

		var hosts []struct {
			Hostname string `json:"hostname"`
			Addr     string `json:"addr"`
		}

		e.cephJSON(t, &hosts, "orch", "host", "ls")

		gotHosts := map[string]string{}
		for _, h := range hosts {
			gotHosts[h.Hostname] = h.Addr
		}

		for _, h := range cluster.Hosts {
			if gotHosts[h.Name] != h.Addr {
				t.Errorf("orch host ls: %s at %q, want %s", h.Name, gotHosts[h.Name], h.Addr)
			}
		}

		if len(hosts) != len(cluster.Hosts) {
			t.Errorf("orch host ls lists %d hosts, want %d", len(hosts), len(cluster.Hosts))
		}

		// every inventory daemon, running, with the digest Talos runs
		e.waitDaemons(t, func(ds []daemon) bool { return allRunning(ds, "") && len(ds) == len(cluster.Daemons) })

		var ds []daemon
		e.cephJSON(t, &ds, "orch", "ps")

		byName := map[string]daemon{}
		for _, d := range ds {
			byName[d.Name] = d
		}

		for _, d := range cluster.Daemons {
			h, _ := cluster.Host(d.Host)
			name := d.Type + "." + d.ID

			if d.OSDID != nil {
				name = "osd." + strconv.Itoa(*d.OSDID)
			}

			got, ok := byName[name]
			if !ok || got.Hostname != h.Name {
				t.Errorf("orch ps: %s missing or on the wrong host (%+v)", name, got)

				continue
			}

			statuses, err := e.tc.ContainerStatuses(context.Background(), h.Addr)
			if err != nil {
				t.Fatal(err)
			}

			if s := statuses[cluster.DocName(d)]; len(got.Digests) != 1 || got.Digests[0] != s.Image {
				t.Errorf("orch ps: %s digest %v, Talos runs %s", name, got.Digests, s.Image)
			}
		}

		out, err := e.run(t, "shell", "--", "ceph", "orch", "apply", "mon", "3")
		if err == nil || !strings.Contains(out, "does not support") {
			t.Errorf("orch apply was not refused as unsupported: %v", err)
		}
	})

	t.Run("agent requires a client certificate", func(t *testing.T) {
		conn, err := tls.Dial("tcp", net.JoinHostPort(n1, "4721"), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}) //nolint:gosec // only the agent's side is checked
		if err == nil {
			// TLS 1.3 reports a missing client certificate on the first read
			_, err = conn.Read(make([]byte, 1))
			conn.Close() //nolint:errcheck
		}

		if err == nil {
			t.Error("agent answered a client without a certificate")
		}
	})

	t.Run("agent restart and mgr failover", func(t *testing.T) {
		st := e.state(t)
		h2, _ := st.Host(n2)

		if err := e.tc.Restart(context.Background(), n2, st.DocName(state.Daemon{Type: "agent", ID: h2.Name})); err != nil {
			t.Fatal(err)
		}

		e.ok(t, "shell", "--", "ceph", "mgr", "fail")
		e.waitDaemons(t, func(ds []daemon) bool { return allRunning(ds, "") })
	})

	t.Run("agent gone and back", func(t *testing.T) {
		st := e.state(t)
		h2, _ := st.Host(n2)
		agentDoc := st.DocName(state.Daemon{Type: "agent", ID: h2.Name})

		del, err := spec.Render(spec.Delete("ContainerConfig", agentDoc))
		if err != nil {
			t.Fatal(err)
		}

		if err := e.tc.Patch(context.Background(), n2, del); err != nil {
			t.Fatal(err)
		}

		e.waitDaemons(t, func(ds []daemon) bool { return allStatus(ds, h2.Name, statusUnknown) })

		// host add redeploys the host's documents, the agent with them
		e.ok(t, "host", "add", n2)
		e.waitDaemons(t, func(ds []daemon) bool { return allRunning(ds, "") })
	})

	t.Run("jobs", func(t *testing.T) {
		// the command's exit status is the CLI's, with its output
		out, err := e.run(t, "shell", "--", "sh", "-c", "echo job-output; exit 3")

		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || !strings.Contains(out, "job-output") {
			t.Errorf("nonzero exit: want exit status 3 with the output, got %v", err)
		}

		// a job that runs into its timeout is cleaned up all the same
		out, err = e.run(t, "shell", "--timeout", "45s", "--", "sleep", "600")
		if err == nil || !strings.Contains(out, "timed out waiting for job") {
			t.Errorf("want a job timeout, got %v", err)
		}

		// a cancelled CLI (ctrl-c) cleans up its job too
		cmd := exec.Command(e.bin, "--talosconfig", e.talosconfig, "shell", "--host", n1, "--timeout", "30m", "--", "sleep", "3600")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}

		prefix := "ceph-" + e.state(t).Short() + "-job-"
		deadline := time.Now().Add(3 * time.Minute)

		for len(e.running(t, n1, prefix)) == 0 {
			if time.Now().After(deadline) {
				_ = cmd.Process.Kill()

				t.Fatal("the job never started")
			}

			time.Sleep(time.Second)
		}

		if err := cmd.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()

		select {
		case err := <-done:
			if err == nil {
				t.Error("cancelled shell exited 0")
			}
		case <-time.After(7 * time.Minute): // cleanup is bounded at 6 minutes, far below the job timeout
			_ = cmd.Process.Kill()

			t.Fatal("cancelled shell did not exit")
		}

		e.noJobsLeft(t)
	})

	t.Run("host reboot", func(t *testing.T) {
		st := e.state(t)
		h, _ := st.Host(n3)

		before, err := e.tc.BootID(context.Background(), n3)
		if err != nil {
			t.Fatal(err)
		}

		e.ok(t, "host", "reboot", h.Name)

		if after, err := e.tc.BootID(context.Background(), n3); err != nil || after == before {
			t.Errorf("node did not reboot: boot id %q, was %q (%v)", after, before, err)
		}

		out := e.ok(t, "shell", "--", "ceph", "-s")
		if !strings.Contains(out, "3 osds: 3 up") {
			t.Errorf("not all OSDs up after the reboot")
		}

		e.waitDaemons(t, func(ds []daemon) bool { return allRunning(ds, h.Name) })
	})

	t.Run("data", func(t *testing.T) {
		out := e.ok(t, "shell", "--", "sh", "-c",
			"ceph osd pool create itest 8 >/dev/null 2>&1; head -c 4194304 /dev/urandom > /tmp/in && rados -p itest put obj /tmp/in && rados -p itest get obj /tmp/out && md5sum /tmp/in /tmp/out")
		sums := strings.Fields(out)
		if len(sums) < 4 || sums[0] != sums[2] {
			t.Errorf("object read back differs: %q", out)
		}
	})

	t.Run("rm and redeploy a mon", func(t *testing.T) {
		h, _ := e.state(t).Host(n3)

		e.ok(t, "rm", "mon."+h.Name)
		e.ok(t, "deploy", "mon", n3)

		out := e.ok(t, "shell", "--", "ceph", "quorum_status")
		if !strings.Contains(out, h.Name) {
			t.Errorf("redeployed mon not in quorum")
		}
	})

	t.Run("rm --zap and redeploy an OSD", func(t *testing.T) {
		st := e.state(t)
		h, _ := st.Host(n3)

		var osd string

		for _, d := range st.DaemonsOf(state.TypeOSD, h.Name) {
			if d.OSDID != nil {
				osd = "osd." + strconv.Itoa(*d.OSDID)
			}
		}

		if osd == "" {
			t.Fatal("no OSD on the third node")
		}

		e.ok(t, "rm", "--force", "--zap", osd)

		// a label left on the device would make the new OSD refuse to start
		e.ok(t, "deploy", "osd", n3, e.device)

		out := e.ok(t, "shell", "--", "ceph", "-s")
		if !strings.Contains(out, "3 osds: 3 up") {
			t.Errorf("not all OSDs up after the redeploy")
		}
	})

	t.Run("rgw behind the vip", func(t *testing.T) {
		vip := getenv("CEPHADM_TALOS_VIP", "10.5.0.200/24")

		e.ok(t, "deploy", "rgw", n1)
		e.ok(t, "deploy", "rgw", n2)
		e.ok(t, "deploy", "vip", n1, "--vip", vip)
		e.ok(t, "deploy", "vip", n2)

		ip, _, _ := strings.Cut(vip, "/")

		out := e.ok(t, "shell", "--", "sh", "-c", "for i in $(seq 30); do curl -skf https://"+ip+"/ && exit 0; sleep 2; done; exit 1")
		if !strings.Contains(out, "ListAllMyBucketsResult") {
			t.Errorf("the VIP does not answer with S3")
		}
	})

	t.Run("upgrade between digests", func(t *testing.T) {
		if fixB == "" {
			t.Skip("set CEPHADM_TALOS_FIXTURE_A and _B (hack/fixtures.sh)")
		}

		before := e.instanceGens(t)

		e.ok(t, "upgrade", "--image", fixB)

		if st := e.state(t); st.Image != fixB {
			t.Errorf("state image %q, want %q", st.Image, fixB)
		}

		for name, gen := range e.instanceGens(t) {
			// keepalived runs its own image, an upgrade of Ceph leaves it alone
			if strings.Contains(name, "-vip-") {
				continue
			}

			if gen <= before[name] {
				t.Errorf("%s was not restarted (generation %d)", name, gen)
			}
		}
	})

	t.Run("same digest restarts nothing", func(t *testing.T) {
		if fixB == "" {
			t.Skip("set CEPHADM_TALOS_FIXTURE_A and _B (hack/fixtures.sh)")
		}

		before := e.instanceGens(t)

		e.ok(t, "upgrade", "--image", fixB)

		for name, gen := range e.instanceGens(t) {
			if gen != before[name] {
				t.Errorf("%s was restarted (generation %d, was %d)", name, gen, before[name])
			}
		}
	})

	t.Run("cached tag and refresh", func(t *testing.T) {
		if fixTag == "" || fixB == "" {
			t.Skip("set CEPHADM_TALOS_FIXTURE_A, _B and _TAG (hack/fixtures.sh)")
		}

		// --refresh first: a node may still cache the tag from an earlier run
		crane(t, "copy", "--insecure", fixA, fixTag)
		e.ok(t, "upgrade", "--image", fixTag, "--refresh")

		if st := e.state(t); st.Image != digestOf(fixTag, fixA) {
			t.Fatalf("tag resolved to %q, want the digest of A", st.Image)
		}

		crane(t, "copy", "--insecure", fixB, fixTag)

		before := e.instanceGens(t)
		e.ok(t, "upgrade", "--image", fixTag)

		if st := e.state(t); st.Image != digestOf(fixTag, fixA) {
			t.Errorf("cached tag re-resolved without --refresh: %q", st.Image)
		}

		for name, gen := range e.instanceGens(t) {
			if gen != before[name] {
				t.Errorf("%s was restarted by a same-digest upgrade", name)
			}
		}

		e.ok(t, "upgrade", "--image", fixTag, "--refresh")

		if st := e.state(t); st.Image != digestOf(fixTag, fixB) {
			t.Errorf("--refresh did not re-resolve the tag: %q", st.Image)
		}
	})

	t.Run("host rm and add", func(t *testing.T) {
		st := e.state(t)
		h3, _ := st.Host(n3)

		for _, d := range st.Daemons {
			if d.Host != h3.Name {
				continue
			}

			name := d.Type + "." + d.ID
			if d.OSDID != nil {
				name = "osd." + strconv.Itoa(*d.OSDID)
			}

			e.ok(t, "rm", "--force", "--zap", name)
		}

		agentDoc := st.DocName(state.Daemon{Type: "agent", ID: h3.Name})

		e.ok(t, "host", "rm", h3.Name)

		if left := e.containers(t, n3, agentDoc); len(left) > 0 {
			t.Errorf("agent left on the removed host: %v", left)
		}

		e.ok(t, "host", "add", n3)

		deadline := time.Now().Add(3 * time.Minute)
		for len(e.running(t, n3, agentDoc)) == 0 {
			if time.Now().After(deadline) {
				t.Fatal("agent not running after host add")
			}

			time.Sleep(3 * time.Second)
		}
	})

	t.Run("rm-cluster --zap", func(t *testing.T) {
		prefix := "ceph-" + e.state(t).Short() + "-"

		e.ok(t, "rm-cluster", "--zap", "--yes-i-really-mean-it")

		for _, n := range e.nodes {
			if left := e.containers(t, n, prefix); len(left) > 0 {
				t.Errorf("containers left on %s: %v", n, left)
			}
		}
	})
}

type daemon struct {
	Name     string   `json:"daemon_name"`
	Hostname string   `json:"hostname"`
	Status   int      `json:"status"` // orchestrator DaemonDescriptionStatus
	Desc     string   `json:"status_desc"`
	Digests  []string `json:"container_image_digests"`
}

// DaemonDescriptionStatus values (orchestrator/_interface.py).
const (
	statusRunning = 1
	statusUnknown = -2
)

// cephJSON runs a ceph command with --format json in a job and decodes it.
func (e *env) cephJSON(t *testing.T, v any, args ...string) {
	t.Helper()

	out := e.ok(t, append(append([]string{"shell", "--", "ceph"}, args...), "--format", "json")...)

	start := strings.IndexAny(out, "[{")
	if start < 0 || json.Unmarshal([]byte(out[start:]), v) != nil {
		t.Fatalf("ceph %s: not JSON: %s", strings.Join(args, " "), out)
	}
}

// waitDaemons polls `ceph orch ps --refresh` until ok or 4 minutes passed.
func (e *env) waitDaemons(t *testing.T, ok func([]daemon) bool) {
	t.Helper()

	var ds []daemon

	for deadline := time.Now().Add(4 * time.Minute); time.Now().Before(deadline); time.Sleep(5 * time.Second) {
		ds = nil
		e.cephJSON(t, &ds, "orch", "ps", "--refresh")

		if ok(ds) {
			return
		}
	}

	t.Fatalf("orch ps did not reach the expected state: %+v", ds)
}

func allRunning(ds []daemon, host string) bool { return allStatus(ds, host, statusRunning) }

// allStatus reports whether every daemon (of the host, if given) has the status.
func allStatus(ds []daemon, host string, status int) bool {
	n := 0

	for _, d := range ds {
		if host != "" && d.Hostname != host {
			continue
		}

		n++

		if d.Status != status {
			return false
		}
	}

	return n > 0
}

// running returns the containers with the prefix that are in state running.
func (e *env) running(t *testing.T, node, prefix string) []string {
	t.Helper()

	st, err := e.tc.ContainerStatuses(context.Background(), node)
	if err != nil {
		t.Fatal(err)
	}

	var out []string

	for name, s := range st {
		if strings.HasPrefix(name, prefix) && s.State == containers.ContainerStateRunning {
			out = append(out, name)
		}
	}

	return out
}

// noJobsLeft checks that no job container or instance is left on any node.
func (e *env) noJobsLeft(t *testing.T) {
	t.Helper()

	prefix := "ceph-" + e.state(t).Short() + "-job-"

	for _, n := range e.nodes {
		if left := e.containers(t, n, prefix); len(left) > 0 {
			t.Errorf("job containers left on %s: %v", n, left)
		}

		ids, err := e.tc.InstanceContainers(context.Background(), n)
		if err != nil {
			t.Fatal(err)
		}

		for _, id := range ids {
			if strings.HasPrefix(id, prefix) {
				t.Errorf("job instance left on %s: %s", n, id)
			}
		}
	}
}

// instanceGens returns the instance generation of every daemon container.
func (e *env) instanceGens(t *testing.T) map[string]uint64 {
	t.Helper()

	st := e.state(t)
	out := map[string]uint64{}

	for _, d := range st.Daemons {
		h, _ := st.Host(d.Host)

		g, err := e.tc.InstanceGeneration(context.Background(), h.Addr, st.DocName(d))
		if err != nil {
			t.Fatal(err)
		}

		out[st.DocName(d)] = g
	}

	return out
}

func crane(t *testing.T, args ...string) {
	t.Helper()

	if out, err := exec.Command("crane", args...).CombinedOutput(); err != nil {
		t.Fatalf("crane %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// digestOf returns tag's repository with the digest of ref, the form Talos reports.
func digestOf(tag, ref string) string {
	repo := tag
	if i := strings.LastIndex(tag, ":"); i > strings.LastIndex(tag, "/") {
		repo = tag[:i]
	}

	_, digest, _ := strings.Cut(ref, "@")

	return repo + "@" + digest
}
