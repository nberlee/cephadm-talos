package orch

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"gopkg.in/yaml.v3"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// JobCleanupError means a job document could not be removed from a node. It is
// never ignorable, unlike the failure of the job's command itself.
type JobCleanupError struct {
	Name string
	Err  error
}

func (e *JobCleanupError) Error() string {
	return fmt.Sprintf("job %s could not be removed, delete its ContainerConfig by hand before anything else: %v", e.Name, e.Err)
}

func (e *JobCleanupError) Unwrap() error { return e.Err }

// cleanupErr returns the job cleanup part of an error, if any.
func cleanupErr(err error) error {
	var ce *JobCleanupError
	if errors.As(err, &ce) {
		return ce
	}

	return nil
}

// forceable reports whether --force may ignore a job error: only when the
// command itself ran and failed. Apply errors, timeouts and cleanup failures
// leave it unknown whether the command ran, so they always count.
func forceable(res JobResult, err error) bool {
	return res.RC != 0 && cleanupErr(err) == nil
}

// JobResult is the output of an admin job.
type JobResult struct {
	Output string
	RC     int
}

// Job runs a shell command with the admin key in a running Ceph container on
// node, through Talos exec (plan 03, item 11), and returns its output (stdout
// and stderr together).
func (o *Orch) Job(ctx context.Context, node, cmd string, timeout time.Duration) (JobResult, error) {
	return o.jobInput(ctx, node, cmd, nil, timeout)
}

// jobInput is Job with input for the command's stdin.
func (o *Orch) jobInput(ctx context.Context, node, cmd string, input []byte, timeout time.Duration) (JobResult, error) {
	if o.Talos.DryRun {
		o.printf("# exec on %s: %s\n", node, cmd)

		return JobResult{}, nil
	}

	jctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var out syncBuffer

	rc, target, err := o.execAdmin(jctx, node, []string{"bash", "-c", cmd}, input, &out, &out)
	if err != nil {
		if jctx.Err() != nil && ctx.Err() == nil {
			return JobResult{}, fmt.Errorf("timed out running %q in %s", cmd, target)
		}

		return JobResult{}, err
	}

	res := JobResult{Output: out.String(), RC: rc}
	if rc != 0 {
		return res, fmt.Errorf("command %q failed with rc=%d:\n%s", cmd, rc, res.Output)
	}

	return res, nil
}

// execAdmin runs argv in a running Ceph container on node with the admin key.
// The key goes over stdin, as its first line, into the CEPH_ARGS environment of
// this exec only: it is in no file, no machine config and no process's
// arguments, and Talos audits only the command line. input follows the key on
// stdin, for the command itself.
func (o *Orch) execAdmin(ctx context.Context, node string, argv []string, input []byte, stdout, stderr io.Writer) (int, string, error) {
	k, err := o.key("client.admin")
	if err != nil {
		return 0, "", err
	}

	// nothing ran without a target: the caller may try another node
	targets, err := o.execTargets(ctx, node)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %w", talos.ErrExecNotStarted, err)
	}

	script := `IFS= read -r key || exit 70; export CEPH_ARGS="-n client.admin --key $key"; unset key; exec "$@"`

	// a container that stops while the exec is set up (a restarting mgr) runs
	// nothing: the next one runs the command
	for _, target := range targets {
		stdin := io.MultiReader(strings.NewReader(k+"\n"), bytes.NewReader(input))

		rc, err := o.Talos.Exec(ctx, node, target, append([]string{"bash", "-c", script, "cephadm-talos-exec"}, argv...), stdin, stdout, stderr)
		if errors.Is(err, talos.ErrExecNotStarted) && target != targets[len(targets)-1] {
			continue
		}

		return rc, target, err
	}

	return 0, "", fmt.Errorf("no running Ceph container on %s to run the command in", node)
}

// statusProbeTimeout bounds the container status query of an admin exec.
const statusProbeTimeout = 15 * time.Second

// execTargets are the running Ceph containers on node in the order admin
// commands try them: mgrs, mons, rgws, OSDs.
func (o *Orch) execTargets(ctx context.Context, node string) ([]string, error) {
	// a node that does not answer leaves time for the next one
	ctx, cancel := context.WithTimeout(ctx, statusProbeTimeout)
	defer cancel()

	st, err := o.Talos.ContainerStatuses(ctx, node)
	if err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("ceph-%s-", o.St.Short())

	var targets []string

	for _, typ := range []string{state.TypeMgr, state.TypeMon, state.TypeRGW, state.TypeOSD} {
		var names []string

		for name, s := range st {
			// a mgr's guard (mgr-guard-<host>) shares the mgr's prefix but has no
			// ceph.conf, keyring or host network: never a target
			if strings.HasPrefix(name, prefix+typ+"-") && !strings.HasPrefix(name, prefix+"mgr-guard-") && s.State == containers.ContainerStateRunning {
				names = append(names, name)
			}
		}

		sort.Strings(names)
		targets = append(targets, names...)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no running Ceph container on %s to run the command in", node)
	}

	return targets, nil
}

// syncBuffer collects stdout and stderr, which Talos writes concurrently.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.b.String()
}

// jobsHostDir is the jobs directory of the cephadm-talos volume on the host.
const jobsHostDir = "/var/mnt/" + spec.RecordsVolumeName + "/" + records.JobsDir

// maxJobResult bounds a job's result file and log.
const maxJobResult = 1 << 20

// runJob applies a `never` job document, waits until it finished, reads its
// result file (or, for a job without the records volume, its log) and removes
// the document again. The result file stays on the node as the job's replay
// record; the agent removes it once the outcome is acknowledged (plan 03, item 8).
func (o *Orch) runJob(ctx context.Context, node string, doc *spec.ContainerConfig, id string, timeout time.Duration) (res JobResult, err error) {
	return o.runJobKeep(ctx, node, doc, id, timeout, false)
}

// runJobKeep is runJob; with keep a job that has not ended (cancelled, timed
// out, or an apply whose outcome is unknown) is left running, for a retry
// under the same journaled id to wait for it again (plan 03, step 7 slice D):
// removing it would leave a job that started and can never finish.
func (o *Orch) runJobKeep(ctx context.Context, node string, doc *spec.ContainerConfig, id string, timeout time.Duration, keep bool) (res JobResult, err error) {
	name, cmd := doc.MetaName, jobEnv(doc, "CMD")

	// a script is named by its job, a one-line command by itself
	if strings.Contains(cmd, "\n") || len(cmd) > 200 {
		cmd = name
	}

	if o.Talos.DryRun {
		return JobResult{}, o.apply(ctx, node, doc)
	}

	ended := false

	// Always clean up, also on timeout, ctrl-c or an apply error (the client may
	// fail after Talos accepted the config). A `never` job left behind runs again
	// on the next boot, where its claim keeps it from repeating its work; a
	// document left behind is still an error of its own.
	defer func() {
		if keep && !ended {
			return
		}

		// cleanup outlives a cancelled or timed out job, but is bounded itself
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 6*time.Minute)
		defer cancel()

		cerr := o.remove(cctx, node, name)
		if cerr == nil {
			cerr = o.waitGone(cctx, node, name, 5*time.Minute)
		}

		if cerr != nil {
			err = errors.Join(err, &JobCleanupError{Name: name, Err: cerr})
		}
	}()

	// the timeout covers every call of the job itself
	jctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := o.apply(jctx, node, doc); err != nil {
		return JobResult{}, err
	}

	var st containers.ContainerStatusSpec

	if err := o.Talos.WaitFor(jctx, node, talos.InstanceTypes, timeout, func(ctx context.Context) (bool, error) {
		all, err := o.Talos.ContainerStatuses(ctx, node)
		if err != nil {
			// a transient failure is retried; only a permanent one ends the wait
			return false, talos.Permanent(err)
		}

		s, ok := all[name]
		st = s

		return ok && (s.State == containers.ContainerStateCompleted || s.State == containers.ContainerStateFailed), nil
	}); err != nil {
		if ctx.Err() == nil {
			return JobResult{}, fmt.Errorf("job %s (%q) did not finish: %w", name, cmd, err)
		}

		return JobResult{}, err
	}

	ended = true

	if !usesRecords(doc) {
		out, err := o.Talos.Logs(jctx, node, name)
		if err != nil {
			return JobResult{}, err
		}

		res := JobResult{Output: out, RC: int(st.ExitCode)}
		if st.State == containers.ContainerStateFailed {
			return res, fmt.Errorf("job %s failed: %s", name, st.Error)
		}

		return res, nil
	}

	b, rerr := o.Talos.ReadFile(jctx, node, jobsHostDir+"/"+o.St.FSID+"."+id+".result", maxJobResult)
	if rerr != nil {
		// no result: refused (other inputs, uncertain) or failed before running
		return JobResult{RC: int(st.ExitCode)}, fmt.Errorf("job %s (%q) %w (%s, exit %d): %s", name, cmd, errNoJobResult, st.State, st.ExitCode, st.Error)
	}

	res, inputs, err := parseJobResult(b)
	if err != nil {
		return JobResult{}, fmt.Errorf("job %s: %w", name, err)
	}

	if want := jobEnv(doc, "JOB_INPUTS"); inputs != want {
		return JobResult{}, fmt.Errorf("job %s: the result is for other inputs (%s, want %s)", name, inputs, want)
	}

	// a job that wrote its result exits with its command's code, or 0 when it
	// replays an earlier result; any other failure (e.g. 70: the result could
	// not be made durable) means the result is not to be trusted
	if st.State == containers.ContainerStateFailed && int(st.ExitCode) != res.RC {
		return JobResult{}, fmt.Errorf("job %s ended with exit %d after writing a result with rc %d: %s", name, st.ExitCode, res.RC, st.Error)
	}

	if res.RC != 0 {
		return res, fmt.Errorf("command %q failed with rc=%d:\n%s", cmd, res.RC, res.Output)
	}

	return res, nil
}

// usesRecords reports whether a job document mounts the records volume, i.e.
// writes a result file.
func usesRecords(doc *spec.ContainerConfig) bool {
	for _, m := range doc.MountsConfig {
		if m.VolumeMount != nil && m.VolumeMount.VolumeName == spec.RecordsVolumeName {
			return true
		}
	}

	return false
}

// parseJobResult reads a job's result file: "rc <n>", "inputs <hash>", then its output.
func parseJobResult(b []byte) (JobResult, string, error) {
	head, rest, _ := strings.Cut(string(b), "\n")
	in, out, _ := strings.Cut(rest, "\n")

	var rc int
	if _, err := fmt.Sscanf(head, "rc %d", &rc); err != nil {
		return JobResult{}, "", fmt.Errorf("malformed result %q", head)
	}

	inputs, ok := strings.CutPrefix(in, "inputs ")
	if !ok || inputs == "" {
		return JobResult{}, "", fmt.Errorf("result without inputs: %q", in)
	}

	return JobResult{Output: out, RC: rc}, inputs, nil
}

// jobEnv returns a job document's environment variable.
func jobEnv(doc *spec.ContainerConfig, key string) string {
	for _, e := range doc.ContainerEnvironment {
		if v, ok := strings.CutPrefix(e, key+"="); ok {
			return v
		}
	}

	return ""
}

// jobInputs identifies what a job does, so the same id with other inputs is refused.
func jobInputs(parts ...string) string { return render.JobInputs(parts...) }

// Shell runs a ceph command (or any shell command) as an admin job and prints the output.
func (o *Orch) Shell(ctx context.Context, host string, cmd []string, timeout time.Duration) (int, error) {
	return o.ShellInput(ctx, host, cmd, nil, timeout)
}

// ShellInput is Shell with input for the command's stdin, after the admin key
// on the exec's stdin (a spec with a private key never goes on a command line).
func (o *Orch) ShellInput(ctx context.Context, host string, cmd []string, input []byte, timeout time.Duration) (int, error) {
	var h state.Host

	if host != "" {
		// an explicit host is used as is, also when it is in maintenance (diagnostics, recovery)
		var ok bool
		if h, ok = o.St.Host(host); !ok {
			return 1, fmt.Errorf("unknown host %q", host)
		}
	} else if !o.opened {
		// without the cluster state (no mon answers, or recovery): any node
		// with a running mgr or mon container of the cluster (plan 03, step 7
		// slice D, item 8)
		rec, err := state.LoadRecovery(o.St.FSID)
		if err != nil {
			return 1, err
		}

		if h, err = o.offlineExecHost(ctx, rec); err != nil {
			return 1, err
		}
	} else {
		var err error
		if h, err = o.adminHost(); err != nil {
			return 1, err
		}
	}

	res, err := o.jobInput(ctx, h.Addr, shellJoin(cmd), input, timeout)
	fmt.Fprint(o.Out, res.Output)

	// a failing command is reported through its exit code; a leftover job never is
	if err != nil && res.RC != 0 && cleanupErr(err) == nil {
		return res.RC, nil
	}

	return res.RC, err
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// shellJoin quotes argv for bash -c.
func shellJoin(args []string) string {
	if len(args) == 1 {
		// a single argument is taken as a shell snippet, e.g. "ceph -s; ceph osd tree"
		return args[0]
	}

	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shellQuote(a)
	}

	return strings.Join(q, " ")
}

// PS lists all daemons with their Talos container status, like `cephadm ls` / `ceph orch ps`.
func (o *Orch) PS(ctx context.Context, w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tHOST\tSTATE\tRESTARTS\tIMAGE\tCONTAINER")

	known := map[string]bool{}

	for _, h := range o.St.Hosts {
		st, err := o.Talos.ContainerStatuses(ctx, h.Addr)
		if err != nil {
			fmt.Fprintf(tw, "?\t%s\terror: %v\t\t\t\n", h.Name, err)

			continue
		}

		for _, d := range o.St.Daemons {
			if d.Host != h.Name {
				continue
			}

			name := o.St.DocName(d)
			known[h.Name+"/"+name] = true

			s, ok := st[name]
			stateStr, image, restarts := "missing", "", ""

			if h.Maintenance && !ok {
				stateStr = "stopped (maintenance)"
			}

			if ok {
				stateStr, image, restarts = s.State.String(), s.Image, fmt.Sprint(s.RestartCount)

				if s.Error != "" {
					stateStr += " (" + s.Error + ")"
				}

				if len(s.WaitingFor) > 0 {
					stateStr += " waiting for " + strings.Join(s.WaitingFor, ",")
				}
			}

			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", displayName(d), h.Name, stateStr, restarts, image, name)
		}

		if o.St.Agent != nil {
			name := o.agentDocName(h)
			known[h.Name+"/"+name] = true

			stateStr := "missing"
			if s, ok := st[name]; ok {
				stateStr = s.State.String()
				fmt.Fprintf(tw, "agent.%s\t%s\t%s\t%d\t%s\t%s\n", h.Name, h.Name, stateStr, s.RestartCount, s.Image, name)
			} else {
				fmt.Fprintf(tw, "agent.%s\t%s\t%s\t-\t-\t%s\n", h.Name, h.Name, stateStr, name)
			}
		}

		// containers of this cluster Talos runs but the inventory does not know (e.g. leftover jobs)
		var stray []string

		for name := range st {
			if strings.HasPrefix(name, "ceph-"+o.St.Short()+"-") && !known[h.Name+"/"+name] {
				stray = append(stray, name)
			}
		}

		sort.Strings(stray)

		for _, name := range stray {
			s := st[name]
			fmt.Fprintf(tw, "-\t%s\t%s (not in inventory)\t%d\t%s\t%s\n", h.Name, s.State, s.RestartCount, s.Image, name)
		}
	}

	if err := tw.Flush(); err != nil {
		return err
	}

	// the agents' jobs whose outcome is not known (plan 04, step 4)
	o.psUnresolved(ctx, w)

	return nil
}

func displayName(d state.Daemon) string {
	if d.Type == state.TypeOSD && d.OSDID != nil {
		return fmt.Sprintf("osd.%d", *d.OSDID)
	}

	return d.Type + "." + d.ID
}

func (o *Orch) lookup(name string) (state.Daemon, state.Host, error) {
	d, ok := o.St.Find(name)
	if !ok {
		return d, state.Host{}, fmt.Errorf("unknown daemon %q (see `cephadm-talos ps`)", name)
	}

	h, ok := o.St.Host(d.Host)
	if !ok {
		return d, h, fmt.Errorf("host %s of %s not in inventory", d.Host, name)
	}

	return d, h, nil
}

// Logs prints (or follows) the log of a daemon.
func (o *Orch) Logs(ctx context.Context, name string, follow bool) error {
	d, h, err := o.lookup(name)
	if err != nil {
		return err
	}

	if follow {
		return o.Talos.FollowLogs(ctx, h.Addr, o.St.DocName(d), o.Out)
	}

	logs, err := o.Talos.Logs(ctx, h.Addr, o.St.DocName(d))
	fmt.Fprint(o.Out, logs)

	return err
}

// Restart restarts a daemon container.
func (o *Orch) Restart(ctx context.Context, name string) error {
	d, h, err := o.lookup(name)
	if err != nil {
		return err
	}

	return o.Talos.Restart(ctx, h.Addr, o.St.DocName(d))
}

// Remove stops a daemon and removes it from the cluster, like `ceph orch daemon rm`.
//
// The inventory entry is only dropped once every step succeeded, so a failed
// removal can simply be re-run; each step is idempotent.
func (o *Orch) Remove(ctx context.Context, name string, force, zap bool) error {
	d, h, err := o.lookup(name)
	if err != nil {
		return err
	}

	adm, err := o.confirmedAdminHost()
	// without a reachable mon, only a forced local teardown is possible: no cluster-side
	// step runs, e.g. a mon is not removed from the monmap and an OSD is not purged
	local := err != nil
	if local && !force {
		return fmt.Errorf("no mon host available to run the cluster-side steps (use --force to only stop %s): %w", name, err)
	}

	if local {
		if zap {
			return fmt.Errorf("refusing --zap without a reachable mon: the OSD could not be purged first")
		}

		o.printf("warning: no mon available, only stopping %s; its cluster-side cleanup stays pending, re-run `cephadm-talos rm %s` later\n", name, name)
	}

	if d.Type == state.TypeMon && len(o.St.DaemonsOf(state.TypeMon, "")) == 1 && !force {
		return fmt.Errorf("refusing to remove the last mon (use --force)")
	}

	if d.Type == state.TypeOSD {
		// a prepare job of this deployment left behind (an interrupted deploy) must
		// be gone before its result is read, the device zapped or the deployment forgotten
		if d.DeployID != "" {
			if err := o.remove(ctx, h.Addr, o.osdPrepareDocName(d)); err != nil {
				return err
			}

			if err := o.waitGone(ctx, h.Addr, o.osdPrepareDocName(d), 5*time.Minute); err != nil {
				return err
			}
		}

		if err := o.ensureOSDID(ctx, &d, h, force, zap); err != nil {
			return err
		}
	}

	// cluster-side steps while the daemon still runs
	switch {
	case local:
	case d.Type == state.TypeMon:
		// a mon has to leave the monmap while there is still a quorum to commit it:
		// stopping it first can leave e.g. 1 of 2 mons running, which has no majority
		o.printf("removing mon.%s from the monmap\n", d.ID)

		// ok-to-rm checks quorum against the resulting monmap: with one mon down,
		// removing another could leave a map whose majority can't be reached
		cmd := "ceph mon ok-to-rm " + shellQuote(d.ID) + " && ceph mon remove " + shellQuote(d.ID)
		if force {
			cmd = "ceph mon remove " + shellQuote(d.ID)
		}

		if res, err := o.Job(ctx, adm.Addr, cmd, 5*time.Minute); err != nil && !(force && forceable(res, err)) {
			return err
		}
	case d.Type == state.TypeOSD && d.OSDID != nil && !d.Purged:
		id := *d.OSDID
		o.printf("marking osd.%d out\n", id)

		if res, err := o.Job(ctx, adm.Addr, osdIfExists(id, d.OSDUUID, "ceph osd out %d"), 5*time.Minute); err != nil && !(force && forceable(res, err)) {
			return err
		}

		if !force {
			// cephadm waits for the PGs to drain; we only check it is safe right now
			if _, err := o.Job(ctx, adm.Addr, osdIfExists(id, d.OSDUUID, "ceph osd safe-to-destroy %d"), 5*time.Minute); err != nil {
				return fmt.Errorf("osd.%d is not safe to destroy yet (data still migrating?), retry later or use --force: %w", id, err)
			}
		}
	}

	o.printf("stopping %s on %s\n", displayName(d), h.Name)

	if err := o.removeDoc(ctx, h, d); err != nil {
		return err
	}

	// applying the config does not wait for the container to go away
	if err := o.waitGone(ctx, h.Addr, o.St.DocName(d), 5*time.Minute); err != nil {
		return err
	}

	// cluster-side cleanup once the daemon is stopped
	var cleanup string

	switch d.Type {
	case state.TypeRGW:
		cleanup = "ceph auth rm client.rgw." + d.ID
	case state.TypeMgr:
		cleanup = "ceph auth rm mgr." + d.ID
	case state.TypeOSD:
		if d.OSDID != nil && !d.Purged {
			// purge needs the OSD down; it is stopped, so mark it down instead of waiting for the grace period
			cleanup = osdIfExists(*d.OSDID, d.OSDUUID, "ceph osd down %[1]d && ceph osd purge %[1]d --yes-i-really-mean-it")
		}
	}

	if cleanup != "" && !local {
		if _, err := o.Job(ctx, adm.Addr, cleanup, 5*time.Minute); err != nil {
			return fmt.Errorf("%s stopped, but cluster cleanup failed; re-run `cephadm-talos rm %s`: %w", displayName(d), name, err)
		}

		if d.Type == state.TypeOSD {
			d.Purged = true
			o.St.AddDaemon(d)

			if err := o.save(); err != nil {
				return err
			}
		}
	}

	if local {
		d.LocalOnly = true
		o.St.AddDaemon(d)

		return o.save()
	}

	if d.Type == state.TypeOSD && zap {
		o.printf("wiping %s on %s\n", d.Device, h.Name)

		// ceph-volume zap, not `talosctl wipe disk`: bluestore keeps label copies
		// at 1G/10G/100G/1000G that a FAST wipe of the disk start leaves behind
		if err := o.zap(ctx, h, d.OSDDevice(), d.DiskSerial, randHex(3)); err != nil {
			return fmt.Errorf("osd removed, but wiping %s failed; re-run `cephadm-talos rm --zap %s`: %w", d.Device, name, err)
		}
	}

	o.St.RemoveDaemon(d)

	if err := o.save(); err != nil {
		return err
	}

	if d.Type == state.TypeMon {
		return o.pushConf(ctx)
	}

	// the remaining keepalived instances drop it from their unicast peers
	if d.Type == state.TypeVIP {
		return o.applyRGWAndVIP(ctx, "")
	}

	return nil
}

// removeDoc deletes a daemon's document. An RGW's host keepalived depends on
// it, and Talos refuses a config that names a missing container: that
// keepalived is rendered without the dependency in the same apply.
func (o *Orch) removeDoc(ctx context.Context, h state.Host, d state.Daemon) error {
	var vips []any

	if d.Type == state.TypeRGW {
		// only a keepalived the node has: one stopped for maintenance stays stopped
		configured, err := o.configuredContainers(ctx, h.Addr, "ceph-"+o.St.Short()+"-")
		if err != nil {
			return err
		}

		without := *o.St
		without.Daemons = slices.DeleteFunc(slices.Clone(o.St.Daemons), func(x state.Daemon) bool { return x.Type == d.Type && x.ID == d.ID })

		for _, v := range without.DaemonsOf(state.TypeVIP, h.Name) {
			if v.LocalOnly || v.Purged || !slices.Contains(configured, o.St.DocName(v)) {
				continue
			}

			doc, err := render.Daemon(&without, h, v, o.St.Image, o.key, o.secret)
			if err != nil {
				return err
			}

			vips = append(vips, doc)
		}
	}

	// a mgr's guard names it: removed in the same apply (plan 04, step 5, item 2b)
	if d.Type == state.TypeMgr {
		return o.apply(ctx, h.Addr, spec.Delete("ContainerConfig", render.MgrGuardName(o.St, d)), spec.Delete("ContainerConfig", o.St.DocName(d)))
	}

	if len(vips) == 0 {
		return o.remove(ctx, h.Addr, o.St.DocName(d))
	}

	return o.apply(ctx, h.Addr, append(vips, spec.Delete("ContainerConfig", o.St.DocName(d)))...)
}

// RemoveCluster removes the whole cluster from every host (plan 03, step 7
// slice D, item 6). A cluster its agents own is suspended first, so no grant,
// job or leader tick races the removal; the zap targets are fixed after that,
// from the state read again and the nodes' preparation jobs, and journaled
// with the ids of the jobs that zap them. An interrupted removal continues
// from the journal.
func (o *Orch) RemoveCluster(ctx context.Context, zap bool, opts SuspendOptions) error {
	// one removal (or suspension) at a time, from the journal as it is on disk
	unlock, err := state.Lock(o.St.FSID)
	if err != nil {
		return err
	}
	defer unlock()

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil {
		return err
	}

	removing := rec != nil && rec.Phase == state.PhaseRemoving && rec.Removal != nil

	switch {
	case removing && rec.Removal.Zap != zap:
		return fmt.Errorf("the interrupted removal was started %s --zap: run it again the same way", map[bool]string{true: "with", false: "without"}[rec.Removal.Zap])
	case zap && !o.opened && !removing:
		// zap first refuses, before anything is suspended or removed
		return errors.New("--zap needs the cluster's state, which names the OSD devices, and it cannot be read; remove the cluster without --zap and wipe the disks with talosctl")
	}

	// before the handoff the CLI is the writer and the agents own nothing
	owned := rec != nil || o.St.Agent != nil && !(o.opened && !o.Managed())

	// a dry run of a removal its agents own would suspend them, or record a
	// step of the journal it only simulated
	if owned && o.Talos.DryRun {
		return errors.New("rm-cluster of a cluster its agents own has no dry run: it suspends them and journals its steps")
	}

	if owned && (rec == nil || rec.Phase == state.PhaseSuspending || rec.Phase == state.PhaseSuspended) {
		// the published revocation list before any agent is called, as every
		// other command reads it (plan 04, step 3); without the mons, the saved one
		if o.opened && o.Managed() {
			if err := o.RefreshCRL(ctx); err != nil {
				o.printf("warning: the revocation list: %v\n", err)
			}
		}

		if rec, err = o.suspendLocked(ctx, opts); err != nil {
			return err
		}
	}

	if rec != nil && rec.Phase != state.PhaseSuspended && rec.Phase != state.PhaseRecovering && rec.Phase != state.PhaseRemoving {
		return fmt.Errorf("recovery session %s is %s", rec.Session, rec.Phase)
	}

	// a recovery apply of an agent with no known outcome reserves its node
	if rec != nil && !removing {
		for _, h := range journaledHosts(rec) {
			if err := o.agentReserved(ctx, rec, h); err != nil {
				return fmt.Errorf("%s: %w", h.Name, err)
			}
		}
	}

	removal := &state.Removal{Zap: zap, Image: o.St.Image}

	switch {
	case removing:
		removal = rec.Removal // as it was started
	case zap:
		if removal.Targets, err = o.zapTargets(ctx, rec); err != nil {
			return err
		}
	}

	if rec != nil && !removing {
		rec.Phase, rec.Removal = state.PhaseRemoving, removal
		if err := rec.Save(); err != nil {
			return err
		}
	}

	if !removal.DocsRemoved {
		if err := o.removeDocuments(ctx, o.removalHosts(rec)); err != nil {
			return err
		}

		if rec != nil {
			removal.DocsRemoved = true
			if err := rec.Save(); err != nil {
				return err
			}
		}
	}

	for _, t := range removal.Targets {
		if err := o.zapTarget(ctx, rec, removal, t); err != nil {
			return err
		}
	}

	if removal.Zap {
		for _, h := range o.removalHosts(rec) {
			o.printf("deleting /var/mnt/ceph/%s on %s\n", o.St.FSID, h.Name)

			id, err := o.removalJob(rec, "rm-data/"+h.Name)
			if err != nil {
				return err
			}

			dir := "/var/lib/ceph/" + o.St.FSID
			doc := daemons.HostJob(daemons.Params{
				Name: fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), id), Image: removal.Image, FSID: o.St.FSID, ID: "job",
			}, id, jobInputs("rm-data", h.Name, dir), "rm -rf "+shellQuote(dir))

			if _, err := o.runJobKeep(ctx, h.Addr, doc, id, 10*time.Minute, rec != nil); err != nil {
				return err
			}
		}
	}

	if o.Talos.DryRun {
		return nil
	}

	// the journal goes with the rest of the workstation's state
	if err := os.RemoveAll(o.St.Dir()); err != nil {
		return err
	}

	cur := filepath.Join(state.Root(), "current")
	if b, err := os.ReadFile(cur); err == nil && strings.TrimSpace(string(b)) == o.St.FSID {
		_ = os.Remove(cur)
	}

	o.printf("cluster %s removed\n", o.St.FSID)

	return nil
}

// zapTarget zaps one disk of a removal under its journaled job id. A disk
// known only from a preparation is zapped only with this cluster's BlueStore
// label; one without it is left as it is.
func (o *Orch) zapTarget(ctx context.Context, rec *state.Recovery, removal *state.Removal, t state.ZapTarget) error {
	id, err := o.removalJob(rec, "zap/"+t.Host+"/"+t.Serial)
	if err != nil {
		return err
	}

	o.printf("zapping %s on %s\n", t.Device, t.Host)

	st := *o.St
	st.Image = removal.Image
	doc := render.Zap(&st, state.Host{Name: t.Host, Addr: t.Addr}, id, t.Device, t.Serial, !t.Labelled)

	res, err := o.runJobKeep(ctx, t.Addr, doc, id, 10*time.Minute, rec != nil)

	// only the command's verified refusal: a cleanup that failed is an error
	var cleanup *JobCleanupError
	if err != nil && t.Labelled && res.RC == zapNoLabel && !errors.As(err, &cleanup) && !errors.Is(err, errNoJobResult) {
		o.printf("%s on %s carries no BlueStore label of this cluster: left as it is\n", t.Device, t.Host)

		return nil
	}

	return err
}

// errNoJobResult marks a job that left no result file: its exit code is
// not the command's verified result.
var errNoJobResult = errors.New("left no result")

// zapNoLabel is zap.sh's exit code for a disk without a BlueStore label of
// the cluster.
const zapNoLabel = 67

// removalHosts are the hosts a removal goes through: the state's and the
// contacts, and every host a recovery session found.
func (o *Orch) removalHosts(rec *state.Recovery) []state.Host {
	hosts := o.St.AllHosts()

	if rec != nil {
		names := make([]string, 0, len(rec.Hosts))
		for n := range rec.Hosts {
			names = append(names, n)
		}

		sort.Strings(names)

		for _, n := range names {
			if !slices.ContainsFunc(hosts, func(h state.Host) bool { return h.Name == n }) && rec.Hosts[n].Addr != "" {
				hosts = append(hosts, state.Host{Name: n, Addr: rec.Hosts[n].Addr})
			}
		}
	}

	return hosts
}

// removalJob is the id of a removal's job for its purpose: journaled before
// its document is applied when a session runs the removal, fresh otherwise.
func (o *Orch) removalJob(rec *state.Recovery, purpose string) (string, error) {
	if rec == nil {
		return randHex(3), nil
	}

	if j, ok := rec.Jobs[purpose]; ok {
		return j.ID, nil
	}

	j := &state.RecoveryJob{ID: randHex(3), Inputs: purpose}
	rec.Jobs[purpose] = j

	return j.ID, rec.Save()
}

// removeDocuments removes every cluster document, the agents included, from
// each host and waits until every instance is gone.
func (o *Orch) removeDocuments(ctx context.Context, hosts []state.Host) error {
	prefix := "ceph-" + o.St.Short() + "-"

	// members and contacts: a node enrolled without a successful publication too
	for _, h := range hosts {
		names := map[string]bool{}

		for _, d := range o.St.Daemons {
			if d.Host == h.Name {
				names[o.St.DocName(d)] = true

				// an interrupted deploy's prepare job, also before its status appears
				if d.Type == state.TypeOSD && d.DeployID != "" {
					names[o.osdPrepareDocName(d)] = true
				}
			}
		}

		// the agent and its records-init are not daemons in the inventory; remove
		// and wait for them even if their status has not appeared (yet)
		if o.St.Agent != nil {
			names[o.agentDocName(h)] = true
			names[o.recordsInitDocName(h)] = true
		}

		st, err := o.Talos.ContainerStatuses(ctx, h.Addr)
		if err != nil {
			return err
		}

		for name := range st {
			if strings.HasPrefix(name, prefix) {
				names[name] = true
			}
		}

		// the node's own documents: the cluster's state may be unreadable, and a
		// container without a status yet is in no list above
		configured, err := o.configuredContainers(ctx, h.Addr, prefix)
		if err != nil {
			return err
		}

		for _, name := range configured {
			names[name] = true
		}

		docs := append([]any{spec.Delete("EtcFileConfig", "ceph/ceph.conf")}, o.talosFileDeletes()...)
		for name := range names {
			docs = append(docs, spec.Delete("ContainerConfig", name))
		}

		o.printf("removing %d containers and ceph.conf from %s\n", len(names), h.Name)

		if err := o.apply(ctx, h.Addr, docs...); err != nil {
			return err
		}

		for name := range names {
			if err := o.waitGone(ctx, h.Addr, name, 5*time.Minute); err != nil {
				return err
			}
		}
	}

	return nil
}

// zapTargets are the disks a removal zaps, fixed after the suspension: the
// OSDs of the state read again (an accepted creation may have published one
// meanwhile), the disks of the preparation and zap jobs configured on the
// nodes, and, zapped only with this cluster's label, every disk a
// preparation used on a host (the receipts, from the agents' approval
// records). A disk of the state or a job without a known serial refuses the
// zap before anything goes.
func (o *Orch) zapTargets(ctx context.Context, rec *state.Recovery) ([]state.ZapTarget, error) {
	seen := map[string]bool{}
	targets := []state.ZapTarget{}

	add := func(h state.Host, device, serial string, labelled bool) error {
		if serial == "" {
			return fmt.Errorf("--zap: the serial of %s on %s is unknown: remove the cluster without --zap and wipe that disk with talosctl", device, h.Name)
		}

		if !seen[h.Name+"/"+serial] {
			seen[h.Name+"/"+serial] = true
			targets = append(targets, state.ZapTarget{Host: h.Name, Addr: h.Addr, Device: device, Serial: serial, Labelled: labelled})
		}

		return nil
	}

	for _, d := range o.St.DaemonsOf(state.TypeOSD, "") {
		h, ok := o.St.Host(d.Host)
		if !ok {
			continue
		}

		if err := add(h, d.OSDDevice(), d.DiskSerial, false); err != nil {
			return nil, err
		}
	}

	for _, h := range o.removalHosts(rec) {
		envs, err := o.configuredDocs(ctx, h.Addr, "ceph-"+o.St.Short()+"-")
		if err != nil {
			return nil, err
		}

		names := make([]string, 0, len(envs))
		for n := range envs {
			names = append(names, n)
		}

		sort.Strings(names)

		for _, n := range names {
			if env := envs[n].env; env["DEVICE"] != "" && env["OSD_ID"] == "" {
				if err := add(h, env["DEVICE"], env["DISK_SERIAL"], false); err != nil {
					return nil, err
				}
			}
		}

		if rec == nil || rec.Hosts[h.Name] == nil || rec.Hosts[h.Name].Receipt == nil {
			continue
		}

		for _, serial := range rec.Hosts[h.Name].Receipt.Prepared {
			if seen[h.Name+"/"+serial] {
				continue
			}

			link, err := o.diskBySerial(ctx, h.Addr, serial)
			if err != nil {
				return nil, err
			}

			if link == "" {
				o.printf("%s: the disk %s a preparation used is gone\n", h.Name, serial)

				continue
			}

			if err := add(h, link, serial, true); err != nil {
				return nil, err
			}
		}
	}

	return targets, nil
}

// diskBySerial returns the /dev/disk/by-id link of the node's disk with a
// serial, "" if the node has no such disk.
func (o *Orch) diskBySerial(ctx context.Context, node, serial string) (string, error) {
	disks, err := o.Talos.Disks(ctx, node)
	if err != nil {
		return "", err
	}

	for _, disk := range disks {
		ds := disk.TypedSpec()
		if strings.TrimSpace(ds.Serial) != serial {
			continue
		}

		for _, l := range ds.Symlinks {
			if strings.HasPrefix(l, "/dev/disk/by-id/") && strings.Contains(l, serial) {
				return l, nil
			}
		}

		return "", fmt.Errorf("the disk %s on %s has no /dev/disk/by-id link with its serial", serial, node)
	}

	return "", nil
}

// configuredDocs returns the image and environment of each cluster
// container configured on a node.
func (o *Orch) configuredDocs(ctx context.Context, node, prefix string) (map[string]configuredDoc, error) {
	defer o.reading()()

	cfg, err := o.Talos.MachineConfig(ctx, node)
	if err != nil {
		return nil, err
	}

	out := map[string]configuredDoc{}
	dec := yaml.NewDecoder(strings.NewReader(cfg))

	for {
		var m struct {
			Kind        string   `yaml:"kind"`
			Name        string   `yaml:"name"`
			Image       string   `yaml:"image"`
			Environment []string `yaml:"environment"`
			Contents    string   `yaml:"contents"`
			Mounts      []map[string]struct {
				Name        string `yaml:"name"`
				Destination string `yaml:"destination"`
			} `yaml:"mounts"`
		}

		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			return out, nil
		} else if err != nil {
			return nil, fmt.Errorf("%s: machine config: %w", node, err)
		}

		// ceph.conf, under its own key: its fsid line
		if m.Kind == "EtcFileConfig" && m.Name == "ceph/ceph.conf" {
			out[cephConfDoc] = configuredDoc{env: map[string]string{"FSID": confFSID(m.Contents)}}

			continue
		}

		if m.Kind != "ContainerConfig" || !strings.HasPrefix(m.Name, prefix) {
			continue
		}

		env := map[string]string{}

		for _, e := range m.Environment {
			if k, v, ok := strings.Cut(e, "="); ok {
				env[k] = v
			}
		}

		d := configuredDoc{image: m.Image, env: env, volumes: map[string]string{}}

		// every mount, whatever its kind, by destination
		for _, mt := range m.Mounts {
			for kind, v := range mt {
				d.mounts = append(d.mounts, v.Destination)

				if kind == "volume" {
					d.volumes[v.Destination] = v.Name
				}
			}
		}

		out[m.Name] = d
	}
}

// zap destroys all Ceph signatures on a device, from a privileged job on its
// host, under the job id the caller chose.
func (o *Orch) zap(ctx context.Context, h state.Host, device, serial, id string) error {
	if serial == "" {
		return fmt.Errorf("the serial of %s is unknown: zap is bound to the disk's serial", device)
	}

	// zapping needs no cluster access: jobs mount neither ceph.conf nor a key
	_, err := o.runJob(ctx, h.Addr, o.zapDoc(h, id, device, serial), id, 10*time.Minute)

	return err
}

// zapDoc renders the job that zaps a device, bound to its serial. The CLI
// applies it itself, with os:admin, to a disk of an OSD it recorded, which
// may carry no label (a preparation that failed): the job skips the label
// check that agents require without the operator's approval.
func (o *Orch) zapDoc(h state.Host, id, device, serial string) *spec.ContainerConfig {
	return render.Zap(o.St, h, id, device, serial, true)
}

// osdIfExists runs a command for an OSD only if that very OSD (id and uuid)
// still exists. An interrupted removal can then be re-run, and a numeric id
// Ceph meanwhile handed to a new OSD is left alone. Failing to read the
// OSD map fails the command instead of looking like "already gone".
func osdIfExists(id int, uuid, format string) string {
	return fmt.Sprintf("uuids=$(ceph osd dump --format json | python3 -c 'import json,sys; [print(o[\"osd\"], o[\"uuid\"]) for o in json.load(sys.stdin)[\"osds\"]]') || exit $?; "+
		"if grep -qx '%d %s' <<<\"$uuids\"; then %s; else echo 'osd.%d with uuid %s not in the osd map, skipping'; fi",
		id, uuid, fmt.Sprintf(format, id), id, uuid)
}

// ensureOSDID makes sure the numeric id of an OSD is known before it is removed.
// An interrupted deploy may have left it unset while the OSD did get created.
func (o *Orch) ensureOSDID(ctx context.Context, d *state.Daemon, h state.Host, force, zap bool) error {
	if d.OSDID != nil && d.OSDUUID != "" {
		return nil
	}

	// only trust what this very deployment's prepare job reported: ids are reused by Ceph
	if d.DeployID != "" {
		if id, uuid, err := o.preparedOSD(ctx, h, *d); err == nil {
			d.OSDID, d.OSDUUID = &id, uuid
			o.St.AddDaemon(*d)

			return o.save()
		}
	}

	if !force {
		return fmt.Errorf("the OSD id/uuid of %s is unknown (its prepare did not finish); "+
			"refusing to remove without --force, as the device may hold an OSD that was never marked out", displayName(*d))
	}

	// with --force and no verified identity, never touch the cluster: the id may belong to another OSD now
	d.OSDID = nil

	if zap {
		o.printf("warning: zapping %s without a verified OSD identity; purge it manually if it still exists\n", d.Device)
	}

	return nil
}

// waitGone waits until Talos no longer reports a container.
func (o *Orch) waitGone(ctx context.Context, node, name string, timeout time.Duration) error {
	if o.Talos.DryRun {
		return nil
	}

	err := o.Talos.WaitFor(ctx, node, talos.InstanceTypes, timeout, func(ctx context.Context) (bool, error) {
		// the status goes away with the config; the instance only once the process exited
		st, err := o.Talos.ContainerStatuses(ctx, node)
		if err != nil {
			return false, talos.Permanent(err)
		}

		if _, ok := st[name]; ok {
			return false, nil
		}

		left, err := o.Talos.HasInstances(ctx, node, name)
		if err != nil {
			return false, talos.Permanent(err)
		}

		return !left, nil
	})
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return fmt.Errorf("timed out waiting for %s to stop", name)
	}

	return err
}

// Upgrade redeploys all daemons with a new image, one at a time: mons, mgrs, then OSDs.
// The image is pinned to its digest and probed first; refresh re-pulls a tag
// the probing node already has.
func (o *Orch) Upgrade(ctx context.Context, image string, refresh bool) error {
	for _, h := range o.St.Hosts {
		if h.Maintenance {
			return fmt.Errorf("host %s is in maintenance; exit maintenance before upgrading", h.Name)
		}
	}

	if err := o.gateCluster(); err != nil {
		return err
	}

	adm, err := o.adminHost()
	if err != nil {
		return err
	}

	img, err := o.resolveImage(ctx, adm.Addr, image, refresh)
	if err != nil {
		return err
	}

	if err := o.gateImage(img); err != nil {
		return err
	}

	image = img.Ref

	order := []string{state.TypeMon, state.TypeMgr, state.TypeOSD, state.TypeRGW}

	for _, typ := range order {
		for _, d := range o.St.DaemonsOf(typ, "") {
			h, ok := o.St.Host(d.Host)
			if !ok || d.Purged || d.LocalOnly {
				// a purged OSD is half removed: finish with `cephadm-talos rm`, never restart it
				continue
			}

			o.printf("upgrading %s on %s to %s\n", displayName(d), h.Name, image)

			if typ == state.TypeRGW {
				// rgws roll with the VIP drained, like any other rgw restart
				if _, err := o.rollRGWHost(ctx, h, image, rollOpts{}); err != nil {
					return err
				}
			} else {
				doc, err := o.redeployDoc(d, h, image)
				if err != nil {
					return err
				}

				if err := o.apply(ctx, h.Addr, doc); err != nil {
					return err
				}

				if err := o.waitImage(ctx, h.Addr, o.St.DocName(d), image, 15*time.Minute); err != nil {
					return err
				}
			}

			// crude health gate: the cluster must answer before we touch the next daemon
			adm, err := o.adminHost()
			if err != nil {
				return err
			}

			if _, err := o.Job(ctx, adm.Addr, "timeout 120 ceph -s >/dev/null", 5*time.Minute); err != nil {
				return fmt.Errorf("cluster not responding after upgrading %s: %w", displayName(d), err)
			}
		}
	}

	o.St.Image, o.St.CephVersion, o.St.Arch = img.Ref, img.Version, img.Arch

	return o.save()
}

// Redeploy re-renders a daemon's document with the current image (e.g. after changing cephadm-talos itself).
func (o *Orch) Redeploy(ctx context.Context, name string) error {
	d, h, err := o.lookup(name)
	if err != nil {
		return err
	}

	if d.Purged || d.LocalOnly {
		return fmt.Errorf("%s is half removed; finish its removal with `cephadm-talos rm`", name)
	}

	if h.Maintenance {
		return fmt.Errorf("host %s is in maintenance", h.Name)
	}

	// rgw and keepalived restarts always roll (VIP drained, readiness checked)
	if d.Type == state.TypeRGW || d.Type == state.TypeVIP {
		// an explicit redeploy restarts the daemon, like cephadm's stop + start
		_, err := o.rollRGWHost(ctx, h, o.St.Image, rollOpts{force: d.Type})

		return err
	}

	// an interrupted deploy may not have recorded the OSD identity yet: only its
	// own prepare result can tell it, prepare is never run again here
	if d.Type == state.TypeOSD && d.OSDID == nil && !o.Talos.DryRun {
		id, uuid, err := o.preparedOSD(ctx, h, d)
		if err != nil {
			return fmt.Errorf("%s was never prepared successfully, so it cannot be redeployed; remove it with --force: %w", name, err)
		}

		d.OSDID, d.OSDUUID = &id, uuid
		o.St.AddDaemon(d)
		o.printf("%s is osd.%d (%s)\n", name, id, uuid)

		if err := o.save(); err != nil {
			return err
		}
	}

	doc, err := o.redeployDoc(d, h, o.St.Image)
	if err != nil {
		return err
	}

	if err := o.apply(ctx, h.Addr, doc); err != nil {
		return err
	}

	return nil
}

// redeployDoc re-renders the document of an existing daemon (internal/render).
func (o *Orch) redeployDoc(d state.Daemon, h state.Host, image string) (*spec.ContainerConfig, error) {
	return render.Daemon(o.St, h, d, image, o.key, o.secret)
}

// Hosts prints the host inventory.
func (o *Orch) Hosts(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tADDR\tDAEMONS")

	for _, h := range o.St.Hosts {
		var ds []string

		for _, d := range o.St.Daemons {
			if d.Host == h.Name {
				ds = append(ds, displayName(d))
			}
		}

		fmt.Fprintf(tw, "%s\t%s\t%s\n", h.Name, h.Addr, strings.Join(ds, ","))
	}

	return tw.Flush()
}

// configuredContainers lists the ContainerConfig documents with prefix in a
// node's machine config.
func (o *Orch) configuredContainers(ctx context.Context, node, prefix string) ([]string, error) {
	// only reads: a dry run lists them too
	defer o.reading()()

	cfg, err := o.Talos.MachineConfig(ctx, node)
	if err != nil {
		return nil, err
	}

	var names []string

	dec := yaml.NewDecoder(strings.NewReader(cfg))

	for {
		var m map[string]any
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			return names, nil
		} else if err != nil {
			return nil, fmt.Errorf("%s: machine config: %w", node, err)
		}

		if name, ok := m["name"].(string); ok && m["kind"] == "ContainerConfig" && strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
}
