package orch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/mgrmodule"
	"github.com/nberlee/cephadm-talos/internal/records"
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
	if o.Talos.DryRun {
		o.printf("# exec on %s: %s\n", node, cmd)

		return JobResult{}, nil
	}

	jctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var out syncBuffer

	rc, target, err := o.execAdmin(jctx, node, []string{"bash", "-c", cmd}, nil, &out, &out)
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

	target, err := o.execTarget(ctx, node)
	if err != nil {
		return 0, "", err
	}

	script := `IFS= read -r key || exit 70; export CEPH_ARGS="-n client.admin --key $key"; unset key; exec "$@"`
	stdin := io.MultiReader(strings.NewReader(k+"\n"), bytes.NewReader(input))

	rc, err := o.Talos.Exec(ctx, node, target, append([]string{"bash", "-c", script, "cephadm-talos-exec"}, argv...), stdin, stdout, stderr)

	return rc, target, err
}

// execTarget picks the running Ceph container on node that admin commands run
// in: a mgr, else a mon, an rgw or an OSD (all have the ceph CLI and ceph.conf).
func (o *Orch) execTarget(ctx context.Context, node string) (string, error) {
	st, err := o.Talos.ContainerStatuses(ctx, node)
	if err != nil {
		return "", err
	}

	prefix := fmt.Sprintf("ceph-%s-", o.St.Short())

	for _, typ := range []string{state.TypeMgr, state.TypeMon, state.TypeRGW, state.TypeOSD} {
		var names []string

		for name, s := range st {
			if strings.HasPrefix(name, prefix+typ+"-") && s.State == containers.ContainerStateRunning {
				names = append(names, name)
			}
		}

		if len(names) > 0 {
			sort.Strings(names)

			return names[0], nil
		}
	}

	return "", fmt.Errorf("no running Ceph container on %s to run the command in", node)
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
	name, cmd := doc.MetaName, jobEnv(doc, "CMD")

	// a script is named by its job, a one-line command by itself
	if strings.Contains(cmd, "\n") || len(cmd) > 200 {
		cmd = name
	}

	if o.Talos.DryRun {
		return JobResult{}, o.apply(ctx, node, doc)
	}

	// Always clean up, also on timeout, ctrl-c or an apply error (the client may
	// fail after Talos accepted the config). A `never` job left behind runs again
	// on the next boot, where its claim keeps it from repeating its work; a
	// document left behind is still an error of its own.
	defer func() {
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
		return JobResult{RC: int(st.ExitCode)}, fmt.Errorf("job %s (%q) left no result (%s, exit %d): %s", name, cmd, st.State, st.ExitCode, st.Error)
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
func jobInputs(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))

	return hex.EncodeToString(h[:])
}

// Shell runs a ceph command (or any shell command) as an admin job and prints the output.
func (o *Orch) Shell(ctx context.Context, host string, cmd []string, timeout time.Duration) (int, error) {
	var h state.Host

	if host != "" {
		// an explicit host is used as is, also when it is in maintenance (diagnostics, recovery)
		var ok bool
		if h, ok = o.St.Host(host); !ok {
			return 1, fmt.Errorf("unknown host %q", host)
		}
	} else {
		var err error
		if h, err = o.adminHost(); err != nil {
			return 1, err
		}
	}

	res, err := o.Job(ctx, h.Addr, shellJoin(cmd), timeout)
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

	return tw.Flush()
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

	if err := o.remove(ctx, h.Addr, o.St.DocName(d)); err != nil {
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
		if err := o.zap(ctx, h, d.OSDDevice()); err != nil {
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

// RemoveCluster removes every document of this cluster from every host, like
// `cephadm rm-cluster`: daemons, leftover jobs and ceph.conf. With zap, OSD
// devices are zapped and the cluster's data directories deleted as well.
// The local state is removed last, so a failed run can be repeated.
func (o *Orch) RemoveCluster(ctx context.Context, zap bool) error {
	prefix := "ceph-" + o.St.Short() + "-"

	for _, h := range o.St.Hosts {
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

	if zap {
		for _, d := range o.St.DaemonsOf(state.TypeOSD, "") {
			h, ok := o.St.Host(d.Host)
			if !ok {
				continue
			}

			o.printf("zapping %s on %s\n", d.Device, h.Name)

			if err := o.zap(ctx, h, d.OSDDevice()); err != nil {
				return err
			}
		}

		for _, h := range o.St.Hosts {
			o.printf("deleting /var/mnt/ceph/%s on %s\n", o.St.FSID, h.Name)

			id := randHex(3)
			dir := "/var/lib/ceph/" + o.St.FSID
			doc := daemons.HostJob(daemons.Params{
				Name: fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), id), Image: o.St.Image, FSID: o.St.FSID, ID: "job",
			}, id, jobInputs("rm-data", h.Name, dir), "rm -rf "+shellQuote(dir))

			if _, err := o.runJob(ctx, h.Addr, doc, id, 10*time.Minute); err != nil {
				return err
			}
		}
	}

	if o.Talos.DryRun {
		return nil
	}

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

// zap destroys all Ceph signatures on a device, from a privileged job on its host.
func (o *Orch) zap(ctx context.Context, h state.Host, device string) error {
	id := randHex(3)
	cmd := "ceph-volume lvm zap " + shellQuote(device)
	doc := daemons.DeviceJob(daemons.Params{
		Name: fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), id), Image: o.St.Image, FSID: o.St.FSID, ID: "job",
	}, id, jobInputs("zap", h.Name, device), cmd)
	// zapping needs no cluster access: jobs mount neither ceph.conf nor a key
	_, err := o.runJob(ctx, h.Addr, doc, id, 10*time.Minute)

	return err
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

// redeployDoc re-renders the document of an existing daemon. Its data dir is
// already initialised, so the mon mode and keyrings only matter for a fresh start.
func (o *Orch) redeployDoc(d state.Daemon, h state.Host, image string) (*spec.ContainerConfig, error) {
	p := daemons.Params{Name: o.St.DocName(d), Image: image, FSID: o.St.FSID, ID: d.ID, Addr: h.Addr, Device: d.Device, DeployID: d.DeployID, OSDUUID: d.OSDUUID}
	if d.OSDID != nil {
		p.OSDID = *d.OSDID
	}

	adm, err := o.adminKeyring()
	if err != nil {
		return nil, err
	}

	switch d.Type {
	case state.TypeMon:
		p.Keyring = daemons.Keyring("mon.", o.St.Keys["mon."], "mon", "allow *") + adm
		p.Mode = "join"
		p.Addrv = monAddrv(h.Addr)
		p.DeployID = d.DeployID

		return daemons.Mon(p), nil
	case state.TypeMgr:
		p.Keyring = daemons.Keyring("mgr."+d.ID, o.St.Keys["mgr."+d.ID])

		return daemons.Mgr(p, mgrmodule.Names()...), nil
	case state.TypeOSD:
		// no key: activation takes the OSD's own key from the label
		p.Device = d.OSDDevice()

		return daemons.OSD(p), nil
	case state.TypeRGW:
		p.Keyring = daemons.Keyring("client.rgw."+d.ID, o.St.Keys["client.rgw."+d.ID])
		p.Port, p.TLSPEM = o.St.RGW.Port, o.St.RGW.Cert+o.St.RGW.Key

		return daemons.RGW(p), nil
	case state.TypeVIP:
		o.vipParams(&p, d)

		// keepalived has its own image and does not follow `upgrade`
		return daemons.VIP(p, o.St.RGW.KeepalivedImage), nil
	}

	return nil, fmt.Errorf("unknown daemon type %q", d.Type)
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
