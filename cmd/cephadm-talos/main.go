// cephadm-talos is a cephadm-like proof of concept that deploys and manages Ceph
// daemons on Talos Linux as ContainerConfig machine config documents.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/orch"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

const usage = `cephadm-talos - cephadm-like Ceph orchestration on Talos Linux (proof of concept)

Usage:
  cephadm-talos [global flags] <command> [args]

Commands:
  bootstrap --mon-node <ip> --agent-image IMG [--image IMG] [--refresh] [--crl-fail-closed]
                                           create a cluster: 1 mon + 1 mgr on the node
  host add <ip>                            add a Talos node (volume + ceph.conf)
  host ls                                  list hosts
  host rm <host>                           forget a host without daemons (handed over: ceph orch host rm)
  host forget [--node-is-gone] <host>      end a removed host's retirement whose agent does not retire: take its node over
                                           through Talos (--node-is-gone: the node will not return), then ceph orch talos host forgotten
  host maintenance enter|exit [--force] <host>
                                           ok-to-stop + noout + stop the host's daemons, or undo
  host reboot [--force] <host>             maintenance enter, Talos reboot, maintenance exit
  deploy mon|mgr <host>                    deploy a daemon on a host
  deploy osd <host> <device>               deploy an OSD on a raw device (e.g. /dev/vdb)
  deploy rgw <host> [--port 443] [--cert F --key F]
                                           deploy a radosgw serving HTTPS (generated CA by default)
  deploy vip <host> [--vip IP/PREFIX]      deploy keepalived holding the RGW virtual IP
  ps                                       list daemons with their Talos container status
  logs [-f] <daemon>                       daemon log (daemon: mon.<host>, osd.<id>, ...)
  restart <daemon>                         restart a daemon container
  redeploy <daemon>                        re-render and re-apply a daemon document
  rm [--force] [--zap] <daemon>            remove a daemon (osd: out, safe-to-destroy, purge)
  upgrade --image IMG [--refresh]          rolling image upgrade: mons, mgrs, osds
  shell [--host H] [--stdin] -- <cmd...>   run a command with the admin keyring on a node (--stdin: pass stdin on)
  orch [--request U] [-i F|-] -- <words>   run a ceph orch command once per request uuid (retry with --request)
  handoff                                  hand the nodes to their agents and the state to the leader
  suspend [--reboot] [--force]             suspend the agents and the leader for a recovery session
  recover mons [--image REF] [--member HOST]...
                                           bring the mons of a suspended cluster back on their stores (--member: a host the
                                           session left out is a real member: suspend it as one first, then recover it)
  resume                                   end the recovery session: agents re-adopt their nodes, a new leader takes over
  agent restore <host> [--previous]        in a recovery session: apply a suspended host's agent again (--previous: the known good image)
  resolve <host> [<operation>]             fail a job whose outcome is uncertain once it cannot run (without operation: list them)
  approve [--image REF] [--prepare H:DISK] [--zap H:DISK] [--drop H:SERIAL:ACTION] [--show]
                                           sign and publish the operator's approval of images and disks
  crl-policy closed|open                   the agents' policy for a revocation list past its nextUpdate (default open)
  rm-cluster [--zap] [--reboot] [--force] --yes-i-really-mean-it
                                           remove the whole cluster from all hosts (suspends a handed-over one first)
  conf                                     print the generated ceph.conf
  agent                                    run the node agent (inside its container)

Global flags:
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	global := flag.NewFlagSet("cephadm-talos", flag.ExitOnError)
	talosconfig := global.String("talosconfig", "", "talosconfig path (default: $TALOSCONFIG or ~/.talos/config, or the one saved at bootstrap)")
	talosContext := global.String("context", "", "talosconfig context (default: saved at bootstrap)")
	fsid := global.String("fsid", "", "cluster fsid (default: the last bootstrapped cluster)")
	dryRun := global.Bool("dry-run", false, "print the machine config patches instead of applying them")
	verbose := global.Bool("v", false, "print Talos API calls")
	skipVersion := global.Bool("skip-version-check", false, "skip the Talos and Ceph version gates (testing only)")
	global.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		global.PrintDefaults()
	}

	_ = global.Parse(os.Args[1:])

	args := global.Args()
	if len(args) == 0 {
		global.Usage()
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// the agent runs in a container on every Ceph node and needs no cluster state
	if args[0] == "agent" && len(args) == 1 {
		return agent.Main(ctx)
	}

	// prepares the agent's records on every boot, as root with CHOWN and FOWNER (plan 03, item 6)
	if args[0] == "records-init" {
		return records.Init(records.Mount, daemons.AgentUID, daemons.AgentUID)
	}

	// reads (and with --session suspends) an agent's records, in a recovery job
	// on a node whose agent does not answer (plan 03, step 7 slice D)
	if args[0] == "records" {
		return recordsJob(args[1:])
	}

	// stored in the cluster state at bootstrap: must not depend on the working directory
	if *talosconfig != "" {
		abs, err := filepath.Abs(*talosconfig)
		if err != nil {
			return err
		}

		*talosconfig = abs
	}

	tc := &talos.Client{Flags: talos.Conn{Talosconfig: *talosconfig, Context: *talosContext}, DryRun: *dryRun, Verbose: *verbose, Out: os.Stdout}
	defer tc.Close() //nolint:errcheck
	o := &orch.Orch{Talos: tc, Out: os.Stdout, SkipVersionCheck: *skipVersion}

	cmd, args := args[0], args[1:]

	if cmd == "bootstrap" {
		fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
		node := fs.String("mon-node", "", "IP of the Talos node for the first mon and mgr")
		image := fs.String("image", orch.DefaultImage, "Ceph container image (pinned to its digest)")
		refresh := fs.Bool("refresh", false, "pull the image tag again even if the node has it")
		agentImage := fs.String("agent-image", "", "cephadm-talos agent image (hack/agent-image.sh builds one)")
		crlClosed := fs.Bool("crl-fail-closed", false, "agents refuse all but the operator's calls while their revocation list is past its nextUpdate")
		_ = fs.Parse(args)

		o.CRLFailClosed = *crlClosed

		if *node == "" {
			return errors.New("bootstrap needs --mon-node <ip>")
		}

		return o.Bootstrap(ctx, *node, *image, *agentImage, *refresh)
	}

	st, err := state.Load(*fsid)
	if err != nil {
		return err
	}

	o.St = st

	// connection details saved in the state, unless overridden on the command line
	tc.Default = talos.Conn{Talosconfig: st.Talosconfig, Context: st.Context}
	tc.Hosts = map[string]talos.Conn{}

	for _, h := range st.Hosts {
		tc.Hosts[h.Addr] = talos.Conn{Talosconfig: h.Talosconfig, Context: h.Context}
	}

	// the cluster's state is in its mons (plan 03, item 4); a dry run reads it too.
	// rm-cluster also works when no mon answers: it removes what the nodes
	// known to this workstation configure
	// recovery needs no cluster state, and neither does shell during a
	// session: both start before Open and the CLI's maintenance (plan 03,
	// step 7 slice D, items 7 and 8)
	if cmd == "recover" {
		if len(args) == 0 || args[0] != "mons" {
			return errors.New("recover mons [--image REF] [--member HOST]...")
		}

		fs := flag.NewFlagSet("recover mons", flag.ExitOnError)
		image := fs.String("image", "", "the Ceph image (by digest) of a mon whose document is applied again, if its node has no other")

		var members stringList

		fs.Var(&members, "member", "a host the session left out is a real member: suspend it as one first, then recover it (repeatable)")
		_ = fs.Parse(args[1:])

		return o.RecoverMons(ctx, *image, members)
	}

	if cmd == "shell" && o.InRecovery() {
		return runCommand(ctx, o, cmd, args)
	}

	var localCA, localImage string
	if st.Agent != nil {
		localCA, localImage = st.Agent.CACert, st.Agent.Image
	}

	localRetiring := st.Retiring

	offline := false

	if err := o.Open(ctx); err != nil {
		if cmd != "rm-cluster" && cmd != "suspend" && cmd != "shell" {
			return err
		}

		offline = true

		fmt.Fprintln(os.Stderr, "warning:", err)
		fmt.Fprintln(os.Stderr, "warning: working from the hosts in this workstation's state")
	} else if o.St.Agent != nil && (o.St.Agent.CACert != localCA || o.St.Agent.Image != localImage || o.St.RetiringChanged(localRetiring)) {
		// kept locally for a suspension or recovery without the mons
		if err := o.KeepLocal(); err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
	}

	if cmd == "rm-cluster" {
		return rmCluster(ctx, o, args)
	}

	// without the cluster state, shell execs into a mgr or mon container of
	// the nodes this workstation knows, and the CLI writes nothing
	if offline && cmd == "shell" {
		return runCommand(ctx, o, cmd, args)
	}

	// the operator's certificate is renewed on any command, also after the
	// handoff, and its public copy kept equal to it (plan 04, step 1)
	if !offline {
		if err := o.EnsureOperatorCert(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "warning: the operator certificate:", err)
		}

		// a replaced operator certificate is revoked, retried on every command,
		// and the published revocation list read before any agent is called
		// (plan 04, step 3)
		if err := o.RevokePending(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}

		if o.Managed() {
			if err := o.RefreshCRL(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "warning: the revocation list:", err)
			}
		}
	}

	if cmd == "suspend" {
		fs := flag.NewFlagSet("suspend", flag.ExitOnError)
		reboot := fs.Bool("reboot", false, "reboot a node whose unanswering agent's last apply may still land, instead of waiting up to 10 minutes")
		force := fs.Bool("force", false, "remove a job an unanswering agent started that still runs, instead of waiting for it")
		_ = fs.Parse(args)

		_, err := o.Suspend(ctx, orch.SuspendOptions{Reboot: *reboot, Force: *force})

		return err
	}

	if cmd == "resume" {
		return o.Resume(ctx)
	}

	// part of a recovery session, with the host's agent suspended (plan 04, step 2)
	if cmd == "agent" {
		if len(args) == 0 || args[0] != "restore" {
			return errors.New("agent restore <host> [--previous]")
		}

		fs := flag.NewFlagSet("agent restore", flag.ExitOnError)
		previous := fs.Bool("previous", false, "the known good image: an unfinished agent upgrade's from-image, else the one the last upgrade upgraded from")
		_ = fs.Parse(args[1:])

		// the flag before or after the host
		host := fs.Arg(0)
		if fs.NArg() > 0 {
			_ = fs.Parse(fs.Args()[1:])
		}

		if host == "" || fs.NArg() != 0 {
			return errors.New("agent restore <host> [--previous]")
		}

		return o.RestoreAgent(ctx, host, *previous)
	}

	// an agent's job whose outcome is uncertain, failed by the operator (plan
	// 04, step 4); also while the cluster is suspended
	if cmd == "resolve" {
		switch len(args) {
		case 1:
			return o.ListUnresolved(ctx, args[0])
		case 2:
			return o.Resolve(ctx, args[0], args[1])
		}

		return errors.New("resolve <host> [<operation>]")
	}

	// once a leader owns the cluster state the CLI reads it and changes
	// nothing itself (plan 03, step 6): changes go through `ceph orch`
	if o.Managed() {
		switch cmd {
		case "ps", "ls", "conf", "logs", "shell", "handoff", "approve", "orch", "crl-policy":
		case "host":
			// enrollment, then `ceph orch host add` (plan 03, step 7), and a
			// removed host's node taken over (plan 04, step 6)
			if len(args) == 0 || args[0] != "ls" && args[0] != "add" && args[0] != "forget" {
				return orch.ErrManaged
			}
		default:
			return orch.ErrManaged
		}

		return runCommand(ctx, o, cmd, args)
	}

	// agent certificates are renewed on every command, also read-only ones,
	// and host documents that did not reach every host (ceph.conf, renewed
	// certificates) are retried: until plan 03 the CLI is the only place
	// renewal happens
	if err := o.RenewAgentCerts(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}

	if err := o.RetryPendingConf(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}

	// the talos mgr module's inventory follows every change: published now if
	// an earlier command could not, and again when this command is done
	if err := o.Publish(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "warning:", err)
	}

	defer func() {
		if err := o.Publish(context.WithoutCancel(ctx)); err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
	}()

	switch cmd {
	case "ps", "ls", "conf", "logs":
	default:
		if err := o.RetryPendingRGW(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
	}

	return runCommand(ctx, o, cmd, args)
}

// stringList is a repeatable flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)

	return nil
}

// runCommand runs one command on the opened cluster.
func runCommand(ctx context.Context, o *orch.Orch, cmd string, args []string) error {
	switch cmd {
	case "host":
		if len(args) == 0 {
			return errors.New("host add|ls|rm|forget")
		}

		switch args[0] {
		case "add":
			if len(args) != 2 {
				return errors.New("host add <ip>")
			}

			if o.Managed() {
				return o.Enroll(ctx, args[1])
			}

			_, err := o.AddHost(ctx, args[1])

			return err
		case "ls":
			return o.Hosts(os.Stdout)
		case "rm":
			if len(args) != 2 {
				return errors.New("host rm <host>")
			}

			return o.RemoveHost(ctx, args[1])
		case "forget":
			fs := flag.NewFlagSet("host forget", flag.ExitOnError)
			gone := fs.Bool("node-is-gone", false, "the node does not answer Talos and will not return: only tell the module")
			_ = fs.Parse(args[1:])

			// the flag before or after the host
			host := fs.Arg(0)
			if fs.NArg() > 0 {
				_ = fs.Parse(fs.Args()[1:])
			}

			if host == "" || fs.NArg() != 0 {
				return errors.New("host forget [--node-is-gone] <host>")
			}

			return o.HostForget(ctx, host, *gone)
		case "maintenance":
			if len(args) < 3 {
				return errors.New("host maintenance enter|exit [--force] <host>")
			}

			fs := flag.NewFlagSet("maintenance", flag.ExitOnError)
			force := fs.Bool("force", false, "enter even if ok-to-stop fails")
			_ = fs.Parse(args[2:])

			if fs.NArg() != 1 {
				return errors.New("host maintenance enter|exit [--force] <host>")
			}

			switch args[1] {
			case "enter":
				return o.MaintenanceEnter(ctx, fs.Arg(0), *force)
			case "exit":
				return o.MaintenanceExit(ctx, fs.Arg(0))
			}

			return fmt.Errorf("unknown maintenance command %q", args[1])
		case "reboot":
			fs := flag.NewFlagSet("reboot", flag.ExitOnError)
			force := fs.Bool("force", false, "reboot even if ok-to-stop fails")
			_ = fs.Parse(args[1:])

			if fs.NArg() != 1 {
				return errors.New("host reboot [--force] <host>")
			}

			return o.HostReboot(ctx, fs.Arg(0), *force)
		}

		return fmt.Errorf("unknown host command %q", args[0])
	case "deploy":
		if len(args) < 2 {
			return errors.New("deploy mon|mgr <host> | deploy osd <host> <device> | deploy rgw|vip <host> [flags]")
		}

		switch args[0] {
		case "rgw":
			fs := flag.NewFlagSet("deploy rgw", flag.ExitOnError)
			port := fs.Int("port", 443, "HTTPS port (first rgw only)")
			cert := fs.String("cert", "", "PEM certificate (chain) to use instead of the generated one")
			key := fs.String("key", "", "PEM private key for --cert")
			_ = fs.Parse(args[2:])

			return o.DeployRGW(ctx, args[1], orch.RGWOptions{Port: *port, CertFile: *cert, KeyFile: *key})
		case "vip":
			fs := flag.NewFlagSet("deploy vip", flag.ExitOnError)
			vip := fs.String("vip", "", "virtual IP with prefix length, e.g. 10.5.0.200/24 (first vip only)")
			image := fs.String("image", "", "keepalived image (default "+orch.DefaultKeepalivedImage+")")
			_ = fs.Parse(args[2:])

			return o.DeployVIP(ctx, args[1], *vip, *image)
		}

		dev := ""
		if len(args) > 2 {
			dev = args[2]
		}

		return o.Deploy(ctx, args[0], args[1], dev)
	case "ps", "ls":
		return o.PS(ctx, os.Stdout)
	case "logs":
		fs := flag.NewFlagSet("logs", flag.ExitOnError)
		follow := fs.Bool("f", false, "follow")
		_ = fs.Parse(args)

		if fs.NArg() != 1 {
			return errors.New("logs [-f] <daemon>")
		}

		return o.Logs(ctx, fs.Arg(0), *follow)
	case "restart":
		if len(args) != 1 {
			return errors.New("restart <daemon>")
		}

		return o.Restart(ctx, args[0])
	case "redeploy":
		if len(args) != 1 {
			return errors.New("redeploy <daemon>")
		}

		return o.Redeploy(ctx, args[0])
	case "rm":
		fs := flag.NewFlagSet("rm", flag.ExitOnError)
		force := fs.Bool("force", false, "skip safety checks")
		zap := fs.Bool("zap", false, "osd: wipe the device afterwards (ceph-volume lvm zap)")
		_ = fs.Parse(args)

		if fs.NArg() != 1 {
			return errors.New("rm [--force] [--zap] <daemon>")
		}

		return o.Remove(ctx, fs.Arg(0), *force, *zap)
	case "upgrade":
		fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
		image := fs.String("image", "", "new Ceph container image (pinned to its digest)")
		refresh := fs.Bool("refresh", false, "pull the image tag again even if the node has it")
		_ = fs.Parse(args)

		if *image == "" {
			return errors.New("upgrade --image <image>")
		}

		return o.Upgrade(ctx, *image, *refresh)
	case "orch":
		fs := flag.NewFlagSet("orch", flag.ExitOnError)
		request := fs.String("request", "", "the request uuid of an earlier invocation to retry (default: a new one)")
		in := fs.String("i", "", "input file for the command (- for stdin), never on a command line")
		_ = fs.Parse(args)

		if fs.NArg() == 0 {
			return errors.New("orch [--request <uuid>] [-i <file>|-] -- <ceph orch words...>")
		}

		var input []byte

		switch *in {
		case "":
		case "-":
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
			if err != nil {
				return err
			}

			input = b
		default:
			b, err := os.ReadFile(*in)
			if err != nil {
				return err
			}

			input = b
		}

		if len(input) > 1<<20 {
			return errors.New("orch -i: more than 1 MiB of input")
		}

		rc, err := o.Orch(ctx, *request, fs.Args(), input)
		if err != nil {
			return err
		}

		if rc != 0 {
			os.Exit(rc)
		}

		return nil
	case "shell":
		fs := flag.NewFlagSet("shell", flag.ExitOnError)
		host := fs.String("host", "", "host to run on (default: first mon host)")
		timeout := fs.Duration("timeout", 5*time.Minute, "give up after")
		stdin := fs.Bool("stdin", false, "pass this command's stdin to the command (e.g. ceph ... -i -), never on a command line")
		_ = fs.Parse(args)

		if fs.NArg() == 0 {
			return errors.New("shell [--host H] [--stdin] -- <cmd...>")
		}

		var input []byte

		if *stdin {
			b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
			if err != nil {
				return err
			}

			if len(b) > 1<<20 {
				return errors.New("shell --stdin: more than 1 MiB of input")
			}

			input = b
		}

		rc, err := o.ShellInput(ctx, *host, fs.Args(), input, *timeout)
		if err != nil {
			return err
		}

		os.Exit(rc)
	case "handoff":
		return o.Handoff(ctx)
	case "approve":
		return approve(ctx, o, args)
	case "crl-policy":
		if len(args) != 1 {
			return errors.New("crl-policy closed|open")
		}

		return o.SetCRLPolicy(ctx, args[0])
	case "conf":
		fmt.Print(o.CephConf())

		return nil
	}

	return fmt.Errorf("unknown command %q, see cephadm-talos -h (%s)", cmd, strings.Join([]string{"bootstrap", "host", "deploy", "ps", "logs", "rm", "upgrade", "shell"}, ", "))
}

// listFlag collects a repeated flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func approve(ctx context.Context, o *orch.Orch, args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)

	var c orch.ApprovalChange

	fs.Var((*listFlag)(&c.AddImages), "image", "approve an image by digest (repeatable)")
	fs.Var((*listFlag)(&c.DropImages), "drop-image", "withdraw an image (repeatable)")
	fs.Var((*listFlag)(&c.Prepare), "prepare", "approve one OSD preparation on <host>:<serial> or <host>:/dev/<disk> (repeatable)")
	fs.Var((*listFlag)(&c.Zap), "zap", "approve one zap without the label check on <host>:<serial> or <host>:/dev/<disk> (repeatable)")
	fs.Var((*listFlag)(&c.Drop), "drop", "withdraw a disk entry <host>:<serial>:<action> (repeatable)")
	show := fs.Bool("show", false, "print the last approval")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *show {
		return o.ShowApproval()
	}

	a, err := o.Approve(ctx, c)
	if err != nil {
		return err
	}

	fmt.Printf("approval %d published: %d images, %d disk entries\n", a.Serial, len(a.Images), len(a.Disks))

	return nil
}

func rmCluster(ctx context.Context, o *orch.Orch, args []string) error {
	fs := flag.NewFlagSet("rm-cluster", flag.ExitOnError)
	zap := fs.Bool("zap", false, "also zap OSD devices and delete /var/mnt/ceph/<fsid> on every host")
	yes := fs.Bool("yes-i-really-mean-it", false, "confirm")
	reboot := fs.Bool("reboot", false, "suspending: reboot a node whose unanswering agent's last apply may still land, instead of waiting")
	force := fs.Bool("force", false, "suspending: remove a job an unanswering agent started that still runs, instead of waiting for it")
	_ = fs.Parse(args)

	if !*yes {
		return fmt.Errorf("this destroys cluster %s; pass --yes-i-really-mean-it", o.St.FSID)
	}

	return o.RemoveCluster(ctx, *zap, orch.SuspendOptions{Reboot: *reboot, Force: *force})
}

// uuidRe is an fsid.
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// recordsJob is the recovery job's command: it reads the agent's records,
// records the suspension with --session, and writes the report as its result.
// With --retire it retires the records instead (plan 04, step 6): marks the
// serials of their identity record and moves them aside; the caller has
// checked that no agent document of the cluster is on the node. With
// --serial, a host's journaled serial: --retire refuses records that do not
// list it, and missing records under a retirement mark of it read as retired;
// with --none-ok missing records read as retired whatever the marks (an
// enrollment's look at a node that may never have held any). Current records
// that do not list --serial are refused before anything is recorded or settled:
// another generation's; a member's job passes --any-generation.
func recordsJob(args []string) error {
	fs := flag.NewFlagSet("records", flag.ExitOnError)
	fsid := fs.String("fsid", "", "cluster fsid")
	job := fs.String("job", "", "job id")
	inputs := fs.String("inputs", "", "job inputs")
	session := fs.String("session", "", "record the suspension for this recovery session")
	settle := fs.Bool("settle-self", false, "first settle an interrupted self-update's apply intent as failed (agent restore)")
	retire := fs.Bool("retire", false, "retire the records: mark their serials and move them aside (host forget, re-enrollment)")
	serial := fs.String("serial", "", "the host's journaled agent server certificate serial (decimal)")
	boot := fs.String("boot", "", "the node's boot id, as the caller read it from Talos (default: the kernel's)")
	anyGeneration := fs.Bool("any-generation", false, "--serial only recognizes records moved aside: current records need not list it (a member, whose renewal may be in progress)")
	noneOK := fs.Bool("none-ok", false, "no records of the cluster on the node read as retired (an enrollment's look at the node)")
	_ = fs.Parse(args)

	jobs := filepath.Join(records.Mount, records.JobsDir)

	// this cluster's records, where its agent keeps them (another cluster's
	// on the same node are beside them)
	if !uuidRe.MatchString(*fsid) {
		return fmt.Errorf("malformed fsid %q", *fsid)
	}

	// a retirement that ran already replays its result (plan 04, step 6)
	if *retire && agent.JobResultSaved(jobs, *fsid, *job) {
		return nil
	}

	dir := filepath.Join(records.Mount, records.RecordsDir, *fsid)
	recs := &records.Store{Dir: dir}

	rep, err := agent.RecordsReport{}, error(nil)

	switch {
	case *retire && (*settle || *session != ""):
		err = errors.New("--retire goes alone")
	case *retire:
		b := *boot
		if b == "" {
			b = kernelBootID()
		}

		rep, err = agent.RetireRecords(recs, *serial, b, time.Now())
	default:
		if _, err = os.Stat(dir); err != nil {
			// moved aside under the host's serial: retired, not missing
			retired, found, rerr := agent.RetiredRecords(dir, *serial)

			switch {
			case rerr != nil:
				err = rerr
			case found:
				rep, err = retired, nil
			case *noneOK && errors.Is(err, os.ErrNotExist):
				rep, err = agent.RetiredReport(), nil
			default:
				err = fmt.Errorf("no records of cluster %s on the node: %w", *fsid, err)
			}

			break
		}

		settled := ""
		// before anything is recorded or settled
		if !*anyGeneration {
			err = agent.CheckRecordsSerial(recs, *serial)
		}

		if err == nil && *settle {
			settled, err = agent.SettleSelfUpdate(recs)
		}

		if err == nil {
			rep, err = agent.InspectRecords(recs, *session)
			rep.Settled = settled
		}
	}

	if err != nil {
		if werr := agent.WriteJobResult(jobs, *fsid, *job, *inputs, 1, []byte(err.Error())); werr != nil {
			return errors.Join(err, werr)
		}

		return err
	}

	out, err := json.Marshal(rep)
	if err != nil {
		return err
	}

	return agent.WriteJobResult(jobs, *fsid, *job, *inputs, 0, out)
}

// kernelBootID is the node's boot id as Talos reports it (its BootID resource
// is this file), "" if the job cannot read it.
func kernelBootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(b))
}
