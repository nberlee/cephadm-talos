// cephadm-talos is a cephadm-like proof of concept that deploys and manages Ceph
// daemons on Talos Linux as ContainerConfig machine config documents.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/orch"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

const usage = `cephadm-talos - cephadm-like Ceph orchestration on Talos Linux (proof of concept)

Usage:
  cephadm-talos [global flags] <command> [args]

Commands:
  bootstrap --mon-node <ip> --agent-image IMG [--image IMG] [--refresh]
                                           create a cluster: 1 mon + 1 mgr on the node
  host add <ip>                            add a Talos node (volume + ceph.conf)
  host ls                                  list hosts
  host rm <host>                           forget a host without daemons
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
  shell [--host H] -- <cmd...>             run a command with the admin keyring on a node
  rm-cluster [--zap] --yes-i-really-mean-it  remove the whole cluster from all hosts
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
	if args[0] == "agent" {
		return agent.Main(ctx)
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
		_ = fs.Parse(args)

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

	switch cmd {
	case "ps", "ls", "conf", "logs":
	default:
		if err := o.RetryPendingRGW(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		}
	}

	switch cmd {
	case "host":
		if len(args) == 0 {
			return errors.New("host add|ls|rm")
		}

		switch args[0] {
		case "add":
			if len(args) != 2 {
				return errors.New("host add <ip>")
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
	case "shell":
		fs := flag.NewFlagSet("shell", flag.ExitOnError)
		host := fs.String("host", "", "host to run on (default: first mon host)")
		timeout := fs.Duration("timeout", 5*time.Minute, "give up after")
		_ = fs.Parse(args)

		if fs.NArg() == 0 {
			return errors.New("shell [--host H] -- <cmd...>")
		}

		rc, err := o.Shell(ctx, *host, fs.Args(), *timeout)
		if err != nil {
			return err
		}

		os.Exit(rc)
	case "rm-cluster":
		fs := flag.NewFlagSet("rm-cluster", flag.ExitOnError)
		zap := fs.Bool("zap", false, "also zap OSD devices and delete /var/mnt/ceph/<fsid> on every host")
		yes := fs.Bool("yes-i-really-mean-it", false, "confirm")
		_ = fs.Parse(args)

		if !*yes {
			return fmt.Errorf("this destroys cluster %s; pass --yes-i-really-mean-it", st.FSID)
		}

		return o.RemoveCluster(ctx, *zap)
	case "conf":
		fmt.Print(o.CephConf())

		return nil
	}

	return fmt.Errorf("unknown command %q, see cephadm-talos -h (%s)", cmd, strings.Join([]string{"bootstrap", "host", "deploy", "ps", "logs", "rm", "upgrade", "shell"}, ", "))
}
