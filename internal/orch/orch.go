// Package orch implements the cephadm-talos commands: the cephadm-like orchestration
// of Ceph daemons as Talos ContainerConfig documents.
package orch

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/cephx"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/mgrmodule"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

// DefaultImage is the Ceph container image used when none is given.
const DefaultImage = "quay.io/ceph/ceph:v20"

// MinTalos is the minimum Talos version: ContainerConfig (1.14) plus
// EtcFileConfig and `--namespace taloscontainers` for logs/restart (1.15).
const MinTalos = "v1.15.0"

// Orch holds the state of one cluster and a Talos client for it.
type Orch struct {
	St    *state.State
	Talos *talos.Client
	Out   io.Writer
	// SkipVersionCheck skips the Talos and Ceph version gates (testing only)
	SkipVersionCheck bool
}

func (o *Orch) printf(format string, args ...any) { fmt.Fprintf(o.Out, format, args...) }

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)

	return fmt.Sprintf("%x", b)
}

// key returns the secret of an entity, generating it on first use.
func (o *Orch) key(entity string) (string, error) {
	if k, ok := o.St.Keys[entity]; ok {
		return k, nil
	}

	k, err := cephx.NewKey()
	if err != nil {
		return "", err
	}

	o.St.Keys[entity] = k

	return k, nil
}

// monAddrv is the mon address vector; IPv6 addresses need brackets.
func monAddrv(ip string) string {
	return fmt.Sprintf("[v2:%s,v1:%s]", net.JoinHostPort(ip, "3300"), net.JoinHostPort(ip, "6789"))
}

// CephConf renders the minimal ceph.conf shared by all daemons on all hosts.
func (o *Orch) CephConf() string {
	var addrs []string

	v4, v6 := false, false

	for _, a := range o.St.MonAddrs() {
		addrs = append(addrs, monAddrv(a))

		if ip := net.ParseIP(a); ip != nil && ip.To4() == nil {
			v6 = true
		} else {
			v4 = true
		}
	}

	// mgr/osd pick their bind address by family; follow the mon addresses
	if !v4 && !v6 {
		v4 = true
	}

	return fmt.Sprintf(`# managed by cephadm-talos, do not edit
[global]
fsid = %s
mon_host = %s
log_to_file = false
log_to_stderr = true
err_to_stderr = true
mon_cluster_log_to_file = false
mon_cluster_log_to_stderr = true
auth_allow_insecure_global_id_reclaim = false
ms_bind_ipv4 = %t
ms_bind_ipv6 = %t
# small Talos VMs: do not let bluestore autotune into an OOM
osd_memory_target = 1073741824
osd_memory_target_autotune = false
`, o.St.FSID, strings.Join(addrs, ","), v4, v6)
}

// adminKeyring is the client.admin keyring with full caps.
func (o *Orch) adminKeyring() (string, error) {
	k, err := o.key("client.admin")
	if err != nil {
		return "", err
	}

	return daemons.Keyring("client.admin", k, "mon", "allow *", "osd", "allow *", "mds", "allow *", "mgr", "allow *"), nil
}

// writeLocal drops ceph.conf and the admin keyring into the state dir, for use with a local ceph CLI.
func (o *Orch) writeLocal() error {
	if o.Talos.DryRun {
		return nil
	}

	if err := os.MkdirAll(o.St.Dir(), 0o700); err != nil {
		return err
	}

	adm, err := o.adminKeyring()
	if err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(o.St.Dir(), "ceph.conf"), []byte(o.CephConf()), 0o644); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(o.St.Dir(), "ceph.client.admin.keyring"), []byte(adm), 0o600)
}

// apply applies documents to a node in one machine config change.
//
// Talos strategic merge appends list fields (mounts, environment, entrypoint)
// when a named document already exists, so every ContainerConfig is deleted
// first and re-added in a second patch of the same apply. Deleting a document
// that does not exist yet is a no-op.
func (o *Orch) apply(ctx context.Context, node string, docs ...any) error {
	var dels []any

	for _, d := range docs {
		if c, ok := d.(*spec.ContainerConfig); ok {
			dels = append(dels, spec.Delete("ContainerConfig", c.MetaName))
		}
	}

	add, err := spec.Render(docs...)
	if err != nil {
		return err
	}

	if len(dels) == 0 {
		return o.Talos.Patch(ctx, node, add)
	}

	del, err := spec.Render(dels...)
	if err != nil {
		return err
	}

	return o.Talos.Patch(ctx, node, del, add)
}

// remove deletes a ContainerConfig from a node.
func (o *Orch) remove(ctx context.Context, node, name string) error {
	del, err := spec.Render(spec.Delete("ContainerConfig", name))
	if err != nil {
		return err
	}

	return o.Talos.Patch(ctx, node, del)
}

// hostDocs are the per-host documents every Ceph node needs: the
// /var/lib/ceph volume, ceph.conf and the node agent.
func (o *Orch) hostDocs(h state.Host) []any {
	docs := append([]any{spec.CephVolume(), spec.CephConf(o.CephConf())}, o.agentDocs(h)...)
	docs = append(docs, o.inventoryDoc())

	return append(docs, o.mgrFileDocs(o.hasMgr(h))...)
}

// pushConf rewrites ceph.conf on every host (after the mon set changed).
//
// An unreachable host does not stop the others; it is remembered in
// ConfPending and retried by the next command (see RetryPendingConf).
func (o *Orch) pushConf(ctx context.Context) error {
	var failed []string

	for _, h := range o.St.Hosts {
		o.printf("updating ceph.conf on %s\n", h.Name)

		if err := o.apply(ctx, h.Addr, o.hostDocs(h)...); err != nil {
			o.printf("warning: ceph.conf on %s not updated: %v\n", h.Name, err)
			failed = append(failed, h.Name)
		}
	}

	o.St.ConfPending = failed

	if err := o.save(); err != nil {
		return err
	}

	if err := o.writeLocal(); err != nil {
		return err
	}

	if len(failed) > 0 {
		return fmt.Errorf("ceph.conf is outdated on %s; it is retried on the next command", strings.Join(failed, ", "))
	}

	return nil
}

// RetryPendingConf re-pushes ceph.conf if an earlier push left hosts behind.
func (o *Orch) RetryPendingConf(ctx context.Context) error {
	if len(o.St.ConfPending) == 0 || o.Talos.DryRun {
		return nil
	}

	o.printf("retrying the ceph.conf update for %s\n", strings.Join(o.St.ConfPending, ", "))

	return o.pushConf(ctx)
}

// checkTalos verifies the node runs a Talos version with the container APIs we use.
func (o *Orch) checkTalos(ctx context.Context, node string) error {
	if o.Talos.DryRun || o.SkipVersionCheck {
		return nil
	}

	v, err := o.Talos.Version(ctx, node)
	if err != nil {
		return err
	}

	if !versionAtLeast(v, MinTalos) {
		return fmt.Errorf("node %s runs Talos %s, cephadm-talos needs %s or newer (ContainerConfig, EtcFileConfig)", node, v, MinTalos)
	}

	return nil
}

// versionAtLeast compares vMAJOR.MINOR, ignoring patch and pre-release (1.15 alphas count as 1.15).
func versionAtLeast(v, minimum string) bool {
	parse := func(s string) (int, int) {
		s = strings.TrimPrefix(s, "v")
		parts := strings.SplitN(s, ".", 3)

		if len(parts) < 2 {
			return 0, 0
		}

		maj, _ := strconv.Atoi(parts[0])
		mnr, _ := strconv.Atoi(parts[1])

		return maj, mnr
	}

	a1, a2 := parse(v)
	b1, b2 := parse(minimum)

	return a1 > b1 || (a1 == b1 && a2 >= b2)
}

// AddHost registers a Talos node and provisions its Ceph volume and ceph.conf.
func (o *Orch) AddHost(ctx context.Context, addr string) (state.Host, error) {
	return o.addHost(ctx, addr, true)
}

func (o *Orch) addHost(ctx context.Context, addr string, apply bool) (state.Host, error) {
	if err := o.checkTalos(ctx, addr); err != nil {
		return state.Host{}, err
	}

	name := "dry-run-" + strings.NewReplacer(".", "-", ":", "-").Replace(addr)
	if !o.Talos.DryRun {
		n, err := o.Talos.Hostname(ctx, addr)
		if err != nil {
			return state.Host{}, err
		}

		name = n
	}

	h := state.Host{Name: name, Addr: addr}

	// re-adding a known host must not drop its maintenance bookkeeping
	if old, ok := o.St.Host(name); ok {
		h.Maintenance, h.NoOut = old.Maintenance, old.NoOut
		h.Talosconfig, h.Context = old.Talosconfig, old.Context
		h.AgentCert, h.AgentKey = old.AgentCert, old.AgentKey
	}

	if err := o.ensureAgentCert(&h); err != nil {
		return h, err
	}

	o.St.AddHost(h)

	if !apply {
		return h, nil
	}

	if err := o.apply(ctx, addr, o.hostDocs(h)...); err != nil {
		return h, err
	}

	o.printf("added host %s (%s)\n", name, addr)

	return h, o.save()
}

func (o *Orch) save() error {
	if o.Talos.DryRun {
		return nil
	}

	return o.St.Save()
}

// RemoveHost forgets a host. It refuses while daemons are still placed on it.
func (o *Orch) RemoveHost(ctx context.Context, name string) error {
	h, ok := o.St.Host(name)
	if !ok {
		return fmt.Errorf("unknown host %q", name)
	}

	for _, d := range o.St.Daemons {
		if d.Host == h.Name {
			return fmt.Errorf("host %s still has %s.%s, remove its daemons first", h.Name, d.Type, d.ID)
		}
	}

	if h.Maintenance || h.NoOut {
		return fmt.Errorf("host %s is in maintenance; run `cephadm-talos host maintenance exit %s` first, it also clears noout", h.Name, h.Name)
	}

	// the agent first: a failure leaves the host in the inventory, so rm can be repeated
	if err := o.removeAgent(ctx, h); err != nil {
		return err
	}

	// the UserVolumeConfig is left in place: deleting it does not wipe /var/mnt/ceph anyway
	if err := o.apply(ctx, h.Addr, append([]any{spec.Delete("EtcFileConfig", "ceph/ceph.conf")}, o.talosFileDeletes()...)...); err != nil {
		return err
	}

	o.St.RemoveHost(h.Name)

	return o.save()
}

// Bootstrap creates a new cluster with one mon and one mgr on the given node.
func (o *Orch) Bootstrap(ctx context.Context, addr, image, agentImage string, refresh bool) error {
	o.St = state.New(newUUID())

	if agentImage == "" {
		return errors.New("bootstrap needs --agent-image (build one with hack/agent-image.sh)")
	}

	o.St.Talosconfig = o.Talos.Flags.Talosconfig
	o.St.Context = o.Talos.Flags.Context

	// host docs are applied together with the mon below, once ceph.conf has a mon_host
	h, err := o.addHost(ctx, addr, false)
	if err != nil {
		return err
	}

	img, err := o.resolveImage(ctx, addr, image, refresh)
	if err != nil {
		return err
	}

	if err := o.gateImage(img); err != nil {
		return err
	}

	image = img.Ref
	o.St.Image, o.St.CephVersion, o.St.Arch = img.Ref, img.Version, img.Arch

	if err := o.setupAgent(ctx, addr, agentImage, refresh); err != nil {
		return err
	}

	// the host was added before the agent CA existed
	if err := o.ensureAgentCert(&h); err != nil {
		return err
	}

	o.St.AddHost(h)

	o.printf("bootstrapping cluster %s on %s with %s\n", o.St.FSID, h.Name, image)

	mon := state.Daemon{Type: state.TypeMon, ID: h.Name, Host: h.Name, DeployID: randHex(8)}
	mgr := state.Daemon{Type: state.TypeMgr, ID: h.Name, Host: h.Name}
	o.St.AddDaemon(mon)
	o.St.AddDaemon(mgr)

	monKey, err := o.key("mon.")
	if err != nil {
		return err
	}

	mgrKey, err := o.key("mgr." + h.Name)
	if err != nil {
		return err
	}

	osdKey, err := o.key("client.bootstrap-osd")
	if err != nil {
		return err
	}

	adm, err := o.adminKeyring()
	if err != nil {
		return err
	}

	// Like cephadm bootstrap: every initial entity goes into the mon keyring so
	// that `ceph-mon --mkfs` imports it with caps; no round trip to a live mon needed.
	monKeyring := daemons.Keyring("mon.", monKey, "mon", "allow *") + adm +
		daemons.Keyring("client.bootstrap-osd", osdKey, "mon", "profile bootstrap-osd") +
		daemons.Keyring("mgr."+h.Name, mgrKey, "mon", "profile mgr", "osd", "allow *", "mds", "allow *")

	monDoc := daemons.Mon(daemons.Params{
		Name: o.St.DocName(mon), Image: image, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr,
		Keyring: monKeyring, Mode: "bootstrap", Addrv: monAddrv(h.Addr), DeployID: mon.DeployID,
	})
	// no dependsOn on the mon: Talos rejects configs referencing a removed container,
	// which would block removing the bootstrap mon later. ceph-mgr retries by itself.
	mgrDoc := daemons.Mgr(daemons.Params{
		Name: o.St.DocName(mgr), Image: image, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr,
		Keyring: daemons.Keyring("mgr."+h.Name, mgrKey),
	}, mgrmodule.Names()...)

	// the state, the first revision and the pending host are saved before the
	// node is patched: an interrupted bootstrap leaves a state to clean up from
	o.bumpPublished()
	o.St.ConfPending = []string{h.Name}

	if err := o.save(); err != nil {
		return err
	}

	if err := o.apply(ctx, h.Addr, append(o.hostDocs(h), monDoc, mgrDoc)...); err != nil {
		return err
	}

	o.St.ConfPending = nil

	if err := o.save(); err != nil {
		return err
	}

	if err := o.writeLocal(); err != nil {
		return err
	}

	if err := o.waitRunning(ctx, h.Addr, o.St.DocName(mon), 10*time.Minute); err != nil {
		return err
	}

	o.printf("waiting for the mon to form a quorum\n")

	if _, err := o.Job(ctx, h.Addr, "timeout 300 ceph -s", 10*time.Minute); err != nil {
		return err
	}

	if !o.Talos.DryRun {
		if err := o.enableModule(ctx, h.Addr); err != nil {
			return err
		}
	}

	o.printf("\ncluster %s bootstrapped\n  state: %s\n  next:  cephadm-talos host add <ip>; cephadm-talos deploy osd <host> /dev/<disk>\n", o.St.FSID, o.St.Dir())

	return nil
}

// Deploy places a daemon of the given type on a host. arg is the device for OSDs.
func (o *Orch) Deploy(ctx context.Context, typ, hostName, arg string) error {
	if err := o.gateCluster(); err != nil {
		return err
	}

	h, ok := o.St.Host(hostName)
	if !ok {
		var err error

		// accept an unknown IP and add it on the fly, like `ceph orch host add` + apply
		if h, err = o.AddHost(ctx, hostName); err != nil {
			return err
		}
	}

	if h.Maintenance {
		return fmt.Errorf("host %s is in maintenance, run `cephadm-talos host maintenance exit %s` first", h.Name, h.Name)
	}

	if err := o.checkTalos(ctx, h.Addr); err != nil {
		return err
	}

	switch typ {
	case state.TypeMon:
		return o.deployMon(ctx, h)
	case state.TypeMgr:
		return o.deployMgr(ctx, h)
	case state.TypeOSD:
		if arg == "" {
			return errors.New("deploy osd needs a device, e.g. /dev/vdb")
		}

		return o.deployOSD(ctx, h, arg)
	default:
		return fmt.Errorf("unsupported daemon type %q (mon, mgr, osd)", typ)
	}
}

// adminHost picks a host to run admin jobs on: the first mon host whose Talos
// API answers and whose mon container runs, so a single node being down does
// not block the cluster's administration. The choice is made before a job is
// submitted; a job is never retried elsewhere, as it may already have run.
func (o *Orch) adminHost() (state.Host, error) {
	return o.pickAdminHost(false)
}

// confirmedAdminHost is adminHost without the fallback: it fails unless a mon
// host answers and runs its mon.
func (o *Orch) confirmedAdminHost() (state.Host, error) {
	return o.pickAdminHost(true)
}

func (o *Orch) pickAdminHost(strict bool) (state.Host, error) {
	var first *state.Host

	for _, d := range o.St.DaemonsOf(state.TypeMon, "") {
		h, ok := o.St.Host(d.Host)
		if !ok || h.Maintenance {
			continue
		}

		if first == nil {
			first = &h
		}

		if o.Talos.DryRun {
			return h, nil
		}

		st, err := o.Talos.ContainerStatuses(context.Background(), h.Addr)
		if s, ok := st[o.St.DocName(d)]; err == nil && ok && s.State == containers.ContainerStateRunning {
			return h, nil
		}
	}

	if first != nil && !strict {
		// nothing confirmed healthy (e.g. mid-bootstrap): let the job report the problem
		return *first, nil
	}

	if first != nil {
		return state.Host{}, errors.New("no mon host answers with a running mon")
	}

	return state.Host{}, errors.New("no mon in the inventory")
}

func (o *Orch) deployMon(ctx context.Context, h state.Host) error {
	d := state.Daemon{Type: state.TypeMon, ID: h.Name, Host: h.Name, DeployID: randHex(8)}
	if _, ok := o.St.Find("mon." + h.Name); ok {
		return fmt.Errorf("mon.%s already exists", h.Name)
	}

	monKey, err := o.key("mon.")
	if err != nil {
		return err
	}

	adm, err := o.adminKeyring()
	if err != nil {
		return err
	}

	doc := daemons.Mon(daemons.Params{
		Name: o.St.DocName(d), Image: o.St.Image, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr,
		// mon. to mkfs, client.admin to fetch the monmap from the quorum
		Keyring: daemons.Keyring("mon.", monKey, "mon", "allow *") + adm,
		Mode:    "join", Addrv: monAddrv(h.Addr), DeployID: d.DeployID,
	})

	if err := o.apply(ctx, h.Addr, doc); err != nil {
		return err
	}

	o.St.AddDaemon(d)

	if err := o.save(); err != nil {
		return err
	}

	if err := o.waitRunning(ctx, h.Addr, o.St.DocName(d), 10*time.Minute); err != nil {
		return err
	}

	admHost, err := o.adminHost()
	if err != nil {
		return err
	}

	// a running container is not a working mon: wait for it to join the quorum
	quorum := fmt.Sprintf(`for i in $(seq 100); do ceph quorum_status --format json | python3 -c 'import json,sys; sys.exit(0 if %q in json.load(sys.stdin)["quorum_names"] else 1)' && exit 0; sleep 3; done; echo "mon.%s did not join the quorum" >&2; exit 1`, h.Name, h.Name)
	if _, err := o.Job(ctx, admHost.Addr, quorum, 10*time.Minute); err != nil {
		return err
	}

	// only advertise the new mon once it runs, so clients never start against an empty address
	return o.pushConf(ctx)
}

func (o *Orch) deployMgr(ctx context.Context, h state.Host) error {
	d := state.Daemon{Type: state.TypeMgr, ID: h.Name, Host: h.Name}
	if _, ok := o.St.Find("mgr." + h.Name); ok {
		return fmt.Errorf("mgr.%s already exists", h.Name)
	}

	entity := "mgr." + h.Name

	k, err := o.key(entity)
	if err != nil {
		return err
	}

	adm, err := o.adminHost()
	if err != nil {
		return err
	}

	// register the key: there is no mon keyring to put it in after bootstrap
	kr := daemons.Keyring(entity, k, "mon", "profile mgr", "osd", "allow *", "mds", "allow *")
	if _, err := o.Job(ctx, adm.Addr, fmt.Sprintf("echo %s | base64 -d | ceph auth import -i -", base64Std(kr)), 5*time.Minute); err != nil {
		return err
	}

	doc := daemons.Mgr(daemons.Params{
		Name: o.St.DocName(d), Image: o.St.Image, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr,
		Keyring: daemons.Keyring(entity, k),
	}, mgrmodule.Names()...)

	// the mgr starts only once the talos module's files are on the host
	if err := o.apply(ctx, h.Addr, append(o.mgrFileDocs(true), doc)...); err != nil {
		return err
	}

	o.St.AddDaemon(d)

	if err := o.save(); err != nil {
		return err
	}

	return o.waitRunning(ctx, h.Addr, o.St.DocName(d), 10*time.Minute)
}

func (o *Orch) deployOSD(ctx context.Context, h state.Host, device string) error {
	if !strings.HasPrefix(device, "/dev/") {
		return fmt.Errorf("device must be a /dev path, got %q", device)
	}

	d := state.Daemon{Type: state.TypeOSD, ID: h.Name + "-" + filepath.Base(device), Host: h.Name, Device: device, DeployID: randHex(8), OSDUUID: newUUID()}
	if _, ok := o.St.Find("osd." + d.ID); ok {
		return fmt.Errorf("osd on %s:%s already exists", h.Name, device)
	}

	k, err := o.key("client.bootstrap-osd")
	if err != nil {
		return err
	}

	doc := daemons.OSD(daemons.Params{
		Name: o.St.DocName(d), Image: o.St.Image, FSID: o.St.FSID, ID: d.ID, Addr: h.Addr,
		Keyring: daemons.Keyring("client.bootstrap-osd", k), Device: device, DeployID: d.DeployID, OSDUUID: d.OSDUUID,
	})

	if err := o.apply(ctx, h.Addr, doc); err != nil {
		return err
	}

	o.St.AddDaemon(d)

	if err := o.save(); err != nil {
		return err
	}

	if err := o.waitRunning(ctx, h.Addr, o.St.DocName(d), 10*time.Minute); err != nil {
		return err
	}

	// the OSD id is allocated by `ceph osd new` inside the container; it reports it on stdout
	id, uuid, err := o.waitOSDID(ctx, h.Addr, d, 10*time.Minute)
	if err != nil {
		return err
	}

	// older ceph-volume cannot prepare with a given uuid; the marker carries our
	// deploy id, so the uuid it reports is the one this deployment created
	d.OSDID, d.OSDUUID = &id, uuid
	o.St.AddDaemon(d)

	if err := o.save(); err != nil {
		return err
	}

	// the container running says nothing about the OSD being usable: wait for it to be up in the map
	adm, err := o.adminHost()
	if err != nil {
		return err
	}

	if _, err := o.Job(ctx, adm.Addr, osdUpLoop(id, uuid), 10*time.Minute); err != nil {
		return fmt.Errorf("osd.%d did not come up: %w", id, err)
	}

	o.printf("osd.%d up on %s:%s\n", id, h.Name, device)

	return nil
}

// waitOSDID reads the id and uuid an OSD container reports for this deployment.
func (o *Orch) waitOSDID(ctx context.Context, node string, d state.Daemon, timeout time.Duration) (int, string, error) {
	if o.Talos.DryRun {
		return 0, "", nil
	}

	name := o.St.DocName(d)
	deadline := time.Now().Add(timeout)

	for {
		if logs, err := o.Talos.Logs(ctx, node, name); err == nil {
			if id, uuid, ok := parseOSDMarker(logs, d.DeployID); ok {
				return id, uuid, nil
			}

			if msg, ok := parseMarker(logs, "CEPHADM-TALOS-OSD-ERROR=", d.DeployID); ok {
				return 0, "", fmt.Errorf("%s: %s", name, msg)
			}
		}

		if time.Now().After(deadline) {
			return 0, "", fmt.Errorf("timed out waiting for %s to report its OSD id, see `cephadm-talos logs`", name)
		}

		if err := sleep(ctx, 3*time.Second); err != nil {
			return 0, "", err
		}
	}
}

// osdUpLoop waits (inside a job) until osd <id> with this uuid is up, judged
// from one osd map snapshot per try; anything else fails after ~5 minutes.
func osdUpLoop(id int, uuid string) string {
	check := fmt.Sprintf(`import json,sys; sys.exit(0 if any(o["osd"]==%d and o["uuid"]=="%s" and o["up"] for o in json.load(sys.stdin)["osds"]) else 1)`, id, uuid)

	return fmt.Sprintf(`for i in $(seq 100); do ceph osd dump --format json | python3 -c '%s' && exit 0; sleep 3; done; echo "osd.%d (%s) not up" >&2; exit 1`, check, id, uuid)
}

// parseMarker returns the rest of the last "<prefix><deploy id> <msg>" line.
func parseMarker(logs, prefix, deployID string) (string, bool) {
	msg, found := "", false

	for _, l := range strings.Split(logs, "\n") {
		if _, v, ok := strings.Cut(l, prefix); ok {
			if id, rest, ok := strings.Cut(v, " "); ok && id == deployID {
				msg, found = rest, true
			}
		}
	}

	return msg, found
}

// parseOSDMarker finds the last "CEPHADM-TALOS-OSD-ID=<deploy id> <osd id> <uuid>" line of a deployment.
func parseOSDMarker(logs, deployID string) (int, string, bool) {
	var (
		id    int
		uuid  string
		found bool
	)

	for _, l := range strings.Split(logs, "\n") {
		_, v, ok := strings.Cut(l, "CEPHADM-TALOS-OSD-ID=")
		if !ok {
			continue
		}

		f := strings.Fields(v)
		if len(f) != 3 || f[0] != deployID {
			continue
		}

		if n, err := strconv.Atoi(f[1]); err == nil {
			id, uuid, found = n, f[2], true
		}
	}

	return id, uuid, found
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// waitRunning waits until a container is in state running.
func (o *Orch) waitRunning(ctx context.Context, node, name string, timeout time.Duration) error {
	if o.Talos.DryRun {
		return nil
	}

	o.printf("waiting for %s on %s ", name, node)
	defer o.printf("\n")

	last := ""

	err := o.Talos.WaitFor(ctx, node, talos.StatusTypes, timeout, func(ctx context.Context) (bool, error) {
		st, err := o.Talos.ContainerStatuses(ctx, node)
		if err != nil {
			return false, talos.Permanent(err)
		}

		s, ok := st[name]
		if !ok {
			return false, nil
		}

		if s.State.String() != last {
			o.printf("[%s]", s.State)
			last = s.State.String()
		}

		return s.State == containers.ContainerStateRunning, nil
	})
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return fmt.Errorf("timed out waiting for %s to run (last state %q)", name, last)
	}

	return err
}

// waitImage waits until a container runs the given image (after an upgrade patch).
//
// ContainerStatus reports the running image as a digest, so the requested
// reference is resolved through the container's ContainerImageStatus first.
func (o *Orch) waitImage(ctx context.Context, node, name, image string, timeout time.Duration) error {
	if o.Talos.DryRun {
		return nil
	}

	err := o.Talos.WaitFor(ctx, node, talos.ImageTypes, timeout, func(ctx context.Context) (bool, error) {
		img, err := o.Talos.ImageStatus(ctx, node, name)
		if err != nil {
			return false, talos.Permanent(err)
		}

		if !sameImage(img.Image, image) {
			return false, nil
		}

		if img.Error != "" {
			return false, fmt.Errorf("pulling %s for %s: %s", image, name, img.Error)
		}

		if img.Phase != containers.ContainerImagePhaseReady || img.Digest == "" {
			return false, nil
		}

		st, err := o.Talos.ContainerStatuses(ctx, node)
		if err != nil {
			return false, talos.Permanent(err)
		}

		s, ok := st[name]

		return ok && s.State == containers.ContainerStateRunning && s.Image == img.Digest, nil
	})
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		return fmt.Errorf("timed out waiting for %s to run %s", name, image)
	}

	return err
}

// sameImage compares image references; Talos normalizes short references
// (ceph/ceph:v20 becomes docker.io/ceph/ceph:v20).
func sameImage(normalized, want string) bool {
	return normalized == want || strings.HasSuffix(normalized, "/"+want)
}
