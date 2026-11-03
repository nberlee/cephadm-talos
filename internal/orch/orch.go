// Package orch implements the cephadm-talos commands: the cephadm-like orchestration
// of Ceph daemons as Talos ContainerConfig documents.
package orch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/cephx"
	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

// DefaultImage is the Ceph container image used when none is given.
const DefaultImage = "quay.io/ceph/ceph:v21"

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

	// st is the cluster's state in the store, once a mon answers (plan 03, item 4)
	st *store.Store
	// secrets are the state's private keys and passwords (store.SecretPrefix)
	secrets store.Backend
	// opened: the cluster's state was read from its mons
	opened bool
	// inspectMon replaces the inspection job of a mon's store in tests
	inspectMon func(h state.Host) (string, error)
	// settleSelf replaces the records job that settles a self-update in tests
	settleSelf func(h state.Host) (agent.RecordsReport, error)

	// incarnation is the one the state was read from: "cli", or a leader's
	incarnation string
	// sealed, handingOver: the state read was handed over, or being handed over
	sealed, handingOver bool
	// handoff lets the handoff itself save while the state is being handed over
	handoff bool
	// StoreBackend replaces config-key through exec (tests)
	StoreBackend store.Backend
	// AuthGet replaces `auth get` through exec (tests)
	AuthGet func(entity string) (key string, found bool, err error)
	// CRLFailClosed is bootstrap's choice of the agents' revocation list
	// policy (--crl-fail-closed, plan 04 step 3)
	CRLFailClosed bool
	// RevokeCert replaces `ceph orch talos revoke` through exec (tests)
	RevokeCert func(ctx context.Context, serial string, until time.Time) error
	// crl is the agent CA's revocation list the CLI holds (CRL)
	crl *crl.Holder
}

// Managed reports whether the leader owns the cluster state (plan 03, step
// 6): once the CLI sealed its state with a handoff, and once a leader
// published its own. The CLI then only reads and changes nothing on the nodes.
func (o *Orch) Managed() bool {
	return o.incarnation != "" && o.incarnation != Incarnation || o.sealed || o.handingOver
}

// ErrManaged is returned for a change the leader makes now.
var ErrManaged = errors.New("the cluster is managed by its leader: change it with `cephadm-talos shell -- ceph orch ...`")

// Incarnation is the store namespace the CLI publishes in until the leader
// takes over (plan 03, step 4).
const Incarnation = "cli"

// Open reads the cluster's state from the store through the first node that
// answers, after state.Load read the workstation's part.
func (o *Orch) Open(ctx context.Context) error {
	// reading the state changes nothing: a dry run reads the real state too
	defer o.reading()()

	var errs []error

	for _, h := range o.St.Hosts {
		// the current state: the CLI's, or a leader's once one took over
		inc, err := o.chooseIncarnation(ctx, h.Addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", h.Name, err))

			continue
		}

		o.incarnation = inc

		if err := o.openStore(ctx, h.Addr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", h.Name, err))

			continue
		}

		m, err := o.st.Latest(ctx)
		if err != nil {
			return fmt.Errorf("reading the cluster state: %w", err)
		}

		recs := map[string][]byte{}

		for name := range m.Records {
			if recs[name], err = o.st.Read(ctx, m, name); err != nil {
				return fmt.Errorf("reading the cluster state: %w", err)
			}
		}

		if err := o.St.ApplyRecords(recs); err != nil {
			return err
		}

		o.opened, o.sealed, o.handingOver = true, o.St.Sealed, o.St.HandingOver

		// the private keys, for a CLI that still writes the state
		if !o.Managed() {
			if err := o.openSecrets(ctx, h.Addr); err != nil {
				return err
			}

			if err := o.readSecrets(ctx); err != nil {
				return err
			}
		}

		return nil
	}

	return fmt.Errorf("no node with a running Ceph daemon and a mon answers; the cluster state is in its mons: %w", errors.Join(errs...))
}

// reading lets a dry run read the cluster (state, mon auth) for the duration of
// a call that only reads; it returns the function that restores dry-run mode.
func (o *Orch) reading() func() {
	if !o.Talos.DryRun {
		return func() {}
	}

	o.Talos.DryRun = false

	return func() { o.Talos.DryRun = true }
}

func (o *Orch) storeIncarnation() string {
	if o.incarnation == "" {
		return Incarnation
	}

	return o.incarnation
}

// openStore opens the store through a Ceph container on node.
func (o *Orch) openStore(ctx context.Context, node string) error {
	if o.StoreBackend != nil {
		o.st = &store.Store{B: o.StoreBackend, Incarnation: o.storeIncarnation()}

		return nil
	}

	ck, err := o.configKeys(ctx, node, store.Prefix+"inc/"+o.storeIncarnation()+"/")
	if err != nil {
		return err
	}

	o.st = &store.Store{B: ck, Incarnation: o.storeIncarnation()}

	return nil
}

// LoadSecrets reads the secrets into the state also when the cluster is
// managed, for test tools that act as an agent; the state stays read-only.
func (o *Orch) LoadSecrets(ctx context.Context) error {
	if len(o.St.Hosts) == 0 {
		return errors.New("no host to read the secrets through")
	}

	if err := o.openSecrets(ctx, o.St.Hosts[0].Addr); err != nil {
		return err
	}

	return o.readSecrets(ctx)
}

// openSecrets opens the secrets, which only the CLI before the handoff reads
// and writes, through a Ceph container on node.
func (o *Orch) openSecrets(ctx context.Context, node string) (err error) {
	if o.StoreBackend != nil {
		o.secrets = o.StoreBackend

		return nil
	}

	o.secrets, err = o.configKeys(ctx, node, store.SecretPrefix)

	return err
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
// key returns client.admin's secret, which the workstation keeps (local.json),
// or an existing entity's secret from mon auth.
func (o *Orch) key(entity string) (string, error) {
	if entity == "client.admin" {
		if k, ok := o.St.Keys[entity]; ok {
			return k, nil
		}

		return o.newKey(entity) // bootstrap creates it
	}

	return o.existingKey(entity)
}

// existingKey returns the secret of an entity mon auth must already know (plan
// 03, item 4): rendering an existing daemon never invents a key.
func (o *Orch) existingKey(entity string) (string, error) {
	if k, ok := o.St.Keys[entity]; ok {
		return k, nil
	}

	if o.st == nil {
		return "", fmt.Errorf("the key of %s is in mon auth, which is not reachable", entity)
	}

	k, found, err := o.lookupKey(entity)
	if err != nil {
		return "", err
	}

	if !found {
		return "", fmt.Errorf("%s is not in mon auth", entity)
	}

	o.St.Keys[entity] = k

	return k, nil
}

// newKey returns the secret for an entity being created: the one mon auth
// already has (a retried deploy), or a new one, which the caller registers
// (importKey, or the mon keyring at bootstrap).
func (o *Orch) newKey(entity string) (string, error) {
	if k, ok := o.St.Keys[entity]; ok {
		return k, nil
	}

	if o.st != nil {
		k, found, err := o.lookupKey(entity)
		if err != nil {
			return "", err
		}

		if found {
			o.St.Keys[entity] = k

			return k, nil
		}
	}

	k, err := cephx.NewKey()
	if err != nil {
		return "", err
	}

	o.St.Keys[entity] = k

	return k, nil
}

func (o *Orch) lookupKey(entity string) (string, bool, error) {
	if o.AuthGet != nil {
		return o.AuthGet(entity)
	}

	defer o.reading()()

	return o.authGet(entity)
}

// importKey registers a keyring with mon auth; the keyring goes over stdin,
// never on a command line, which Talos audits.
func (o *Orch) importKey(ctx context.Context, keyring string) error {
	if o.Talos.DryRun {
		return nil
	}

	adm, err := o.adminHost()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, configKeyTimeout)
	defer cancel()

	var errb bytes.Buffer

	rc, _, err := o.execAdmin(ctx, adm.Addr, []string{"ceph", "auth", "import", "-i", "-"}, []byte(keyring), &errb, &errb)
	if err != nil {
		return err
	}

	if rc != 0 {
		return fmt.Errorf("auth import: rc %d: %s", rc, strings.TrimSpace(errb.String()))
	}

	return nil
}

// authGet reads an entity's secret from mon auth.
func (o *Orch) authGet(entity string) (string, bool, error) {
	adm, err := o.adminHost()
	if err != nil {
		return "", false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), configKeyTimeout)
	defer cancel()

	var out, errb bytes.Buffer

	rc, _, err := o.execAdmin(ctx, adm.Addr, []string{"ceph", "auth", "get", entity, "--format", "json"}, nil, &out, &errb)
	if err != nil {
		return "", false, err
	}

	if rc == 2 { // ENOENT
		return "", false, nil
	}

	if rc != 0 {
		return "", false, fmt.Errorf("auth get %s: rc %d: %s", entity, rc, strings.TrimSpace(errb.String()))
	}

	var ents []struct {
		Entity string `json:"entity"`
		Key    string `json:"key"`
	}

	if err := json.Unmarshal(out.Bytes(), &ents); err != nil || len(ents) != 1 || ents[0].Entity != entity || ents[0].Key == "" {
		return "", false, fmt.Errorf("auth get %s: unexpected answer", entity)
	}

	return ents[0].Key, true, nil
}

// CephConf renders the minimal ceph.conf shared by all daemons on all hosts.
func (o *Orch) CephConf() string { return render.CephConf(o.St) }

func monAddrv(ip string) string { return daemons.MonAddrv(ip) }

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
// /var/lib/ceph volume, ceph.conf, the node agent and the mgr files.
func (o *Orch) hostDocs(h state.Host) ([]any, error) {
	mgr, err := o.mgrFileDocs(h, o.hasMgr(h))
	if err != nil {
		return nil, err
	}

	docs := append([]any{render.Volume(), spec.CephConf(o.CephConf())}, o.agentDocs(h)...)

	return append(docs, mgr...), nil
}

// pushConf rewrites ceph.conf on every host (after the mon set changed).
//
// An unreachable host does not stop the others; it is remembered in
// ConfPending and retried by the next command (see RetryPendingConf).
func (o *Orch) pushConf(ctx context.Context) error {
	var failed []string

	for _, h := range o.St.Hosts {
		o.printf("updating ceph.conf on %s\n", h.Name)

		docs, err := o.hostDocs(h)
		if err == nil {
			err = o.apply(ctx, h.Addr, docs...)
		}

		if err != nil {
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

	return o.checkCPU(ctx, node)
}

// x86-64-v3 is the CPU level Ceph 21's official builds need (cephadm's
// UPGRADE_MIN_X86_64_ISA_LEVEL): the flags /proc/cpuinfo shows for the v2
// and v3 levels (lzcnt as abm). A CPU without them crashes the daemons with
// SIGILL.
var x8664v3Flags = []string{"cx16", "lahf_lm", "popcnt", "sse4_1", "sse4_2", "ssse3", "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe", "xsave"}

// checkCPU verifies the node's CPU supports x86-64-v3.
func (o *Orch) checkCPU(ctx context.Context, node string) error {
	b, err := o.Talos.ReadFile(ctx, node, "/proc/cpuinfo", 1<<20)
	if err != nil {
		return fmt.Errorf("node %s: reading its CPU flags: %w", node, err)
	}

	if missing := missingFlags(string(b), x8664v3Flags); len(missing) > 0 {
		return fmt.Errorf("node %s's CPU does not support x86-64-v3, which Ceph %s needs (missing %s)", node, SupportedCeph, strings.Join(missing, ", "))
	}

	return nil
}

// missingFlags are the flags the first CPU of a /proc/cpuinfo lacks; all of
// them without a flags line.
func missingFlags(cpuinfo string, want []string) []string {
	have := map[string]bool{}

	for _, line := range strings.Split(cpuinfo, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(k) == "flags" {
			for _, f := range strings.Fields(v) {
				have[f] = true
			}

			break
		}
	}

	var out []string

	for _, f := range want {
		if !have[f] {
			out = append(out, f)
		}
	}

	return out
}

// hostName checks a node's hostname: a part of its certificate identities
// (plan 03, item 3), and lowercase, as Ceph 21 lowercases the host names of
// its specs.
func hostName(name string) error {
	if err := pki.ValidName(name); err != nil {
		return err
	}

	if name != strings.ToLower(name) {
		return fmt.Errorf("host name %q is not supported: Ceph uses host names in lowercase; give the node a lowercase hostname", name)
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

	if err := hostName(name); err != nil {
		return state.Host{}, err
	}

	h := state.Host{Name: name, Addr: addr}

	// re-adding a known host must not drop its maintenance bookkeeping
	if old, ok := o.St.Host(name); ok {
		h.Maintenance, h.NoOut = old.Maintenance, old.NoOut
		h.Talosconfig, h.Context = old.Talosconfig, old.Context
		h.AgentCert, h.AgentKey, h.AgentClientCert, h.AgentClientKey = old.AgentCert, old.AgentKey, old.AgentClientCert, old.AgentClientKey
		h.MgrServerCert, h.MgrServerKey, h.MgrClientCert, h.MgrClientKey = old.MgrServerCert, old.MgrServerKey, old.MgrClientCert, old.MgrClientKey
	}

	if err := o.ensureAgentCert(&h); err != nil {
		return h, err
	}

	o.St.AddHost(h)

	if !apply {
		return h, nil
	}

	docs, err := o.hostDocs(h)
	if err != nil {
		return h, err
	}

	if err := o.apply(ctx, addr, docs...); err != nil {
		return h, err
	}

	o.printf("added host %s (%s)\n", name, addr)

	return h, o.save()
}

// save writes the workstation's part and, once a mon answers, publishes the
// cluster's part (with the mgr module's inventory) to the store.
func (o *Orch) save() error {
	if o.Talos.DryRun {
		return nil
	}

	if o.Managed() && !o.handoff {
		return ErrManaged
	}

	if err := o.St.Save(); err != nil {
		return err
	}

	if o.st == nil {
		return nil // bootstrap, before the first mon: published once it answers
	}

	// the mgr module's inventory (plan 02's schema), now a record of the state:
	// its revision and time change only with its content
	inv, rev, err := render.InventoryRecord(o.St, time.Now())
	if err != nil {
		return err
	}

	o.St.Inventory = rev

	recs, err := o.St.Records() // the cluster record carries the revision
	if err != nil {
		return err
	}

	recs["inventory"] = inv

	ctx, cancel := context.WithTimeout(context.Background(), configKeyTimeout)
	defer cancel()

	// the keys first: a certificate in the state is never newer than its key.
	// A handoff changes no secret, and a resumed one has not read them.
	if !o.Managed() {
		if err := o.writeSecrets(ctx); err != nil {
			return fmt.Errorf("writing the cluster's secrets: %w", err)
		}
	}

	if _, err := o.st.Publish(ctx, recs); err != nil {
		return fmt.Errorf("publishing the cluster state: %w", err)
	}

	return nil
}

// secret looks a secret up in the state the CLI loaded (render.Secret).
func (o *Orch) secret(name string) (string, error) {
	if v := o.St.Secrets()[name]; v != "" {
		return v, nil
	}

	return "", fmt.Errorf("the cluster has no secret %s", name)
}

// readSecrets fills the state's private keys and passwords in from their
// entries below store.SecretPrefix.
func (o *Orch) readSecrets(ctx context.Context) error {
	keys, err := o.secrets.List(ctx, store.SecretPrefix)
	if err != nil {
		return err
	}

	sec := map[string]string{}

	for _, k := range keys {
		v, err := o.secrets.Get(ctx, k)
		if err != nil {
			return err
		}

		sec[strings.TrimPrefix(k, store.SecretPrefix)] = string(v)
	}

	o.St.ApplySecrets(sec)

	return nil
}

// writeSecrets makes the entries below store.SecretPrefix the state's
// secrets: changed and new ones written, gone ones removed.
func (o *Orch) writeSecrets(ctx context.Context) error {
	if o.secrets == nil {
		return errors.New("the secrets are not open")
	}

	want := o.St.Secrets()

	keys, err := o.secrets.List(ctx, store.SecretPrefix)
	if err != nil {
		return err
	}

	var (
		set  []store.KV
		gone []string
	)

	have := map[string]bool{}

	for _, k := range keys {
		name := strings.TrimPrefix(k, store.SecretPrefix)
		have[name] = true

		if _, ok := want[name]; !ok {
			gone = append(gone, k)
		}
	}

	for name, v := range want {
		if have[name] {
			if cur, err := o.secrets.Get(ctx, store.SecretPrefix+name); err == nil && string(cur) == v {
				continue
			}
		}

		set = append(set, store.KV{Key: store.SecretPrefix + name, Value: []byte(v)})
	}

	sort.Slice(set, func(i, j int) bool { return set[i].Key < set[j].Key })

	if len(set) > 0 {
		if err := o.secrets.SetMany(ctx, set); err != nil {
			return err
		}
	}

	if len(gone) > 0 {
		return o.secrets.Remove(ctx, gone)
	}

	return nil
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

	// bootstrap places the first mgr on this host
	if err := o.ensureMgrCerts(&h, true); err != nil {
		return err
	}

	o.St.AddHost(h)

	o.printf("bootstrapping cluster %s on %s with %s\n", o.St.FSID, h.Name, image)

	mon := state.Daemon{Type: state.TypeMon, ID: h.Name, Host: h.Name, DeployID: randHex(8)}
	mgr := state.Daemon{Type: state.TypeMgr, ID: h.Name, Host: h.Name}
	o.St.AddDaemon(mon)
	o.St.AddDaemon(mgr)

	monKey, err := o.newKey("mon.")
	if err != nil {
		return err
	}

	mgrKey, err := o.newKey("mgr." + h.Name)
	if err != nil {
		return err
	}

	osdKey, err := o.newKey("client.bootstrap-osd")
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
	mgrDoc, err := render.Daemon(o.St, h, mgr, image, func(string) (string, error) { return mgrKey, nil }, o.secret)
	if err != nil {
		return err
	}

	// the state, the first revision and the pending host are saved before the
	// node is patched: an interrupted bootstrap leaves a state to clean up from
	o.bumpPublished()
	o.St.ConfPending = []string{h.Name}

	if err := o.save(); err != nil {
		return err
	}

	docs, err := o.hostDocs(h)
	if err != nil {
		return err
	}

	if err := o.apply(ctx, h.Addr, append(docs, monDoc, mgrDoc)...); err != nil {
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

	// from here on the cluster's state lives in the mons: the first publication
	if !o.Talos.DryRun {
		if err := o.openStore(ctx, h.Addr); err != nil {
			return err
		}

		if err := o.openSecrets(ctx, h.Addr); err != nil {
			return err
		}

		if err := o.save(); err != nil {
			return err
		}
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

	// a joining mon with the mon. key only (plan 03, item 13)
	doc, err := render.Daemon(o.St, h, d, o.St.Image, func(string) (string, error) { return monKey, nil }, o.secret)
	if err != nil {
		return err
	}

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

	k, err := o.newKey(entity)
	if err != nil {
		return err
	}

	// register the key: there is no mon keyring to put it in after bootstrap
	if err := o.importKey(ctx, daemons.Keyring(entity, k, "mon", "profile mgr", "osd", "allow *", "mds", "allow *")); err != nil {
		return err
	}

	doc, err := render.Daemon(o.St, h, d, o.St.Image, func(string) (string, error) { return k, nil }, o.secret)
	if err != nil {
		return err
	}

	// the mgr's own server and client certificates for the agent channel
	if err := o.ensureMgrCerts(&h, true); err != nil {
		return err
	}

	o.St.AddHost(h)

	// the mgr starts only once the talos module's files are on the host
	mgrFiles, err := o.mgrFileDocs(h, true)
	if err != nil {
		return err
	}

	if err := o.apply(ctx, h.Addr, append(mgrFiles, doc)...); err != nil {
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

	serial, byID, err := o.diskIdentity(ctx, h.Addr, device)
	if err != nil {
		return err
	}

	d := state.Daemon{Type: state.TypeOSD, ID: h.Name + "-" + filepath.Base(device), Host: h.Name, Device: device, DeployID: randHex(8), DiskSerial: serial, DevicePath: byID}
	if _, ok := o.St.Find("osd." + d.ID); ok {
		return fmt.Errorf("osd on %s:%s already exists", h.Name, device)
	}

	k, err := o.key("client.bootstrap-osd")
	if err != nil {
		return err
	}

	// the deployment, cluster and disk identity are recorded before anything
	// touches the disk (plan 03, item 8)
	o.St.AddDaemon(d)

	if err := o.save(); err != nil {
		return err
	}

	job, err := render.OSDPrepare(o.St, h, d, func(string) (string, error) { return k, nil })
	if err != nil {
		return err
	}

	o.printf("preparing %s:%s (%s)\n", h.Name, device, byID)

	res, err := o.runJob(ctx, h.Addr, job, d.DeployID, 15*time.Minute)
	if err != nil {
		return fmt.Errorf("preparing %s:%s did not finish; nothing is retried automatically: check the device and the cluster, then `cephadm-talos rm --force %s`: %w",
			h.Name, device, displayName(d), err)
	}

	id, uuid := 0, "dry-run"
	if !o.Talos.DryRun {
		if id, uuid, err = parsePrepared(res.Output); err != nil {
			return fmt.Errorf("preparing %s:%s: %w", h.Name, device, err)
		}
	}

	d.OSDID, d.OSDUUID = &id, uuid
	o.St.AddDaemon(d)

	if err := o.save(); err != nil {
		return err
	}

	doc, err := render.Daemon(o.St, h, d, o.St.Image, o.key, o.secret)
	if err != nil {
		return err
	}

	if err := o.apply(ctx, h.Addr, doc); err != nil {
		return err
	}

	if err := o.waitRunning(ctx, h.Addr, o.St.DocName(d), 10*time.Minute); err != nil {
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

// osdPrepareInputs binds an OSD's prepare job to its cluster, host, device,
// disk and deployment.
func (o *Orch) osdPrepareInputs(h state.Host, d state.Daemon) string {
	return render.OSDPrepareInputs(o.St, h, d)
}

func (o *Orch) osdPrepareDocName(d state.Daemon) string { return render.OSDPrepareName(o.St, d) }

// diskIdentity returns the serial Talos reports for a device and its
// /dev/disk/by-id link that carries that serial. A disk without both cannot be
// bound to an OSD.
func (o *Orch) diskIdentity(ctx context.Context, node, device string) (string, string, error) {
	if o.Talos.DryRun {
		// a stable device as Talos would report it, so the dry run renders what the real one does
		return "dry-run", "/dev/disk/by-id/dry-run-" + filepath.Base(device), nil
	}

	disks, err := o.Talos.Disks(ctx, node)
	if err != nil {
		return "", "", err
	}

	for _, disk := range disks {
		ds := disk.TypedSpec()
		if ds.DevPath != device {
			continue
		}

		serial := strings.TrimSpace(ds.Serial)
		if serial == "" {
			return "", "", fmt.Errorf("%s has no serial number: an OSD cannot be bound to it", device)
		}

		for _, l := range ds.Symlinks {
			if strings.HasPrefix(l, "/dev/disk/by-id/") && strings.Contains(l, serial) {
				return serial, l, nil
			}
		}

		return "", "", fmt.Errorf("%s (serial %s) has no /dev/disk/by-id link with its serial: an OSD cannot be bound to it", device, serial)
	}

	return "", "", fmt.Errorf("no disk %s on %s", device, node)
}

// parsePrepared reads the id and uuid an osd-prepare job reported.
func parsePrepared(out string) (int, string, error) {
	var (
		id   = -1
		uuid string
	)

	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "osd_id "); ok {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				id = n
			}
		}

		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "osd_uuid "); ok {
			uuid = v
		}
	}

	if id < 0 || uuid == "" {
		return 0, "", fmt.Errorf("the prepare job reported no OSD id and uuid")
	}

	return id, uuid, nil
}

// preparedOSD recovers an OSD's identity from its own deployment's prepare
// result on the host, for a deploy that was interrupted after prepare.
func (o *Orch) preparedOSD(ctx context.Context, h state.Host, d state.Daemon) (int, string, error) {
	b, err := o.Talos.ReadFile(ctx, h.Addr, jobsHostDir+"/"+o.St.FSID+"."+d.DeployID+".result", maxJobResult)
	if err != nil {
		return 0, "", fmt.Errorf("no prepare result for %s: %w", displayName(d), err)
	}

	res, inputs, err := parseJobResult(b)
	if err != nil {
		return 0, "", err
	}

	if inputs != o.osdPrepareInputs(h, d) || res.RC != 0 {
		return 0, "", fmt.Errorf("the prepare result of %s is not a successful one of this deployment", displayName(d))
	}

	return parsePrepared(res.Output)
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

// osdUpLoop waits (as an admin command) until osd <id> with this uuid is up, judged
// from one osd map snapshot per try; anything else fails after ~5 minutes.
func osdUpLoop(id int, uuid string) string {
	check := fmt.Sprintf(`import json,sys; sys.exit(0 if any(o["osd"]==%d and o["uuid"]=="%s" and o["up"] for o in json.load(sys.stdin)["osds"]) else 1)`, id, uuid)

	return fmt.Sprintf(`for i in $(seq 100); do ceph osd dump --format json | python3 -c '%s' && exit 0; sleep 3; done; echo "osd.%d (%s) not up" >&2; exit 1`, check, id, uuid)
}
