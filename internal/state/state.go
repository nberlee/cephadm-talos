// Package state is the cluster inventory (plan 03, item 4). It lives in the mon
// config-key store as records (internal/store), like cephadm's module store;
// the workstation keeps only what a cephadm admin host keeps, in local.json:
// the fsid, how to reach each node (talosconfig, context, address), the
// operator certificate and the admin key. Daemon keys live only in mon auth.
package state

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// SchemaVersion is the state.json schema this build reads and writes. Before
// the first tagged release there are no migrations: any other version is refused.
const SchemaVersion = 2

// Daemon types.
const (
	TypeMon = "mon"
	TypeMgr = "mgr"
	TypeOSD = "osd"
	TypeRGW = "rgw"
	TypeVIP = "vip" // keepalived holding the RGW virtual IP
)

// Host is a Talos node that is part of the Ceph cluster.
type Host struct {
	Name string `json:"name"` // Talos hostname, used as mon/mgr id
	Addr string `json:"addr"` // node IP, used both for talosctl -n and as Ceph public addr
	// Maintenance: the host's daemons are stopped (their documents removed) and noout
	// is set for it, like `ceph orch host maintenance enter`
	Maintenance bool `json:"maintenance,omitempty"`
	// NoOut: the CLI's maintenance enter (before the handoff) set `osd set-group
	// noout` on this host's CRUSH bucket; after the handoff the mgr module's
	// ledger owns noout (plan 04, step 5)
	NoOut bool `json:"noout,omitempty"`
	// Drain is the host's drain in progress (plan 04, step 5)
	Drain *Drain `json:"drain,omitempty"`
	// Move is the host's address change in progress (plan 04, step 5)
	Move *Move `json:"move,omitempty"`
	// Labels are the host's labels from `ceph orch host add` (stored only)
	Labels []string `json:"labels,omitempty"`
	// Talosconfig and Context override the cluster defaults for this node, so
	// nodes need not share one talosconfig
	Talosconfig string `json:"talosconfig,omitempty"`
	Context     string `json:"context,omitempty"`
	// AgentCert and AgentKey are the agent's server certificate, AgentClientCert
	// and AgentClientKey its client certificate (agent CA, identity agent/<host>)
	// The private keys are secrets: not in the published state (Secrets)
	AgentCert       string `json:"agent_cert,omitempty"`
	AgentKey        string `json:"-"`
	AgentClientCert string `json:"agent_client_cert,omitempty"`
	AgentClientKey  string `json:"-"`
	// AgentKeys, set for agent certificates the mgr module issued (plan 04,
	// step 2), names the secrets of their keys, "<operation>/<attempt>"
	// (SecretIssued); without it the keys are the CLI's (SecretHost)
	AgentKeys string `json:"agent_keys,omitempty"`
	// MgrServerCert, MgrClientCert and their keys are the certificates of the
	// mgr on this host (agent CA, identity mgr/<host>), set while it has one
	MgrServerCert string `json:"mgr_server_cert,omitempty"`
	MgrServerKey  string `json:"-"`
	MgrClientCert string `json:"mgr_client_cert,omitempty"`
	MgrClientKey  string `json:"-"`
	// MgrKeys, set for certificates the mgr module issued, names the secrets
	// of their keys, "<operation>/<attempt>" (SecretIssued); without it the
	// keys are the CLI's (SecretHost)
	MgrKeys string `json:"mgr_keys,omitempty"`
}

// Drain is a host's drain (`ceph orch host drain`, plan 04 step 5): its steps
// run between ledger operations, one at a time, each journaled as
// <Op>.d<Attempt>.
type Drain struct {
	Op  string `json:"op"`
	Zap bool   `json:"zap,omitempty"` // --zap-osd-devices
	// Step is the step in progress: "out" (every OSD of the host marked out
	// at once) or the daemon it removes ("osd.3", "rgw.<host>", ...)
	Step    string `json:"step,omitempty"`
	Attempt int    `json:"attempt,omitempty"`
	// First is the attempt the step began with: a failed step stays recorded
	// while the drain is paused and runs again under a new attempt on resume
	First int `json:"first,omitempty"`
	// Done lists the steps that are not removals once they ended ("out")
	Done []string `json:"done,omitempty"`
	// Stopped by `drain stop`: no new step starts; Paused by a failed step
	// (Error, the step kept), until `ceph orch host drain` again resumes it
	Stopped bool   `json:"stopped,omitempty"`
	Paused  bool   `json:"paused,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Move is a host's address change (`ceph orch host set-addr`, plan 04 step
// 5): its steps run between ledger operations, one at a time, each journaled
// as <Op>.m<Attempt>. Addr becomes To once the leader confirmed the node has
// it (the contact address: the agent, the certificates); each daemon keeps
// From until its own step moves it (Moved).
type Move struct {
	Op   string `json:"op"`
	From string `json:"from"`
	To   string `json:"to"`
	// Step is the step in progress: "confirm", "rgw", "mgr", "osd", "mon",
	// "conf", "certs"
	Step    string `json:"step,omitempty"`
	Attempt int    `json:"attempt,omitempty"`
	// Done lists the steps that ended, and the sub-steps a step must not
	// repeat ("mon.rm": the mon left the monmap)
	Done []string `json:"done,omitempty"`
	// Moved lists the daemons on To ("<type>.<id>"; an OSD by its id,
	// "osd.<n>"; its host's keepalived "vip.<host>")
	Moved []string `json:"moved,omitempty"`
	// VIPOff: the host's keepalived is off during the RGW step, until its
	// peers on the other ingress hosts name To
	VIPOff bool `json:"vip_off,omitempty"`
	// Before is the moved mgr's gid (or instance) before its restart: it is
	// back with another one
	Before string `json:"before,omitempty"`
	// Paused by a failed step (Error, the step kept), until `ceph orch host
	// set-addr` again resumes it
	Paused bool   `json:"paused,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Retiring is a removed host's retirement (`ceph orch host rm`, plan 04 step
// 6): recorded by the removal, which drops the host from the hosts, with the
// agent identity it journals (its address, its certificates and the name of
// their keys, and the certificates its enrollment record carried then); its
// steps run between ledger operations: the strip of its owned documents, the
// retirement grant (journaled <Op>.retire.<Attempt>), the end (the module's
// `retire done`), then the record is cleared.
type Retiring struct {
	Op   string `json:"op"`
	Addr string `json:"addr"`
	// AgentCert and AgentClientCert are the agent's certificates in the state
	// at the removal; AgentKeys names their keys' secrets as Host.AgentKeys
	// ("<operation>/<attempt>", "" for the CLI's host/<host>/agent-*.key)
	AgentCert       string `json:"agent_cert,omitempty"`
	AgentClientCert string `json:"agent_client_cert,omitempty"`
	AgentKeys       string `json:"agent_keys,omitempty"`
	// EnrollCert and EnrollClientCert are the certificates the host's
	// enrollment record (cephadm-talos/enroll/<host>) carried at the removal,
	// "" without one: the end deletes the record only if it still carries them
	EnrollCert       string `json:"enroll_cert,omitempty"`
	EnrollClientCert string `json:"enroll_client_cert,omitempty"`
	// Step is the step in progress: "strip", "grant" or "end"
	Step string `json:"step"`
	// Attempt numbers the steps' journal ids (<Op>.strip.<n>, <Op>.retire.<n>)
	Attempt int `json:"attempt,omitempty"`
	// Since is when the retirement began; Tried when the last strip or grant
	// was sent
	Since time.Time `json:"since"`
	Tried time.Time `json:"tried,omitzero"`
	// Sent: a retirement grant was sent (its journal granting, uncertain or
	// completed); Silent is since when the agent has not answered at Addr
	// (zero while it answers); Retired once the leader takes the retirement
	// as done (the agent answered 410 Gone, or a grant was sent and it has
	// not answered for two minutes)
	Sent    bool      `json:"sent,omitempty"`
	Silent  time.Time `json:"silent,omitzero"`
	Retired bool      `json:"retired,omitempty"`
	// Error is why the retirement waits ("" while it advances), for
	// TALOS_HOST_RETIRING
	Error string `json:"error,omitempty"`
}

// Retirement steps (Retiring.Step).
const (
	RetireStrip = "strip"
	RetireGrant = "grant"
	RetireEnd   = "end"
)

// MoveName is the name a move records a daemon under in Moved.
func MoveName(d Daemon) string {
	if d.Type == TypeOSD && d.OSDID != nil {
		return fmt.Sprintf("osd.%d", *d.OSDID)
	}

	return d.Type + "." + d.ID
}

// DaemonAddr is the address a daemon of the state runs on: its host's, or
// during the host's move the old one until the daemon's own step moved it
// (plan 04, step 5).
func (s *State) DaemonAddr(d Daemon) string {
	h, ok := s.Host(d.Host)
	if !ok {
		return ""
	}

	if m := h.Move; m != nil && !slices.Contains(m.Moved, MoveName(d)) {
		return m.From
	}

	return h.Addr
}

// Published is the revision of what the talos mgr module reads from the nodes
// (inventory, module files, mgr TLS); Hash detects changes.
type Published struct {
	Hash      string    `json:"hash"`
	Revision  int       `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
	// ModuleHash is the published mgr module code; a change needs the mgrs
	// restarted (MgrRestart lists the hosts still to do)
	ModuleHash string   `json:"module_hash,omitempty"`
	MgrRestart []string `json:"mgr_restart,omitempty"`
}

// Agent holds the agent CA, the operator's client certificate and the agent image.
type Agent struct {
	Image string `json:"image"` // digest reference
	// PreviousImage is the image an agent upgrade upgraded from, the known
	// good for `agent restore --previous` (plan 04, step 2)
	PreviousImage string `json:"previous_image,omitempty"`
	CACert        string `json:"ca_cert"`
	CAKey         string `json:"-"` // a secret (Secrets)
	OperatorCert  string `json:"operator_cert"`
	OperatorKey   string `json:"operator_key"`
	// ApprovalKey is the public key every agent pins (internal/approval);
	// ApprovalPriv, its private key, and Approval, the last approval the CLI
	// signed (JSON of approval.Signed), stay on the workstation only
	ApprovalKey  string `json:"approval_key,omitempty"`
	ApprovalPriv string `json:"approval_priv,omitempty"`
	Approval     string `json:"approval,omitempty"`
	// CRLFailClosed is the agents' revocation list policy the CLI renders
	// in their documents (plan 04, step 3): the workstation's only, never
	// in the published state, which the module could write
	CRLFailClosed bool `json:"crl_fail_closed,omitempty"`
	// OperatorRevoke is a renewed operator certificate's predecessor, to be
	// revoked once the module accepts `orch talos revoke` (workstation only)
	OperatorRevoke []PendingRevoke `json:"operator_revoke,omitempty"`
}

// PendingRevoke is a certificate the CLI revokes on every command until the
// module accepted it: its serial (decimal) and expiry.
type PendingRevoke struct {
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
}

// RGW holds the object gateway settings shared by all rgw and vip daemons.
type RGW struct {
	Port int `json:"port"` // HTTPS port of radosgw (beast ssl_port)

	// TLS: a cluster CA and a server certificate for the VIP and all hosts,
	// unless the user supplied their own (UserCert)
	CACert   string `json:"ca_cert,omitempty"`
	CAKey    string `json:"-"` // secrets (Secrets)
	Cert     string `json:"cert"`
	Key      string `json:"-"`
	UserCert bool   `json:"user_cert,omitempty"`

	// VIP held by keepalived (VRRP, unicast between the vip hosts)
	VIP             string `json:"vip,omitempty"` // CIDR, e.g. 10.5.0.200/24
	VRID            int    `json:"vrid,omitempty"`
	VRRPPass        string `json:"-"` // a secret (Secrets)
	KeepalivedImage string `json:"keepalived_image,omitempty"`

	// Certs are the serving certificates the leader rendered (plan 03, step
	// 6e), each RGW naming its own (Daemon.Cert); Cert and Key above are the
	// CLI's, for an RGW that names none
	Certs []RGWCert `json:"certs,omitempty"`
	// VRRPSecret names the secret with the current VRRP password; empty: the
	// CLI's (rgw/vrrp)
	VRRPSecret string `json:"vrrp_secret,omitempty"`
}

// VRRPSecretName is the secret holding the current VRRP password.
func (r *RGW) VRRPSecretName() string {
	if r.VRRPSecret != "" {
		return r.VRRPSecret
	}

	return SecretVRRP
}

// RGWCert is an RGW serving certificate: its id, which names its key's secret
// ("issued/<op>/<attempt>" generated by the module, "user/<op>" the
// operator's), the certificate chain, and whether it is the operator's.
type RGWCert struct {
	ID   string `json:"id"`
	Cert string `json:"cert"`
	User bool   `json:"user,omitempty"`
}

// RGWCertOf is the serving certificate an RGW renders: the one it names, else
// the CLI's; with the name of its key's secret.
func (s *State) RGWCertOf(d Daemon) (cert RGWCert, keySecret string, ok bool) {
	if s.RGW == nil {
		return RGWCert{}, "", false
	}

	if d.Cert == "" {
		return RGWCert{ID: "cli", Cert: s.RGW.Cert, User: s.RGW.UserCert}, SecretRGWServer, s.RGW.Cert != ""
	}

	for _, c := range s.RGW.Certs {
		if c.ID == d.Cert {
			return c, c.ID + "/rgw-server.key", true
		}
	}

	return RGWCert{}, "", false
}

// Daemon is a Ceph daemon placed on a host.
type Daemon struct {
	Type   string `json:"type"`
	ID     string `json:"id"` // mon/mgr: hostname, osd: device basename until the OSD id is known
	Host   string `json:"host"`
	Device string `json:"device,omitempty"`
	OSDID  *int   `json:"osd_id,omitempty"`
	// DeployID identifies one incarnation of a daemon (see mon.sh, osd.sh)
	DeployID string `json:"deploy_id,omitempty"`
	// OSDUUID tells this OSD apart from a later one that reuses its numeric id
	OSDUUID string `json:"osd_uuid,omitempty"`
	// DiskSerial is the OSD device's serial from Talos, recorded before prepare
	// and checked by the prepare job right before the destructive step
	DiskSerial string `json:"disk_serial,omitempty"`
	// DevicePath is the disk's /dev/disk/by-id link carrying its serial, which
	// the prepare job, the OSD daemon and zap use instead of the kernel name
	DevicePath string `json:"device_path,omitempty"`
	// Purged is set once the OSD is gone from the cluster, so a retried rm only wipes
	Purged bool `json:"purged,omitempty"`
	// Leaving: an OSD the leader is removing: not rendered, its identity kept
	// until it is purged and, if asked, zapped
	Leaving bool `json:"leaving,omitempty"`
	// Retiring: the leader's removal of this daemon is about to take its first
	// step that cannot be undone (an OSD's purge, a mon's `mon rm`, a mgr or
	// RGW leaving the state); recorded first, so a drain's stop never abandons
	// it (plan 04, step 5)
	Retiring bool `json:"retiring,omitempty"`
	// Joining: a mon the leader deployed that has not joined the quorum yet;
	// ceph.conf does not name it until it has
	Joining bool `json:"joining,omitempty"`
	// LocalOnly: stopped by a forced `rm` while no mon was reachable; its
	// cluster-side cleanup (mon remove, osd purge, auth rm) is still pending
	LocalOnly bool `json:"local_only,omitempty"`
	// Image is the daemon's own image during or after an upgrade (plan 03,
	// step 6d); empty: the cluster's
	Image string `json:"image,omitempty"`
	// Cert is the serving certificate an RGW renders (RGW.Certs); empty: the CLI's
	Cert string `json:"cert,omitempty"`
}

// Upgrade is an upgrade in progress (plan 03, step 6d): its start operation,
// the target image and its Ceph version, whether it is paused (and why) or
// stopped (it ends with its step), the daemon of the step in progress with
// its attempt, when the step began and its grant ended, and its instance
// before; the daemons done (upgraded, or added during the upgrade with the
// target); Finished once the target is the cluster's image.
type Upgrade struct {
	Op        string    `json:"op"`
	Image     string    `json:"image"`
	Version   string    `json:"version"`
	Paused    bool      `json:"paused,omitempty"`
	Error     string    `json:"error,omitempty"`
	Stopped   bool      `json:"stopped,omitempty"`
	Finished  bool      `json:"finished,omitempty"`
	Step      string    `json:"step,omitempty"`
	Attempt   int       `json:"attempt,omitempty"`
	StepAt    time.Time `json:"step_at,omitzero"`
	GrantedAt time.Time `json:"granted_at,omitzero"`
	// Before is the step daemon's instance before its grant: it is back with
	// a newer one
	Before string   `json:"before,omitempty"`
	Done   []string `json:"done,omitempty"`
}

// AgentUpgrade is an agent upgrade in progress (plan 04, step 2), recorded
// before its first step: its operation, the image it upgrades from and the
// target, the hosts that pulled the target and those done, the host left for
// last (the leader's when it started), whether it is paused (and why), the
// attempt its steps' grants carry (a resume starts a new one), the step in
// progress ("pull/<host>", "self/<host>" or "fail/<host>") and when it
// began; Finished once every host runs the target and it is the agents' image.
type AgentUpgrade struct {
	Op       string    `json:"op"`
	From     string    `json:"from"`
	Image    string    `json:"image"`
	Pulled   []string  `json:"pulled,omitempty"`
	Done     []string  `json:"done,omitempty"`
	Last     string    `json:"last,omitempty"`
	Paused   bool      `json:"paused,omitempty"`
	Error    string    `json:"error,omitempty"`
	Attempt  int       `json:"attempt,omitempty"`
	Step     string    `json:"step,omitempty"`
	StepAt   time.Time `json:"step_at,omitzero"`
	Finished bool      `json:"finished,omitempty"`
	// Verify: resumed; the hosts done are checked to run the target again
	// before the next step (a restore may have put one back on an earlier image)
	Verify bool `json:"verify,omitempty"`
	// Stopping: stopped by the operator, a rollback once no step is in
	// progress; Stopped: the target the rollback gave up, Image then From
	// (plan 04, step 2, item 7)
	Stopping bool   `json:"stopping,omitempty"`
	Stopped  string `json:"stopped,omitempty"`
	// Starting: the rollback a stop just made, until its first step is
	// recorded or it pauses (StepAt is when it was made)
	Starting bool `json:"starting,omitempty"`
}

// ImageOf is the image a daemon runs: its own, else the cluster's.
func (s *State) ImageOf(d Daemon) string {
	if d.Image != "" {
		return d.Image
	}

	return s.Image
}

// NewImage is the image a daemon gets that is created now: an upgrade's
// target while one is in progress, else the cluster's.
func (s *State) NewImage() string {
	if s.Upgrade != nil {
		return s.Upgrade.Image
	}

	return s.Image
}

// Created prepares a daemon the leader creates: during an upgrade it gets the
// target image and counts as done.
func (s *State) Created(d Daemon) Daemon {
	if s.Upgrade != nil {
		d.Image = s.Upgrade.Image
		if name := s.DocName(d); !slices.Contains(s.Upgrade.Done, name) {
			s.Upgrade.Done = append(s.Upgrade.Done, name)
		}
	}

	return d
}

// OSDDevice is the path an OSD's device is used by: its by-id link, or the
// kernel name for an OSD deployed before links were recorded.
func (d Daemon) OSDDevice() string {
	if d.DevicePath != "" {
		return d.DevicePath
	}

	return d.Device
}

// State is the persisted cluster inventory.
type State struct {
	Schema      int       `json:"schema"`
	FSID        string    `json:"fsid"`
	Image       string    `json:"image"`        // digest reference, see orch.resolveImage
	CephVersion string    `json:"ceph_version"` // verified by probing Image
	Arch        string    `json:"arch"`         // uname -m of Image on the probed node
	RGW         *RGW      `json:"rgw,omitempty"`
	Agent       *Agent    `json:"agent,omitempty"`
	Published   Published `json:"published"`
	Talosconfig string    `json:"talosconfig,omitempty"`
	Context     string    `json:"context,omitempty"`
	Hosts       []Host    `json:"hosts"`
	Daemons     []Daemon  `json:"daemons"`
	// Keys caches cephx secrets for one command (entity -> base64 secret); mon
	// auth is authoritative, only client.admin is kept on the workstation
	Keys map[string]string `json:"-"`
	// ConfPending lists hosts whose ceph.conf could not be updated yet; every
	// command retries them first
	ConfPending []string `json:"conf_pending,omitempty"`
	// RGWPending lists hosts whose rgw/vip documents (certificate, peers) could
	// not be updated yet; retried like ConfPending
	RGWPending []string `json:"rgw_pending,omitempty"`
	// HandingOver: a handoff started, nodes are being handed to their agents;
	// Sealed: the CLI handed the cluster over to the leader (plan 03, item 11).
	// In both the CLI changes nothing but the handoff itself
	HandingOver bool `json:"-"`
	Sealed      bool `json:"-"`
	// LedgerApplied: the last operation of the mgr module's ledger the leader
	// carried out; the next ones come after it
	LedgerApplied string `json:"-"`
	// Upgrade is the upgrade in progress, nil without one
	Upgrade *Upgrade `json:"-"`
	// AgentUpgrade is the agent upgrade in progress or the last one finished
	AgentUpgrade *AgentUpgrade `json:"-"`
	// Retiring are the removed hosts whose retirement has not ended, by name
	// (plan 04, step 6): no longer in Hosts
	Retiring map[string]*Retiring `json:"-"`
	// Inventory is the revision of the mgr module's inventory record: bumped,
	// with its time, only when its content changes
	Inventory InventoryRevision `json:"-"`
	// Contacts are nodes the workstation knows but the published state does not
	// (enrolled, but the publication failed): kept for cleanup, not members
	Contacts []Host `json:"-"`

	path string
}

// Root returns the base directory for all cephadm-talos state.
func Root() string {
	if d := os.Getenv("CEPHADM_TALOS_HOME"); d != "" {
		return d
	}

	home, _ := os.UserHomeDir()

	return filepath.Join(home, ".cephadm-talos")
}

// New creates an empty state for a fresh cluster. It is not written until Save.
func New(fsid string) *State {
	return &State{
		Schema: SchemaVersion,
		FSID:   fsid,
		Keys:   map[string]string{},
		path:   filepath.Join(Root(), fsid, "local.json"),
	}
}

// Local is what the workstation keeps of a cluster.
type Local struct {
	Schema      int         `json:"schema"`
	FSID        string      `json:"fsid"`
	Talosconfig string      `json:"talosconfig,omitempty"`
	Context     string      `json:"context,omitempty"`
	Hosts       []LocalHost `json:"hosts"`
	// OperatorCert and OperatorKey are the CLI's client certificate (agent CA)
	OperatorCert string `json:"operator_cert,omitempty"`
	OperatorKey  string `json:"operator_key,omitempty"`
	// ApprovalPriv signs approvals; Approval is the last one signed, the
	// authority over the approvals' history (internal/approval)
	ApprovalPriv string `json:"approval_priv,omitempty"`
	Approval     string `json:"approval,omitempty"`
	// AdminKey is the client.admin secret, as on a cephadm admin host
	AdminKey string `json:"admin_key,omitempty"`
	// AgentCACert and AgentImage are the agent CA's certificate and the agent
	// image (public), for a suspension or recovery while the cluster state
	// cannot be read (plan 03, step 7 slice D)
	AgentCACert string `json:"agent_ca_cert,omitempty"`
	AgentImage  string `json:"agent_image,omitempty"`
	// CRLFailClosed is the agents' revocation list policy, chosen at
	// bootstrap or by `crl-policy` (plan 04, step 3); OperatorRevoke the
	// operator certificate whose revocation is pending
	CRLFailClosed  bool            `json:"crl_fail_closed,omitempty"`
	OperatorRevoke []PendingRevoke `json:"operator_revoke,omitempty"`
}

// LocalHost is how the workstation reaches a node.
type LocalHost struct {
	Name        string `json:"name"`
	Addr        string `json:"addr"`
	Talosconfig string `json:"talosconfig,omitempty"`
	Context     string `json:"context,omitempty"`
}

// Load reads the workstation's part of the given fsid's state, or of the current
// cluster if fsid is empty. The cluster's part comes from the store (ApplyRecords).
func Load(fsid string) (*State, error) {
	if fsid == "" {
		b, err := os.ReadFile(filepath.Join(Root(), "current"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, errors.New("no cluster found: run `cephadm-talos bootstrap` first or pass --fsid")
			}

			return nil, err
		}

		fsid = strings.TrimSpace(string(b))
	}

	st := New(fsid)

	b, err := os.ReadFile(st.path)
	if err != nil {
		return nil, err
	}

	var l Local
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("parse %s: %w", st.path, err)
	}

	if l.Schema != SchemaVersion || l.FSID != fsid {
		return nil, fmt.Errorf("%s has schema %d for %s, this build needs %d for %s: recreate the cluster (no migrations before the first release)",
			st.path, l.Schema, l.FSID, SchemaVersion, fsid)
	}

	st.Talosconfig, st.Context = l.Talosconfig, l.Context

	for _, h := range l.Hosts {
		st.Hosts = append(st.Hosts, Host{Name: h.Name, Addr: h.Addr, Talosconfig: h.Talosconfig, Context: h.Context})
	}

	if l.OperatorCert != "" {
		st.Agent = &Agent{OperatorCert: l.OperatorCert, OperatorKey: l.OperatorKey, ApprovalPriv: l.ApprovalPriv, Approval: l.Approval,
			CACert: l.AgentCACert, Image: l.AgentImage, CRLFailClosed: l.CRLFailClosed, OperatorRevoke: l.OperatorRevoke}
	}

	if l.AdminKey != "" {
		st.Keys["client.admin"] = l.AdminKey
	}

	return st, nil
}

// Dir is the per-cluster state directory (also holds ceph.conf and the admin keyring).
func (s *State) Dir() string { return filepath.Dir(s.path) }

// Save writes the workstation's part (0600: it holds the admin key and the
// operator key) and marks the cluster as current. The cluster's part is
// published to the store by the caller (Records).
func (s *State) Save() error {
	unlock, err := Lock(s.FSID)
	if err != nil {
		return err
	}
	defer unlock()

	return s.SaveLocked()
}

// SaveLocked is Save for a caller that holds the cluster's Lock. A newer
// approval on disk than this state has (another process signed it) is kept.
func (s *State) SaveLocked() error {
	if err := os.MkdirAll(s.Dir(), 0o700); err != nil {
		return err
	}

	if disk, err := LastApproval(s.FSID); err == nil && s.Agent != nil && approvalSerial(disk) > approvalSerial(s.Agent.Approval) {
		s.Agent.Approval = disk
	}

	l := Local{Schema: SchemaVersion, FSID: s.FSID, Talosconfig: s.Talosconfig, Context: s.Context, AdminKey: s.Keys["client.admin"]}

	for _, h := range s.AllHosts() {
		l.Hosts = append(l.Hosts, LocalHost{Name: h.Name, Addr: h.Addr, Talosconfig: h.Talosconfig, Context: h.Context})
	}

	if s.Agent != nil {
		l.OperatorCert, l.OperatorKey = s.Agent.OperatorCert, s.Agent.OperatorKey
		l.AgentCACert, l.AgentImage = s.Agent.CACert, s.Agent.Image
		l.ApprovalPriv, l.Approval = s.Agent.ApprovalPriv, s.Agent.Approval
		l.CRLFailClosed, l.OperatorRevoke = s.Agent.CRLFailClosed, s.Agent.OperatorRevoke
	}

	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}

	// synced before the rename: the last signed approval must survive a crash
	if err := writeSynced(s.path+".tmp", b); err != nil {
		return err
	}

	if err := os.Rename(s.path+".tmp", s.path); err != nil {
		return err
	}

	// the rename itself is durable before anything relies on it
	if d, err := os.Open(s.Dir()); err == nil {
		serr := d.Sync()
		d.Close() //nolint:errcheck

		if serr != nil {
			return serr
		}
	}

	return os.WriteFile(filepath.Join(Root(), "current"), []byte(s.FSID+"\n"), 0o600)
}

// LastApproval reads the last approval this workstation signed for a cluster
// from its local state on disk (JSON of approval.Signed, "" before any).
func LastApproval(fsid string) (string, error) {
	b, err := os.ReadFile(filepath.Join(Root(), fsid, "local.json"))
	if err != nil {
		return "", err
	}

	var l Local
	if err := json.Unmarshal(b, &l); err != nil {
		return "", err
	}

	return l.Approval, nil
}

// approvalSerial is the serial of a signed approval as the workstation keeps
// it (JSON of approval.Signed), 0 if there is none; only for ordering local copies.
func approvalSerial(signed string) int64 {
	var s struct {
		Payload string `json:"payload"`
	}

	if json.Unmarshal([]byte(signed), &s) != nil {
		return 0
	}

	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return 0
	}

	var a struct {
		Serial int64 `json:"serial"`
	}

	if json.Unmarshal(b, &a) != nil {
		return 0
	}

	return a.Serial
}

// Lock takes an exclusive lock for a cluster's workstation state until the
// returned function is called.
func Lock(fsid string) (func(), error) {
	if err := os.MkdirAll(filepath.Join(Root(), fsid), 0o700); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(filepath.Join(Root(), fsid, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close() //nolint:errcheck

		return nil, err
	}

	return func() { f.Close() }, nil //nolint:errcheck
}

// writeSynced writes a file and syncs it.
func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	if _, err := f.Write(b); err != nil {
		f.Close() //nolint:errcheck

		return err
	}

	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck

		return err
	}

	return f.Close()
}

// InventoryRevision identifies a content of the mgr module's inventory.
type InventoryRevision struct {
	Revision  int       `json:"revision"`
	Hash      string    `json:"hash"`
	UpdatedAt time.Time `json:"updated_at"`
}

// cluster is the cluster-wide record: everything but hosts and daemons.
type cluster struct {
	Schema      int       `json:"schema"`
	FSID        string    `json:"fsid"`
	Image       string    `json:"image"`
	CephVersion string    `json:"ceph_version"`
	Arch        string    `json:"arch"`
	RGW         *RGW      `json:"rgw,omitempty"`
	Agent       *Agent    `json:"agent,omitempty"`
	Published   Published `json:"published"`
	ConfPending []string  `json:"conf_pending,omitempty"`
	RGWPending  []string  `json:"rgw_pending,omitempty"`

	Inventory InventoryRevision `json:"inventory"`

	// HandingOver: a handoff started; Sealed: it finished, the CLI writes no more
	HandingOver bool `json:"handing_over,omitempty"`
	Sealed      bool `json:"sealed,omitempty"`
	// LedgerApplied is the last ledger operation the leader carried out
	LedgerApplied string `json:"ledger_applied,omitempty"`
	// Upgrade is the upgrade in progress
	Upgrade *Upgrade `json:"upgrade,omitempty"`
	// AgentUpgrade is the agent upgrade in progress or the last one finished
	AgentUpgrade *AgentUpgrade `json:"agent_upgrade,omitempty"`
	// Retiring are the removed hosts' retirements in progress
	Retiring map[string]*Retiring `json:"retiring,omitempty"`
}

// Secret names: config-key entries below store.SecretPrefix, one per secret.
const (
	SecretAgentCA   = "agent-ca.key"
	SecretRGWCA     = "rgw/ca.key"
	SecretRGWServer = "rgw/server.key"
	SecretVRRP      = "rgw/vrrp"

	// a host's keys, below host/<name>/ (SecretHost)
	SecretAgentServer = "agent-server.key"
	SecretAgentClient = "agent-client.key"
	SecretMgrServer   = "mgr-server.key"
	SecretMgrClient   = "mgr-client.key"
)

// SecretHost is the secret name of one of a host's keys.
func SecretHost(host, key string) string { return "host/" + host + "/" + key }

// SecretIssued is the secret name of a key the mgr module issued for a mgr
// (Host.MgrKeys "<operation>/<attempt>", key SecretMgrServer or SecretMgrClient)
// or an agent (Host.AgentKeys, key SecretAgentServer or SecretAgentClient).
func SecretIssued(ref, key string) string { return "issued/" + ref + "/" + key }

// MgrKeySecret is the secret name of one of a host's mgr keys.
func (h Host) MgrKeySecret(key string) string {
	if h.MgrKeys != "" {
		return SecretIssued(h.MgrKeys, key)
	}

	return SecretHost(h.Name, key)
}

// AgentKeySecret is the secret name of one of a host's agent keys
// (SecretAgentServer or SecretAgentClient).
func (h Host) AgentKeySecret(key string) string {
	if h.AgentKeys != "" {
		return SecretIssued(h.AgentKeys, key)
	}

	return SecretHost(h.Name, key)
}

// Secrets are the state's private keys and passwords, by name: kept apart
// from the published records, in entries the leader cannot read through the
// bridge (plan 03, step 6b). Empty secrets are left out.
func (s *State) Secrets() map[string]string {
	out := map[string]string{}

	put := func(name, v string) {
		if v != "" {
			out[name] = v
		}
	}

	if s.Agent != nil {
		put(SecretAgentCA, s.Agent.CAKey)
	}

	if s.RGW != nil {
		put(SecretRGWCA, s.RGW.CAKey)
		put(SecretRGWServer, s.RGW.Key)
		put(SecretVRRP, s.RGW.VRRPPass)
	}

	for _, h := range s.AllHosts() {
		put(SecretHost(h.Name, SecretAgentServer), h.AgentKey)
		put(SecretHost(h.Name, SecretAgentClient), h.AgentClientKey)
		put(SecretHost(h.Name, SecretMgrServer), h.MgrServerKey)
		put(SecretHost(h.Name, SecretMgrClient), h.MgrClientKey)
	}

	return out
}

// ApplySecrets fills the state's private keys and passwords in.
func (s *State) ApplySecrets(sec map[string]string) {
	if s.Agent != nil {
		s.Agent.CAKey = sec[SecretAgentCA]
	}

	if s.RGW != nil {
		s.RGW.CAKey, s.RGW.Key, s.RGW.VRRPPass = sec[SecretRGWCA], sec[SecretRGWServer], sec[SecretVRRP]
	}

	for _, list := range [][]Host{s.Hosts, s.Contacts} {
		for i := range list {
			h := &list[i]
			h.AgentKey = sec[SecretHost(h.Name, SecretAgentServer)]
			h.AgentClientKey = sec[SecretHost(h.Name, SecretAgentClient)]
			h.MgrServerKey = sec[SecretHost(h.Name, SecretMgrServer)]
			h.MgrClientKey = sec[SecretHost(h.Name, SecretMgrClient)]
		}
	}
}

// Records returns the cluster's part of the state as store records: what the
// workstation keeps (how to reach nodes, the operator certificate, keys) is not
// in them.
func (s *State) Records() (map[string][]byte, error) {
	c := cluster{
		Schema: SchemaVersion, FSID: s.FSID, Image: s.Image, CephVersion: s.CephVersion, Arch: s.Arch,
		RGW: s.RGW, Published: s.Published, ConfPending: s.ConfPending, RGWPending: s.RGWPending, Inventory: s.Inventory,
		HandingOver: s.HandingOver, Sealed: s.Sealed, LedgerApplied: s.LedgerApplied, Upgrade: s.Upgrade, AgentUpgrade: s.AgentUpgrade,
		Retiring: s.Retiring,
	}

	if s.Agent != nil {
		a := *s.Agent
		a.OperatorCert, a.OperatorKey, a.ApprovalPriv, a.Approval = "", "", "", ""
		a.CRLFailClosed, a.OperatorRevoke = false, nil
		c.Agent = &a
	}

	hosts := make([]Host, len(s.Hosts))
	for i, h := range s.Hosts {
		h.Talosconfig, h.Context = "", ""
		hosts[i] = h
	}

	out := map[string][]byte{}

	for name, v := range map[string]any{"cluster": c, "hosts": hosts, "daemons": s.Daemons} {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}

		out[name] = b
	}

	return out, nil
}

// ApplyRecords replaces the cluster's part of the state with the store's records,
// keeping what the workstation holds (node connections, operator certificate, keys).
func (s *State) ApplyRecords(recs map[string][]byte) error {
	var (
		c       cluster
		hosts   []Host
		daemons []Daemon
	)

	for name, v := range map[string]any{"cluster": &c, "hosts": &hosts, "daemons": &daemons} {
		b, ok := recs[name]
		if !ok {
			return fmt.Errorf("state: record %s missing", name)
		}

		if err := json.Unmarshal(b, v); err != nil {
			return fmt.Errorf("state: record %s: %w", name, err)
		}
	}

	if c.Schema != SchemaVersion || c.FSID != s.FSID {
		return fmt.Errorf("state: the store holds schema %d for %s, this build needs %d for %s", c.Schema, c.FSID, SchemaVersion, s.FSID)
	}

	local := map[string]Host{}
	for _, h := range s.AllHosts() {
		local[h.Name] = h
	}

	members := map[string]bool{}

	for i := range hosts {
		members[hosts[i].Name] = true

		if l, ok := local[hosts[i].Name]; ok {
			hosts[i].Talosconfig, hosts[i].Context = l.Talosconfig, l.Context
		}
	}

	// nodes known here but not in the published state stay reachable for cleanup
	var contacts []Host

	for _, h := range s.AllHosts() {
		if !members[h.Name] {
			contacts = append(contacts, Host{Name: h.Name, Addr: h.Addr, Talosconfig: h.Talosconfig, Context: h.Context})
		}
	}

	s.Contacts = contacts

	var operator *Agent
	if s.Agent != nil {
		operator = s.Agent
	}

	s.Image, s.CephVersion, s.Arch, s.RGW, s.Published = c.Image, c.CephVersion, c.Arch, c.RGW, c.Published
	s.ConfPending, s.RGWPending, s.Hosts, s.Daemons = c.ConfPending, c.RGWPending, hosts, daemons
	s.Inventory, s.HandingOver, s.Sealed, s.LedgerApplied, s.Upgrade = c.Inventory, c.HandingOver, c.Sealed, c.LedgerApplied, c.Upgrade
	s.AgentUpgrade, s.Retiring = c.AgentUpgrade, c.Retiring
	s.Agent = c.Agent

	if s.Agent != nil && operator != nil {
		s.Agent.OperatorCert, s.Agent.OperatorKey = operator.OperatorCert, operator.OperatorKey
		s.Agent.ApprovalPriv, s.Agent.Approval = operator.ApprovalPriv, operator.Approval
		// the workstation's, whatever the published state says
		s.Agent.CRLFailClosed, s.Agent.OperatorRevoke = operator.CRLFailClosed, operator.OperatorRevoke
	} else if s.Agent != nil {
		s.Agent.CRLFailClosed, s.Agent.OperatorRevoke = false, nil
	}

	return nil
}

// Short is the fsid prefix used in Talos document names (names are limited to 63 chars).
func (s *State) Short() string { return s.FSID[:8] }

// Host looks up a host by name or address.
func (s *State) Host(nameOrAddr string) (Host, bool) {
	for _, h := range s.Hosts {
		if h.Name == nameOrAddr || h.Addr == nameOrAddr {
			return h, true
		}
	}

	return Host{}, false
}

// AddHost adds or updates a host.
func (s *State) AddHost(h Host) {
	for i := range s.Hosts {
		if s.Hosts[i].Name == h.Name {
			s.Hosts[i] = h

			return
		}
	}

	s.Hosts = append(s.Hosts, h)
}

// RemoveHost drops a host from the inventory.
func (s *State) RemoveHost(name string) {
	s.Hosts = slices.DeleteFunc(s.Hosts, func(h Host) bool { return h.Name == name })
	s.Contacts = slices.DeleteFunc(s.Contacts, func(h Host) bool { return h.Name == name })
}

// RetiringHost is a removed host whose retirement has not ended, as a Host
// to reach its agent with: its name, the address and the certificates its
// retirement journaled.
func (s *State) RetiringHost(name string) (Host, *Retiring, bool) {
	r, ok := s.Retiring[name]
	if !ok || r == nil {
		return Host{}, nil, false
	}

	return Host{Name: name, Addr: r.Addr, AgentCert: r.AgentCert, AgentClientCert: r.AgentClientCert, AgentKeys: r.AgentKeys}, r, true
}

// AllHosts are the members and the contacts: every node this cluster may have
// touched, for cleanup.
func (s *State) AllHosts() []Host {
	out := slices.Clone(s.Hosts)

	for _, c := range s.Contacts {
		if !slices.ContainsFunc(out, func(h Host) bool { return h.Name == c.Name }) {
			out = append(out, c)
		}
	}

	return out
}

// DocName is the Talos ContainerConfig name of a daemon.
//
// Talos container names are limited to 63 characters of [a-z0-9-], while
// hostnames may be longer and contain uppercase letters. Names that need
// changing are lowercased, cut and suffixed with a hash of the full name, so
// they stay unique; valid names are left as they are.
func (s *State) DocName(d Daemon) string {
	name := fmt.Sprintf("ceph-%s-%s-%s", s.Short(), d.Type, d.ID)

	clean := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		}

		return '-'
	}, name)

	// a trailing '-' (hostname "node-") is legal for Talos but not for our own check
	if clean == name && len(name) <= 63 && !strings.HasSuffix(name, "-") {
		return name
	}

	sum := sha256.Sum256([]byte(name))
	prefix := clean
	if len(prefix) > 63-9 {
		prefix = prefix[:63-9]
	}

	return strings.TrimRight(prefix, "-") + "-" + hex.EncodeToString(sum[:])[:8]
}

// Find looks a daemon up by "type.id" (as shown by `ps`) or by Talos document name.
func (s *State) Find(name string) (Daemon, bool) {
	for _, d := range s.Daemons {
		if d.Type+"."+d.ID == name || s.DocName(d) == name {
			return d, true
		}

		if d.OSDID != nil && name == fmt.Sprintf("osd.%d", *d.OSDID) {
			return d, true
		}
	}

	return Daemon{}, false
}

// AddDaemon records a daemon, replacing an existing one with the same type and id.
func (s *State) AddDaemon(d Daemon) {
	for i := range s.Daemons {
		if s.Daemons[i].Type == d.Type && s.Daemons[i].ID == d.ID {
			s.Daemons[i] = d

			return
		}
	}

	s.Daemons = append(s.Daemons, d)
}

// RemoveDaemon drops a daemon from the inventory.
func (s *State) RemoveDaemon(d Daemon) {
	s.Daemons = slices.DeleteFunc(s.Daemons, func(x Daemon) bool { return x.Type == d.Type && x.ID == d.ID })
}

// DaemonsOf returns all daemons of a type, optionally filtered by host.
func (s *State) DaemonsOf(typ, host string) []Daemon {
	var out []Daemon

	for _, d := range s.Daemons {
		if d.Type == typ && (host == "" || d.Host == host) {
			out = append(out, d)
		}
	}

	return out
}

// MonAddrs returns the addresses of the mons that joined, in placement
// order, each where it runs (DaemonAddr).
func (s *State) MonAddrs() []string {
	var out []string

	for _, d := range s.DaemonsOf(TypeMon, "") {
		if a := s.DaemonAddr(d); a != "" && !d.Joining {
			out = append(out, a)
		}
	}

	return out
}
