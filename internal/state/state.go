// Package state keeps the cluster inventory on the workstation.
//
// cephadm keeps the equivalent data in the mon config-key store; this PoC keeps
// it in ~/.cephadm-talos/<fsid>/state.json instead (see SHORTCOMINGS.md) until
// the agent moves it to config-key (ROADMAP.md, milestone 3).
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// SchemaVersion is the state.json schema this build reads and writes. Before
// the first tagged release there are no migrations: any other version is refused.
const SchemaVersion = 1

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
	// NoOut: maintenance enter set `osd set-group noout` on this host's CRUSH bucket
	NoOut bool `json:"noout,omitempty"`
	// Talosconfig and Context override the cluster defaults for this node, so
	// nodes need not share one talosconfig
	Talosconfig string `json:"talosconfig,omitempty"`
	Context     string `json:"context,omitempty"`
	// AgentCert and AgentKey are the agent's server certificate, AgentClientCert
	// and AgentClientKey its client certificate (agent CA, identity agent/<host>)
	AgentCert       string `json:"agent_cert,omitempty"`
	AgentKey        string `json:"agent_key,omitempty"`
	AgentClientCert string `json:"agent_client_cert,omitempty"`
	AgentClientKey  string `json:"agent_client_key,omitempty"`
	// MgrServerCert, MgrClientCert and their keys are the certificates of the
	// mgr on this host (agent CA, identity mgr/<host>), set while it has one
	MgrServerCert string `json:"mgr_server_cert,omitempty"`
	MgrServerKey  string `json:"mgr_server_key,omitempty"`
	MgrClientCert string `json:"mgr_client_cert,omitempty"`
	MgrClientKey  string `json:"mgr_client_key,omitempty"`
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
	Image        string `json:"image"` // digest reference
	CACert       string `json:"ca_cert"`
	CAKey        string `json:"ca_key"`
	OperatorCert string `json:"operator_cert"`
	OperatorKey  string `json:"operator_key"`
}

// RGW holds the object gateway settings shared by all rgw and vip daemons.
type RGW struct {
	Port int `json:"port"` // HTTPS port of radosgw (beast ssl_port)

	// TLS: a cluster CA and a server certificate for the VIP and all hosts,
	// unless the user supplied their own (UserCert)
	CACert   string `json:"ca_cert,omitempty"`
	CAKey    string `json:"ca_key,omitempty"`
	Cert     string `json:"cert"`
	Key      string `json:"key"`
	UserCert bool   `json:"user_cert,omitempty"`

	// VIP held by keepalived (VRRP, unicast between the vip hosts)
	VIP             string `json:"vip,omitempty"` // CIDR, e.g. 10.5.0.200/24
	VRID            int    `json:"vrid,omitempty"`
	VRRPPass        string `json:"vrrp_pass,omitempty"`
	KeepalivedImage string `json:"keepalived_image,omitempty"`
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
	// Purged is set once the OSD is gone from the cluster, so a retried rm only wipes
	Purged bool `json:"purged,omitempty"`
	// LocalOnly: stopped by a forced `rm` while no mon was reachable; its
	// cluster-side cleanup (mon remove, osd purge, auth rm) is still pending
	LocalOnly bool `json:"local_only,omitempty"`
}

// State is the persisted cluster inventory.
type State struct {
	Schema      int               `json:"schema"`
	FSID        string            `json:"fsid"`
	Image       string            `json:"image"`        // digest reference, see orch.resolveImage
	CephVersion string            `json:"ceph_version"` // verified by probing Image
	Arch        string            `json:"arch"`         // uname -m of Image on the probed node
	RGW         *RGW              `json:"rgw,omitempty"`
	Agent       *Agent            `json:"agent,omitempty"`
	Published   Published         `json:"published"`
	Talosconfig string            `json:"talosconfig,omitempty"`
	Context     string            `json:"context,omitempty"`
	Hosts       []Host            `json:"hosts"`
	Daemons     []Daemon          `json:"daemons"`
	Keys        map[string]string `json:"keys"` // entity -> base64 cephx secret
	// ConfPending lists hosts whose ceph.conf could not be updated yet; every
	// command retries them first
	ConfPending []string `json:"conf_pending,omitempty"`
	// RGWPending lists hosts whose rgw/vip documents (certificate, peers) could
	// not be updated yet; retried like ConfPending
	RGWPending []string `json:"rgw_pending,omitempty"`

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
		path:   filepath.Join(Root(), fsid, "state.json"),
	}
}

// Load reads the state of the given fsid, or the current cluster if fsid is empty.
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

	st.Schema = 0

	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", st.path, err)
	}

	if st.Schema != SchemaVersion {
		return nil, fmt.Errorf("%s has state schema %d, this build needs %d: recreate the cluster (no migrations before the first release)", st.path, st.Schema, SchemaVersion)
	}

	return st, nil
}

// Dir is the per-cluster state directory (also holds ceph.conf and the admin keyring).
func (s *State) Dir() string { return filepath.Dir(s.path) }

// Save writes the state (0600, it contains every key) and marks it as current.
func (s *State) Save() error {
	if err := os.MkdirAll(s.Dir(), 0o700); err != nil {
		return err
	}

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(s.path+".tmp", b, 0o600); err != nil {
		return err
	}

	if err := os.Rename(s.path+".tmp", s.path); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(Root(), "current"), []byte(s.FSID+"\n"), 0o600)
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

// MonAddrs returns the addresses of the mon hosts, in placement order.
func (s *State) MonAddrs() []string {
	var out []string

	for _, d := range s.DaemonsOf(TypeMon, "") {
		if h, ok := s.Host(d.Host); ok {
			out = append(out, h.Addr)
		}
	}

	return out
}
