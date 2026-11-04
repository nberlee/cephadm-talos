package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// InventorySchema is the version of the inventory record the talos mgr module reads.
const InventorySchema = 1

// InventoryHost is a host of the inventory.
type InventoryHost struct {
	Name        string   `json:"name"`
	Addr        string   `json:"addr"`
	Labels      []string `json:"labels"`
	Maintenance bool     `json:"maintenance,omitempty"`
	// NoOut: the CLI's maintenance set noout (the module's fold takes it over)
	NoOut bool `json:"noout,omitempty"`
	// Drain is the host's drain, as the module reports it (plan 04, step 5)
	Drain *InventoryDrain `json:"drain,omitempty"`
}

// InventoryDrain is a host's drain in progress.
type InventoryDrain struct {
	Op      string `json:"op"`
	Step    string `json:"step,omitempty"`
	Stopped bool   `json:"stopped,omitempty"`
	Paused  bool   `json:"paused,omitempty"`
	Error   string `json:"error,omitempty"`
}

// InventoryDaemon is a daemon of the inventory.
type InventoryDaemon struct {
	DocName      string `json:"doc_name"`
	Host         string `json:"host"`
	DaemonType   string `json:"daemon_type"`
	DaemonID     string `json:"daemon_id"`
	ServiceName  string `json:"service_name"`
	DesiredImage string `json:"desired_image"`
	LocalOnly    bool   `json:"local_only,omitempty"`
	// OSDUUID is a prepared OSD's uuid, which the module checks removals against
	OSDUUID string `json:"osd_uuid,omitempty"`
}

// Inventory is the mgr module's view of the cluster (module.py check_inventory).
type Inventory struct {
	Schema      int               `json:"schema"`
	Revision    int               `json:"revision"`
	UpdatedAt   time.Time         `json:"updated_at"`
	FSID        string            `json:"fsid"`
	Image       string            `json:"image"`
	CephVersion string            `json:"ceph_version"`
	CertExpiry  *time.Time        `json:"cert_expiry,omitempty"`
	Hosts       []InventoryHost   `json:"hosts"`
	Daemons     []InventoryDaemon `json:"daemons"`
	// Upgrade is the upgrade in progress, as the module reports it
	Upgrade *InventoryUpgrade `json:"upgrade,omitempty"`
}

// InventoryUpgrade is an upgrade in progress: the module accepts its controls
// from its ledger and reports this progress in `orch upgrade status`.
type InventoryUpgrade struct {
	Op      string   `json:"op"`
	Image   string   `json:"image"`
	Version string   `json:"version"`
	Paused  bool     `json:"paused,omitempty"`
	Error   string   `json:"error,omitempty"`
	Step    string   `json:"step,omitempty"`
	Done    []string `json:"done"`
}

// InventoryOf derives the mgr module's view of the cluster from the state,
// without revision and time (InventoryRecord); no keys.
func InventoryOf(s *state.State) Inventory {
	inv := Inventory{
		Schema: InventorySchema, FSID: s.FSID, Image: s.Image, CephVersion: s.CephVersion,
		Hosts: []InventoryHost{}, Daemons: []InventoryDaemon{},
	}

	for _, h := range s.Hosts {
		ih := InventoryHost{Name: h.Name, Addr: h.Addr, Labels: append([]string{}, h.Labels...), Maintenance: h.Maintenance, NoOut: h.NoOut}
		if d := h.Drain; d != nil {
			ih.Drain = &InventoryDrain{Op: d.Op, Step: d.Step, Stopped: d.Stopped, Paused: d.Paused, Error: d.Error}
		}

		inv.Hosts = append(inv.Hosts, ih)
	}

	for _, d := range s.Daemons {
		id, typ, svc, img := d.ID, d.Type, d.Type, s.ImageOf(d)

		switch d.Type {
		case state.TypeOSD:
			id = "pending-" + s.DocName(d)
			if d.OSDID != nil {
				id = strconv.Itoa(*d.OSDID)
			}
		case state.TypeRGW:
			svc = "rgw.default"
		case state.TypeVIP:
			typ, svc = "keepalived", "ingress.rgw.default"
			if s.RGW != nil {
				img = s.RGW.KeepalivedImage
			}
		}

		inv.Daemons = append(inv.Daemons, InventoryDaemon{
			DocName: s.DocName(d), Host: d.Host, DaemonType: typ, DaemonID: id, ServiceName: svc,
			DesiredImage: img, LocalOnly: d.LocalOnly, OSDUUID: d.OSDUUID,
		})
	}

	if u := s.Upgrade; u != nil {
		inv.Upgrade = &InventoryUpgrade{Op: u.Op, Image: u.Image, Version: u.Version, Paused: u.Paused, Error: u.Error, Step: u.Step, Done: append([]string{}, u.Done...)}
	}

	if t, ok := earliestCertExpiry(s); ok {
		inv.CertExpiry = &t
	}

	return inv
}

// earliestCertExpiry is the first agent or mgr certificate to expire.
func earliestCertExpiry(s *state.State) (time.Time, bool) {
	if s.Agent == nil {
		return time.Time{}, false
	}

	var first time.Time

	certs := []string{s.Agent.OperatorCert}
	for _, h := range s.Hosts {
		certs = append(certs, h.AgentCert, h.AgentClientCert, h.MgrServerCert, h.MgrClientCert)
	}

	for _, c := range certs {
		if t, err := pki.NotAfter(c); err == nil && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}

	return first, !first.IsZero()
}

// InventoryRecord is the inventory record of the state, and the state's
// inventory revision to keep with it: bumped, with its time, only when the
// content changed since the state's revision. The caller stores the revision
// in the state (its cluster record carries it).
func InventoryRecord(s *state.State, now time.Time) ([]byte, state.InventoryRevision, error) {
	inv := InventoryOf(s)

	b, err := json.Marshal(inv)
	if err != nil {
		return nil, state.InventoryRevision{}, err
	}

	rev := s.Inventory

	sum := sha256.Sum256(b)
	if h := hex.EncodeToString(sum[:]); rev.Hash != h {
		rev = state.InventoryRevision{Revision: rev.Revision + 1, Hash: h, UpdatedAt: now.UTC()}
	}

	inv.Revision, inv.UpdatedAt = rev.Revision, rev.UpdatedAt

	b, err = json.Marshal(inv)

	return b, rev, err
}
