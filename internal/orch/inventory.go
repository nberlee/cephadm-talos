package orch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/mgrmodule"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// InventorySchema is the version of /etc/ceph/talos/inventory.json, read by the talos mgr module.
const InventorySchema = 1

// Files the talos mgr module reads (EtcFileConfig names, below /etc).
const (
	inventoryFile     = "ceph/talos/inventory.json"
	agentCAFile       = daemons.AgentCAFile
	mgrCertFile       = daemons.MgrCertFile
	mgrKeyFile        = daemons.MgrKeyFile
	mgrServerCertFile = daemons.MgrServerCertFile
	mgrServerKeyFile  = daemons.MgrServerKeyFile
	mgrModuleDir      = daemons.MgrModuleDir
)

type invHost struct {
	Name        string   `json:"name"`
	Addr        string   `json:"addr"`
	Labels      []string `json:"labels"`
	Maintenance bool     `json:"maintenance,omitempty"`
}

type invDaemon struct {
	DocName      string `json:"doc_name"`
	Host         string `json:"host"`
	DaemonType   string `json:"daemon_type"`
	DaemonID     string `json:"daemon_id"`
	ServiceName  string `json:"service_name"`
	DesiredImage string `json:"desired_image"`
	LocalOnly    bool   `json:"local_only,omitempty"`
}

type inventory struct {
	Schema      int         `json:"schema"`
	Revision    int         `json:"revision"`
	UpdatedAt   time.Time   `json:"updated_at"`
	FSID        string      `json:"fsid"`
	Image       string      `json:"image"`
	CephVersion string      `json:"ceph_version"`
	CertExpiry  *time.Time  `json:"cert_expiry,omitempty"`
	Hosts       []invHost   `json:"hosts"`
	Daemons     []invDaemon `json:"daemons"`
}

// inventory derives the mgr module's view of the cluster from the state; no keys.
func (o *Orch) inventory() inventory {
	inv := inventory{
		Schema: InventorySchema, FSID: o.St.FSID, Image: o.St.Image, CephVersion: o.St.CephVersion,
		Hosts: []invHost{}, Daemons: []invDaemon{},
	}

	for _, h := range o.St.Hosts {
		inv.Hosts = append(inv.Hosts, invHost{Name: h.Name, Addr: h.Addr, Labels: []string{}, Maintenance: h.Maintenance})
	}

	for _, d := range o.St.Daemons {
		id, typ, svc, img := d.ID, d.Type, d.Type, o.St.Image

		switch d.Type {
		case state.TypeOSD:
			id = "pending-" + o.St.DocName(d)
			if d.OSDID != nil {
				id = strconv.Itoa(*d.OSDID)
			}
		case state.TypeRGW:
			svc = "rgw.default"
		case state.TypeVIP:
			typ, svc = "keepalived", "ingress.rgw.default"
			if o.St.RGW != nil {
				img = o.St.RGW.KeepalivedImage
			}
		}

		inv.Daemons = append(inv.Daemons, invDaemon{
			DocName: o.St.DocName(d), Host: d.Host, DaemonType: typ, DaemonID: id, ServiceName: svc,
			DesiredImage: img, LocalOnly: d.LocalOnly,
		})
	}

	if t, ok := o.earliestCertExpiry(); ok {
		inv.CertExpiry = &t
	}

	return inv
}

// earliestCertExpiry is the first agent or mgr certificate to expire.
func (o *Orch) earliestCertExpiry() (time.Time, bool) {
	if o.St.Agent == nil {
		return time.Time{}, false
	}

	var first time.Time

	certs := []string{o.St.Agent.OperatorCert}
	for _, h := range o.St.Hosts {
		certs = append(certs, h.AgentCert, h.AgentClientCert, h.MgrServerCert, h.MgrClientCert)
	}

	for _, c := range certs {
		if t, err := pki.NotAfter(c); err == nil && (first.IsZero() || t.Before(first)) {
			first = t
		}
	}

	return first, !first.IsZero()
}

// publishedContent is everything the mgr module reads from the nodes (its code
// and TLS files; the inventory is a record in the store), without the revision:
// a change bumps the revision and makes every host pending.
func (o *Orch) publishedContent() string {
	h := sha256.New()

	files := mgrmodule.Files()

	for _, n := range mgrmodule.Names() {
		h.Write([]byte(n + "\x00" + files[n] + "\x00"))
	}

	if a := o.St.Agent; a != nil {
		h.Write([]byte(a.CACert))

		for _, host := range o.St.Hosts {
			h.Write([]byte(host.Name + "\x00" + host.MgrServerCert + host.MgrServerKey + host.MgrClientCert + host.MgrClientKey + "\x00"))
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

// moduleContent identifies the mgr module code.
func moduleContent() string {
	h := sha256.New()
	files := mgrmodule.Files()

	for _, n := range mgrmodule.Names() {
		h.Write([]byte(n + "\x00" + files[n] + "\x00"))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// bumpPublished starts a new revision if the published content changed. A
// changed module also needs every mgr restarted: Python code is loaded once.
func (o *Orch) bumpPublished() bool {
	sum := o.publishedContent()
	if sum == o.St.Published.Hash {
		return false
	}

	p := &o.St.Published
	p.Hash, p.Revision, p.UpdatedAt = sum, p.Revision+1, time.Now().UTC()

	if mod := moduleContent(); mod != p.ModuleHash {
		if p.ModuleHash != "" {
			for _, d := range o.St.DaemonsOf(state.TypeMgr, "") {
				if !slices.Contains(p.MgrRestart, d.Host) {
					p.MgrRestart = append(p.MgrRestart, d.Host)
				}
			}
		}

		p.ModuleHash = mod
	}

	return true
}

// moduleWritten reports whether every module file is on the host's disk.
func (o *Orch) moduleWritten(ctx context.Context, h state.Host) (bool, error) {
	files := mgrmodule.Files()

	for _, n := range mgrmodule.Names() {
		ok, err := o.Talos.EtcFileWritten(ctx, h.Addr, mgrModuleDir+"/"+n, files[n])
		if err != nil || !ok {
			return false, err
		}
	}

	return true, nil
}

// restartMgrs restarts the mgrs that still run an older module, once their
// host has the new files; it is retried by the next command.
func (o *Orch) restartMgrs(ctx context.Context) error {
	var left []string

	var errs []error

	for _, host := range o.St.Published.MgrRestart {
		h, ok := o.St.Host(host)
		mgrs := o.St.DaemonsOf(state.TypeMgr, host)

		if !ok || len(mgrs) == 0 {
			continue // the mgr is gone
		}

		if slices.Contains(o.St.ConfPending, host) || h.Maintenance {
			left = append(left, host)

			continue
		}

		// the config was accepted, but Talos writes the files afterwards
		written, err := o.moduleWritten(ctx, h)
		if err != nil || !written {
			if err != nil {
				errs = append(errs, err)
			}

			left = append(left, host)

			continue
		}

		o.printf("restarting mgr.%s for the new mgr module\n", host)

		if err := o.Talos.Restart(ctx, h.Addr, o.St.DocName(mgrs[0])); err != nil {
			errs = append(errs, err)
			left = append(left, host)
		}
	}

	o.St.Published.MgrRestart = left

	if err := o.save(); err != nil {
		return err
	}

	return errors.Join(errs...)
}

// Publish pushes the inventory and the mgr module files to every host when
// they changed. The new revision and the pending hosts are saved before any
// node is patched, so an interrupted push is retried by the next command.
func (o *Orch) Publish(ctx context.Context) error {
	if o.Talos.DryRun || o.St == nil {
		return nil
	}

	if o.bumpPublished() {
		for _, h := range o.St.Hosts {
			if !slices.Contains(o.St.ConfPending, h.Name) {
				o.St.ConfPending = append(o.St.ConfPending, h.Name)
			}
		}

		if err := o.save(); err != nil {
			return err
		}

		if err := o.pushConf(ctx); err != nil {
			return err
		}
	}

	if len(o.St.Published.MgrRestart) == 0 {
		return nil
	}

	return o.restartMgrs(ctx)
}

// mgrFileDocs are the module and its TLS files on a mgr host, or their
// removal elsewhere (internal/render).
func (o *Orch) mgrFileDocs(h state.Host, withMgr bool) ([]any, error) {
	r, err := render.MgrFiles(o.St, h, withMgr)
	if err != nil {
		return nil, err
	}

	docs := r.Upsert
	for _, ref := range r.Remove {
		docs = append(docs, spec.Delete(ref.Kind, ref.Name))
	}

	return docs, nil
}

// talosFileDeletes removes everything the talos mgr module reads from a host.
func (o *Orch) talosFileDeletes() []any {
	docs, _ := o.mgrFileDocs(state.Host{}, false) // removals only: no error

	return append([]any{spec.Delete("EtcFileConfig", inventoryFile)}, docs...)
}

// hasMgr reports whether a mgr is placed on the host.
func (o *Orch) hasMgr(h state.Host) bool {
	return len(o.St.DaemonsOf(state.TypeMgr, h.Name)) > 0
}

// enableModule turns on the talos mgr module (installed as cephadm) and makes it the orchestrator backend.
func (o *Orch) enableModule(ctx context.Context, node string) error {
	o.printf("enabling the talos mgr module\n")

	// a mgr that just started has not reported its modules yet: enabling waits for it
	check := `for i in $(seq 60); do ceph mgr module enable cephadm 2>/dev/null && break; sleep 2; done; ` +
		`ceph mgr module enable cephadm || exit 1; ceph orch set backend cephadm || exit 1; ` +
		`for i in $(seq 60); do ceph orch status --format json 2>/dev/null | grep -q '"available": true' && exit 0; sleep 2; done; ` +
		`echo "the talos orchestrator did not become available" >&2; ceph orch status >&2; exit 1`

	if _, err := o.Job(ctx, node, check, 5*time.Minute); err != nil {
		return fmt.Errorf("enabling the talos mgr module: %w", err)
	}

	return nil
}
