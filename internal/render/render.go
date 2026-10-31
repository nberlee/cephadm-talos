// Package render turns the cluster state into the documents a host carries
// (plan 03, step 4): daemon containers, OSD preparation and zap jobs, the image
// probe, ceph.conf, the mgr module and its TLS files, and the ceph volume. The
// CLI and the leader render with it, and the agents admit exactly these
// renderings (internal/agent/admit.go re-renders the same templates).
//
// Rendering only reads: it never creates keys, issues certificates, allocates
// ids or changes the state it is given. Keys come from a lookup that returns
// an existing entity's secret or fails. The agent's own documents (the agent,
// its records-init and their volume) and the bootstrap mon stay the CLI's and
// are not rendered here.
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/mgrmodule"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// Key returns an existing entity's secret from mon auth; it never creates one.
type Key func(entity string) (string, error)

// Ref names a document to remove.
type Ref struct {
	Kind string
	Name string
}

// Documents are documents to put on a host and documents to remove from it.
type Documents struct {
	Upsert []any
	Remove []Ref
}

// CephConf is the cluster's ceph.conf, from the mons in placement order.
func CephConf(s *state.State) string { return daemons.CephConf(s.FSID, s.MonAddrs()) }

// Volume is the ceph volume every Ceph host has.
func Volume() any { return spec.CephVolume() }

// mgrTLS are the mgr's TLS files below /etc, with their modes.
var mgrTLS = []string{daemons.AgentCAFile, daemons.MgrCertFile, daemons.MgrKeyFile, daemons.MgrServerCertFile, daemons.MgrServerKeyFile}

// MgrFiles are the mgr module and its TLS identity on a host that runs (or is
// about to run) a mgr, or their removal from one that does not. A mgr host
// must have its certificates already: rendering issues none.
func MgrFiles(s *state.State, h state.Host, withMgr bool) (Documents, error) {
	var out Documents

	if !withMgr {
		for _, n := range mgrmodule.Names() {
			out.Remove = append(out.Remove, Ref{Kind: "EtcFileConfig", Name: daemons.MgrModuleDir + "/" + n})
		}

		for _, f := range mgrTLS {
			out.Remove = append(out.Remove, Ref{Kind: "EtcFileConfig", Name: f})
		}

		return out, nil
	}

	if s.Agent == nil || s.Agent.CACert == "" || h.MgrClientCert == "" || h.MgrClientKey == "" || h.MgrServerCert == "" || h.MgrServerKey == "" {
		return Documents{}, fmt.Errorf("the mgr of %s has no certificates yet", h.Name)
	}

	files := mgrmodule.Files()
	for _, n := range mgrmodule.Names() {
		out.Upsert = append(out.Upsert, spec.EtcFile(daemons.MgrModuleDir+"/"+n, 0o644, files[n]))
	}

	out.Upsert = append(out.Upsert,
		spec.EtcFile(daemons.AgentCAFile, 0o644, s.Agent.CACert),
		spec.EtcFile(daemons.MgrCertFile, 0o644, h.MgrClientCert),
		spec.EtcFile(daemons.MgrKeyFile, 0o600, h.MgrClientKey),
		spec.EtcFile(daemons.MgrServerCertFile, 0o644, h.MgrServerCert),
		spec.EtcFile(daemons.MgrServerKeyFile, 0o600, h.MgrServerKey))

	return out, nil
}

// Daemon renders the container of a daemon of the state with the given image
// (an upgrade renders the candidate before the state changes). A mon renders
// as a joining mon with the mon. key only; its deploy id is kept, as a new one
// rebuilds its store. An OSD needs its id, uuid and stable device: prepare it
// first.
func Daemon(s *state.State, h state.Host, d state.Daemon, image string, key Key) (*spec.ContainerConfig, error) {
	p := daemons.Params{Name: s.DocName(d), Image: image, FSID: s.FSID, ID: d.ID, Addr: h.Addr, DeployID: d.DeployID}

	switch d.Type {
	case state.TypeMon:
		k, err := key("mon.")
		if err != nil {
			return nil, err
		}

		p.Keyring, p.Mode, p.Addrv = daemons.MonKeyring(k), "join", daemons.MonAddrv(h.Addr)

		return daemons.Mon(p), nil
	case state.TypeMgr:
		k, err := key("mgr." + d.ID)
		if err != nil {
			return nil, err
		}

		p.Keyring = daemons.Keyring("mgr."+d.ID, k)

		return daemons.Mgr(p, mgrmodule.Names()...), nil
	case state.TypeOSD:
		if d.OSDID == nil || d.OSDUUID == "" {
			return nil, fmt.Errorf("osd %s has no id and uuid yet: its preparation did not finish", d.ID)
		}

		if !strings.HasPrefix(d.DevicePath, "/dev/disk/by-id/") {
			return nil, fmt.Errorf("osd %s has no stable device", d.ID)
		}

		// no key: activation takes the OSD's own key from the label
		p.Device, p.OSDID, p.OSDUUID = d.DevicePath, *d.OSDID, d.OSDUUID

		return daemons.OSD(p), nil
	case state.TypeRGW:
		if s.RGW == nil || s.RGW.Cert == "" || s.RGW.Key == "" {
			return nil, errors.New("rgw: no serving certificate yet")
		}

		k, err := key("client.rgw." + d.ID)
		if err != nil {
			return nil, err
		}

		p.Keyring = daemons.Keyring("client.rgw."+d.ID, k)
		p.Port, p.TLSPEM = s.RGW.Port, s.RGW.Cert+s.RGW.Key

		return daemons.RGW(p), nil
	case state.TypeVIP:
		if s.RGW == nil || s.RGW.VIP == "" || s.RGW.KeepalivedImage == "" {
			return nil, errors.New("vip: no virtual IP or keepalived image")
		}

		vipParams(s, &p, d)

		// stopped before its host's RGW, so the VIP moves first (plan 03, item 12)
		for _, r := range s.DaemonsOf(state.TypeRGW, h.Name) {
			if !r.LocalOnly && !r.Purged {
				p.DependsOn = append(p.DependsOn, s.DocName(r))
			}
		}

		// keepalived has its own image and does not follow upgrades
		return daemons.VIP(p, s.RGW.KeepalivedImage), nil
	}

	return nil, fmt.Errorf("unknown daemon type %q", d.Type)
}

// vipParams sets a keepalived's VRRP parameters: priority by placement order
// (the first is preferred), the other VIP hosts as unicast peers.
func vipParams(s *state.State, p *daemons.Params, d state.Daemon) {
	r := s.RGW
	p.Port, p.VIP, p.VRID, p.VRRPPass = r.Port, r.VIP, r.VRID, r.VRRPPass
	p.Priority = 150

	for i, other := range s.DaemonsOf(state.TypeVIP, "") {
		if other.ID == d.ID {
			p.Priority = 150 - 10*i
		} else if oh, ok := s.Host(other.Host); ok {
			p.Peers = append(p.Peers, oh.Addr)
		}
	}
}

// JobInputs hashes what a job does; its records refuse the same id with other
// inputs.
func JobInputs(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))

	return hex.EncodeToString(h[:])
}

// OSDPrepareName is the document of an OSD deployment's preparation job.
func OSDPrepareName(s *state.State, d state.Daemon) string {
	return s.DocName(state.Daemon{Type: "osd-prepare", ID: d.DeployID})
}

// OSDPrepareInputs are the inputs of an OSD deployment's preparation: the
// cluster, the host, the disk by its stable device and serial, the deployment.
func OSDPrepareInputs(s *state.State, h state.Host, d state.Daemon) string {
	return JobInputs("osd-prepare", s.FSID, h.Name, d.DevicePath, d.DiskSerial, d.DeployID)
}

// OSDPrepare renders the job that prepares an OSD's disk, with the
// bootstrap-osd key; its job id is the deployment id.
func OSDPrepare(s *state.State, h state.Host, d state.Daemon, key Key) (*spec.ContainerConfig, error) {
	if !strings.HasPrefix(d.DevicePath, "/dev/disk/by-id/") || d.DiskSerial == "" || d.DeployID == "" {
		return nil, fmt.Errorf("osd %s: no stable device, serial or deployment", d.ID)
	}

	k, err := key("client.bootstrap-osd")
	if err != nil {
		return nil, err
	}

	return daemons.OSDPrepare(daemons.Params{
		Name: OSDPrepareName(s, d), Image: s.Image, FSID: s.FSID, ID: "job",
		Keyring: daemons.Keyring("client.bootstrap-osd", k), Device: d.DevicePath, DiskSerial: d.DiskSerial,
	}, d.DeployID, OSDPrepareInputs(s, h, d)), nil
}

// Zap renders the job that zaps a device, bound to its serial; id is a fresh
// six-hex job id.
func Zap(s *state.State, h state.Host, id, device, serial string) *spec.ContainerConfig {
	return daemons.Zap(daemons.Params{
		Name: s.DocName(state.Daemon{Type: "job", ID: id}), Image: s.Image, FSID: s.FSID, ID: "job",
		Device: device, DiskSerial: serial,
	}, id, JobInputs("zap", h.Name, device, serial))
}

// Probe renders the container that reads an image's Ceph version; id is a
// fresh six-hex job id.
func Probe(s *state.State, id, image string) *spec.ContainerConfig {
	return daemons.Probe(s.DocName(state.Daemon{Type: "probe", ID: id}), image)
}
