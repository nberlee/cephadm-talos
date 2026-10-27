// Package daemons turns a Ceph daemon into a Talos ContainerConfig document.
//
// This is the equivalent of cephadm's `deploy` (unit.run + systemd unit): the
// container runs a small bash entrypoint that does any one-time initialisation
// (mkfs, ceph-volume prepare) idempotently and then execs the daemon in the
// foreground. Talos restarts it 5s after it exits.
package daemons

import (
	"embed"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/nberlee/cephadm-talos/internal/spec"
)

//go:embed scripts/*.sh
var scripts embed.FS

// Params describes one daemon instance.
type Params struct {
	Name      string // ContainerConfig name
	Image     string
	FSID      string
	ID        string   // daemon id (mon/mgr: hostname)
	Addr      string   // public address of the host
	Keyring   string   // keyring file contents for this daemon
	Device    string   // OSD only
	OSDUUID   string   // OSD only: the osd fsid to prepare the device with
	Port      int      // rgw/vip: RGW HTTPS port
	TLSPEM    string   // rgw: certificate + key
	VIP       string   // vip: CIDR of the virtual IP
	VRID      int      // vip: VRRP router id
	VRRPPass  string   // vip: VRRP password (max 8 chars)
	Priority  int      // vip: VRRP priority
	Peers     []string // vip: addresses of the other vip hosts
	Mode      string   // mon only: "bootstrap" or "join"
	KeyType   string   // mon only: cephx key type of the cluster (cephx.KeyAES...)
	Addrv     string   // mon only: address vector, e.g. [v2:10.5.0.3:3300,v1:10.5.0.3:6789]
	DeployID  string   // changes when the daemon is (re)created, not on redeploy/upgrade
	DependsOn []string
}

func script(name string) string {
	common, err := scripts.ReadFile("scripts/common.sh")
	if err != nil {
		panic(err)
	}

	body, err := scripts.ReadFile("scripts/" + name + ".sh")
	if err != nil {
		panic(err)
	}

	return string(common) + "\n" + string(body)
}

func boolPtr(b bool) *bool { return &b }

func base(p Params, typ string) spec.ContainerConfig {
	c := spec.ContainerConfig{
		Header:     spec.Header{APIVersion: "v1alpha1", Kind: "ContainerConfig", Name: p.Name},
		Image:      p.Image,
		Entrypoint: []string{"/bin/bash", "-c", script(typ)},
		Environment: []string{
			"FSID=" + p.FSID,
			"ID=" + p.ID,
			"ADDR=" + p.Addr,
			"CEPHADM_TALOS_KEYRING=" + base64.StdEncoding.EncodeToString([]byte(p.Keyring)),
			// ceph images print a lot of python warnings when HOME is unset
			"HOME=/tmp",
			"DEPLOY_ID=" + p.DeployID,
		},
		Mounts: []spec.Mount{
			{UserVolume: &spec.UserVolumeMount{Name: spec.VolumeName, Destination: "/var/lib/ceph"}},
			{HostPath: &spec.HostPathMount{Source: "/etc/ceph", Destination: "/etc/ceph", Options: []string{"ro"}}},
			{Tmpfs: &spec.TmpfsMount{Destination: "/tmp"}},
			{Tmpfs: &spec.TmpfsMount{Destination: "/var/run/ceph"}},
			{Tmpfs: &spec.TmpfsMount{Destination: "/var/log/ceph"}},
		},
		Network: &spec.Network{Mode: "host"},
		DependsOn: &spec.DependsOn{
			Networks:   []string{"addresses"},
			Time:       boolPtr(true),
			Paths:      []string{"/etc/ceph/ceph.conf"},
			Containers: p.DependsOn,
		},
	}

	return c
}

// Mon renders a ceph-mon container. Mode "bootstrap" creates a fresh monmap,
// "join" fetches it from the running quorum (the keyring must then hold client.admin).
func Mon(p Params) spec.ContainerConfig {
	c := base(p, "mon")
	c.Environment = append(c.Environment, "MODE="+p.Mode, "ADDRV="+p.Addrv, "KEY_TYPE="+p.KeyType)
	// restricted profile: no capabilities, read-only rootfs
	c.Security = &spec.Security{Profile: "restricted"}

	return c
}

// Mgr renders a ceph-mgr container.
func Mgr(p Params) spec.ContainerConfig {
	c := base(p, "mgr")
	c.Security = &spec.Security{Profile: "restricted"}

	return c
}

// OSD renders a ceph-osd container on a raw block device.
//
// It has to be privileged: ceph-volume reads and labels the device, mounts a
// tmpfs for the OSD dir and needs udev data for device inspection.
func OSD(p Params) spec.ContainerConfig {
	c := base(p, "osd")
	c.Environment = append(c.Environment, "DEVICE="+p.Device, "OSD_UUID="+p.OSDUUID)
	c.Security = &spec.Security{Profile: "privileged"}
	c.Mounts = append(c.Mounts,
		spec.Mount{HostPath: &spec.HostPathMount{Source: "/dev", Destination: "/dev"}},
		spec.Mount{HostPath: &spec.HostPathMount{Source: "/run/udev", Destination: "/run/udev", Options: []string{"ro"}}},
		spec.Mount{Tmpfs: &spec.TmpfsMount{Destination: "/run/lock"}},
		// not on the host volume: the bootstrap key must not outlive the container, and
		// `ceph-volume raw activate` rebuilds the OSD dir from the device label on every start
		spec.Mount{Tmpfs: &spec.TmpfsMount{Destination: "/var/lib/ceph/bootstrap-osd"}},
		spec.Mount{Tmpfs: &spec.TmpfsMount{Destination: "/var/lib/ceph/osd"}},
	)
	c.DependsOn.Paths = append(c.DependsOn.Paths, p.Device)

	return c
}

// RGW renders a radosgw container serving HTTPS on p.Port.
func RGW(p Params) spec.ContainerConfig {
	c := base(p, "rgw")
	c.Environment = append(c.Environment,
		fmt.Sprintf("PORT=%d", p.Port),
		"TLS_PEM="+base64.StdEncoding.EncodeToString([]byte(p.TLSPEM)))
	// no capabilities except binding a port below 1024 (443)
	c.Security = &spec.Security{Profile: "restricted", Capabilities: &spec.Capabilities{Add: []string{"NET_BIND_SERVICE"}}}

	return c
}

// VIP renders a keepalived container holding the RGW virtual IP.
//
// It needs NET_ADMIN to add the address and NET_RAW for VRRP and gratuitous ARP.
// Talos's own VIP can't be used: it elects the holder through etcd.
func VIP(p Params, image string) spec.ContainerConfig {
	c := base(p, "vip")
	c.Image = image
	c.Environment = append(c.Environment,
		fmt.Sprintf("PORT=%d", p.Port),
		"VIP="+p.VIP,
		fmt.Sprintf("VRID=%d", p.VRID),
		"VRRP_PASS="+p.VRRPPass,
		fmt.Sprintf("PRIORITY=%d", p.Priority),
		"PEERS="+strings.Join(p.Peers, " "))
	c.Security = &spec.Security{Profile: "restricted", Capabilities: &spec.Capabilities{Add: []string{"NET_ADMIN", "NET_RAW", "NET_BROADCAST"}}}
	// keepalived needs neither the Ceph volume nor ceph.conf
	c.Mounts = []spec.Mount{
		{Tmpfs: &spec.TmpfsMount{Destination: "/tmp"}},
		{Tmpfs: &spec.TmpfsMount{Destination: "/run"}},
		{Tmpfs: &spec.TmpfsMount{Destination: "/var/run/ceph"}},
		{Tmpfs: &spec.TmpfsMount{Destination: "/var/log/ceph"}},
	}
	c.DependsOn.Paths = nil

	return c
}

// Job renders a one-shot admin command container (cephadm-talos's replacement for `cephadm shell`).
func Job(p Params, job, cmd string) spec.ContainerConfig {
	c := base(p, "job")
	c.Environment = append(c.Environment, "JOB="+job, "CMD="+cmd)
	c.Security = &spec.Security{Profile: "restricted"}
	// jobs only need ceph.conf; no access to the daemon data
	c.Mounts = []spec.Mount{
		{HostPath: &spec.HostPathMount{Source: "/etc/ceph", Destination: "/etc/ceph", Options: []string{"ro"}}},
		{Tmpfs: &spec.TmpfsMount{Destination: "/tmp"}},
		{Tmpfs: &spec.TmpfsMount{Destination: "/var/run/ceph"}},
		{Tmpfs: &spec.TmpfsMount{Destination: "/var/log/ceph"}},
	}
	c.DependsOn.Time = nil

	return c
}

// HostJob is a privileged Job with the host's /var/lib/ceph volume, for cleanup.
func HostJob(p Params, job, cmd string) spec.ContainerConfig {
	c := DeviceJob(p, job, cmd)
	c.Mounts = append(c.Mounts, spec.Mount{UserVolume: &spec.UserVolumeMount{Name: spec.VolumeName, Destination: "/var/lib/ceph"}})

	return c
}

// DeviceJob is a Job with raw device access, for zapping OSD devices.
func DeviceJob(p Params, job, cmd string) spec.ContainerConfig {
	c := Job(p, job, cmd)
	c.Security = &spec.Security{Profile: "privileged"}
	c.Mounts = append(c.Mounts,
		spec.Mount{HostPath: &spec.HostPathMount{Source: "/dev", Destination: "/dev"}},
		spec.Mount{HostPath: &spec.HostPathMount{Source: "/run/udev", Destination: "/run/udev", Options: []string{"ro"}}},
		spec.Mount{Tmpfs: &spec.TmpfsMount{Destination: "/run/lock"}},
	)

	return c
}

// Keyring formats a keyring section. caps is a list of "service", "capspec" pairs.
func Keyring(entity, key string, caps ...string) string {
	s := fmt.Sprintf("[%s]\n\tkey = %s\n", entity, key)

	for i := 0; i+1 < len(caps); i += 2 {
		s += fmt.Sprintf("\tcaps %s = \"%s\"\n", caps[i], caps[i+1])
	}

	return s
}
