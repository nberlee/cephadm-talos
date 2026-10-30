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
	"slices"
	"strings"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/config/types/container"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/spec"
)

//go:embed scripts/*.sh
var scripts embed.FS

// Params describes one daemon instance.
type Params struct {
	Name       string // ContainerConfig name
	Image      string
	FSID       string
	ID         string   // daemon id (mon/mgr: hostname)
	Addr       string   // public address of the host
	Keyring    string   // keyring file contents for this daemon
	Device     string   // OSD only
	OSDUUID    string   // OSD only: the uuid of the prepared OSD
	OSDID      int      // OSD only: the id of the prepared OSD
	DiskSerial string   // OSD prepare only: the serial the device must have
	Port       int      // rgw/vip: RGW HTTPS port
	TLSPEM     string   // rgw: certificate + key
	VIP        string   // vip: CIDR of the virtual IP
	VRID       int      // vip: VRRP router id
	VRRPPass   string   // vip: VRRP password (max 8 chars)
	Priority   int      // vip: VRRP priority
	Peers      []string // vip: addresses of the other vip hosts
	Mode       string   // mon only: "bootstrap" or "join"
	Addrv      string   // mon only: address vector, e.g. [v2:10.5.0.3:3300,v1:10.5.0.3:6789]
	DeployID   string   // changes when the daemon is (re)created, not on redeploy/upgrade
	DependsOn  []string
}

// rawScript returns an embedded script without common.sh, for a job's command.
func rawScript(name string) string {
	b, err := scripts.ReadFile("scripts/" + name + ".sh")
	if err != nil {
		panic(err)
	}

	return string(b)
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

func base(p Params, typ string) *spec.ContainerConfig {
	c := spec.Container(p.Name, p.Image)
	c.ContainerEntrypoint = []string{"/bin/bash", "-c", script(typ)}
	c.ContainerEnvironment = []string{
		"FSID=" + p.FSID,
		"ID=" + p.ID,
		"ADDR=" + p.Addr,
		"CEPHADM_TALOS_KEYRING=" + base64.StdEncoding.EncodeToString([]byte(p.Keyring)),
		// ceph images print a lot of python warnings when HOME is unset
		"HOME=/tmp",
		"DEPLOY_ID=" + p.DeployID,
	}
	c.MountsConfig = []spec.Mount{
		spec.UserVolume(spec.VolumeName, "/var/lib/ceph"),
		spec.HostPath("/etc/ceph", "/etc/ceph", "ro"),
		spec.Tmpfs("/tmp"),
		spec.Tmpfs("/var/run/ceph"),
		spec.Tmpfs("/var/log/ceph"),
	}
	c.NetworkConfig = spec.HostNetwork()
	c.DependsOnConfig = &container.ContainerDependsOn{
		NetworksConfig:   []string{"addresses"},
		TimeConfig:       boolPtr(true),
		PathsConfig:      []string{"/etc/ceph/ceph.conf"},
		ContainersConfig: running(p.DependsOn),
	}

	return c
}

// Mon renders a ceph-mon container. Mode "bootstrap" creates a fresh monmap,
// "join" fetches it from the running quorum (the keyring must then hold client.admin).
func Mon(p Params) *spec.ContainerConfig {
	c := base(p, "mon")
	c.ContainerEnvironment = append(c.ContainerEnvironment, "MODE="+p.Mode, "ADDRV="+p.Addrv)
	// restricted profile: no capabilities, read-only rootfs
	c.SecurityConfig = spec.Restricted()

	return c
}

// Mgr renders a ceph-mgr container with the talos mgr module: moduleFiles
// are its files on the host below /etc/ceph/mgr/cephadm. They are mounted over
// the image's cephadm module (/usr/share/ceph/mgr/cephadm), which needs SSH and
// cannot work on Talos: Ceph only accepts cephadm, rook or test_orchestrator
// as orchestrator backend. The mgr waits for the files.
func Mgr(p Params, moduleFiles ...string) *spec.ContainerConfig {
	c := base(p, "mgr")
	c.SecurityConfig = spec.Restricted()
	c.MountsConfig = append(c.MountsConfig, spec.HostPath("/etc/ceph/mgr/cephadm", "/usr/share/ceph/mgr/cephadm", "ro"))

	for _, f := range moduleFiles {
		c.DependsOnConfig.PathsConfig = append(c.DependsOnConfig.PathsConfig, "/etc/ceph/mgr/cephadm/"+f)
	}

	return c
}

// OSD renders a ceph-osd container on a raw block device.
//
// It has to be privileged: ceph-volume reads and labels the device, mounts a
// tmpfs for the OSD dir and needs udev data for device inspection.
func OSD(p Params) *spec.ContainerConfig {
	c := base(p, "osd")
	c.ContainerEnvironment = append(c.ContainerEnvironment, "DEVICE="+p.Device, fmt.Sprintf("OSD_ID=%d", p.OSDID), "OSD_UUID="+p.OSDUUID)
	c.SecurityConfig = spec.Privileged()
	c.MountsConfig = append(c.MountsConfig,
		spec.HostPath("/dev", "/dev"),
		spec.HostPath("/run/udev", "/run/udev", "ro"),
		spec.Tmpfs("/run/lock"),
		// `ceph-volume raw activate` rebuilds the OSD dir from the device label on every start
		spec.Tmpfs("/var/lib/ceph/osd"),
	)
	c.DependsOnConfig.PathsConfig = append(c.DependsOnConfig.PathsConfig, p.Device)

	return c
}

// RGW renders a radosgw container serving HTTPS on p.Port.
func RGW(p Params) *spec.ContainerConfig {
	c := base(p, "rgw")
	c.ContainerEnvironment = append(c.ContainerEnvironment,
		fmt.Sprintf("PORT=%d", p.Port),
		"TLS_PEM="+base64.StdEncoding.EncodeToString([]byte(p.TLSPEM)))
	// no capabilities except binding a port below 1024 (443)
	c.SecurityConfig = spec.Restricted("NET_BIND_SERVICE")

	return c
}

// VIP renders a keepalived container holding the RGW virtual IP.
//
// It needs NET_ADMIN to add the address and NET_RAW for VRRP and gratuitous ARP.
// Talos's own VIP can't be used: it elects the holder through etcd.
func VIP(p Params, image string) *spec.ContainerConfig {
	c := base(p, "vip")
	c.ContainerImage = image
	c.ContainerEnvironment = append(c.ContainerEnvironment,
		fmt.Sprintf("PORT=%d", p.Port),
		"VIP="+p.VIP,
		fmt.Sprintf("VRID=%d", p.VRID),
		"VRRP_PASS="+p.VRRPPass,
		fmt.Sprintf("PRIORITY=%d", p.Priority),
		"PEERS="+strings.Join(p.Peers, " "))
	c.SecurityConfig = spec.Restricted("NET_ADMIN", "NET_RAW", "NET_BROADCAST")
	// keepalived needs neither the Ceph volume nor ceph.conf
	c.MountsConfig = []spec.Mount{
		spec.Tmpfs("/tmp"),
		spec.Tmpfs("/run"),
		spec.Tmpfs("/var/run/ceph"),
		spec.Tmpfs("/var/log/ceph"),
	}
	c.DependsOnConfig.PathsConfig = nil

	return c
}

// AgentUID is the uid and gid the agent runs as: the owner of the machined socket.
const AgentUID = 50

// Agent renders the node agent: read-only Talos access over the machined
// socket, its status served on the host network (internal/agent).
func Agent(name, recordsInit, image, caPEM, certPEM, keyPEM, clientCertPEM, clientKeyPEM string) *spec.ContainerConfig {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	c := spec.Container(name, image)
	c.ContainerEnvironment = []string{
		agent.EnvCA + "=" + b64(caPEM),
		agent.EnvCert + "=" + b64(certPEM),
		agent.EnvKey + "=" + b64(keyPEM),
		agent.EnvClientCert + "=" + b64(clientCertPEM),
		agent.EnvClientKey + "=" + b64(clientKeyPEM),
	}
	c.RunAsConfig = spec.RunAs(AgentUID, AgentUID)
	c.SecurityConfig = spec.Restricted()
	c.SecurityConfig.SecurityMachinedAccess = true
	c.NetworkConfig = spec.HostNetwork()
	// its records, prepared on every boot by records-init (plan 03, item 6)
	c.MountsConfig = []spec.Mount{spec.UserVolume(spec.RecordsVolumeName, records.Mount)}
	c.DependsOnConfig = &container.ContainerDependsOn{ContainersConfig: []container.ContainerDependency{spec.Succeeded(recordsInit)}}

	return c
}

// RecordsInit renders the container that prepares the agent's records
// directories on every boot: the agent binary as root, with only the
// capabilities chown and chmod need (plan 03 spike: CHOWN alone fails at chmod
// once the directory belongs to the agent).
func RecordsInit(name, image string) *spec.ContainerConfig {
	c := spec.Container(name, image)
	c.ContainerEntrypoint = []string{"/cephadm-talos", "records-init"}
	c.RunAsConfig = spec.RunAs(0, 0)
	c.SecurityConfig = spec.Restricted("CHOWN", "FOWNER")
	c.MountsConfig = []spec.Mount{spec.UserVolume(spec.RecordsVolumeName, records.Mount)}
	c.RestartConfig = spec.RestartOnFailure(3)

	return c
}

// Probe renders a container that prints the Ceph version and architecture of
// an image and exits, read back from its log. Unlike a Job it needs nothing from
// a cluster (no records volume, no ceph.conf), so it runs before bootstrap.
func Probe(name, image string) *spec.ContainerConfig {
	c := spec.Container(name, image)
	c.ContainerEntrypoint = []string{"/bin/bash", "-c", script("probe")}
	c.ContainerEnvironment = []string{"HOME=/tmp"}
	c.SecurityConfig = spec.Restricted()
	c.MountsConfig = []spec.Mount{spec.Tmpfs("/tmp"), spec.Tmpfs("/var/run/ceph"), spec.Tmpfs("/var/log/ceph")}
	c.RestartConfig = spec.RestartNever()

	return c
}

// Job renders a one-shot job (plan 03, item 8): a `never` container with the
// cephadm-talos volume's jobs directory, which claims its id, records that it
// started and writes its result there. inputs identifies what it does: the same
// id with other inputs is refused. Jobs get no Ceph key.
func Job(p Params, job, inputs, cmd string) *spec.ContainerConfig {
	p.Keyring = ""
	c := base(p, "job")
	c.ContainerEnvironment = append(c.ContainerEnvironment, "JOB="+job, "JOB_INPUTS="+inputs, "CMD="+cmd,
		"JOBS="+records.Mount+"/"+records.JobsDir)
	c.SecurityConfig = spec.Restricted()
	c.MountsConfig = []spec.Mount{
		spec.UserVolume(spec.RecordsVolumeName, records.Mount),
		spec.Tmpfs("/tmp"),
		spec.Tmpfs("/var/run/ceph"),
		spec.Tmpfs("/var/log/ceph"),
	}
	c.DependsOnConfig.TimeConfig = nil
	c.DependsOnConfig.PathsConfig = nil
	c.RestartConfig = spec.RestartNever()

	return c
}

// OSDPrepare renders the job that prepares a raw device as a new OSD (plan 03,
// item 8): privileged, with the device, ceph.conf, the Ceph volume and the
// bootstrap-osd key only. It ignores SIGTERM for its whole process tree and has
// the longest stop timeout, so a reboot during prepare waits for it.
func OSDPrepare(p Params, job, inputs string) *spec.ContainerConfig {
	key := p.Keyring
	c := DeviceJob(p, job, inputs, rawScript("osd-prepare"))
	// a job's environment has an empty key; this one carries the bootstrap-osd key
	c.ContainerEnvironment = slices.DeleteFunc(c.ContainerEnvironment, func(e string) bool { return strings.HasPrefix(e, "CEPHADM_TALOS_KEYRING=") })
	c.ContainerEnvironment = append(c.ContainerEnvironment,
		"CEPHADM_TALOS_KEYRING="+base64.StdEncoding.EncodeToString([]byte(key)),
		"DEVICE="+p.Device, "DISK_SERIAL="+p.DiskSerial, "JOB_IGNORE_TERM=1")
	c.MountsConfig = append(c.MountsConfig,
		spec.UserVolume(spec.VolumeName, "/var/lib/ceph"),
		spec.HostPath("/etc/ceph", "/etc/ceph", "ro"),
		// the bootstrap key must not outlive the job; the OSD dir is rebuilt on activation
		spec.Tmpfs("/var/lib/ceph/bootstrap-osd"),
		spec.Tmpfs("/var/lib/ceph/osd"),
	)
	c.DependsOnConfig.PathsConfig = []string{"/etc/ceph/ceph.conf", p.Device}
	c.ContainerStopTimeout = MaxStopTimeout

	return c
}

// MaxStopTimeout is the longest stop timeout Talos accepts.
const MaxStopTimeout = 4 * time.Minute

// HostJob is a privileged Job with the host's /var/lib/ceph volume, for cleanup.
func HostJob(p Params, job, inputs, cmd string) *spec.ContainerConfig {
	c := DeviceJob(p, job, inputs, cmd)
	c.MountsConfig = append(c.MountsConfig, spec.UserVolume(spec.VolumeName, "/var/lib/ceph"))

	return c
}

// DeviceJob is a Job with raw device access, for zapping OSD devices.
func DeviceJob(p Params, job, inputs, cmd string) *spec.ContainerConfig {
	c := Job(p, job, inputs, cmd)
	c.SecurityConfig = spec.Privileged()
	c.MountsConfig = append(c.MountsConfig,
		spec.HostPath("/dev", "/dev"),
		spec.HostPath("/run/udev", "/run/udev", "ro"),
		spec.Tmpfs("/run/lock"),
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

// running lists containers that must be running and healthy first.
func running(names []string) []container.ContainerDependency {
	if len(names) == 0 {
		return nil
	}

	deps := make([]container.ContainerDependency, len(names))
	for i, n := range names {
		deps[i] = container.ContainerDependency{DependencyName: n}
	}

	return deps
}
