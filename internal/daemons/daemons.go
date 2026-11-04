// Package daemons turns a Ceph daemon into a Talos ContainerConfig document.
//
// This is the equivalent of cephadm's `deploy` (unit.run + systemd unit): the
// container runs a small bash entrypoint that does any one-time initialisation
// (mkfs, ceph-volume prepare) idempotently and then execs the daemon in the
// foreground. Talos restarts it 5s after it exits.
package daemons

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/siderolabs/talos/pkg/machinery/config/types/container"

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
	ID         string // daemon id (mon/mgr: hostname)
	Addr       string // public address of the host
	Keyring    string // keyring file contents for this daemon
	Device     string // OSD only
	OSDUUID    string // OSD only: the uuid of the prepared OSD
	OSDID      int    // OSD only: the id of the prepared OSD
	DiskSerial string // OSD prepare only: the serial the device must have
	// ZapUnlabelled: a zap without the label check, which needs an approval
	ZapUnlabelled bool
	Port          int      // rgw/vip: RGW HTTPS port
	TLSPEM        string   // rgw: certificate + key
	TLSUser       bool     // rgw: the operator's certificate, not a generated one
	VIP           string   // vip: CIDR of the virtual IP
	VRID          int      // vip: VRRP router id
	VRRPPass      string   // vip: VRRP password (max 8 chars)
	Priority      int      // vip: VRRP priority
	Peers         []string // vip: addresses of the other vip hosts
	Mode          string   // mon only: "bootstrap" or "join"
	Addrv         string   // mon only: address vector, e.g. [v2:10.5.0.3:3300,v1:10.5.0.3:6789]
	DeployID      string   // changes when the daemon is (re)created, not on redeploy/upgrade
	DependsOn     []string
}

// Daemons restart after RestartDelay, backing off to RestartMaxDelay (plan 03,
// item 12).
const (
	RestartDelay    = 5 * time.Second
	RestartMaxDelay = 2 * time.Minute
)

// RGWStopTimeout lets radosgw drain: rgw_exit_timeout_secs (pinned to 120s
// by rgw.sh) plus 10s. With rgw_graceful_stop it finishes requests in flight first.
const RGWStopTimeout = 130 * time.Second

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
	// a crash loop (an OSD started before the mons have quorum) backs off in Talos
	c.RestartConfig = spec.RestartBackoff(RestartDelay, RestartMaxDelay)
	c.DependsOnConfig = &container.ContainerDependsOn{
		NetworksConfig:   []string{"addresses"},
		TimeConfig:       boolPtr(true),
		PathsConfig:      []string{"/etc/ceph/ceph.conf"},
		ContainersConfig: running(p.DependsOn),
	}

	return c
}

// Mon renders a ceph-mon container. Mode "bootstrap" creates a fresh monmap
// (the first mon, whose keyring also seeds mon auth); "join" makes the mon's
// store from ceph.conf's mon_host and the mon. key alone, as cephadm does, and
// the mon joins the quorum on its own.
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

// MgrGuardDelay is how long a mgr's guard holds its mgr up after its host's
// stop began (mgr-guard.sh).
const MgrGuardDelay = 4 * time.Second

// MgrGuard renders the guard of a host's mgr (plan 04, step 5, item 2b): it
// depends on the mgr running, so Talos's reverse dependsOn shutdown order
// stops it first on its host's stop and the mgr only after it exited, which it
// does MgrGuardDelay after SIGTERM: the agent's going-down report reaches its
// own host's module, which records host_down and fails over. ceph-mgr itself
// exits at once on SIGTERM. The Ceph image, no capabilities, no mounts, no
// network: it only sleeps. A restart or redeploy of the mgr alone does not
// touch it.
func MgrGuard(name, image, fsid, id, mgr string) *spec.ContainerConfig {
	c := spec.Container(name, image)
	c.ContainerEntrypoint = []string{"/bin/bash", "-c", rawScript("mgr-guard")}
	c.ContainerEnvironment = []string{"FSID=" + fsid, "ID=" + id}
	c.SecurityConfig = spec.Restricted()
	c.RestartConfig = spec.RestartBackoff(RestartDelay, RestartMaxDelay)
	c.DependsOnConfig = &container.ContainerDependsOn{ContainersConfig: running([]string{mgr})}

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

	if p.TLSUser {
		c.ContainerEnvironment = append(c.ContainerEnvironment, "TLS_USER=1")
	}

	// no capabilities except binding a port below 1024 (443)
	c.SecurityConfig = spec.Restricted("NET_BIND_SERVICE")
	c.ContainerStopTimeout = RGWStopTimeout

	return c
}

// VIP renders a keepalived container holding the RGW virtual IP. Its
// dependency on its host's RGW (p.DependsOn) makes Talos stop it first on a
// reboot, shutdown or upgrade, so the VIP moves before the RGW drains.
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

// Files a mgr host has besides ceph.conf (EtcFileConfig names, below /etc): the
// mgr module and its TLS identity for the agent channel.
const (
	AgentCAFile       = "ceph/talos/agent-ca.crt"
	MgrCertFile       = "ceph/talos/mgr-client.crt"
	MgrKeyFile        = "ceph/talos/mgr-client.key"
	MgrServerCertFile = "ceph/talos/mgr-server.crt"
	MgrServerKeyFile  = "ceph/talos/mgr-server.key"
	// the module is installed as "cephadm": Ceph accepts only cephadm, rook and
	// test_orchestrator as orchestrator backend (orchestrator/module.py)
	MgrModuleDir = "ceph/mgr/cephadm"
)

// The agent's environment: its TLS identity (base64 PEM) and the image
// repositories its admission policy allows (plan 03, item 13), space-separated.
const (
	EnvCA         = "CEPHADM_TALOS_AGENT_CA"
	EnvCert       = "CEPHADM_TALOS_AGENT_CERT"
	EnvKey        = "CEPHADM_TALOS_AGENT_KEY"
	EnvClientCert = "CEPHADM_TALOS_AGENT_CLIENT_CERT"
	EnvClientKey  = "CEPHADM_TALOS_AGENT_CLIENT_KEY"
	EnvImageRepos = "CEPHADM_TALOS_IMAGE_REPOS"
	// EnvApprovalKey is the public key of the operator's approvals (internal/approval)
	EnvApprovalKey = "CEPHADM_TALOS_APPROVAL_KEY"
	// EnvCRLFailClosed, "1", makes the agent refuse all but the revocation
	// list's delivery and the operator's calls while its list is past its
	// nextUpdate (plan 04, step 3); a pinned input, set by the CLI only
	EnvCRLFailClosed = "CEPHADM_TALOS_CRL_FAIL_CLOSED"
)

// ImageRepository is the repository of an image reference, normalized as
// Talos pulls it (docker.io/library/... for short names).
func ImageRepository(ref string) (string, error) {
	n, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return "", err
	}

	return n.Name(), nil
}

// AgentUID is the uid and gid the agent runs as: the owner of the machined socket.
const AgentUID = 50

// Agent renders the node agent: Talos access to its own node over the machined
// socket, its status served on the host network (internal/agent). repos are
// the image repositories its admission policy allows; crlClosed sets the
// fail-closed revocation list policy.
func Agent(name, recordsInit, image string, repos []string, approvalKey string, crlClosed bool, caPEM, certPEM, keyPEM, clientCertPEM, clientKeyPEM string) *spec.ContainerConfig {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	c := spec.Container(name, image)
	c.ContainerEnvironment = []string{
		EnvCA + "=" + b64(caPEM),
		EnvCert + "=" + b64(certPEM),
		EnvKey + "=" + b64(keyPEM),
		EnvClientCert + "=" + b64(clientCertPEM),
		EnvClientKey + "=" + b64(clientKeyPEM),
		EnvImageRepos + "=" + strings.Join(repos, " "),
		EnvApprovalKey + "=" + approvalKey,
	}
	if crlClosed {
		c.ContainerEnvironment = append(c.ContainerEnvironment, EnvCRLFailClosed+"=1")
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

// RecordsJob renders the recovery job that reads an agent's records, and
// with session records its suspension (plan 03, step 7 slice D): the agent
// binary as the agent's user, with the records volume only. It writes its
// report as a job result.
func RecordsJob(name, image, fsid, job, inputs, session string) *spec.ContainerConfig {
	c := spec.Container(name, image)
	c.ContainerEntrypoint = []string{"/cephadm-talos", "records", "--fsid", fsid, "--job", job, "--inputs", inputs}
	if session != "" {
		c.ContainerEntrypoint = append(c.ContainerEntrypoint, "--session", session)
	}

	c.ContainerEnvironment = []string{"JOB=" + job, "JOB_INPUTS=" + inputs, "CMD=records " + job}
	c.RunAsConfig = spec.RunAs(AgentUID, AgentUID)
	c.SecurityConfig = spec.Restricted()
	c.MountsConfig = []spec.Mount{spec.UserVolume(spec.RecordsVolumeName, records.Mount)}
	c.RestartConfig = spec.RestartNever()

	return c
}

// RecordsSettleJob is RecordsJob that first settles an interrupted
// self-update's apply intent (`agent restore`, plan 04 step 2): the agent's
// records only, nothing on the node.
func RecordsSettleJob(name, image, fsid, job, inputs string) *spec.ContainerConfig {
	c := RecordsJob(name, image, fsid, job, inputs, "")
	c.ContainerEntrypoint = append(c.ContainerEntrypoint, "--settle-self")

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

// ProbeCmd is the probe job's command: the image's Ceph version and CPU
// architecture, as Probe prints them.
const ProbeCmd = `ceph --version; echo "arch $(uname -m)"`

// ProbeInputs are the inputs of a probe job: the cluster, the host, the image.
func ProbeInputs(fsid, host, image string) string {
	return JobInputs("probe", fsid, host, image)
}

// ProbeJob renders the image probe as a job (plan 03, step 6d): the leader
// reads its output from the job's result, as it cannot read container logs.
func ProbeJob(p Params, job, host string) *spec.ContainerConfig {
	return Job(p, job, ProbeInputs(p.FSID, host, p.Image), ProbeCmd)
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

// Zap renders the job that wipes an OSD device (plan 03, item 8), bound to the
// disk's serial like OSDPrepare.
func Zap(p Params, job, inputs string) *spec.ContainerConfig {
	c := DeviceJob(p, job, inputs, rawScript("zap"))
	c.ContainerEnvironment = append(c.ContainerEnvironment, "DEVICE="+p.Device, "DISK_SERIAL="+p.DiskSerial)

	// the script requires a BlueStore label of this cluster (and of this OSD)
	// unless the operator approved zapping the disk as it is
	if p.ZapUnlabelled {
		c.ContainerEnvironment = append(c.ContainerEnvironment, "ZAP_UNLABELLED=1")
	}

	if p.OSDUUID != "" {
		c.ContainerEnvironment = append(c.ContainerEnvironment, "ZAP_OSD_UUID="+p.OSDUUID)
	}

	return c
}

// JobInputs hashes what a job does; its records refuse the same id with other
// inputs.
func JobInputs(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))

	return hex.EncodeToString(h[:])
}

// PrepareInputs are the inputs of an OSD deployment's preparation: the
// cluster, the host, the disk by its stable device and serial, the deployment.
func PrepareInputs(fsid, host, device, serial, deployID string) string {
	return JobInputs("osd-prepare", fsid, host, device, serial, deployID)
}

// ZapInputs are the inputs of a zap: the host, the disk, and what the job
// checks before it wipes (the label, or none with an approval; an OSD's uuid).
func ZapInputs(host, device, serial string, unlabelled bool, osdUUID string) string {
	mode := "label"
	if unlabelled {
		mode = "unlabelled"
	}

	return JobInputs("zap", host, device, serial, mode, osdUUID)
}

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

// MonKeyring is a joining mon's keyring: the mon. key with its fixed caps.
func MonKeyring(key string) string { return Keyring("mon.", key, "mon", "allow *") }

// MonAddrv is the mon address vector; IPv6 addresses need brackets.
func MonAddrv(ip string) string {
	return fmt.Sprintf("[v2:%s,v1:%s]", net.JoinHostPort(ip, "3300"), net.JoinHostPort(ip, "6789"))
}

// CephConf renders the minimal ceph.conf shared by all daemons on all hosts,
// from the fsid and the mon addresses. The agent renders it the same way to
// admit a granted ceph.conf (plan 03, item 13).
func CephConf(fsid string, monAddrs []string) string {
	var addrs []string

	v4, v6 := false, false

	for _, a := range monAddrs {
		addrs = append(addrs, MonAddrv(a))

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
`, fsid, strings.Join(addrs, ","), v4, v6)
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
