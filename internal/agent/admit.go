package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/siderolabs/talos/pkg/machinery/config/types/runtime"

	"github.com/nberlee/cephadm-talos/internal/cephx"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/mgrmodule"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// Policy is the agent's admission policy (plan 03, item 13). Every granted
// document must be one of the cluster's kinds, rendered by the template
// compiled into the agent from parameters that pass their type: the agent
// extracts the parameters, renders the template and requires Talos's encoding
// of both to be identical. Anything else is refused. Its inputs come from the
// CLI at handoff, in the agent's own document, which no grant can change.
type Policy struct {
	FSID   string
	Host   string   // the agent's host: the mgr TLS files must be this host's mgr's
	Repos  []string // image repositories the cluster's images come from
	CACert string   // the agent CA, PEM
}

// Disk is what Talos reports of one of the node's disks.
type Disk struct {
	Serial   string
	Symlinks []string
}

// facts are what the policy checks parameters against.
type facts struct {
	disks []Disk
	// containers are the ContainerConfig names the node has or the revision adds
	containers map[string]bool
}

var (
	daemonIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	deployIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
	shortIDRe  = regexp.MustCompile(`^[0-9a-f]{6}$`)
	inputsRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	osdIDRe    = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)
	vrrpPassRe = regexp.MustCompile(`^[A-Za-z0-9]{1,8}$`)
	serialRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	keyringRe  = regexp.MustCompile(`^\[([^\]\n]+)\]\n\tkey = ([^\n]*)\n`)
	monHostRe  = regexp.MustCompile(`(?m)^mon_host = (.*)$`)
	addrvRe    = regexp.MustCompile(`^\[v2:(.+):3300,v1:(.+):6789\]$`)
)

// containerKinds are the ContainerConfig kinds a grant can carry, by the type in
// their name; longer types first, as "osd-prepare" begins like "osd".
var containerKinds = []string{"osd-prepare", "mon", "mgr", "osd", "rgw", "vip", "probe", "job"}

// Check runs the policy over a revision's documents as Apply does, against
// the node's disks and the ContainerConfig names it has; removals pass. The
// leader can check a revision before it grants it.
func (p *Policy) Check(docs []Doc, disks []Disk, containers []string) error {
	f := facts{disks: disks, containers: map[string]bool{}}
	for _, c := range containers {
		f.containers[c] = true
	}

	typed := map[string]typedDoc{}
	seen := map[string]bool{}

	for _, d := range docs {
		if seen[d.Key()] {
			return fmt.Errorf("%s twice", d.Key())
		}

		seen[d.Key()] = true

		if d.Kind == "ContainerConfig" {
			f.containers[d.Name] = d.YAML != nil
		}

		if d.YAML == nil {
			continue
		}

		td, err := checkDoc(d)
		if err != nil {
			return fmt.Errorf("%s: %w", d.Key(), err)
		}

		typed[d.Key()] = td
	}

	return p.check(docs, typed, f)
}

// check admits every document of a revision that is not a removal.
func (p *Policy) check(docs []Doc, typed map[string]typedDoc, f facts) error {
	for _, d := range docs {
		if d.YAML == nil {
			continue
		}

		if err := p.admit(d, typed[d.Key()], f); err != nil {
			return fmt.Errorf("%s refused: %w", d.Key(), err)
		}
	}

	return nil
}

// admit checks one granted document. Removals are not checked: a grant may
// remove any of the cluster's documents (the Node refuses the CLI's own).
func (p *Policy) admit(d Doc, td typedDoc, f facts) error {
	switch d.Kind {
	case "ContainerConfig":
		return p.admitContainer(d, td, f)
	case "EtcFileConfig":
		return p.admitFile(d, td)
	case "UserVolumeConfig":
		if d.Name == spec.VolumeName {
			return same(td, spec.CephVolume())
		}
	}

	return errors.New("not a kind the agent admits")
}

// same requires a document to be exactly the rendering of a template.
func same(td typedDoc, want any) error {
	b, err := spec.Render(want)
	if err != nil {
		return fmt.Errorf("rendering the template: %w", err)
	}

	docs, err := typedDocs(b)
	if err != nil || len(docs) != 1 {
		return fmt.Errorf("rendering the template: %w", err)
	}

	for _, w := range docs {
		if w.hash != td.hash {
			return errors.New("differs from its template")
		}
	}

	return nil
}

// env reads a container's environment into a map; every name once.
func envMap(list []string) (map[string]string, error) {
	m := make(map[string]string, len(list))

	for _, e := range list {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			return nil, errors.New("an environment entry without '='")
		}

		if _, dup := m[k]; dup {
			return nil, errors.New("an environment variable twice") // the name is input, not quoted
		}

		m[k] = v
	}

	return m, nil
}

func (p *Policy) prefix() string { return "ceph-" + (&state.State{FSID: p.FSID}).Short() + "-" }

func (p *Policy) docName(typ, id string) string {
	return (&state.State{FSID: p.FSID}).DocName(state.Daemon{Type: typ, ID: id})
}

// image checks an image reference: a digest from one of the allowed repositories.
func (p *Policy) image(ref string) error {
	n, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return errors.New("image: not a reference")
	}

	if _, ok := n.(reference.Canonical); !ok {
		return errors.New("image: not pinned to a digest")
	}

	if _, ok := n.(reference.Tagged); ok {
		return errors.New("image: a tag next to the digest")
	}

	if !slices.Contains(p.Repos, n.Name()) {
		return errors.New("image: not from the cluster's repositories")
	}

	return nil
}

// keyring checks a base64 keyring parameter: empty when want is "", else
// exactly want's entity with its key, rendered with the kind's fixed caps.
func keyring(b64, entity string, caps ...string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", errors.New("keyring: not base64")
	}

	if entity == "" {
		if len(raw) != 0 {
			return "", errors.New("keyring: this kind carries no key")
		}

		return "", nil
	}

	m := keyringRe.FindStringSubmatch(string(raw))
	if m == nil || m[1] != entity {
		return "", fmt.Errorf("keyring: not the key of %s", entity)
	}

	if err := cephx.Valid(m[2]); err != nil {
		return "", fmt.Errorf("keyring: %w", err)
	}

	k := daemons.Keyring(entity, m[2], caps...)
	if string(raw) != k {
		return "", fmt.Errorf("keyring: more than the key of %s with its caps", entity)
	}

	return k, nil
}

// device checks a device parameter: a /dev/disk/by-id link of one of the
// node's disks that carries the disk's serial; it returns that serial.
func device(path string, f facts) (string, error) {
	if !strings.HasPrefix(path, "/dev/disk/by-id/") {
		return "", errors.New("device: not a /dev/disk/by-id link")
	}

	for _, d := range f.disks {
		serial := strings.TrimSpace(d.Serial)
		if serial != "" && slices.Contains(d.Symlinks, path) && strings.Contains(path, serial) {
			return serial, nil
		}
	}

	return "", errors.New("device: not a disk of this node, by its serial")
}

// ip checks an IP address parameter. Zones are refused: their text is free
// and would reach ceph.conf and the scripts.
func ip(v, what string) error {
	a, err := netip.ParseAddr(v)
	if err != nil || a.Zone() != "" || a.String() != v {
		return fmt.Errorf("%s: not an IP address", what)
	}

	return nil
}

func intIn(v, what string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(v)
	if err != nil || strconv.Itoa(n) != v || n < lo || n > hi {
		return 0, fmt.Errorf("%s: not an integer in [%d, %d]", what, lo, hi)
	}

	return n, nil
}

func (p *Policy) admitContainer(d Doc, td typedDoc, f facts) error {
	c, ok := td.doc.(*spec.ContainerConfig)
	if !ok {
		return errors.New("not a ContainerConfig")
	}

	rest, ok := strings.CutPrefix(d.Name, p.prefix())
	if !ok {
		return errors.New("not the cluster's")
	}

	env, err := envMap(c.ContainerEnvironment)
	if err != nil {
		return err
	}

	// the kind whose id renders exactly this name: a host named "prepare" has
	// OSDs whose names begin like an OSD preparation's
	var kind string

	for _, k := range containerKinds {
		if !strings.HasPrefix(rest, k+"-") {
			continue
		}

		id := env["ID"]

		switch k {
		case "probe":
			id = strings.TrimPrefix(rest, "probe-")
		case "osd-prepare", "job":
			id = env["JOB"]
		}

		if id != "" && p.docName(k, id) == d.Name {
			kind = k

			break
		}
	}

	if kind == "" {
		return errors.New("not a kind a grant can carry, or its id is not the one in its name")
	}

	if err := p.image(c.ContainerImage); err != nil {
		return err
	}

	var deps []string

	if c.DependsOnConfig != nil {
		for _, dep := range c.DependsOnConfig.ContainersConfig {
			if !strings.HasPrefix(dep.DependencyName, p.prefix()) || !f.containers[dep.DependencyName] {
				return errors.New("dependsOn: not a document of the cluster on this node")
			}

			deps = append(deps, dep.DependencyName)
		}
	}

	if kind == "probe" {
		id := strings.TrimPrefix(rest, "probe-")
		if !shortIDRe.MatchString(id) || p.docName("probe", id) != d.Name {
			return errors.New("name: not a probe's")
		}

		return same(td, daemons.Probe(d.Name, c.ContainerImage))
	}

	// the parameters every other kind has (daemons.base)
	params := daemons.Params{Name: d.Name, Image: c.ContainerImage, FSID: env["FSID"], ID: env["ID"], Addr: env["ADDR"], DeployID: env["DEPLOY_ID"], DependsOn: deps}

	if params.FSID != p.FSID {
		return errors.New("FSID: not the cluster's")
	}

	if params.Addr != "" {
		if err := ip(params.Addr, "ADDR"); err != nil {
			return err
		}
	}

	if params.DeployID != "" && !deployIDRe.MatchString(params.DeployID) {
		return errors.New("DEPLOY_ID: not a deploy id")
	}

	switch kind {
	case "osd-prepare", "job":
		return p.admitJob(kind, d, td, env, params, f)
	}

	if !daemonIDRe.MatchString(params.ID) || p.docName(kind, params.ID) != d.Name {
		return errors.New("ID: not the daemon id in the document's name")
	}

	if err := ip(params.Addr, "ADDR"); err != nil {
		return err
	}

	switch kind {
	case "mon":
		if env["MODE"] != "join" {
			return errors.New("MODE: a granted mon joins the quorum")
		}

		if params.Keyring, err = keyring(env["CEPHADM_TALOS_KEYRING"], "mon.", "mon", "allow *"); err != nil {
			return err
		}

		params.Mode, params.Addrv = "join", daemons.MonAddrv(params.Addr)

		return same(td, daemons.Mon(params))
	case "mgr":
		if params.Keyring, err = keyring(env["CEPHADM_TALOS_KEYRING"], "mgr."+params.ID); err != nil {
			return err
		}

		return same(td, daemons.Mgr(params, mgrmodule.Names()...))
	case "osd":
		if _, err := device(env["DEVICE"], f); err != nil {
			return err
		}

		if !osdIDRe.MatchString(env["OSD_ID"]) {
			return errors.New("OSD_ID: not an OSD id")
		}

		if !uuidRe.MatchString(env["OSD_UUID"]) {
			return errors.New("OSD_UUID: not a uuid")
		}

		if _, err := keyring(env["CEPHADM_TALOS_KEYRING"], ""); err != nil {
			return err
		}

		params.Device, params.OSDUUID = env["DEVICE"], env["OSD_UUID"]
		params.OSDID, _ = strconv.Atoi(env["OSD_ID"])

		return same(td, daemons.OSD(params))
	case "rgw":
		if params.Keyring, err = keyring(env["CEPHADM_TALOS_KEYRING"], "client.rgw."+params.ID); err != nil {
			return err
		}

		if params.Port, err = intIn(env["PORT"], "PORT", 1, 65535); err != nil {
			return err
		}

		pemb, err := base64.StdEncoding.DecodeString(env["TLS_PEM"])
		if err != nil {
			return errors.New("TLS_PEM: not base64")
		}

		// any serving certificate with its matching key: the cluster's RGW CA or the user's own
		if _, err := tls.X509KeyPair(pemb, pemb); err != nil {
			return errors.New("TLS_PEM: not a certificate with its key")
		}

		params.TLSPEM = string(pemb)

		return same(td, daemons.RGW(params))
	case "vip":
		if _, err := keyring(env["CEPHADM_TALOS_KEYRING"], ""); err != nil {
			return err
		}

		if params.Port, err = intIn(env["PORT"], "PORT", 1, 65535); err != nil {
			return err
		}

		if _, err := netip.ParsePrefix(env["VIP"]); err != nil {
			return errors.New("VIP: not an address with its prefix length")
		}

		if params.VRID, err = intIn(env["VRID"], "VRID", 1, 255); err != nil {
			return err
		}

		if params.Priority, err = intIn(env["PRIORITY"], "PRIORITY", 1, 254); err != nil {
			return err
		}

		if !vrrpPassRe.MatchString(env["VRRP_PASS"]) {
			return errors.New("VRRP_PASS: not 1 to 8 letters and digits")
		}

		for _, peer := range strings.Fields(env["PEERS"]) {
			if err := ip(peer, "PEERS"); err != nil {
				return err
			}

			params.Peers = append(params.Peers, peer)
		}

		params.VIP, params.VRRPPass = env["VIP"], env["VRRP_PASS"]

		return same(td, daemons.VIP(params, c.ContainerImage))
	}

	return errors.New("not a kind a grant can carry")
}

// admitJob checks an OSD preparation or a zap: the job id in its name, its
// inputs hash, and the device by its serial.
func (p *Policy) admitJob(kind string, d Doc, td typedDoc, env map[string]string, params daemons.Params, f facts) error {
	job := env["JOB"]

	switch {
	case kind == "osd-prepare" && !deployIDRe.MatchString(job), kind == "job" && !shortIDRe.MatchString(job):
		return errors.New("JOB: not a job id")
	case p.docName(kind, job) != d.Name:
		return errors.New("JOB: not the job id in the document's name")
	case params.ID != "job" || params.Addr != "" || params.DeployID != "":
		return errors.New("ID, ADDR, DEPLOY_ID: not a job's")
	case !inputsRe.MatchString(env["JOB_INPUTS"]):
		return errors.New("JOB_INPUTS: not an inputs hash")
	}

	serial, err := device(env["DEVICE"], f)
	if err != nil {
		return err
	}

	if !serialRe.MatchString(env["DISK_SERIAL"]) || env["DISK_SERIAL"] != serial {
		return errors.New("DISK_SERIAL: not the serial of the device")
	}

	params.Device, params.DiskSerial = env["DEVICE"], serial

	if kind == "osd-prepare" {
		if params.Keyring, err = keyring(env["CEPHADM_TALOS_KEYRING"], "client.bootstrap-osd"); err != nil {
			return err
		}

		return same(td, daemons.OSDPrepare(params, job, env["JOB_INPUTS"]))
	}

	if _, err := keyring(env["CEPHADM_TALOS_KEYRING"], ""); err != nil {
		return err
	}

	return same(td, daemons.Zap(params, job, env["JOB_INPUTS"]))
}

// admitFile checks one of the cluster's files below /etc/ceph.
func (p *Policy) admitFile(d Doc, td typedDoc) error {
	f, ok := td.doc.(*runtime.EtcFileConfigV1Alpha1)
	if !ok {
		return errors.New("not an EtcFileConfig")
	}

	files := mgrmodule.Files()

	switch name := d.Name; {
	case name == "ceph/ceph.conf":
		addrs, err := monHosts(f.Contents)
		if err != nil {
			return err
		}

		return same(td, spec.CephConf(daemons.CephConf(p.FSID, addrs)))
	case strings.HasPrefix(name, daemons.MgrModuleDir+"/"):
		n := strings.TrimPrefix(name, daemons.MgrModuleDir+"/")
		if !slices.Contains(mgrmodule.Names(), n) {
			return errors.New("not a file of the mgr module")
		}

		// byte-identical to the module compiled into the agent
		return same(td, spec.EtcFile(name, 0o644, files[n]))
	case name == daemons.AgentCAFile:
		return same(td, spec.EtcFile(name, 0o644, p.CACert))
	case name == daemons.MgrCertFile, name == daemons.MgrServerCertFile:
		usage := x509.ExtKeyUsageClientAuth
		if name == daemons.MgrServerCertFile {
			usage = x509.ExtKeyUsageServerAuth
		}

		if err := p.mgrCert(f.Contents, usage); err != nil {
			return err
		}

		return same(td, spec.EtcFile(name, 0o644, f.Contents))
	case name == daemons.MgrKeyFile, name == daemons.MgrServerKeyFile:
		if err := privateKey(f.Contents); err != nil {
			return err
		}

		return same(td, spec.EtcFile(name, 0o600, f.Contents))
	}

	return errors.New("not one of the cluster's files")
}

// monHosts reads the mon addresses out of a ceph.conf's mon_host.
func monHosts(conf string) ([]string, error) {
	m := monHostRe.FindAllStringSubmatch(conf, -1)
	if len(m) != 1 {
		return nil, errors.New("ceph.conf: not one mon_host")
	}

	var addrs []string

	for _, v := range strings.Split(m[0][1], ",[") {
		if !strings.HasPrefix(v, "[") {
			v = "[" + v
		}

		a := addrvRe.FindStringSubmatch(v)
		if a == nil || a[1] != a[2] {
			return nil, errors.New("ceph.conf: mon_host is not a list of mon addresses")
		}

		host := strings.TrimSuffix(strings.TrimPrefix(a[1], "["), "]")
		if err := ip(host, "mon_host"); err != nil {
			return nil, err
		}

		addrs = append(addrs, host)
	}

	return addrs, nil
}

// mgrCert checks a mgr certificate: one PEM certificate the agent CA issued to
// this host's mgr of this cluster, for the given use.
func (p *Policy) mgrCert(contents string, usage x509.ExtKeyUsage) error {
	block, rest := pem.Decode([]byte(contents))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("not one PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("not a certificate")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(p.CACert)) {
		return errors.New("no agent CA")
	}

	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return errors.New("not issued by the agent CA for this use")
	}

	if _, err := pki.Require(cert, pki.Identity{FSID: p.FSID, Role: pki.RoleMgr, Name: p.Host}); err != nil {
		return errors.New("not this host's mgr's certificate")
	}

	return nil
}

// privateKey checks one PEM private key.
func privateKey(contents string) error {
	block, rest := pem.Decode([]byte(contents))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return errors.New("not one PEM private key")
	}

	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return nil
	}

	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return nil
	}

	return errors.New("not a private key")
}
