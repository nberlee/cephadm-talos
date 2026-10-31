package orch

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/siderolabs/talos/pkg/machinery/config/config"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/cephx"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/render"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

// policyOrch is inventoryOrch with what every grantable kind needs: digest
// images, keys in mon auth, an RGW with its certificate and a VIP on h1.
func policyOrch(t *testing.T) *Orch {
	t.Helper()

	o := inventoryOrch(t)
	o.St.Image = "quay.io/ceph/ceph@sha256:" + strings.Repeat("ab", 32)

	caCert, caKey, err := pki.NewCA("rgw CA", 1)
	if err != nil {
		t.Fatal(err)
	}

	cert, key, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "rgw", IPs: []string{"10.5.0.100"}, Usage: x509.ExtKeyUsageServerAuth, Years: 1})
	if err != nil {
		t.Fatal(err)
	}

	o.St.RGW = &state.RGW{
		Port: 443, CACert: caCert, CAKey: caKey, Cert: cert, Key: key,
		VIP: "10.5.0.100/24", VRID: 51, VRRPPass: "0a1b2c3d", KeepalivedImage: "quay.io/ceph/keepalived@sha256:" + strings.Repeat("cd", 32),
	}

	for _, e := range []string{"mon.", "mgr.h1", "client.rgw.h1", "client.bootstrap-osd"} {
		k, err := cephx.NewKey()
		if err != nil {
			t.Fatal(err)
		}

		o.St.Keys[e] = k
	}

	osd, _ := o.St.Find("osd.3")
	osd.OSDUUID, osd.DiskSerial, osd.DevicePath, osd.DeployID = "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f", "QM00001", "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00001", "0123456789abcdef"
	o.St.AddDaemon(osd)
	o.St.AddDaemon(state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"})
	o.St.AddDaemon(state.Daemon{Type: state.TypeVIP, ID: "h1", Host: "h1"})

	return o
}

func docOf(t *testing.T, d any) agent.Doc {
	t.Helper()

	b, err := spec.Render(d)
	if err != nil {
		t.Fatal(err)
	}

	cd := d.(config.Document)

	return agent.Doc{Kind: cd.Kind(), Name: d.(config.NamedDocument).Name(), YAML: b}
}

// hostRevision renders everything the CLI puts on h1 that a grant can carry.
func hostRevision(t *testing.T, o *Orch) ([]agent.Doc, []string) {
	t.Helper()

	h, _ := o.St.Host("h1")

	var docs []agent.Doc

	var names []string

	for _, d := range o.St.Daemons {
		if d.Host != "h1" {
			continue
		}

		c, err := o.redeployDoc(d, h, o.St.Image)
		if err != nil {
			t.Fatalf("%s.%s: %v", d.Type, d.ID, err)
		}

		docs = append(docs, docOf(t, c))
		names = append(names, c.MetaName)
	}

	osd, _ := o.St.Find("osd.3")
	jobs := []*spec.ContainerConfig{
		prepareDoc(t, o, h, osd, o.St.Keys["client.bootstrap-osd"]),
		o.zapDoc(h, "a1b2c3", osd.DevicePath, osd.DiskSerial),
	}

	for _, c := range jobs {
		docs = append(docs, docOf(t, c))
	}

	docs = append(docs, docOf(t, spec.CephConf(o.CephConf())), docOf(t, spec.CephVolume()))

	for _, f := range mustDocs(t)(o.mgrFileDocs(h, true)) {
		docs = append(docs, docOf(t, f))
	}

	return docs, names
}

func testPolicy(o *Orch) *agent.Policy {
	return &agent.Policy{FSID: o.St.FSID, Host: "h1", Repos: o.imageRepos(), CACert: o.St.Agent.CACert}
}

var testDisks = []agent.Disk{{Serial: "QM00001", Symlinks: []string{"/dev/disk/by-id/ata-QEMU_HARDDISK_QM00001", "/dev/disk/by-path/pci-0000:00:1f.2-ata-1"}}}

// The agents admit every document the CLI renders: the leader renders them
// with the same code (plan 03, item 13).
func TestAgentsAdmitWhatTheCLIRenders(t *testing.T) {
	o := policyOrch(t)
	docs, names := hostRevision(t, o)

	kinds := map[string]bool{}
	for _, d := range docs {
		kinds[d.Kind+"/"+strings.SplitN(strings.TrimPrefix(d.Name, "ceph-"+o.St.Short()+"-"), "-", 2)[0]] = true
	}

	for _, want := range []string{"ContainerConfig/mon", "ContainerConfig/mgr", "ContainerConfig/osd", "ContainerConfig/rgw", "ContainerConfig/vip", "ContainerConfig/job", "EtcFileConfig/ceph/ceph.conf", "UserVolumeConfig/ceph"} {
		if !kinds[want] {
			t.Errorf("no %s in the revision", want)
		}
	}

	if err := testPolicy(o).Check(docs, testDisks, names); err != nil {
		t.Fatal(err)
	}

	// the image probe, before an upgrade
	probe := docOf(t, daemonsProbe(o, "c0ffee"))
	if err := testPolicy(o).Check([]agent.Doc{probe}, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func daemonsProbe(o *Orch, id string) *spec.ContainerConfig {
	return daemons.Probe(o.St.DocName(state.Daemon{Type: "probe", ID: id}), o.St.Image)
}

// envSet replaces or adds an environment variable.
func envSet(c *spec.ContainerConfig, name, value string) {
	for i, e := range c.ContainerEnvironment {
		if strings.HasPrefix(e, name+"=") {
			c.ContainerEnvironment[i] = name + "=" + value

			return
		}
	}

	c.ContainerEnvironment = append(c.ContainerEnvironment, name+"="+value)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Every way a grant could carry more than its kind allows is refused.
func TestAgentsRefuseWhatTheTemplatesDoNot(t *testing.T) {
	o := policyOrch(t)
	_, names := hostRevision(t, o)
	h, _ := o.St.Host("h1")

	render := func(typ string) *spec.ContainerConfig {
		for _, d := range o.St.Daemons {
			if d.Host == "h1" && d.Type == typ {
				c, err := o.redeployDoc(d, h, o.St.Image)
				if err != nil {
					t.Fatal(err)
				}

				return c
			}
		}

		t.Fatalf("no %s on h1", typ)

		return nil
	}

	osd, _ := o.St.Find("osd.3")
	otherCA, otherCAKey, _ := pki.NewCA("other", 1)
	otherMgr, _, _ := pki.Issue(otherCA, otherCAKey, pki.Leaf{CommonName: "mgr", Usage: x509.ExtKeyUsageClientAuth, Years: 1, Identity: &pki.Identity{FSID: o.St.FSID, Role: pki.RoleMgr, Name: "h1"}})
	h2Mgr, _, _ := pki.Issue(o.St.Agent.CACert, o.St.Agent.CAKey, pki.Leaf{CommonName: "mgr", Usage: x509.ExtKeyUsageClientAuth, Years: 1, Identity: &pki.Identity{FSID: o.St.FSID, Role: pki.RoleMgr, Name: "h2"}})
	adm, _ := cephx.NewKey()

	cases := map[string]func() any{
		"privileged mon": func() any { c := render("mon"); c.SecurityConfig = spec.Privileged(); return c },
		"an added host path": func() any {
			c := render("mgr")
			c.MountsConfig = append(c.MountsConfig, spec.HostPath("/var", "/host", "ro"))
			return c
		},
		"an added env var":   func() any { c := render("mgr"); envSet(c, "LD_PRELOAD", "/tmp/x.so"); return c },
		"another entrypoint": func() any { c := render("mon"); c.ContainerEntrypoint = []string{"/bin/sh", "-c", "id"}; return c },
		"an image by tag":    func() any { c := render("mon"); c.ContainerImage = "quay.io/ceph/ceph:v20.2.4"; return c },
		"another repository": func() any {
			c := render("mon")
			c.ContainerImage = "evil.example/ceph@sha256:" + strings.Repeat("ab", 32)
			return c
		},
		"a tag and a digest": func() any {
			c := render("mon")
			c.ContainerImage = "quay.io/ceph/ceph:v20@sha256:" + strings.Repeat("ab", 32)
			return c
		},
		"mon with the admin key": func() any {
			c := render("mon")
			envSet(c, "CEPHADM_TALOS_KEYRING", b64(o.monKeyringFor(t)+"[client.admin]\n\tkey = "+adm+"\n"))
			return c
		},
		"mgr with another entity": func() any {
			c := render("mgr")
			envSet(c, "CEPHADM_TALOS_KEYRING", b64("[client.admin]\n\tkey = "+adm+"\n"))
			return c
		},
		"mgr key with extra caps": func() any {
			c := render("mgr")
			envSet(c, "CEPHADM_TALOS_KEYRING", b64("[mgr.h1]\n\tkey = "+adm+"\n\tcaps mon = \"allow *\"\n"))
			return c
		},
		"a bootstrap mon":       func() any { c := render("mon"); envSet(c, "MODE", "bootstrap"); return c },
		"an id not in the name": func() any { c := render("mgr"); envSet(c, "ID", "h2"); return c },
		"another cluster":       func() any { c := render("mgr"); envSet(c, "FSID", "00000000-0000-4000-8000-000000000000"); return c },
		"a dependency outside the cluster": func() any {
			c := render("mon")
			c.DependsOnConfig.ContainersConfig = append(c.DependsOnConfig.ContainersConfig, spec.Succeeded("app"))
			return c
		},
		"an OSD on an unknown disk":              func() any { c := render("osd"); envSet(c, "DEVICE", "/dev/disk/by-id/ata-OTHER"); return c },
		"an OSD by kernel name":                  func() any { c := render("osd"); envSet(c, "DEVICE", "/dev/sda"); return c },
		"a VRRP password with a shell character": func() any { c := render("vip"); envSet(c, "VRRP_PASS", "a;reboot"); return c },
		"an RGW certificate without its key":     func() any { c := render("rgw"); envSet(c, "TLS_PEM", b64(o.St.RGW.Cert)); return c },
		"a zap of another serial":                func() any { return o.zapDoc(h, "a1b2c3", osd.DevicePath, "QM99999") },
		"a zap with a command": func() any {
			c := o.zapDoc(h, "a1b2c3", osd.DevicePath, osd.DiskSerial)
			envSet(c, "CMD", "rm -rf /var/lib/ceph")
			return c
		},
		"a prepare without its key": func() any { return prepareDoc(t, o, h, osd, "") },
		"an unknown kind": func() any {
			c := render("mgr")
			c.MetaName = "ceph-" + o.St.Short() + "-shell-h1"
			return c
		},
		"a ceph.conf with another option": func() any {
			return spec.CephConf(o.CephConf() + "debug_ms = 20\n")
		},
		"a ceph.conf with an option in a zone": func() any {
			return spec.CephConf(daemons.CephConf(o.St.FSID, []string{"::1%x\rmon_host = 10.5.0.3\rdebug_ms = 20\r#"}))
		},
		"a mon address with a zone": func() any { c := render("mon"); envSet(c, "ADDR", "fe80::1%eth0"); return c },
		"a VIP peer with a zone": func() any {
			c := render("vip")
			envSet(c, "PEERS", "fe80::1%x;reboot")
			return c
		},
		"a duplicated secret env name": func() any {
			c := render("mgr")
			c.ContainerEnvironment = append(c.ContainerEnvironment, "SECRETVALUE=1", "SECRETVALUE=2")
			return c
		},
		"a ceph.conf with another fsid": func() any {
			return spec.CephConf(strings.Replace(o.CephConf(), o.St.FSID, "00000000-0000-4000-8000-000000000000", 1))
		},
		"a changed module file":             func() any { return spec.EtcFile(mgrModuleDir+"/module.py", 0o644, "import os\n") },
		"another agent CA":                  func() any { return spec.EtcFile(agentCAFile, 0o644, otherCA) },
		"a mgr certificate of another CA":   func() any { return spec.EtcFile(mgrCertFile, 0o644, otherMgr) },
		"a mgr certificate of another host": func() any { return spec.EtcFile(mgrCertFile, 0o644, h2Mgr) },
		"a mgr key readable by all":         func() any { return spec.EtcFile(mgrKeyFile, 0o644, h.MgrClientKey) },
		"another file":                      func() any { return spec.EtcFile("ceph/talos/inventory.json", 0o644, "{}") },
	}

	pol := testPolicy(o)

	for name, mk := range cases {
		d := docOf(t, mk())
		if err := pol.Check([]agent.Doc{d}, testDisks, names); err == nil {
			t.Errorf("%s admitted", name)
		} else if strings.Contains(err.Error(), adm) || strings.Contains(err.Error(), "a;reboot") || strings.Contains(err.Error(), "SECRETVALUE") {
			t.Errorf("%s: the error carries a value: %v", name, err)
		}
	}
}

// monKeyringFor is the mon. keyring the CLI renders for a joining mon.
func (o *Orch) monKeyringFor(t *testing.T) string {
	t.Helper()

	return daemons.MonKeyring(o.St.Keys["mon."])
}

// A document that does not decode is refused without its contents in the
// error, and a pre-check sees every document once.
func TestPolicyErrorsAndDuplicates(t *testing.T) {
	o := policyOrch(t)
	h, _ := o.St.Host("h1")
	pol := testPolicy(o)

	// a misspelt field next to a private key: Talos's decoder quotes values
	bad := []byte("apiVersion: v1alpha1\nkind: EtcFileConfig\nname: " + mgrKeyFile + "\nmode: 0o600\ncontent: |\n" +
		"  " + strings.ReplaceAll(strings.TrimSpace(h.MgrClientKey), "\n", "\n  ") + "\n")
	err := pol.Check([]agent.Doc{{Kind: "EtcFileConfig", Name: mgrKeyFile, YAML: bad}}, nil, nil)

	if err == nil || strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), strings.Split(h.MgrClientKey, "\n")[1]) {
		t.Fatalf("undecodable key document: %v", err)
	}

	if err := pol.Check([]agent.Doc{{Kind: "EtcFileConfig", Name: mgrKeyFile, YAML: []byte("contents: [" + h.MgrClientKey)}}, nil, nil); err == nil || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("broken YAML: %v", err)
	}

	// an arbitrary probe hidden behind a valid one of the same name
	good := docOf(t, daemonsProbe(o, "c0ffee"))
	evil := daemonsProbe(o, "c0ffee")
	evil.ContainerEntrypoint = []string{"/bin/sh", "-c", "id"}

	if err := pol.Check([]agent.Doc{docOf(t, evil), good}, nil, nil); err == nil {
		t.Fatal("a duplicate passed the pre-check")
	}
}

// An OSD on a host named "prepare" is an OSD, not an OSD preparation.
func TestPolicyKindByIDNotPrefix(t *testing.T) {
	o := policyOrch(t)
	o.St.AddHost(state.Host{Name: "prepare", Addr: "10.5.0.9"})

	d := state.Daemon{Type: state.TypeOSD, ID: "prepare-sda", Host: "prepare", OSDID: new(int), OSDUUID: "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f",
		DevicePath: "/dev/disk/by-id/ata-QEMU_HARDDISK_QM00001", DiskSerial: "QM00001", DeployID: "0123456789abcdef"}
	h, _ := o.St.Host("prepare")

	c, err := o.redeployDoc(d, h, o.St.Image)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(c.MetaName, "ceph-"+o.St.Short()+"-osd-prepare-") {
		t.Fatalf("name %s does not collide", c.MetaName)
	}

	pol := &agent.Policy{FSID: o.St.FSID, Host: "prepare", Repos: o.imageRepos(), CACert: o.St.Agent.CACert}
	if err := pol.Check([]agent.Doc{docOf(t, c)}, testDisks, nil); err != nil {
		t.Fatal(err)
	}
}

func prepareDoc(t *testing.T, o *Orch, h state.Host, d state.Daemon, key string) *spec.ContainerConfig {
	t.Helper()

	c, err := render.OSDPrepare(o.St, h, d, func(string) (string, error) { return key, nil })
	if err != nil {
		t.Fatal(err)
	}

	return c
}

// mustDocs unwraps a list of documents, failing the test on an error.
func mustDocs(t *testing.T) func([]any, error) []any {
	return func(docs []any, err error) []any {
		t.Helper()

		if err != nil {
			t.Fatal(err)
		}

		return docs
	}
}

// A dry-run OSD deploy renders what the real one does, with a stable device.
func TestDryRunOSDDeployRenders(t *testing.T) {
	o := fakeOrch(t, talostest.New(t))
	o.St.Image = "quay.io/ceph/ceph@sha256:" + strings.Repeat("ab", 32)
	o.St.Keys["client.bootstrap-osd"], _ = cephx.NewKey()
	o.St.AddHost(state.Host{Name: "h1", Addr: "node"})
	o.St.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1"})

	var out bytes.Buffer

	o.Talos.DryRun, o.Talos.Out = true, &out

	h, _ := o.St.Host("h1")
	if err := o.deployOSD(context.Background(), h, "/dev/vdb"); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"osd-prepare-", "DEVICE=/dev/disk/by-id/dry-run-vdb", "name: ceph-" + o.St.Short() + "-osd-h1-vdb"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the dry run misses %q", want)
		}
	}
}

// Removing an RGW updates its host's keepalived in the same apply: Talos
// refuses a config that names a missing container.
func TestRemovingAnRGWDropsTheVIPDependency(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)
	ctx := context.Background()

	pol := policyOrch(t)
	o.St.Image, o.St.RGW, o.St.Keys = pol.St.Image, pol.St.RGW, pol.St.Keys
	o.St.AddHost(state.Host{Name: "h1", Addr: "node"})

	rgw := state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"}
	vip := state.Daemon{Type: state.TypeVIP, ID: "h1", Host: "h1"}
	o.St.AddDaemon(rgw)
	o.St.AddDaemon(vip)

	h, _ := o.St.Host("h1")

	r, err := o.redeployDoc(rgw, h, o.St.Image)
	if err != nil {
		t.Fatal(err)
	}

	v, err := o.redeployDoc(vip, h, o.St.Image)
	if err != nil {
		t.Fatal(err)
	}

	if err := o.apply(ctx, "node", r, v); err != nil {
		t.Fatal(err)
	}

	// the RGW alone cannot go
	if err := o.remove(ctx, "node", o.St.DocName(rgw)); err == nil {
		t.Fatal("Talos took a config naming a missing container")
	}

	if err := o.removeDoc(ctx, h, rgw); err != nil {
		t.Fatal(err)
	}

	cfg, err := o.Talos.MachineConfig(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(cfg, "name: "+o.St.DocName(rgw)+"\n") || !strings.Contains(cfg, "name: "+o.St.DocName(vip)) {
		t.Fatalf("after removing the rgw:\n%s", cfg)
	}
}

// A host in maintenance has neither document: removing its RGW starts no keepalived.
func TestRemovingAnRGWInMaintenanceKeepsTheVIPStopped(t *testing.T) {
	f := talostest.New(t, images())
	o := fakeOrch(t, f)
	ctx := context.Background()

	pol := policyOrch(t)
	o.St.Image, o.St.RGW, o.St.Keys = pol.St.Image, pol.St.RGW, pol.St.Keys
	o.St.AddHost(state.Host{Name: "h1", Addr: "node", Maintenance: true})

	rgw := state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"}
	vip := state.Daemon{Type: state.TypeVIP, ID: "h1", Host: "h1"}
	o.St.AddDaemon(rgw)
	o.St.AddDaemon(vip)

	h, _ := o.St.Host("h1")
	if err := o.removeDoc(ctx, h, rgw); err != nil {
		t.Fatal(err)
	}

	cfg, err := o.Talos.MachineConfig(ctx, "node")
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(cfg, o.St.DocName(vip)) {
		t.Fatalf("keepalived started on a host in maintenance:\n%s", cfg)
	}
}
