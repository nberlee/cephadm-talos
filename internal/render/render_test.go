package render

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
)

const image = "quay.io/ceph/ceph@sha256:abababababababababababababababababababababababababababababababab"

func testState() *state.State {
	s := state.New("eb8dac3e-0ba7-4795-8feb-a80e8593331f")
	s.Image = image
	s.Agent = &state.Agent{CACert: "CA"}
	s.RGW = &state.RGW{Port: 443, Cert: rgwServer.cert, Key: rgwServer.key, VIP: "10.5.0.100/24", VRID: 51, VRRPPass: "0a1b2c3d", KeepalivedImage: "quay.io/ceph/keepalived@sha256:cd"}

	s.AddHost(state.Host{Name: "h1", Addr: "10.5.0.2", MgrClientCert: mgrClient.cert, MgrClientKey: mgrClient.key, MgrServerCert: mgrServer.cert, MgrServerKey: mgrServer.key})
	s.AddHost(state.Host{Name: "h2", Addr: "10.5.0.3"})

	id := 3
	s.AddDaemon(state.Daemon{Type: state.TypeMon, ID: "h1", Host: "h1", DeployID: "0123456789abcdef"})
	s.AddDaemon(state.Daemon{Type: state.TypeMgr, ID: "h1", Host: "h1"})
	s.AddDaemon(state.Daemon{Type: state.TypeOSD, ID: "h1-sda", Host: "h1", OSDID: &id, OSDUUID: "8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f", DevicePath: "/dev/disk/by-id/ata-X_QM1", DiskSerial: "QM1", DeployID: "fedcba9876543210"})
	s.AddDaemon(state.Daemon{Type: state.TypeVIP, ID: "h2", Host: "h2"})
	s.AddDaemon(state.Daemon{Type: state.TypeVIP, ID: "h1", Host: "h1"})

	return s
}

func keys(entity string) (string, error) { return "KEY-" + entity, nil }

type pair struct{ cert, key string }

var mgrClient, mgrServer, rgwServer = issuePair(x509.ExtKeyUsageClientAuth), issuePair(x509.ExtKeyUsageServerAuth), issuePair(x509.ExtKeyUsageServerAuth)

func issuePair(usage x509.ExtKeyUsage) pair {
	caCert, caKey, err := pki.NewCA("test", 1)
	if err != nil {
		panic(err)
	}

	cert, key, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "h1", Usage: usage, Years: 1})
	if err != nil {
		panic(err)
	}

	return pair{cert, key}
}

// secrets looks a secret up in the state, as the CLI and the leader do.
func secrets(s *state.State) Secret {
	return func(name string) (string, error) {
		if v, ok := s.Secrets()[name]; ok {
			return v, nil
		}

		return "", errors.New("no secret " + name)
	}
}

func env(t *testing.T, list []string, name string) string {
	t.Helper()

	for _, e := range list {
		if v, ok := strings.CutPrefix(e, name+"="); ok {
			return v
		}
	}

	t.Fatalf("no %s", name)

	return ""
}

// snapshot is everything of a state, also its fields kept out of JSON.
func snapshot(t *testing.T, s *state.State) string {
	t.Helper()

	b, err := json.Marshal(struct {
		S         *state.State
		Keys      map[string]string
		Contacts  []state.Host
		Inventory state.InventoryRevision
		Agent     *state.Agent
		RGW       *state.RGW
	}{s, s.Keys, s.Contacts, s.Inventory, s.Agent, s.RGW})
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

func TestRenderingChangesNothing(t *testing.T) {
	s := testState()
	before := snapshot(t, s)

	h1, _ := s.Host("h1")
	h2, _ := s.Host("h2")

	for _, d := range s.Daemons {
		dh, _ := s.Host(d.Host)
		if _, err := Daemon(s, dh, d, image, keys, secrets(s)); err != nil {
			t.Fatalf("%s.%s: %v", d.Type, d.ID, err)
		}
	}

	osd, _ := s.Find("osd.3")

	_, err1 := MgrFiles(s, h1, true, secrets(s))
	_, err2 := MgrFiles(s, h2, false, secrets(s))
	_, err3 := OSDPrepare(s, h1, osd, keys)

	if err := errors.Join(err1, err2, err3); err != nil {
		t.Fatal(err)
	}

	_ = Zap(s, h1, "a1b2c3", osd.DevicePath, osd.DiskSerial)
	_ = Probe(s, "c0ffee", image)
	_ = CephConf(s)
	_ = OSDPrepareInputs(s, h1, osd)

	if after := snapshot(t, s); after != before {
		t.Fatalf("rendering changed the state:\n%s\n%s", before, after)
	}
}

func TestDaemonRendering(t *testing.T) {
	s := testState()
	h1, _ := s.Host("h1")
	h2, _ := s.Host("h2")

	mon, _ := s.Find("mon.h1")

	// a candidate image is rendered before the state changes; the mon keeps its deploy id
	c, err := Daemon(s, h1, mon, "quay.io/ceph/ceph@sha256:ef", keys, secrets(s))
	if err != nil || c.ContainerImage != "quay.io/ceph/ceph@sha256:ef" || env(t, c.ContainerEnvironment, "DEPLOY_ID") != mon.DeployID || env(t, c.ContainerEnvironment, "MODE") != "join" {
		t.Fatalf("mon: %v", err)
	}

	// keepalived keeps its own image; priority follows placement order
	vip1, _ := s.Find("vip.h1")
	vip2, _ := s.Find("vip.h2")

	c1, err := Daemon(s, h1, vip1, image, keys, secrets(s))
	if err != nil {
		t.Fatal(err)
	}

	c2, err := Daemon(s, h2, vip2, image, keys, secrets(s))
	if err != nil {
		t.Fatal(err)
	}

	if c1.ContainerImage != s.RGW.KeepalivedImage || env(t, c2.ContainerEnvironment, "PRIORITY") != "150" || env(t, c1.ContainerEnvironment, "PRIORITY") != "140" || env(t, c1.ContainerEnvironment, "PEERS") != "10.5.0.3" {
		t.Errorf("vip: %v %v", c1.ContainerEnvironment, c2.ContainerEnvironment)
	}
}

func TestIncompleteInputsAreRefused(t *testing.T) {
	s := testState()
	h1, _ := s.Host("h1")
	h2, _ := s.Host("h2")
	osd, _ := s.Find("osd.3")

	unprepared := osd
	unprepared.OSDID = nil

	kernel := osd
	kernel.DevicePath = ""

	noKey := func(string) (string, error) { return "", errors.New("not in mon auth") }
	mon, _ := s.Find("mon.h1")

	cases := map[string]func() error{
		"an OSD without its id":           func() error { _, err := Daemon(s, h1, unprepared, image, keys, secrets(s)); return err },
		"an OSD by kernel name":           func() error { _, err := Daemon(s, h1, kernel, image, keys, secrets(s)); return err },
		"a prepare by kernel name":        func() error { _, err := OSDPrepare(s, h1, kernel, keys); return err },
		"a mon without its key":           func() error { _, err := Daemon(s, h1, mon, image, noKey, secrets(s)); return err },
		"a mgr host without certificates": func() error { _, err := MgrFiles(s, h2, true, secrets(s)); return err },
		"a mgr key that does not match its certificate": func() error {
			s := testState()
			s.Hosts[0].MgrClientKey = mgrServer.key
			_, err := MgrFiles(s, h1, true, secrets(s))
			return err
		},
		"an RGW without its key": func() error {
			_, err := Daemon(s, h1, state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"}, image, keys, secrets(&state.State{}))
			return err
		},
		"an RGW key that does not match its certificate": func() error {
			s := testState()
			s.RGW.Key = mgrServer.key
			_, err := Daemon(s, h1, state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"}, image, keys, secrets(s))
			return err
		},
		"an RGW without a certificate": func() error {
			s := testState()
			s.RGW.Cert = ""
			_, err := Daemon(s, h1, state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"}, image, keys, secrets(s))
			return err
		},
	}

	for name, run := range cases {
		if run() == nil {
			t.Errorf("%s rendered", name)
		}
	}
}

func TestMgrFilesRemovalsAreReferences(t *testing.T) {
	s := testState()
	h2, _ := s.Host("h2")

	r, err := MgrFiles(s, h2, false, secrets(s))
	if err != nil || len(r.Upsert) != 0 || len(r.Remove) == 0 {
		t.Fatalf("%+v %v", r, err)
	}

	for _, ref := range r.Remove {
		if ref.Kind != "EtcFileConfig" || !strings.HasPrefix(ref.Name, "ceph/") {
			t.Errorf("removal %+v", ref)
		}
	}
}

func TestPrepareInputsUseTheStableDevice(t *testing.T) {
	s := testState()
	h1, _ := s.Host("h1")
	osd, _ := s.Find("osd.3")

	c, err := OSDPrepare(s, h1, osd, keys)
	if err != nil {
		t.Fatal(err)
	}

	if env(t, c.ContainerEnvironment, "DEVICE") != osd.DevicePath || env(t, c.ContainerEnvironment, "JOB_INPUTS") != OSDPrepareInputs(s, h1, osd) || env(t, c.ContainerEnvironment, "JOB") != osd.DeployID {
		t.Error("the prepare job does not render its own inputs")
	}
}

func TestDaemonDocuments(t *testing.T) {
	s := testState()
	s.AddDaemon(state.Daemon{Type: state.TypeRGW, ID: "h1", Host: "h1"})
	h1, _ := s.Host("h1")

	vip, _ := s.Find("vip.h1")

	c, err := Daemon(s, h1, vip, image, keys, secrets(s))
	if err != nil {
		t.Fatal(err)
	}

	// keepalived stops before its host's RGW
	rgwDoc := s.DocName(state.Daemon{Type: state.TypeRGW, ID: "h1"})
	if deps := c.DependsOnConfig.ContainersConfig; len(deps) != 1 || deps[0].DependencyName != rgwDoc {
		t.Fatalf("vip dependencies %+v", deps)
	}

	// daemons back off in Talos; the RGW drains
	rgw, _ := s.Find("rgw.h1")

	r, err := Daemon(s, h1, rgw, image, keys, secrets(s))
	if err != nil {
		t.Fatal(err)
	}

	if r.RestartConfig == nil || *r.RestartConfig.RestartDelay != daemons.RestartDelay || *r.RestartConfig.RestartMaxDelay != daemons.RestartMaxDelay || r.ContainerStopTimeout != daemons.RGWStopTimeout {
		t.Fatalf("rgw restart %+v, stop timeout %s", r.RestartConfig, r.ContainerStopTimeout)
	}

	// an RGW on its way out is no dependency
	rgw.LocalOnly = true
	s.AddDaemon(rgw)

	if c, _ = Daemon(s, h1, vip, image, keys, secrets(s)); len(c.DependsOnConfig.ContainersConfig) != 0 {
		t.Fatalf("dependency on a leaving rgw: %+v", c.DependsOnConfig.ContainersConfig)
	}
}
