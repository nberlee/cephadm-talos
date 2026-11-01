package state

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRefusesOtherSchemas(t *testing.T) {
	t.Setenv("CEPHADM_TALOS_HOME", t.TempDir())

	st := New("eb8dac3e-0ba7-4795-8feb-a80e8593331f")
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(""); err != nil {
		t.Fatalf("current schema: %v", err)
	}

	for _, body := range []string{
		`{"fsid":"eb8dac3e-0ba7-4795-8feb-a80e8593331f"}`,
		`{"schema":3,"fsid":"eb8dac3e-0ba7-4795-8feb-a80e8593331f"}`,
	} {
		if err := os.WriteFile(filepath.Join(st.Dir(), "local.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "schema") {
			t.Errorf("%s: want a schema error, got %v", body, err)
		}
	}
}

func TestRecordsRoundTripWithoutLocalParts(t *testing.T) {
	t.Setenv("CEPHADM_TALOS_HOME", t.TempDir())

	st := New("eb8dac3e-0ba7-4795-8feb-a80e8593331f")
	st.Image = "img"
	st.Talosconfig = "/home/op/talosconfig"
	st.Agent = &Agent{Image: "agent", CACert: "ca", CAKey: "cakey", OperatorCert: "opcert", OperatorKey: "opkey"}
	st.Hosts = []Host{{Name: "h1", Addr: "10.0.0.1", Talosconfig: "/tc", Context: "c", AgentCert: "ac"}}
	st.Daemons = []Daemon{{Type: TypeMon, ID: "h1", Host: "h1"}}
	st.Keys["client.admin"], st.Keys["mon."] = "adminkey", "monkey"

	recs, err := st.Records()
	if err != nil {
		t.Fatal(err)
	}

	all := ""
	for _, v := range recs {
		all += string(v)
	}

	for _, local := range []string{"opkey", "opcert", "/tc", "/home/op/talosconfig", "adminkey", "monkey"} {
		if strings.Contains(all, local) {
			t.Errorf("%s in the cluster records", local)
		}
	}

	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	back, err := Load("")
	if err != nil {
		t.Fatal(err)
	}

	if err := back.ApplyRecords(recs); err != nil {
		t.Fatal(err)
	}

	// the cluster's private keys come from the secrets, not the records
	if strings.Contains(all, "cakey") {
		t.Error("the agent CA key is in the cluster records")
	}

	back.ApplySecrets(st.Secrets())

	h, _ := back.Host("h1")
	if back.Image != "img" || h.Talosconfig != "/tc" || h.AgentCert != "ac" || back.Agent.OperatorKey != "opkey" || back.Agent.CAKey != "cakey" ||
		back.Keys["client.admin"] != "adminkey" || back.Keys["mon."] != "" || len(back.Daemons) != 1 {
		t.Errorf("round trip: %+v %+v %+v", back, h, back.Agent)
	}
}

func TestSecretsCoverEveryPrivateValue(t *testing.T) {
	s := New("eb8dac3e-0ba7-4795-8feb-a80e8593331f")
	s.Agent = &Agent{CACert: "C", CAKey: "ca-key"}
	s.RGW = &RGW{CAKey: "rgw-ca-key", Key: "rgw-key", VRRPPass: "vrrp-pass"}
	s.AddHost(Host{Name: "h1", AgentKey: "agent-1", AgentClientKey: "agent-2", MgrServerKey: "mgr-1", MgrClientKey: "mgr-2"})
	s.Contacts = []Host{{Name: "h2", AgentKey: "contact-1"}}

	recs, err := s.Records()
	if err != nil {
		t.Fatal(err)
	}

	all := ""
	for _, r := range recs {
		all += string(r)
	}

	sec := s.Secrets()

	for _, v := range []string{"ca-key", "rgw-ca-key", "rgw-key", "vrrp-pass", "agent-1", "agent-2", "mgr-1", "mgr-2", "contact-1"} {
		found := false

		for _, got := range sec {
			found = found || got == v
		}

		if !found {
			t.Errorf("%q is not a secret", v)
		}

		if strings.Contains(all, v) {
			t.Errorf("%q is in the published records", v)
		}
	}

	back := New(s.FSID)
	if err := back.ApplyRecords(recs); err != nil {
		t.Fatal(err)
	}

	back.Contacts = []Host{{Name: "h2"}}
	back.ApplySecrets(sec)

	if back.Agent.CAKey != "ca-key" || back.RGW.VRRPPass != "vrrp-pass" || back.Hosts[0].MgrClientKey != "mgr-2" || back.Contacts[0].AgentKey != "contact-1" {
		t.Fatalf("secrets lost: %+v %+v %+v", back.Agent, back.RGW, back.Hosts)
	}
}

// The approval key signs what agents admit: it is neither published nor a
// secret the mgr could read (plan 03, step 6c).
func TestTheApprovalKeyStaysOnTheWorkstation(t *testing.T) {
	t.Setenv("CEPHADM_TALOS_HOME", t.TempDir())

	s := New("eb8dac3e-0ba7-4795-8feb-a80e8593331f")
	s.Agent = &Agent{CACert: "C", ApprovalKey: "public-key", ApprovalPriv: "private-key", Approval: "last-approval", OperatorCert: "op"}

	recs, err := s.Records()
	if err != nil {
		t.Fatal(err)
	}

	all := ""
	for _, r := range recs {
		all += string(r)
	}

	for _, v := range s.Secrets() {
		all += v
	}

	if strings.Contains(all, "private-key") || strings.Contains(all, "last-approval") || !strings.Contains(all, "public-key") {
		t.Fatalf("published or secret: %s", all)
	}

	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	back, err := Load(s.FSID)
	if err != nil || back.Agent == nil || back.Agent.ApprovalPriv != "private-key" || back.Agent.Approval != "last-approval" {
		t.Fatalf("not kept on the workstation: %+v %v", back.Agent, err)
	}
}

// A save keeps a newer approval another process signed meanwhile.
func TestASaveKeepsANewerApproval(t *testing.T) {
	t.Setenv("CEPHADM_TALOS_HOME", t.TempDir())

	signed := func(serial int) string {
		p := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"serial":%d}`, serial)))

		return `{"payload":"` + p + `","signature":"x"}`
	}

	s := New("eb8dac3e-0ba7-4795-8feb-a80e8593331f")
	s.Agent = &Agent{OperatorCert: "op", Approval: signed(2)}
	must(t, s.Save())

	old := New(s.FSID)
	old.Agent = &Agent{OperatorCert: "op", Approval: signed(1)}
	must(t, old.Save())

	if got, err := LastApproval(s.FSID); err != nil || got != signed(2) {
		t.Fatalf("approval on disk %s %v", got, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}
