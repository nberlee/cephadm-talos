package state

import (
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
		`{"schema":2,"fsid":"eb8dac3e-0ba7-4795-8feb-a80e8593331f"}`,
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

	h, _ := back.Host("h1")
	if back.Image != "img" || h.Talosconfig != "/tc" || h.AgentCert != "ac" || back.Agent.OperatorKey != "opkey" || back.Agent.CAKey != "cakey" ||
		back.Keys["client.admin"] != "adminkey" || back.Keys["mon."] != "" || len(back.Daemons) != 1 {
		t.Errorf("round trip: %+v %+v %+v", back, h, back.Agent)
	}
}
