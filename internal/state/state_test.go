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
		if err := os.WriteFile(filepath.Join(st.Dir(), "state.json"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "state schema") {
			t.Errorf("%s: want a schema error, got %v", body, err)
		}
	}
}
