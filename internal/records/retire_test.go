package records

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRetireMarksEverySerialThenMovesTheSetAside(t *testing.T) {
	vol := t.TempDir()
	dir := filepath.Join(vol, "fsid")
	s := Store{Dir: dir}

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := s.Write("ownership", []byte("{}")); err != nil {
		t.Fatal(err)
	}

	if err := Retire(dir, nil); err == nil {
		t.Fatal("retired under no serial")
	}

	if err := Retire(dir, []string{"11", "12"}); err != nil {
		t.Fatal(err)
	}

	// moved aside under the latest, every serial marked with its name
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the set stayed: %v", err)
	}

	if b, err := os.ReadFile(filepath.Join(vol, "fsid.retired.12", "ownership")); err != nil || string(b) != "{}" {
		t.Fatalf("the set moved aside: %q %v", b, err)
	}

	for _, serial := range []string{"11", "12"} {
		if ok, err := Marked(dir, serial); err != nil || !ok {
			t.Errorf("serial %s: marked %v %v", serial, ok, err)
		}

		if b, _ := os.ReadFile(filepath.Join(vol, MarkName("fsid", serial))); string(b) != "fsid.retired.12\n" {
			t.Errorf("mark %s: %q", serial, b)
		}
	}

	if ok, err := Marked(dir, "13"); err != nil || ok {
		t.Fatalf("an unlisted serial: %v %v", ok, err)
	}

	// again: retired already
	if err := Retire(dir, []string{"11", "12"}); err != nil {
		t.Fatalf("again: %v", err)
	}

	// a new set beside a set moved aside under the same serial is refused
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Retire(dir, []string{"12"}); err == nil {
		t.Fatal("moved over a set moved aside")
	}

	// none at all: missing
	if err := Retire(filepath.Join(vol, "other"), []string{"1"}); err == nil {
		t.Fatal("retired missing records")
	}
}

func TestRetireFinishesAMoveAfterItsMarks(t *testing.T) {
	vol := t.TempDir()
	dir := filepath.Join(vol, "fsid")

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// a stop after the marks, before the move
	if err := (Store{Dir: vol}).Write(MarkName("fsid", "7"), []byte("fsid.retired.7\n")); err != nil {
		t.Fatal(err)
	}

	if err := Retire(dir, []string{"7"}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(vol, "fsid.retired.7")); err != nil {
		t.Fatal(err)
	}
}
