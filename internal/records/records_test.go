package records

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

func TestWriteReadListRemove(t *testing.T) {
	s := Store{Dir: t.TempDir()}

	if err := s.Check(); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Read("op-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing record: %v", err)
	}

	for _, v := range []string{"one", "two"} {
		if err := s.Write("op-1", []byte(v)); err != nil {
			t.Fatal(err)
		}
	}

	if b, err := s.Read("op-1"); err != nil || string(b) != "two" {
		t.Fatalf("read %q %v", b, err)
	}

	_ = s.Write("op-2", nil)

	if names, _ := s.List("op-"); !slices.Equal(names, []string{"op-1", "op-2"}) {
		t.Fatalf("list %v", names)
	}

	if err := s.Remove("op-1"); err != nil {
		t.Fatal(err)
	}

	if err := s.Remove("op-1"); err != nil {
		t.Fatalf("removing twice: %v", err)
	}

	ents, _ := os.ReadDir(s.Dir)
	for _, e := range ents {
		if e.Name() != "op-2" {
			t.Errorf("left behind: %s", e.Name())
		}
	}
}

func TestNamesAreChecked(t *testing.T) {
	s := Store{Dir: t.TempDir()}

	for _, n := range []string{"", "../x", "a/b", ".hidden", "-x"} {
		if err := s.Write(n, nil); err == nil {
			t.Errorf("wrote %q", n)
		}
	}
}

func TestCreateClaimsOnce(t *testing.T) {
	s := Store{Dir: t.TempDir()}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)

	for range 20 {
		wg.Go(func() {
			err := s.Create("job-1.claim", []byte("x"))
			if err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, fs.ErrExist) {
				t.Error(err)
			}
		})
	}

	wg.Wait()

	if wins != 1 {
		t.Fatalf("%d claims won", wins)
	}
}

func TestCheckRefusesAMissingOrFileDir(t *testing.T) {
	dir := t.TempDir()

	if err := (Store{Dir: filepath.Join(dir, "missing")}).Check(); err == nil {
		t.Error("missing directory accepted")
	}

	f := filepath.Join(dir, "file")
	_ = os.WriteFile(f, nil, 0o600)

	if err := (Store{Dir: f}).Check(); err == nil {
		t.Error("a file accepted as the directory")
	}
}

func TestInitKeepsRecords(t *testing.T) {
	mount := t.TempDir()
	uid, gid := os.Getuid(), os.Getgid()

	if err := Init(mount, uid, gid); err != nil {
		t.Fatal(err)
	}

	s := Store{Dir: filepath.Join(mount, RecordsDir)}
	if err := s.Write("session", []byte("kept")); err != nil {
		t.Fatal(err)
	}

	// the next boot: Talos resets the root, records-init runs again
	_ = os.Chmod(mount, 0o755)

	if err := Init(mount, uid, gid); err != nil {
		t.Fatal(err)
	}

	if b, err := s.Read("session"); err != nil || string(b) != "kept" {
		t.Fatalf("record after a second init: %q %v", b, err)
	}

	for d, want := range map[string]fs.FileMode{RecordsDir: 0o700 | fs.ModeDir, JobsDir: 0o777 | fs.ModeSticky | fs.ModeDir} {
		fi, err := os.Stat(filepath.Join(mount, d))
		if err != nil || fi.Mode() != want {
			t.Errorf("%s: mode %v %v, want %v", d, fi.Mode(), err, want)
		}
	}
}
