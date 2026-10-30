// Package records is the agent's durable state on its node (plan 03, item 6):
// sessions, ownership, suspension and operation records in the records
// directory of the cephadm-talos user volume, and the job claims and results
// next to it. Every write goes to a temporary name, is synced, renamed into
// place and the directory synced, so a record is either the old or the new one
// after a crash. Missing, corrupt or unwritable records block every change.
package records

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Layout of the cephadm-talos volume, as the agent sees it.
const (
	// Mount is where the volume is mounted in the agent and the jobs.
	Mount = "/var/lib/cephadm-talos"
	// RecordsDir holds the agent's records: uid/gid AgentUID, mode 0700.
	RecordsDir = "records"
	// JobsDir holds job claims and results: owned by the agent, mode 1777, so
	// jobs (which may run as root) create their files and only the agent, the
	// directory's owner, removes them.
	JobsDir = "jobs"
)

// name is the only form a record or job file name may take.
var name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$`)

// ErrNotFound is returned for a record that does not exist.
var ErrNotFound = errors.New("record not found")

// Store is a directory of atomically written records.
type Store struct {
	Dir string
}

// Check verifies the store can be used: it exists, is a directory, and a probe
// record can be written, synced and removed.
func (s Store) Check() error {
	fi, err := os.Stat(s.Dir)
	if err != nil {
		return fmt.Errorf("records: %w", err)
	}

	if !fi.IsDir() {
		return fmt.Errorf("records: %s is not a directory", s.Dir)
	}

	if err := s.Write(".probe", []byte("ok\n")); err != nil {
		return err
	}

	return s.Remove(".probe")
}

func (s Store) path(n string) (string, error) {
	if n != ".probe" && !name.MatchString(n) {
		return "", fmt.Errorf("records: invalid name %q", n)
	}

	return filepath.Join(s.Dir, n), nil
}

// Write replaces a record atomically: temporary file, fsync, rename, fsync of the directory.
func (s Store) Write(n string, data []byte) error {
	p, err := s.path(n)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(s.Dir, ".tmp-"+n+"-*")
	if err != nil {
		return fmt.Errorf("records: %w", err)
	}

	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck

		return fmt.Errorf("records: write %s: %w", n, err)
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck

		return fmt.Errorf("records: sync %s: %w", n, err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("records: close %s: %w", n, err)
	}

	if err := os.Rename(tmp.Name(), p); err != nil {
		return fmt.Errorf("records: rename %s: %w", n, err)
	}

	return s.syncDir()
}

// Create writes a record only if none exists yet (an atomic claim); it returns
// fs.ErrExist if one does.
func (s Store) Create(n string, data []byte) error {
	p, err := s.path(n)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(s.Dir, ".tmp-"+n+"-*")
	if err != nil {
		return fmt.Errorf("records: %w", err)
	}

	defer os.Remove(tmp.Name()) //nolint:errcheck

	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck

		return fmt.Errorf("records: write %s: %w", n, err)
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck

		return fmt.Errorf("records: sync %s: %w", n, err)
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	// a hard link fails if the name exists: the record appears whole or not at all
	if err := os.Link(tmp.Name(), p); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fs.ErrExist
		}

		return fmt.Errorf("records: claim %s: %w", n, err)
	}

	return s.syncDir()
}

// Read returns a record, or ErrNotFound.
func (s Store) Read(n string) ([]byte, error) {
	p, err := s.path(n)
	if err != nil {
		return nil, err
	}

	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("records: read %s: %w", n, err)
	}

	return b, nil
}

// List returns the names of the records with the prefix, without temporaries.
func (s Store) List(prefix string) ([]string, error) {
	ents, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, fmt.Errorf("records: %w", err)
	}

	var out []string

	for _, e := range ents {
		if n := e.Name(); strings.HasPrefix(n, prefix) && !strings.HasPrefix(n, ".") && e.Type().IsRegular() {
			out = append(out, n)
		}
	}

	return out, nil
}

// Remove deletes a record if it exists, and syncs the directory.
func (s Store) Remove(n string) error {
	p, err := s.path(n)
	if err != nil {
		return err
	}

	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("records: remove %s: %w", n, err)
	}

	return s.syncDir()
}

func (s Store) syncDir() error {
	d, err := os.Open(s.Dir)
	if err != nil {
		return fmt.Errorf("records: %w", err)
	}

	defer d.Close() //nolint:errcheck

	if err := d.Sync(); err != nil {
		return fmt.Errorf("records: sync directory: %w", err)
	}

	return nil
}
