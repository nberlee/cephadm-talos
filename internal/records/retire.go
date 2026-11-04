package records

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// A retired records set (plan 04, step 6 part A): the set of a cluster,
// RecordsDir/<fsid>, is moved aside within the volume to
// RecordsDir/<fsid>.retired.<serial>, named by the latest serial of the
// agent server certificates it ran under, and every serial it ran under
// gets a retirement mark beside it, RecordsDir/<fsid>.mark.<serial>, which
// holds the name of the set moved aside. The marks are written before the
// move: a stop between them leaves marks and the set in place, and the move
// is finished by whoever retires it again; never a moved set without marks.

// RetiredName is the name a set is moved aside to.
func RetiredName(set, serial string) string { return set + ".retired." + serial }

// MarkName is the name of a serial's retirement mark.
func MarkName(set, serial string) string { return set + ".mark." + serial }

// Marked reports whether serial has a retirement mark beside the set dir.
func Marked(dir, serial string) (bool, error) {
	if serial == "" {
		return false, nil
	}

	p := filepath.Join(filepath.Dir(dir), MarkName(filepath.Base(dir), serial))
	if !name.MatchString(filepath.Base(p)) {
		return false, fmt.Errorf("records: invalid serial %q", serial)
	}

	_, err := os.Stat(p)

	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	}

	return false, fmt.Errorf("records: %w", err)
}

// Retire marks every serial, then moves the set aside under the last one
// (the latest). A set already moved aside under it is retired already; a set
// moved aside under that name that is not this one is refused.
func Retire(dir string, serials []string) error {
	if len(serials) == 0 {
		return errors.New("records: no serial to retire the records under")
	}

	parent, set := filepath.Dir(dir), filepath.Base(dir)
	latest := serials[len(serials)-1]
	moved := RetiredName(set, latest)
	vol := Store{Dir: parent}

	for _, s := range serials {
		if s == "" || !name.MatchString(MarkName(set, s)) || !name.MatchString(moved) {
			return fmt.Errorf("records: invalid serial %q", s)
		}
	}

	_, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if _, merr := os.Stat(filepath.Join(parent, moved)); merr == nil {
			return nil // moved aside already
		}

		return fmt.Errorf("records: %w", err)
	} else if err != nil {
		return fmt.Errorf("records: %w", err)
	}

	if _, err := os.Stat(filepath.Join(parent, moved)); err == nil {
		return fmt.Errorf("records: %s exists already", moved)
	}

	for _, s := range serials {
		if err := vol.Write(MarkName(set, s), []byte(moved+"\n")); err != nil {
			return err
		}
	}

	if err := os.Rename(dir, filepath.Join(parent, moved)); err != nil {
		return fmt.Errorf("records: move aside: %w", err)
	}

	return vol.syncDir()
}
