package records

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Init prepares the volume for the agent (the records-init container, run on
// every boot as root with only CHOWN and FOWNER): Talos resets the volume root
// to 0:0 0755 on every mount, so the directories below it are created or
// repaired here, never emptied. The records directory belongs to uid:gid
// with mode 0700; the jobs directory to uid:gid with mode 1777.
func Init(mount string, uid, gid int) error {
	for _, d := range []struct {
		name string
		mode fs.FileMode
	}{
		{RecordsDir, 0o700},
		{JobsDir, 0o777 | fs.ModeSticky},
	} {
		p := filepath.Join(mount, d.name)

		if err := os.Mkdir(p, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("records-init: %w", err)
		}

		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("records-init: %w", err)
		}

		if !fi.IsDir() {
			return fmt.Errorf("records-init: %s is not a directory", p)
		}

		if err := os.Lchown(p, uid, gid); err != nil {
			return fmt.Errorf("records-init: %w", err)
		}

		if err := os.Chmod(p, d.mode); err != nil {
			return fmt.Errorf("records-init: %w", err)
		}
	}

	d, err := os.Open(mount)
	if err != nil {
		return err
	}

	defer d.Close() //nolint:errcheck

	return d.Sync()
}
