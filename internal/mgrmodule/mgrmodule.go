// Package mgrmodule embeds the talos Ceph mgr module, which cephadm-talos
// installs on every mgr host as EtcFileConfig documents, under the module
// name cephadm (see daemons.Mgr).
package mgrmodule

import (
	"embed"
	"io/fs"
	"path"
	"sort"
	"strings"
)

//go:embed talos/*.py
var files embed.FS

// Files returns the module's Python files by name (e.g. "module.py").
func Files() map[string]string {
	out := map[string]string{}

	_ = fs.WalkDir(files, "talos", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(path.Base(p), "test_") {
			return err
		}

		b, err := files.ReadFile(p)
		if err != nil {
			return err
		}

		out[path.Base(p)] = string(b)

		return nil
	})

	return out
}

// Names returns the module's file names, sorted.
func Names() []string {
	files := Files()

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}

	sort.Strings(names)

	return names
}
