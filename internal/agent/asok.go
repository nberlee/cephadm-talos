package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// The agent's execs are read-only admin socket queries (plan 03, item 8):
// `ceph --admin-daemon <socket> <command>` in the daemon's own container, with
// a command from asokCommands and the socket of the daemon the container
// runs. They change nothing, start no other program and carry no secret.

// asokCommands are the admin socket commands the agent may run.
var asokCommands = map[string]bool{"version": true}

// asokTimeout bounds one exec; asokOutput bounds what is read of it.
const (
	asokTimeout = 10 * time.Second
	asokOutput  = 64 << 10
)

// Execer runs a command in one of the node's containers and returns its exit
// code (talos.Client.Exec on the local socket).
type Execer func(ctx context.Context, container string, args []string, stdout, stderr io.Writer) (int, error)

// asokEntity is the Ceph entity a daemon container runs, from its document:
// its kind from the name and its id from its environment; "" for containers
// without an admin socket (keepalived, jobs, the probe).
func asokEntity(fsid string, c *spec.ContainerConfig) string {
	env := map[string]string{}

	for _, e := range c.ContainerEnvironment {
		if k, v, ok := strings.Cut(e, "="); ok {
			env[k] = v
		}
	}

	st := &state.State{FSID: fsid}

	for typ, entity := range map[string]func() string{
		state.TypeMon: func() string { return "mon." + env["ID"] },
		state.TypeMgr: func() string { return "mgr." + env["ID"] },
		state.TypeOSD: func() string { return "osd." + env["OSD_ID"] },
		state.TypeRGW: func() string { return "client.rgw." + env["ID"] },
	} {
		if env["ID"] != "" && c.MetaName == st.DocName(state.Daemon{Type: typ, ID: env["ID"]}) {
			if typ == state.TypeOSD && !osdIDRe.MatchString(env["OSD_ID"]) {
				return ""
			}

			if typ != state.TypeOSD && !daemonIDRe.MatchString(env["ID"]) {
				return ""
			}

			return entity()
		}
	}

	return ""
}

// asokPath is a daemon's admin socket: Ceph's default for the cluster "ceph".
func asokPath(entity string) string { return "/var/run/ceph/ceph-" + entity + ".asok" }

// limitedWriter keeps the first n bytes and reports whether more came.
type limitedWriter struct {
	buf  bytes.Buffer
	n    int
	over bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if room := w.n - w.buf.Len(); room < len(p) {
		w.over = true

		if room > 0 {
			w.buf.Write(p[:room])
		}

		return len(p), nil
	}

	return w.buf.Write(p)
}

// asok runs one allowlisted admin socket command in a daemon's container.
func asok(ctx context.Context, exec Execer, container, entity, command string) ([]byte, error) {
	if !asokCommands[command] {
		return nil, errors.New("admin socket command not allowed")
	}

	ctx, cancel := context.WithTimeout(ctx, asokTimeout)
	defer cancel()

	out := &limitedWriter{n: asokOutput}

	rc, err := exec(ctx, container, []string{"ceph", "--admin-daemon", asokPath(entity), command}, out, io.Discard)
	if err != nil {
		return nil, err
	}

	if rc != 0 || out.over {
		return nil, errors.New("admin socket query failed")
	}

	return out.buf.Bytes(), nil
}

// daemonVersion asks a daemon for the Ceph version it runs.
func daemonVersion(ctx context.Context, exec Execer, container, entity string) (string, error) {
	out, err := asok(ctx, exec, container, entity, "version")
	if err != nil {
		return "", err
	}

	var v struct {
		Version string `json:"version"`
	}

	if err := json.Unmarshal(out, &v); err != nil || v.Version == "" || len(v.Version) > 64 {
		return "", errors.New("admin socket: no version")
	}

	return v.Version, nil
}
