package daemons

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeDaemon is a ceph-mgr or ceph-mon on PATH: --mkfs succeeds; otherwise it
// logs its start and its SIGTERM (then exits 7), or with FAKE_CRASH exits 9.
const fakeDaemon = `#!/bin/bash
for a in "$@"; do [ "$a" = --mkfs ] && exit 0; done
trap 'echo term >> "$FAKE_LOG"; exit 7' TERM
echo started >> "$FAKE_LOG"
[ -n "${FAKE_CRASH:-}" ] && exit 9
while :; do sleep 0.05; done
`

// runWrapper runs a daemon's entrypoint (common.sh and its script, its
// /var paths in a temporary directory) with the fake daemon.
func runWrapper(t *testing.T, typ string, crash bool) (*exec.Cmd, string) {
	t.Helper()

	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	must(t, os.MkdirAll(bin, 0o755))
	must(t, os.WriteFile(filepath.Join(bin, "ceph-"+typ), []byte(fakeDaemon), 0o755))

	body := strings.ReplaceAll(script(typ), "/var/", dir+"/var/")
	logFile := filepath.Join(dir, "log")

	cmd := exec.Command(bash, "-c", body)
	cmd.Env = []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "FSID=f", "ID=h1", "MODE=join", "ADDRV=[v2:10.5.0.2:3300,v1:10.5.0.2:6789]",
		"DEPLOY_ID=0123456789abcdef", "CEPHADM_TALOS_KEYRING=" + base64.StdEncoding.EncodeToString([]byte("[x]\n")), "FAKE_LOG=" + logFile}

	if crash {
		cmd.Env = append(cmd.Env, "FAKE_CRASH=1")
	}

	must(t, cmd.Start())

	return cmd, logFile
}

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

func logOf(path string) string {
	b, _ := os.ReadFile(path)

	return string(b)
}

// TestTheDelayedStop: SIGTERM to the entrypoint alone (Talos signals PID 1
// only) leaves the daemon running for the delay, then reaches it; the
// container exits with the daemon's status. A daemon that exits by itself
// ends it with its status (plan 04, step 5, item 2b).
func TestTheDelayedStop(t *testing.T) {
	for typ, delay := range map[string]time.Duration{"mgr": 4 * time.Second, "mon": 6 * time.Second} {
		t.Run(typ, func(t *testing.T) {
			t.Parallel()

			cmd, logFile := runWrapper(t, typ, false)

			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(logOf(logFile), "started") {
				if time.Now().After(deadline) {
					t.Fatalf("the daemon did not start: %q", logOf(logFile))
				}

				time.Sleep(20 * time.Millisecond)
			}

			start := time.Now()
			must(t, cmd.Process.Signal(syscall.SIGTERM))

			time.Sleep(delay - time.Second)

			if strings.Contains(logOf(logFile), "term") {
				t.Fatalf("the daemon got SIGTERM before %s", delay)
			}

			err := cmd.Wait()
			took := time.Since(start)

			if cmd.ProcessState.ExitCode() != 7 || !strings.Contains(logOf(logFile), "term") {
				t.Fatalf("exit %v (%d), log %q", err, cmd.ProcessState.ExitCode(), logOf(logFile))
			}

			if took < delay || took > delay+3*time.Second {
				t.Fatalf("stopped %s after the signal, want about %s", took, delay)
			}

			// a crash ends the entrypoint at once with the daemon's status
			crash, _ := runWrapper(t, typ, true)
			_ = crash.Wait()

			if crash.ProcessState.ExitCode() != 9 {
				t.Fatalf("a crash exited %d", crash.ProcessState.ExitCode())
			}
		})
	}
}

func TestTheMgrAndTheMonStopTimeout(t *testing.T) {
	p := Params{Name: "ceph-f-mgr-h1", Image: "quay.io/ceph/ceph@sha256:aa", FSID: "f", ID: "h1", Addr: "10.5.0.2"}

	for name, c := range map[string]interface{ StopTimeout() time.Duration }{"mgr": Mgr(p), "mon": Mon(p)} {
		if c.StopTimeout() != DelayedStopTimeout || DelayedStopTimeout != 20*time.Second {
			t.Errorf("%s: stop timeout %s", name, c.StopTimeout())
		}
	}

	// the entrypoints run their daemon as a child, not exec'd
	for _, typ := range []string{"mgr", "mon"} {
		if s := script(typ); strings.Contains(s, "exec ceph-") || !strings.Contains(s, "run_delayed ") {
			t.Errorf("%s execs its daemon", typ)
		}
	}
}
