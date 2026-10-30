package daemons

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runJobScript runs scripts/job.sh as Talos would, with a stand-in for
// common.sh's log, against a jobs directory.
func runJobScript(t *testing.T, jobs, inputs, cmd string) (int, string) {
	t.Helper()

	body, err := scripts.ReadFile("scripts/job.sh")
	if err != nil {
		t.Fatal(err)
	}

	c := exec.Command("bash", "-c", "set -euo pipefail\nlog() { echo \"cephadm-talos: $*\" >&2; }\n"+string(body))
	c.Env = append(os.Environ(), "JOBS="+jobs, "FSID=f1", "JOB=j1", "JOB_INPUTS="+inputs, "CMD="+cmd)

	out, _ := c.CombinedOutput()

	return c.ProcessState.ExitCode(), string(out)
}

func TestJobProtocol(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}

	jobs := t.TempDir()
	marker := filepath.Join(t.TempDir(), "runs")
	cmd := "echo run >> " + marker + "; echo did-it; exit 3"

	rc, out := runJobScript(t, jobs, "in-1", cmd)
	if rc != 3 || !strings.Contains(out, "did-it") {
		t.Fatalf("first run: rc %d, %q", rc, out)
	}

	res, err := os.ReadFile(filepath.Join(jobs, "f1.j1.result"))
	if err != nil || string(res) != "rc 3\ninputs in-1\ndid-it" {
		t.Fatalf("result %q %v", res, err)
	}

	// the next boot: the job reports its result and does not run again
	rc, out = runJobScript(t, jobs, "in-1", cmd)
	if rc != 0 || !strings.Contains(out, "already ran") {
		t.Fatalf("replay: rc %d, %q", rc, out)
	}

	if runs, _ := os.ReadFile(marker); strings.Count(string(runs), "run") != 1 {
		t.Fatalf("command ran %d times", strings.Count(string(runs), "run"))
	}

	// the same id with other inputs is refused, also when a result exists
	if rc, out = runJobScript(t, jobs, "in-2", cmd); rc != 65 || !strings.Contains(out, "other inputs") {
		t.Fatalf("other inputs with a result: rc %d, %q", rc, out)
	}

	// started but no result: uncertain, not run again
	_ = os.Remove(filepath.Join(jobs, "f1.j1.result"))

	if rc, out = runJobScript(t, jobs, "in-1", cmd); rc != 75 || !strings.Contains(out, "uncertain") {
		t.Fatalf("uncertain: rc %d, %q", rc, out)
	}

	// the same id with other inputs is refused
	if rc, out = runJobScript(t, jobs, "in-2", cmd); rc != 65 || !strings.Contains(out, "other inputs") {
		t.Fatalf("other inputs: rc %d, %q", rc, out)
	}

	if runs, _ := os.ReadFile(marker); strings.Count(string(runs), "run") != 1 {
		t.Fatalf("command ran %d times", strings.Count(string(runs), "run"))
	}

	ents, _ := os.ReadDir(jobs)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temporary left behind: %s", e.Name())
		}
	}
}

// Two runs racing past the claim: exactly one starts the command.
func TestJobStartsOnce(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}

	jobs := t.TempDir()
	marker := filepath.Join(t.TempDir(), "runs")
	cmd := "echo run >> " + marker + "; sleep 0.2"

	done := make(chan int, 8)
	for range 8 {
		go func() {
			rc, _ := runJobScript(t, jobs, "in-1", cmd)
			done <- rc
		}()
	}

	codes := map[int]int{}
	for range 8 {
		codes[<-done]++
	}

	if runs, _ := os.ReadFile(marker); strings.Count(string(runs), "run") != 1 {
		t.Fatalf("command ran %d times (exit codes %v)", strings.Count(string(runs), "run"), codes)
	}
}
