package daemons

import (
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/config/config"
)

func TestTheMgrGuard(t *testing.T) {
	c := MgrGuard("ceph-f-mgrguard-h1", "quay.io/ceph/ceph@sha256:aa", "f", "h1", "ceph-f-mgr-h1")

	// no capabilities, no mounts, no network of the host
	if c.SecurityConfig == nil || c.SecurityConfig.SecurityProfile != config.ContainerSecurityProfileRestricted || len(c.SecurityConfig.CapabilitiesAdd()) != 0 ||
		len(c.MountsConfig) != 0 || c.NetworkConfig != nil {
		t.Fatalf("guard: %+v %+v %+v", c.SecurityConfig, c.MountsConfig, c.NetworkConfig)
	}

	// it depends on its mgr running: Talos stops it first, the mgr after it
	deps := c.DependsOnConfig.ContainersConfig
	if len(deps) != 1 || deps[0].DependencyName != "ceph-f-mgr-h1" || c.ContainerImage != "quay.io/ceph/ceph@sha256:aa" {
		t.Fatalf("dependency %+v, image %s", deps, c.ContainerImage)
	}

	if strings.Join(c.ContainerEnvironment, " ") != "FSID=f ID=h1" || c.ContainerEntrypoint[2] != rawScript("mgr-guard") {
		t.Fatalf("environment %v", c.ContainerEnvironment)
	}
}

// TestTheMgrGuardsTrap runs the guard's script and signals every process of
// it at once, as Talos does (WithKillAll): it exits 0, MgrGuardDelay later.
func TestTheMgrGuardsTrap(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}

	cmd := exec.Command(bash, "-c", rawScript("mgr-guard"))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond) // its sleep runs

	start := time.Now()
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	err = cmd.Wait()
	took := time.Since(start)

	if err != nil || cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("exit: %v (%d)", err, cmd.ProcessState.ExitCode())
	}

	if took < MgrGuardDelay-200*time.Millisecond || took > MgrGuardDelay+3*time.Second {
		t.Fatalf("exited %s after the signal, want about %s", took, MgrGuardDelay)
	}
}
