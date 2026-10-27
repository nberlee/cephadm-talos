// Package talos is a thin wrapper around the talosctl CLI.
//
// We shell out instead of using the machinery Go module: ContainerConfig and
// EtcFileConfig are new in Talos 1.14/1.15 and talosctl is the stable surface.
package talos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Client runs talosctl against one Talos cluster.
type Client struct {
	Bin         string // talosctl binary, defaults to "talosctl" in PATH
	Talosconfig string
	Context     string
	DryRun      bool
	Verbose     bool
	Out         io.Writer // where dry-run patches are printed
}

func (c *Client) args(node string, args ...string) []string {
	var out []string

	if c.Talosconfig != "" {
		out = append(out, "--talosconfig", c.Talosconfig)
	}

	if c.Context != "" {
		out = append(out, "--context", c.Context)
	}

	if node != "" {
		out = append(out, "-n", node)
	}

	return append(out, args...)
}

func (c *Client) run(ctx context.Context, node string, args ...string) ([]byte, error) {
	bin := c.Bin
	if bin == "" {
		bin = "talosctl"
	}

	full := c.args(node, args...)

	if c.Verbose {
		fmt.Fprintln(os.Stderr, "+ talosctl", strings.Join(full, " "))
	}

	cmd := exec.CommandContext(ctx, bin, full...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("talosctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}

	return out, nil
}

// Patch applies a multi-document machine config patch to a node without rebooting it.
//
// Named documents (ContainerConfig, EtcFileConfig, UserVolumeConfig) are added or
// replaced by kind+name; a document carrying `$patch: delete` removes it.
//
// Several patches are applied in order within one machine config apply, so a
// delete followed by an add replaces a document atomically.
func (c *Client) Patch(ctx context.Context, node string, patches ...[]byte) error {
	if c.DryRun {
		for _, docs := range patches {
			fmt.Fprintf(c.Out, "# --- patch for node %s ---\n%s\n", node, docs)
		}

		return nil
	}

	dir, err := os.MkdirTemp("", "cephadm-talos-patch-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	args := []string{"patch", "machineconfig", "--mode", "no-reboot"}

	for i, docs := range patches {
		// the patch contains keyrings: keep it 0600 and remove it right away
		f := filepath.Join(dir, fmt.Sprintf("patch-%d.yaml", i))
		if err := os.WriteFile(f, docs, 0o600); err != nil {
			return err
		}

		args = append(args, "--patch", "@"+f)
	}

	_, err = c.run(ctx, node, args...)

	return err
}

// ContainerStatus is the spec of a ContainerStatuses.containers.talos.dev resource.
type ContainerStatus struct {
	ID           string   `json:"-"`
	State        string   `json:"state"`
	Health       string   `json:"health"`
	Image        string   `json:"image"`
	PID          uint32   `json:"pid"`
	ExitCode     int32    `json:"exitCode"`
	RestartCount uint64   `json:"restartCount"`
	Error        string   `json:"error"`
	WaitingFor   []string `json:"waitingFor"`
}

// ContainerStatuses returns the status of every ContainerConfig container on a node, keyed by name.
func (c *Client) ContainerStatuses(ctx context.Context, node string) (map[string]ContainerStatus, error) {
	if c.DryRun {
		return map[string]ContainerStatus{}, nil
	}

	out, err := c.run(ctx, node, "get", "containerstatus", "-o", "json")
	if err != nil {
		return nil, err
	}

	// talosctl -o json emits a stream of JSON objects, one per resource
	res := map[string]ContainerStatus{}
	dec := json.NewDecoder(bytes.NewReader(out))

	for dec.More() {
		var r struct {
			Metadata struct {
				ID string `json:"id"`
			} `json:"metadata"`
			Spec ContainerStatus `json:"spec"`
		}

		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("decode containerstatus: %w", err)
		}

		r.Spec.ID = r.Metadata.ID
		res[r.Metadata.ID] = r.Spec
	}

	return res, nil
}

// ImageStatus is the spec of a ContainerImageStatuses.containers.talos.dev resource
// (one per container, same ID as the container).
type ImageStatus struct {
	Phase  string `json:"phase"`
	Image  string `json:"image"`  // normalized reference, e.g. quay.io/ceph/ceph:v20
	Digest string `json:"digest"` // sha256:..., what ContainerStatus.Image reports once running
	Error  string `json:"error"`
}

// ImageStatus returns the image pull status of a ContainerConfig container.
func (c *Client) ImageStatus(ctx context.Context, node, name string) (ImageStatus, error) {
	out, err := c.run(ctx, node, "get", "containerimagestatus", name, "-o", "json")
	if err != nil {
		return ImageStatus{}, err
	}

	var r struct {
		Spec ImageStatus `json:"spec"`
	}

	if err := json.Unmarshal(out, &r); err != nil {
		return ImageStatus{}, fmt.Errorf("decode containerimagestatus: %w", err)
	}

	return r.Spec, nil
}

// HasInstances reports whether any ContainerInstanceSpec of a container is left.
// Instances keep a finalizer until their process is gone, unlike ContainerStatus
// which disappears as soon as the ContainerConfig is deleted.
func (c *Client) HasInstances(ctx context.Context, node, name string) (bool, error) {
	out, err := c.run(ctx, node, "get", "containerinstancespec", "-o", "json")
	if err != nil {
		return false, err
	}

	dec := json.NewDecoder(bytes.NewReader(out))

	for dec.More() {
		var r struct {
			Spec struct {
				ContainerID string `json:"containerID"`
			} `json:"spec"`
		}

		if err := dec.Decode(&r); err != nil {
			return false, fmt.Errorf("decode containerinstancespec: %w", err)
		}

		if r.Spec.ContainerID == name {
			return true, nil
		}
	}

	return false, nil
}

// MachineConfig returns the node's current machine config (all documents, YAML).
func (c *Client) MachineConfig(ctx context.Context, node string) (string, error) {
	out, err := c.run(ctx, node, "get", "machineconfig", "v1alpha1", "-o", "jsonpath={.spec}")

	return string(out), err
}

// InstanceGeneration returns the highest ContainerInstanceSpec generation of a
// container; Talos creates a new generation whenever it replaces the instance.
func (c *Client) InstanceGeneration(ctx context.Context, node, name string) (uint64, error) {
	out, err := c.run(ctx, node, "get", "containerinstancespec", "-o", "json")
	if err != nil {
		return 0, err
	}

	var gen uint64

	dec := json.NewDecoder(bytes.NewReader(out))

	for dec.More() {
		var r struct {
			Spec struct {
				ContainerID string `json:"containerID"`
				Generation  uint64 `json:"generation"`
			} `json:"spec"`
		}

		if err := dec.Decode(&r); err != nil {
			return 0, fmt.Errorf("decode containerinstancespec: %w", err)
		}

		if r.Spec.ContainerID == name && r.Spec.Generation > gen {
			gen = r.Spec.Generation
		}
	}

	return gen, nil
}

// Logs returns the full log of a ContainerConfig container.
func (c *Client) Logs(ctx context.Context, node, name string) (string, error) {
	if c.DryRun {
		return "", nil
	}

	out, err := c.run(ctx, node, "logs", "--namespace", "taloscontainers", name)

	// talosctl prefixes every line with "<node>: "
	return strings.ReplaceAll("\n"+string(out), "\n"+node+": ", "\n")[1:], err
}

// FollowLogs streams the log of a container to w until ctx is done.
func (c *Client) FollowLogs(ctx context.Context, node, name string, w io.Writer) error {
	bin := c.Bin
	if bin == "" {
		bin = "talosctl"
	}

	cmd := exec.CommandContext(ctx, bin, c.args(node, "logs", "--namespace", "taloscontainers", "-f", name)...)
	cmd.Stdout = w
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// Restart restarts a ContainerConfig container.
func (c *Client) Restart(ctx context.Context, node, name string) error {
	if c.DryRun {
		fmt.Fprintf(c.Out, "# restart %s on %s\n", name, node)

		return nil
	}

	_, err := c.run(ctx, node, "restart", "--namespace", "taloscontainers", name)

	return err
}

// Wipe wipes a block device (e.g. /dev/vdb) that is not used as a Talos volume.
func (c *Client) Wipe(ctx context.Context, node, device string) error {
	if c.DryRun {
		fmt.Fprintf(c.Out, "# wipe %s on %s\n", device, node)

		return nil
	}

	_, err := c.run(ctx, node, "wipe", "disk", strings.TrimPrefix(device, "/dev/"))

	return err
}

// Reboot reboots a node and waits until it is back.
func (c *Client) Reboot(ctx context.Context, node string) error {
	if c.DryRun {
		fmt.Fprintf(c.Out, "# reboot %s\n", node)

		return nil
	}

	_, err := c.run(ctx, node, "reboot", "--wait", "--timeout", "20m")

	return err
}

// Hostname returns the Talos hostname of a node.
func (c *Client) Hostname(ctx context.Context, node string) (string, error) {
	out, err := c.run(ctx, node, "get", "hostnamestatus", "-o", "jsonpath={.spec.hostname}")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

// Version returns the Talos server version tag of a node.
func (c *Client) Version(ctx context.Context, node string) (string, error) {
	out, err := c.run(ctx, node, "version", "--short")
	if err != nil {
		return "", err
	}

	// output contains both Client and Server sections; take the last "Tag:" line
	tag := ""

	for _, l := range strings.Split(string(out), "\n") {
		if t, ok := strings.CutPrefix(strings.TrimSpace(l), "Tag:"); ok {
			tag = strings.TrimSpace(t)
		}
	}

	return tag, nil
}
