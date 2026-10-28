Target: comment on https://github.com/siderolabs/talos/issues/14729 (`talosctl exec` into containers)

---

Following up from #14220. [`DebugService.ContainerRun`](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/api/machine/debug.proto) already streams stdin, signals, TTY resize, output and the exit code, so exec could build on it.

**In short, for `talosctl exec` we would like to see:**

1. Run in an existing `taloscontainers` container: its namespaces, cgroup, user and capabilities. The `talosctl debug` CLI rejects `--namespace=taloscontainers` today.
2. Separate stdout and stderr for non-TTY commands; `ContainerRun` merges both into `stdout_data`.
3. The command's exit status as the CLI exit status; `talosctl debug` turns a nonzero code into a Go error.
4. An audit log entry with caller, command and target container.

**Use cases**

- Debugging a running container with its own view of mounts and network.
- Daemon CLIs that talk over a local Unix socket, or tools that need the container's mounts and devices.
- Scripts and controllers that depend on the exit status.

**Our case**: Ceph on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)): `ceph daemon osd.3 config show` (admin socket, works without mons) and `ceph-volume raw list`. The workaround is two config applies per command. @hkraal lists this as "Day-2 access" in "Ceph on Talos without Kubernetes".
