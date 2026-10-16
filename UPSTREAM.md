# Draft: feature request for siderolabs/talos

**Not filed yet.** This is a draft issue text, based on building cephadm-talos, a cephadm-like Ceph orchestrator on `ContainerConfig`, and testing it against Talos v1.15.0-alpha.1.

---

## ContainerConfig: lifecycle controls (restart policy, stopped state, exec, stop timeout)

### Use case

`ContainerConfig` (1.14) makes it possible to run host-level daemons without Kubernetes. We used it to run a Ceph cluster: mon, mgr and OSD daemons, each as one `ContainerConfig` with host networking, a `UserVolumeConfig` directory volume, `EtcFileConfig` for `ceph.conf`, and privileged OSDs with `/dev`.

That works: bootstrap, rolling upgrades, OSD replacement and node maintenance were all tested on a QEMU cluster. But several things a node-level orchestrator needs had to be emulated, and each emulation has sharp edges. Every field below exists for systemd units and podman/docker containers. cephadm, the upstream Ceph orchestrator, relies on all of them.

### 1. Restart policy (`always` / `on-failure` / `never`) and backoff

Today a container is always restarted 5s after it exits, with no backoff.

- **One-shot tasks are impossible.** Examples are `ceph -s`, `ceph osd purge`, wiping a disk, and a `mkfs` that must run exactly once. Our workaround: the command prints its result between markers and then sleeps forever, the client reads the result with `talosctl logs`, and then deletes the document. If the document is not deleted, for example because the client crashes, the command runs again on the next reboot. For a disk zap that is destructive.
- **No backoff.** A crash-looping daemon hammers its peers every 5s; we add a 30s sleep in our own entrypoint.

Proposal: `restart: {policy: always|on-failure|never, delay: 5s, maxDelay: 5m}`. Also expose a terminal "completed" state with the exit code in `ContainerStatus`, so a client can wait for a one-shot container and collect its exit code.

### 2. Stopped / disabled state without deleting the document

There is no way to stop a container and keep it stopped, across reboots, while keeping its definition. `talosctl service stop` does not apply, and `talosctl restart --namespace taloscontainers` only restarts.

For node maintenance (cephadm `host maintenance enter` = `systemctl disable --now ceph-<fsid>.target`) we delete every document of the host and re-render them from client-side state on exit. That means:

- the orchestrator has to keep a full copy of every document;
- each enter/exit is two machine config changes, which grow the config history;
- secrets in the environment are written to the config again each time.

Proposal: `enabled: false` (or `desiredState: stopped`) on `ContainerConfig`. The container is stopped but its spec, image and status stay, and applying `true` starts it again.

### 3. Exec (or a one-shot run) via the API

There is no `exec` into a `ContainerConfig` container, and `talosctl debug` cannot use the `taloscontainers` namespace, privileged mode or host mounts. Every admin command therefore costs two machine config applies and about 8s.

Proposal: either `talosctl exec --namespace taloscontainers <name> -- cmd` (an RBAC-gated API, like `kubectl exec`), or a "run once" API that takes a ContainerConfig-like spec, runs it to completion and returns the exit code and output, without touching the machine config.

### 4. Configurable stop timeout and ordered shutdown

- The grace period between SIGTERM and SIGKILL is hard-coded at 10s (`gracefulShutdownTimeout`). Some daemons need longer, for example an interrupted `ceph-volume prepare`, or databases flushing.
- On shutdown, every container is stopped concurrently. `dependsOn` is used for start ordering only. Stopping in reverse dependency order, or an optional `stopAfter`, would allow ordered teardown (clients before servers).

Proposal: `stopTimeout: 30s` and stop in reverse `dependsOn` order.

### 5. Smaller items

- `dependsOn` on another node's container cannot be expressed. That is fine and expected, but worth stating in the docs: cluster-level ordering stays with the orchestrator.
- `ContainerStatus.image` reports only the digest. Also reporting the requested reference makes it easier to see which tag is running; today `ContainerImageStatus` has to be joined in.
- An init process (`init: true`, like `podman --init`) would avoid the PID 1 signal pitfall. A shell entrypoint as PID 1 ignores SIGTERM unless it traps it, so it always runs into the SIGKILL.

### Environment

Talos v1.15.0-alpha.1 (QEMU), `quay.io/ceph/ceph:v20.2.3` / `v20.2.4`.
