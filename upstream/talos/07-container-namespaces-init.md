Title: Talos Containers: host IPC/PID, shared namespaces between containers, and an init process

## Feature Request

### Description

Allow containers to use the host IPC/PID namespace, to share namespaces with another container (pod-style), and to run a minimal init as PID 1.

#### Problem

A `ContainerConfig` always gets its own IPC and PID namespace, and there is no way to group containers that must share namespaces. The entrypoint is PID 1 and responsible for its duties, including signal handling and orphan reaping; shell wrappers often get these wrong.

#### Use cases

- **Sidecars**: a main process plus a helper that must share localhost, IPC or PIDs (a metrics or log shipper, an auth proxy, a TLS terminator).
- **Software that uses shared memory with host processes** or other containers (`--ipc=host`).
- **Shell or script entrypoints** that need child reaping and signal forwarding from a minimal init, as `podman --init` and `docker --init` provide. Wrappers must still forward signals to their own children, or rely on the init's documented process-group forwarding.

#### Why we need it

cephadm runs every Ceph daemon with `--ipc=host`, and some Ceph services as groups: the iSCSI gateway with `tcmu-runner`, and SMB as samba + winbind + ctdb with init containers. Our own shell entrypoints have to trap TERM themselves; before they did, every stop ran into the SIGKILL.

#### Proposal

```yaml
apiVersion: v1alpha1
kind: ContainerConfig
name: app-sidecar
namespaces:
  ipc: host                    # host | container:<name> | private (default)
  pid: private
  network: container:app       # alongside today's host/none
init: true                     # minimal init as PID 1
```

- `container:<name>` joins the namespaces of another container on the same node and implies a start dependency.
- Restarting a container that owns a shared namespace restarts its dependents, so they join the new namespace.

#### Acceptance criteria

- Two containers can share IPC and network namespaces and reach each other via localhost and shared memory.
- With `init: true`, the init process reaps adopted children and forwards termination signals with documented semantics. Applications remain responsible for their own graceful shutdown.

#### Related

#14676, #14733, #14688. Our use: [cephadm-talos](https://github.com/nberlee/cephadm-talos); cephadm daemon definitions in [ceph/src/cephadm/cephadmlib/daemons](https://github.com/ceph/ceph/tree/tentacle/src/cephadm/cephadmlib/daemons).
