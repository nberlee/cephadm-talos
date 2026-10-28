Title: Talos Containers: stopped state that keeps the document

## Feature Request

### Description

Allow a `ContainerConfig` container to be stopped and kept stopped, across reboots, without removing its document.

#### Problem

The only way to stop a container and keep it stopped is to remove its document. There is no `enabled`/`state` field, `talosctl restart --namespace taloscontainers` only restarts, and `talosctl service stop` does not apply to containers. Removing the document means whoever stops it must keep a copy to restore it, any secrets in it are written to the config again on start, and each stop/start is a full config change.

#### Use cases

- **Temporarily disable a service**: a backup agent during a migration, an exporter while debugging, a service that misbehaves until a fix is ready.
- **Node maintenance**: stop the workloads on a node, do the work, start them again with exactly the same spec (the systemd `disable --now` / `enable --now` pattern).
- **Prepared but inactive containers**, such as a standby that an operator or controller starts on demand.

#### Why we need it

cephadm's `host maintenance enter` stops every Ceph daemon on a host and keeps them stopped across reboots until `exit`. On Talos we delete all of the host's documents and re-render them from client-side state on exit.

#### Proposal

```yaml
apiVersion: v1alpha1
kind: ContainerConfig
name: backup-agent
enabled: false        # or `state: stopped`; default true
image: example.org/backup-agent:1.2.3
```

- `enabled: false`: the container is stopped (normal graceful stop) and not started on boot. The spec and image stay; status shows `stopped`.
- Setting it back to `true` starts it with the same spec.
- Containers that `dependsOn` a stopped container wait, as they do for one that is not running.
- Optionally, a `talosctl` stop/start command that updates the same persistent field, so nobody has to edit YAML by hand.

#### Acceptance criteria

- A stopped container stays stopped across reboots and keeps its spec and image.
- Starting it again needs no copy of the original document on the client.

#### Related

#14733, #14732, #12764. "Coordinated maintenance" in "Ceph on Talos without Kubernetes" by @hkraal (Exonet). Our use: [cephadm-talos](https://github.com/nberlee/cephadm-talos) `host maintenance`.
