# Roadmap

The proof of concept showed that Ceph runs on Talos `ContainerConfig` without Kubernetes. The goal now is a production cephadm clone: the `ceph orch` interface and the dashboard's orchestrator pages on Talos nodes, for pinned Ceph releases, with a capability matrix that marks each command, spec field and service as implemented, deferred or unsupported. Decisions:

- Go owns the orchestration logic. A thin Python mgr module `talos` implements `orchestrator.Orchestrator` and forwards to it.
- Talos is reached only through `github.com/siderolabs/talos/pkg/machinery`, never `talosctl`.
- License MPL-2.0. Behaviour is reimplemented from Ceph documentation and observed cephadm behaviour; no cephadm Python code or tests are copied or translated.
- Talos feature requests and their status are tracked in [upstream/talos/README.md](upstream/talos/README.md).

## Architecture

Talos containers are node-local: Talos has no cluster scheduler, no failover and no cluster-wide identity for them, and nodes need not share a Talos CA. In steady state each agent calls only its own node's Talos API; the workstation CLI contacts nodes remotely for bootstrap and recovery, with a talosconfig per node or context.

- **`cephadm-talos agent`**, one `ContainerConfig` per Ceph node with `machinedAccess` (which grants every Talos role locally). It changes only its own node: apply and remove documents, watch `ContainerStatus`, pull images, reboot and upgrade the node when granted. It preserves documents it does not own.
- **Leader.** The mgr module in the active mgr is the leader; the active mgr gid identifies the leader incarnation (the mgrmap epoch also changes without a leadership change). The module talks to the agent on its node over a unix socket in a directory shared by both containers (fixed uid/gid and permissions, reconnect across restarts); that agent runs the Go serve loop (scheduler, apply, upgrade, certificates).
- **Cluster operations** run through the active mgr with its credentials, per an explicit routing matrix: `mon_command` for monitor commands and mon-proxied mgr commands, daemon commands where needed, and controlled tool execution for things like `radosgw-admin` (RGW multisite). Each route's capabilities are tested; agents never receive `client.admin`.
- **Desired state and grants** live in the mon config-key store under `mgr/talos/`, as bounded records: immutable revisions published through a manifest, rate-limited status, completed operations compacted, no command output. Value sizes are validated against `mon_config_key_max_entry_size` for each supported release. Agents poll; a rados object with watch/notify may add wakeups later.
- **Fencing.** Config-key writes are not conditional on the writer still being active, so state is published in a namespace per leader incarnation and agents ignore publications from any other incarnation. Before disruptive work (reboot, upgrade, stop, zap) an agent needs a fresh monitor answer confirming the leader, and a grant bound to the exact desired revision and operation inputs; cached maps do not count, and without an answer it does nothing. Agents record accepted and started operations locally. A new leader keeps outstanding operations reserved until their agents acknowledge cancellation or their effects are reconciled; expiry alone releases nothing. Delayed publications and already authorized actions are covered by failure tests before this counts as fencing.
- **Operation journal.** Every multi-step operation has an id, immutable inputs and recorded local evidence. Job entrypoints check that id against a local completion marker before running, so a job document that survives a reboot does not run again. Completion records are kept until the job document is removed and its instance is gone. Before retrying, a step reconciles its actual effects (on disk, in the cluster, in the node config); an uncertain outcome leads to reconciliation, not automatic rollback.
- **Quorum loss.** Agents keep running workloads as they are and apply no new changes. Daemons removed on purpose stay removed (tombstones). Mon recovery goes through the CLI, which does not depend on config-key and stops reconciliation before changing node config.
- **Bootstrap.** The CLI deploys the first mon and mgr, writes the initial state, credentials and agents, installs the mgr module, then hands ownership of the node configs to the agents.
- **Single writer.** Talos has no conditional apply, so an agent can still overwrite an operator's concurrent change. Single-writer ownership is therefore an operational rule: manual config changes go through an explicit handoff; the agent detects drift it did not make and suspends reconciliation on that node.
- **Host-local commands.** Until Talos exec ([#14729](https://github.com/siderolabs/talos/issues/14729)) lands, every host-local command runs as a job document on the agent's own node. Afterwards, exec is used where a running container already has the binaries, mounts, devices and privileges; job documents remain for initial provisioning, offline repair and destructive device work. Both paths use the same operation and result protocol.

Out of scope for v1: Omni-managed nodes. Omni applies the full config it composes from its own patches, so documents written by an agent directly would be removed on its next apply (inferred from Omni source). Support would mean the agent writing Omni `ConfigPatch` resources instead.

## Talos dependencies

| Talos feature | Status | Until then |
|---|---|---|
| Exec into a running container | [#14729](https://github.com/siderolabs/talos/issues/14729#issuecomment-6445955564), filed | Job documents, about 8s and two config applies per command |
| Redacted secret config volumes | [#14221](https://github.com/siderolabs/talos/issues/14221#issuecomment-6439662907), filed, maintainers lean yes | Keyrings as env vars in `ContainerConfig`, not redacted |
| Restart policy, terminal status, backoff | [#14733](https://github.com/siderolabs/talos/issues/14733#issuecomment-6440031175), filed; durable one-shot rejected | Idempotent entrypoints; jobs park after finishing and rerun after a reboot if their document survives; backoff in the entrypoint |
| Raw volume handed over as a device | [#14730](https://github.com/siderolabs/talos/issues/14730#issuecomment-6446999321), filed | OSDs run privileged with host `/dev` |
| `RLIMIT_NOFILE` inherited from the host | [#14551](https://github.com/siderolabs/talos/issues/14551), accepted | 1024 open files per container |
| Shared namespaces, init (draft 07) | held | No SMB service |
| `memlock` and other rlimits (draft 08) | held | No NVMe-oF gateway |

Handled in the orchestrator, not requested: stopped state (agents re-render from desired state), pre-shutdown hooks (only orchestrator-driven maintenance sets `noout`), conditional apply (single-writer rule above), layer-2 VIP (keepalived).

## Milestones

Each milestone ends with its QEMU tests passing; destructive provisioning and upgrades are gated on their failure tests.

### 1. Contract

- Supported Talos and Ceph releases; versioned state schema and socket protocol. Before the first tagged release, unknown versions are refused without migration; migrations start with the first release.
- The capability matrix: `ceph orch` commands (including host drain, `pause`/`resume`, upgrade `pause`/`resume`/`stop`/`status`, spec preview and export), spec fields, services, dashboard pages. The mgr module overrides only implemented `Orchestrator` methods.

### 2. Foundation

- Replace the `talosctl` shell-out in `internal/talos` with `pkg/machinery/client`: `ApplyConfiguration` with the current merge semantics (unrelated documents kept), COSI `safe.StateWatch` on `ContainerStatus` instead of polling, `Logs`, `Restart`, `Reboot`, `UpgradeWithOptions`, `ImagePull` in the `taloscontainers` namespace, disk inventory.
- Digest pinning: resolve tags to digests and store them with the verified Ceph version. Only AES256KRB5 keys; key-type selection is removed.
- QEMU vertical slice: bootstrap, deploy, a job, reboot and upgrade with a pinned digest.

### 3. Control plane

- The agent and its image (Ceph image plus the Go binary), the mgr module and its installation in every supported mgr image, the shared socket.
- CephX identities with a tested capability matrix: the mgr for cluster operations (routing matrix above), a narrow per-host agent identity, separate provisioning keys (e.g. bootstrap-osd) for local jobs. `client.admin` is not handed to agents.
- State moves from the workstation `state.json` to config-key. No adoption of earlier clusters: no backwards compatibility before the first release.
- Job and OSD identity results as files the agent reads and cleans up (durably written, outside the cluster data removed by `rm-cluster --zap`), replacing log scraping; job completion markers so a job document that survives a reboot does not run again.
- Leader incarnations, fencing, grants, journal, quorum-loss behaviour, bootstrap handoff, CLI recovery.
- Agent self-upgrade: the agent is never removed by host maintenance; upgrade intent is recorded first, the image pre-pulled, non-leader agents go first, leadership moves before the leader's agent is upgraded, and the CLI can restore a known-good agent image.
- Tests: mgr failover during an operation, stale leader, network partition, quorum loss, failed agent upgrade.

### 4. Security

- Documented trust boundary: an agent with `machinedAccess` is root on its node and can read every local daemon credential.
- Release gate: no production release without redacted secret delivery (config volumes from #14221) or an explicit, documented acceptance of the exposure by the operator. Redaction is not encryption and does not clean old config history.
- Credential rotation and host revocation, no secrets in logs, status or the journal.

### 5. Parity

- Service specs and the scheduler: `count`, `count_per_host`, `hosts`, `label`, `host_pattern`; apply and reconfig loop; `ceph orch ls/ps/apply/rm/daemon`.
- Hosts: add, remove, labels, maintenance, drain, `host ls --detail` from Talos resources.
- OSDs: one `RawVolumeConfig` partition per OSD with `ceph-volume raw` (after @hkraal), Talos volume encryption with defined unlock and key recovery, device inventory, drive groups, a removal queue that waits for PGs to drain. Separate DB/WAL devices are deferred. Existing whole-device OSDs stay as they are; partitions come only with new provisioning or an evacuation. Operations are bound to disk identity, cluster fsid and OSD uuid; ambiguous matches are rejected.
- OSD provisioning records device, OSD uuid, allocated id and key before any irreversible step. Recovery reuses them, or runs a guarded `purge-new` after proving no initialized OSD exists. This addresses the stuck OSD after a reboot between `ceph osd new` and mkfs; crashes after each step are tested.
- Upgrade: cephadm order, `ok-to-stop` with retries, `noout`, wait for active+clean, staggered filters.
- Certificates: cluster CA, renewal, rotation without dropping the VIP.
- Services, each tied to its Talos blocker: MDS, RGW multisite, NFS, ingress beyond the active/passive VIP, crash, ceph-exporter and the monitoring stack (as in @hkraal's setup) have no known Talos blocker; SMB needs draft 07; NVMe-oF needs draft 08; iSCSI is to be validated.
- Host tuning through `SysctlConfig` and `KernelModuleConfig`.
- Tests: full cluster power cycle (cross-node start order is a crash loop today), Talos upgrade of every node, disk renumbering and replacement.

### 6. Operations

- Metrics and health checks for the orchestrator itself: agent freshness, desired vs observed revision, reconcile errors, leader, outstanding grants, operation progress.
- Secret-free audit records and a support bundle.
- Runbooks: bootstrap, backup and restore of orchestrator state, quorum-loss recovery, failed agent upgrade, disk replacement, Talos maintenance outside the orchestrator.

## Credits

Henk Kraal ([@hkraal](https://github.com/hkraal), Exonet), "Ceph on Talos without Kubernetes": a Talos raw partition per OSD instead of LVM, digest-pinned images, restricted by default with OSDs as the only privileged daemons, and the cephadm monitoring stack on Talos.
