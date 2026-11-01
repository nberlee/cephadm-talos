# Roadmap

The proof of concept showed that Ceph runs on Talos `ContainerConfig` without Kubernetes. The goal now is a production cephadm clone: the `ceph orch` interface and the dashboard's orchestrator pages on Talos nodes, for pinned Ceph releases, with a capability matrix that marks each command, spec field and service as implemented, deferred or unsupported. The end goal is everything cephadm supports: every entry of the [capability matrix](docs/capabilities.md) implemented, or unsupported only for a stated reason such as a missing Talos feature. Decisions:

- Go owns the orchestration logic. A thin Python mgr module `talos` implements `orchestrator.Orchestrator` and forwards to it.
- Talos is reached only through `github.com/siderolabs/talos/pkg/machinery`, never `talosctl`.
- License MPL-2.0. Behaviour is reimplemented from Ceph documentation and observed cephadm behaviour; no cephadm Python code or tests are copied or translated.
- Talos feature requests and their status are tracked in [upstream/talos/README.md](upstream/talos/README.md).

## Architecture

Talos containers are node-local: Talos has no cluster scheduler, no failover and no cluster-wide identity for them, and nodes need not share a Talos CA. In steady state each agent calls only its own node's Talos API; the workstation CLI contacts nodes remotely for bootstrap and recovery, with a talosconfig per node or context.

- **`cephadm-talos agent`**, one `ContainerConfig` per Ceph node with `machinedAccess` (which grants every Talos role locally), a static binary in a `FROM scratch` image with no Ceph identity and no mon access. The mgr reaches it over mutual TLS on port 4721 (plan 02). From plan 03 it changes only its own node: apply and remove documents, pull images, reboot and upgrade the node when granted. It preserves documents it does not own.
- **Leader.** The mgr module in the active mgr is the leader; the active mgr gid identifies the leader incarnation (the mgrmap epoch also changes without a leadership change). Where the Go serve loop (scheduler, apply, upgrade, certificates) runs relative to the Python module is decided in plan 03.
- **Cluster operations** run through the active mgr with its credentials, per an explicit routing matrix: `mon_command` for monitor commands and mon-proxied mgr commands, daemon commands where needed, and controlled tool execution for things like `radosgw-admin` (RGW multisite). Each route's capabilities are tested; agents never receive `client.admin`.
- **Desired state and grants** live in the mon config-key store under `mgr/talos/`, as bounded records: immutable revisions published through a manifest, completed operations compacted, no command output. Value sizes are validated against `mon_config_key_max_entry_size` for each supported release. Agents cannot read config-key, so the leader delivers each host's desired state and grants to its agent over mutual TLS.
- **Fencing.** Config-key writes are not conditional on the writer still being active, so state is published in a namespace per leader incarnation and agents ignore publications from any other incarnation. Before disruptive work (reboot, upgrade, stop, zap) an agent needs a fresh confirmation that the sender is the current leader, and a grant bound to the exact desired revision and operation inputs; without a confirmation it does nothing. Agents have no mon access, so plan 03 defines how they get that confirmation (for example from the mgrs, each with its own client certificate). Agents record accepted and started operations locally. A new leader keeps outstanding operations reserved until their agents acknowledge cancellation or their effects are reconciled; expiry alone releases nothing. Delayed publications and already authorized actions are covered by failure tests before this counts as fencing.
- **Operation journal.** Every multi-step operation has an id, immutable inputs and recorded local evidence. Job entrypoints check that id against a local completion marker before running, so a job document that survives a reboot does not run again. Completion records are kept until the job document is removed and its instance is gone. Before retrying, a step reconciles its actual effects (on disk, in the cluster, in the node config); an uncertain outcome leads to reconciliation, not automatic rollback.
- **Quorum loss.** Agents keep running workloads as they are and apply no new changes. Daemons removed on purpose stay removed (tombstones). Mon recovery goes through the CLI, which does not depend on config-key and stops reconciliation before changing node config.
- **Bootstrap.** The CLI deploys the first mon and mgr, creates the initial keys and imports them into the mon (as `cephadm bootstrap` does), writes the initial state to config-key, deploys the agents, installs the mgr module, then hands ownership of the node configs to the agents.
- **Single writer.** Talos has no conditional apply, so an agent can still overwrite an operator's concurrent change. Single-writer ownership is therefore an operational rule: manual config changes go through an explicit handoff; the agent detects drift it did not make and suspends reconciliation on that node.
- **Host-local commands.** With Talos exec ([#14729](https://github.com/siderolabs/talos/issues/14729), [PR #14781](https://github.com/siderolabs/talos/pull/14781)), commands that a running daemon container can run go through exec, from the agent on its own node or from the CLI with its talosconfig; secrets go over stdin. Job documents (`restart: never`, [PR #14795](https://github.com/siderolabs/talos/pull/14795)) remain for initial provisioning, offline repair and destructive device work. Both paths use the same operation and result protocol ([plan 03](docs/plans/03-write-path.md)).

Out of scope for v1: Omni-managed nodes. Omni applies the full config it composes from its own patches, so documents written by an agent directly would be removed on its next apply (inferred from Omni source). Support would mean the agent writing Omni `ConfigPatch` resources instead.

## Talos dependencies

| Talos feature | Status | Until then |
|---|---|---|
| Exec into a running container | [#14729](https://github.com/siderolabs/talos/issues/14729#issuecomment-6445955564), [PR #14781](https://github.com/siderolabs/talos/pull/14781) open; used from plan 03 | Job documents, about 8s and two config applies per command |
| Redacted secret config volumes | [#14221](https://github.com/siderolabs/talos/issues/14221#issuecomment-6439662907), filed, maintainers lean yes | Keyrings as env vars in `ContainerConfig`, not redacted |
| Restart policy, terminal status, backoff | [#14733](https://github.com/siderolabs/talos/issues/14733#issuecomment-6440031175), [PR #14795](https://github.com/siderolabs/talos/pull/14795) open (draft); durable one-shot rejected; used from plan 03 | Idempotent entrypoints; jobs park after finishing and rerun after a reboot if their document survives; backoff in the entrypoint |
| Stop timeout and shutdown order | [#14732](https://github.com/siderolabs/talos/issues/14732), [PR #14788](https://github.com/siderolabs/talos/pull/14788) open; used from plan 03 | 10s for every container, all stopped at once |
| Host PID recorded for `machinedAccess` containers | [PR #14603](https://github.com/siderolabs/talos/pull/14603), open | Workload isolation off on Ceph nodes (`docs/support.md`) |
| Raw volume handed over as a device | [#14730](https://github.com/siderolabs/talos/issues/14730#issuecomment-6467332527), [PR #14775](https://github.com/siderolabs/talos/pull/14775) merged 2026-10-30; used by the OSD redesign (milestone 5) | OSDs run privileged with host `/dev` |
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

Split in two plans.

Plan 02, the read path ([plan](docs/plans/02-agents-and-read-path.md)): the agent (`FROM scratch`, status over mutual TLS), the `talos` mgr module answering `orch status`, `orch host ls` and `orch ps`, the inventory as files on the nodes; the CLI stays the only writer and `state.json` stays authoritative.

Plan 03, the write path:

- State and credentials move into the cluster, the way cephadm keeps them:
  - The mon auth database is authoritative for CephX identities. Deployment creates or retrieves them through the matching provisioning path: `auth get-or-create` for ordinary service identities, the shared `mon.` identity for additional mons, and ceph-volume's `ceph osd new` registration for OSDs. Rendering a document reads existing keyrings with `auth get`; offline recovery reuses surviving credentials as described below. Daemon keyrings stay in their deployed node documents, as cephadm writes them to the host; there is no separate key inventory on the workstation. `bootstrap` imports the initial identities through the mon keyring and then discards its temporary copies, keeping the daemon credentials and the workstation's `client.admin` keyring.
  - Inventory, service specs and host records live in config-key under `mgr/talos/`, following cephadm's module store (`mgr/cephadm/inventory`, `mgr/cephadm/host.<name>`, `mgr/cephadm/spec.<service>`). The `talos` module keeps its own certificate and private key store in that namespace, including the agent CA key, like cephadm's certificate manager (`cert_store.*`).
  - The workstation keeps what a cephadm admin host keeps: `ceph.conf` and the `client.admin` keyring, plus the talosconfig and context per node and the fsid; `state.json` goes away. For recovery without mons, the CLI stops reconciliation and reads the surviving node documents through Talos, reusing their keyrings without calling mon auth or generating new keys; a missing credential is an explicit failure. Tested with all mons stopped and no local inventory.
- CephX identities with a tested capability matrix: the mgr for cluster operations (routing matrix above), separate provisioning keys (e.g. bootstrap-osd) for local jobs. Agents have no Ceph identity.
- Job and OSD identity results as files the agent reads and cleans up (durably written, outside the cluster data removed by `rm-cluster --zap`), replacing log scraping; job completion markers so a job document that survives a reboot does not run again.
- The mgr takes over deploying agents and issuing and renewing their certificates (daily check, renewal 30 days before expiry, like cephadm's certificate manager), and `orch host drain`.
- Leader incarnations, fencing, grants, journal, quorum-loss behaviour, bootstrap handoff, CLI recovery.
- Agent self-upgrade: the agent is never removed by host maintenance; upgrade intent is recorded first, the image pre-pulled, non-leader agents go first, leadership moves before the leader's agent is upgraded, and the CLI can restore a known-good agent image.
- Tests: mgr failover during an operation, stale leader, network partition, quorum loss, failed agent upgrade.

### 4. Security

- Documented trust boundary: an agent with `machinedAccess` is root on its node and can read every local daemon credential.
- Release gate: no production release without redacted secret delivery (config volumes from #14221) or an explicit, documented acceptance of the exposure by the operator. Redaction is not encryption and does not clean old config history.
- Credential rotation and host revocation, including rotation of the agent CA (with an overlap in which both CAs are trusted) and revocation of a removed host's agent certificate; no secrets in logs, status or the journal.
- Hardening from the security review of the agent channel (2026-11-01, [docs/architecture.md](docs/architecture.md), "Known gaps"), with where each lands:
  - Secrets out of the published cluster state (plan 03, step 6b): done for the agent CA key, every host's agent and mgr TLS private keys, the RGW CA and serving keys and the VRRP password, which are config-key entries of their own that the bridge's store calls cannot reach; the bridge releases only the RGW serving key, the VRRP password and a mgr host's TLS keys. Since part 3 the bridge decides from the module's ledger, not from the inventory the leader publishes, and the module issues a new mgr's certificates itself.
  - The bridge (plan 03, step 6b): done for its own listener on loopback (confirmations stay on the mutually authenticated port the other agents reach), a fresh `mgr dump` before every call that changes something, and config-key writes limited to the module's own incarnation. Key release follows the module's ledger (plan 03, step 6b, part 3): `auth get` and `secret get` release only what the fold of the CLI's sealed state and the module's accepted operations has, never from the leader's journal or inventory; adds open a generation of the daemon and removals retire it through the module, so no old operation releases a credential again; a release is not bound to the one operation being carried out, only to the fold.
  - The bootstrap mon's document, which carries `client.admin` and the first keys, is replaced by the joining template before the handoff seals (plan 03, step 7).
  - Admission (plan 03, step 6c, before the leader runs OSD preparation or zap; done except the RGW certificate checks, which come with 6e, and except freshness: approvals are protected against rollback per agent only): image digests and disks approved by an authority whose signing key and decisions are outside the granting leader's control, including its local `os:admin` (the local mgr's key does not qualify: it is in the leader host's machine config; candidate: the operator's certificate on the workstation), versioned, with defined transitions for an upgrade; unapproved digests and disks are refused; a zap also needs an OSD label of this fsid or a recorded approval; a mgr key must match its certificate; an RGW certificate must be within its validity and for the names it serves.
  - Ceph messenger encryption (`ms_cluster_mode`, `ms_service_mode`, `ms_client_mode` set to `secure`), measured on the test cluster first (milestone 5).
  - Prerequisite for the next three (plan 04, design first): authenticated, freshness-checked delivery of revocations and of evidence of the active incarnation to every verifier (agents and module), persisted, with defined behaviour under partition and restart, and not forgeable by a standby mgr with its normal credentials. Today agents get neither: heartbeats come only from their own host's mgr.
  - Revocation (plan 04, with renewal): a denylist of certificate serials every endpoint checks, delivered as above; the module reloads its server certificate and signing key when their files change; generated RGW certificates renewed before they expire.
  - Confirmations bound to the active incarnation (to be designed, plan 04): today a host with both a mgr certificate and an agent certificate, such as a compromised standby mgr host, can sign confirmations for itself. Candidates: a per-incarnation signing key the active module publishes where only the mons can vouch for it, or the agents learning the active incarnation from the mons through the module's own channel.
  - Agent endpoints that only the leader needs (`/v1/node`, `/v1/operations`) answer only the current leader, once agents can verify it (plan 04, after the prerequisite above).
  - Accepted for now: Talos has no conditional machine config apply, so the drift check and the apply are not atomic and a concurrent writer outside cephadm-talos can be overwritten. The request ([upstream/talos](upstream/talos/README.md), draft 01) is not filed; revisit if multi-writer setups without Omni matter.

### 5. Parity

- Service specs and the scheduler: `count`, `count_per_host`, `hosts`, `label`, `host_pattern`; apply and reconfig loop; `ceph orch ls/ps/apply/rm/daemon`.
- Hosts: add, remove, labels, maintenance, drain, `host ls --detail` from Talos resources.
- OSDs: one `RawVolumeConfig` partition per OSD with `ceph-volume raw` (after @hkraal), handed to an unprivileged OSD container as a device (PR #14775; caps CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID, `/run/udev` read-only, `--no-tmpfs`), Talos volume encryption with defined unlock and key recovery, device inventory, drive groups, a removal queue that waits for PGs to drain. Separate DB/WAL devices are deferred. Existing whole-device OSDs stay as they are; partitions come only with new provisioning or an evacuation. Operations are bound to disk identity, cluster fsid and OSD uuid; ambiguous matches are rejected.
- OSD provisioning records device, OSD uuid, allocated id and key before any irreversible step. Recovery reuses them, or runs a guarded `purge-new` after proving no initialized OSD exists. This addresses the stuck OSD after a reboot between `ceph osd new` and mkfs; crashes after each step are tested.
- Upgrade: cephadm order, `ok-to-stop` with retries, `noout`, wait for active+clean, staggered filters.
- Certificates: cluster CA, renewal, rotation without dropping the VIP.
- RGW ingress, first among the services because our own clusters run it today and multisite builds on it: cephadm's `ingress` service in both its forms, keepalived only (`keepalive_only`, what the keepalived VIP built in the PoC does, moved to the leader in plan 03 step 6) and HAProxy behind keepalived balancing across the RGWs, with `virtual_ips_list`, `first_virtual_router_id`, unicast or multicast VRRP (`use_keepalived_multicast`) and HAProxy's monitoring endpoint. No known Talos blocker. Beyond cephadm, a BGP mode: every host with a healthy RGW announces the VIP through Talos's native BGP (`BGPInstanceConfig`), the routers balance across them with ECMP and BFD detects a failed host fast; it can replace keepalived where the network has BGP routers. A spike comes first ([plan](docs/plans/spike-bgp-ingress.md)).
- RGW multisite, after ingress because our own clusters run it today and its sync endpoints are usually the ingress VIPs: realms, zonegroups and zones through the `rgw` mgr module (`ceph rgw realm bootstrap`, `ceph rgw zone create` with a realm token) and `radosgw-admin` through the routing matrix above, RGW specs with `rgw_realm`, `rgw_zonegroup` and `rgw_zone`, the sync user, sync endpoints and the TLS trust between clusters (the generated RGW CA or the user's own certificates), and our own sequencing for upgrades across zones and a procedure for removing a zone (cephadm upgrades by daemon type and removes no zone). No known Talos blocker: it runs on the RGW container type that exists.
- CephFS, after RGW ingress and multisite: our clusters do not run it today, but it is wanted. `mds` services (`ceph fs volume create`, `ceph orch apply mds`, standby and standby-replay daemons), cephadm's MDS handling during upgrades, `cephfs-mirror`, and NFS (NFS-Ganesha through the `nfs` mgr module, exports, its ingress). No known Talos blocker.
- Monitoring: the cephadm monitoring stack (as in @hkraal's setup): `prometheus`, `alertmanager`, `grafana`, `node-exporter`, `ceph-exporter`, `loki` and `promtail`, with service discovery through the mgr, the dashboard's Grafana and alert integration, TLS and authentication as cephadm sets them up, and their data on Talos volumes. `node-exporter` reads host metrics (host network, `/proc`, `/sys` and the root filesystem read-only), which is to be validated on Talos.
- Other services: `crash`, `rbd-mirror`, `mgmt-gateway`, `oauth2-proxy`, `snmp-gateway`, the Jaeger tracing services, `elasticsearch` and custom `container` services have no known Talos blocker; ingress for NFS, with its PROXY protocol option (`enable_haproxy_protocol`), comes with CephFS; SMB needs draft 07; NVMe-oF needs draft 08; iSCSI is to be validated; `node-proxy` is to be validated (it talks to the BMC over Redfish).
- Host tuning through `SysctlConfig` and `KernelModuleConfig`.
- Tests: full cluster power cycle (cross-node start order is a crash loop today), Talos upgrade of every node, disk renumbering and replacement.

### 6. Operations

- Metrics and health checks for the orchestrator itself: agent freshness, desired vs observed revision, reconcile errors, leader, outstanding grants, operation progress.
- Secret-free audit records and a support bundle.
- Runbooks: bootstrap, backup and restore of orchestrator state, quorum-loss recovery, failed agent upgrade, disk replacement, Talos maintenance outside the orchestrator.

## Credits

Henk Kraal ([@hkraal](https://github.com/hkraal), Exonet), "Ceph on Talos without Kubernetes": a Talos raw partition per OSD instead of LVM, digest-pinned images, restricted by default with OSDs as the only privileged daemons, and the cephadm monitoring stack on Talos.
