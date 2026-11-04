# Roadmap

The proof of concept showed that Ceph runs on Talos `ContainerConfig` without Kubernetes. The goal now is a production cephadm clone: the `ceph orch` interface and the dashboard's orchestrator pages on Talos nodes, for pinned Ceph releases, with a capability matrix that marks each command, spec field and service as implemented, deferred or unsupported. The end goal is everything cephadm supports: every entry of the [capability matrix](docs/capabilities.md) implemented, or unsupported only for a stated reason such as a missing Talos feature. Decisions:

- Go owns the orchestration logic. A Python mgr module, installed as `cephadm`, implements `orchestrator.Orchestrator`: it accepts commands into its ledger, and the leader in the Go agent carries them out.
- Talos is reached only through `github.com/siderolabs/talos/pkg/machinery`, never `talosctl`.
- License MPL-2.0. Behaviour is reimplemented from Ceph documentation and observed cephadm behaviour; no cephadm Python code or tests are copied or translated.
- Talos feature requests and their status are tracked in [upstream/talos/README.md](upstream/talos/README.md).

## Architecture

Talos containers are node-local: Talos has no cluster scheduler, no failover and no cluster-wide identity for them, and nodes need not share a Talos CA. After the handoff each agent calls only its own node's Talos API (plan 04's optional leader-enrollment mode lets the leader's agent also reach other nodes' Talos API, for enrollment, repair and removal only); the workstation CLI contacts nodes remotely for bootstrap, enrollment and recovery, with a talosconfig per node or context. [docs/architecture.md](docs/architecture.md) is the reference for every component, channel, credential and check, and for the known gaps.

- **Backend and namespace `cephadm`.** Ceph accepts only `cephadm`, `rook` and `test_orchestrator` as orchestrator backend, so the mgr module is installed under the name `cephadm`. It implements `orchestrator.Orchestrator` for what is built and refuses the rest. Its store is config-key below `mgr/cephadm/talos/`; what the bridge must not reach (its ledger, the secrets, the control and enrollment records) is below `cephadm-talos/`, outside `mgr/`, which the mgr neither caches nor logs.
- **Agent.** `cephadm-talos agent`, one `ContainerConfig` per Ceph node with `machinedAccess` (root-equivalent on its node, `os:admin` on the local socket), a static binary in a `FROM scratch` image with no Ceph identity and no mon access. It changes only its own node (except the leader's agent in plan 04's optional mode, which writes other nodes' agent documents only): applies and removes the cluster's documents, runs jobs, reboots, only with a grant from the leader and a fresh confirmation from the active mgr, and only within its admission policy and the operator's signed approval of images and disks. It keeps every other document as it is, and detects drift.
- **Leader placement and bridge.** The leader is code in the agent on the active mgr's node, the leader while that mgr's module heartbeats it; an incarnation is one active mgr process, identified by its gid. It reaches the mons only through the bridge, a loopback listener of the local module, which checks before every call that changes something or releases a credential that its incarnation is active, and releases keys only for operations the module accepted into its ledger.
- **Identities.** One agent CA per cluster issues per-role certificates whose identity (fsid, role, name) every endpoint checks: agent server and client, mgr server and client, and the operator's client certificate, which only the CLI holds. Daemons keep their CephX keys in mon auth, read with `auth get` when a document is rendered.
- **Enrollment.** After the handoff the CLI enrolls a node (its certificates and agent, no cluster document) and runs `ceph orch host add`; plan 04 adds an optional mode in which the leader enrolls a node of the same Talos CA with `ceph orch host add` alone.
- **Publication and fencing.** The cluster state is published in config-key per incarnation, as records plus a manifest; a new leader takes over from the newest publication, closes the earlier incarnations' sessions on every agent (a session floor), imports their journals and resolves their operations from the agents' records. A grant counts only with a confirmation the active mgr gives for that revision and operation; a stale leader's grants are refused. Config-key writes are not conditional, so fencing is about correctness, not attackers.
- **Ingress exception.** Of the service specs, `apply -i` takes one today: a keepalived-only ingress in front of the RGWs, the exception to deferred specs until milestone 5 (host specs of enrolled nodes go to `add_host`).
- **Durable records.** Every agent keeps its records (ownership, operations, session floor, fence, approvals, the jobs it ran) on its own `cephadm-talos` volume, written and synced before each effect; jobs are `restart: never` containers whose result files are their replay protection; an uncertain outcome is reconciled, never rolled back automatically.
- **Quorum loss.** Agents keep running workloads as they are; no new confirmation can be given, so nothing new starts beyond an action already confirmed (an apply, restart or reboot whose confirmation, valid for 10 seconds, came before). Mon recovery goes through the CLI, which suspends the agents and the leader first.
- **CLI roles.** The CLI bootstraps, hands the cluster over and from then on changes nothing itself except enrollment, approvals, recovery (`suspend`, `recover mons`, `resume`) and `rm-cluster`; changes go through `ceph orch`, `shell` runs through exec.
- **Single writer.** Talos has no conditional apply, so an agent can still overwrite an operator's concurrent change. Single-writer ownership is an operational rule: the agent detects drift it did not make and stops applying on that node.

Out of scope for v1: Omni-managed nodes. Omni applies the full config it composes from its own patches, so documents written by an agent directly would be removed on its next apply (inferred from Omni source). Support would mean the agent writing Omni `ConfigPatch` resources instead.

## Talos dependencies

Talos baseline: the nodes and `pkg/machinery` come from one combined build of our four PRs (#14775, #14781, #14788, #14795) until they are in a Talos release; the supported Talos release becomes the first one containing them ([docs/support.md](docs/support.md)).

| Talos feature | Status | Until then |
|---|---|---|
| Exec into a running container | [#14729](https://github.com/siderolabs/talos/issues/14729#issuecomment-6445955564), [PR #14781](https://github.com/siderolabs/talos/pull/14781) open; used since plan 03 (combined build) | none: required |
| Redacted secret config volumes | [#14221](https://github.com/siderolabs/talos/issues/14221#issuecomment-6439662907), filed, maintainers lean yes | Keyrings as env vars in `ContainerConfig`, not redacted |
| Restart policy, terminal status, backoff | [#14733](https://github.com/siderolabs/talos/issues/14733#issuecomment-6440031175), [PR #14795](https://github.com/siderolabs/talos/pull/14795) open (draft); used since plan 03 (combined build) | none: required |
| Stop timeout and shutdown order | [#14732](https://github.com/siderolabs/talos/issues/14732), [PR #14788](https://github.com/siderolabs/talos/pull/14788) merged 2026-11-03; used since plan 03 (combined build) | none: required |
| Host PID recorded for `machinedAccess` containers | [PR #14603](https://github.com/siderolabs/talos/pull/14603), open | Workload isolation off on Ceph nodes (`docs/support.md`) |
| Raw volume handed over as a device | [#14730](https://github.com/siderolabs/talos/issues/14730#issuecomment-6467332527), [PR #14775](https://github.com/siderolabs/talos/pull/14775) merged 2026-10-30; used by the OSD redesign (milestone 5) | OSDs run privileged with host `/dev` |
| `RLIMIT_NOFILE` inherited from the host | [#14551](https://github.com/siderolabs/talos/issues/14551), accepted | 1024 open files per container |
| Shared namespaces, init (draft 07) | held | No SMB service |
| `memlock` and other rlimits (draft 08) | held | No NVMe-oF gateway |

Handled in the orchestrator, not requested: stopped state (agents re-render from desired state), pre-shutdown hooks (orchestrator-driven maintenance sets `noout`; a Talos reboot or shutdown outside the orchestrator gets a best-effort `noout`, from the agent's report of the stop sequence, plan 04), conditional apply (single-writer rule above), layer-2 VIP (keepalived).

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

Split in plans 02, 03 and 04; the milestone is done only after plan 04. Plan 05 (ACME) follows separately.

Plan 02, the read path ([plan](docs/plans/02-agents-and-read-path.md), done): the agent (`FROM scratch`, status over mutual TLS), the mgr module answering `orch status`, `orch host ls` and `orch ps`, the inventory as files on the nodes; the CLI stayed the only writer.

Plan 03, the write path ([plan](docs/plans/03-write-path.md), done):

- The cluster state and credentials in the cluster, as cephadm keeps them: CephX identities in mon auth (`auth get-or-create`, the shared `mon.` key, ceph-volume's `ceph osd new`), read with `auth get` when a document is rendered; the cluster state in config-key, published per leader incarnation; private keys as config-key entries of their own outside `mgr/`. The workstation keeps `ceph.conf`, the `client.admin` keyring, the nodes' contacts and the operator's credentials; `state.json` is gone.
- Per-role identities from the agent CA, the bridge, confirmations, heartbeats and incarnations; the agents' durable records; `never` jobs with result files and replay protection.
- Agents as the only writers of their nodes after the handoff: revisions, reservations and confirmations, the admission policy and the operator's signed approvals of images and disks, drift, the leader's journal and takeover.
- The `ceph orch` commands of the [capability matrix](docs/capabilities.md): daemons, OSDs, hosts, maintenance, power cycles, upgrades, RGW and a keepalived-only ingress, accepted by the module into its ledger and carried out by the leader.
- CLI roles: bootstrap and handoff, enrollment with `orch host add`, `shell` and `orch` through exec, suspension of the agents and the leader, recovery of mons on their stores and resumption with a new leader incarnation, `rm-cluster` after the handoff.

Plan 04, lifecycle ([plan](docs/plans/04-lifecycle.md), signed off 2026-11-03):

- The module renews the agent, mgr and generated RGW certificates (daily check, 30 days before expiry; generated RGW certificates at most 1 year, as browsers may access the RGWs), the CLI the operator's; revocation through a CRL of the agent CA, delivered with the module's status polls (a stale one fails open by default, a fail-closed setting for high-security clusters).
- Agent document updates through the agent itself, against its own policy; self-upgrade (pre-pulled, non-leader agents first, the leader's agent last after a failover, a known-good image to restore).
- Optional leader-enrollment mode, when every Ceph node is a control plane of one Talos CA: `ceph orch host add` alone, repair of a failed agent, removed hosts cleaned up, the leader's agent minting short-lived Talos credentials through its own socket; without it the CLI enrolls as today.
- `orch host drain`, a best-effort noout when Talos reboots or shuts down outside the orchestrator, ledger compaction and journal pruning, resolving an uncertain job.
- Optional Talos discovery mode: renames, replacements and address changes detected by node id (an address change followed one mon at a time), auto adoption as an opt-in, the CLI's contacts recovered from the members.
- Broader failure tests: network partitions, failed agent upgrades, more simultaneous failures.

Plan 05, ACME for the RGW serving certificate ([plan](docs/plans/05-acme.md), signed off 2026-11-03): a custom ACME server (step-ca, 24 hour certificates), HTTP-01, hot reload through beast `config://`, trust from the Talos system store; later the other HTTPS endpoints.

### 4. Security

- Documented trust boundary: an agent with `machinedAccess` is root on its node and can read every local daemon credential.
- Release gate: no production release without redacted secret delivery (config volumes from #14221) or an explicit, documented acceptance of the exposure by the operator. Redaction is not encryption and does not clean old config history.
- Credential rotation and host revocation, including rotation of the agent CA (with an overlap in which both CAs are trusted) and of the operator's approval key, and revocation of a removed host's agent certificate (plan 04); no secrets in logs, status or the journal.
- Hardening from the security review of the agent channel (2026-11-01, [docs/architecture.md](docs/architecture.md), "Known gaps"), with where each lands:
  - Secrets out of the published cluster state (plan 03, step 6b): done for the agent CA key, every host's agent and mgr TLS private keys, the RGW CA and serving keys and the VRRP password, which are config-key entries of their own that the bridge's store calls cannot reach; the bridge releases only the RGW serving key, the VRRP password and a mgr host's TLS keys. Since part 3 the bridge decides from the module's ledger, not from the inventory the leader publishes, and the module issues a new mgr's certificates itself.
  - The bridge (plan 03, step 6b): done for its own listener on loopback (confirmations stay on the mutually authenticated port the other agents reach), a fresh `mgr dump` before every call that changes something, and config-key writes limited to the module's own incarnation. Key release follows the module's ledger (plan 03, step 6b, part 3): `auth get` and `secret get` release only what the fold of the CLI's sealed state and the module's accepted operations has, never from the leader's journal or inventory; adds open a generation of the daemon and removals retire it through the module, so no old operation releases a credential again; a release is not bound to the one operation being carried out, only to the fold.
  - The bootstrap mon's document, which carries `client.admin` and the first keys, is replaced by the joining template before the handoff seals (plan 03, step 7): done.
  - Admission (plan 03, step 6c, before the leader runs OSD preparation or zap; done except freshness: approvals are protected against rollback per agent only; an operator RGW certificate is checked for its validity period, its names are the operator's): image digests and disks approved by an authority whose signing key and decisions are outside the granting leader's control, including its local `os:admin` (the local mgr's key does not qualify: it is in the leader host's machine config; candidate: the operator's certificate on the workstation), versioned, with defined transitions for an upgrade; unapproved digests and disks are refused; a zap also needs an OSD label of this fsid or a recorded approval; a mgr key must match its certificate; an RGW certificate must be within its validity and for the names it serves.
  - Ceph messenger encryption (`ms_cluster_mode`, `ms_service_mode`, `ms_client_mode` set to `secure`), measured on the test cluster first (milestone 5).
  - Revocation (plan 04): a CRL of the agent CA every endpoint checks, delivered with the module's status polls to every agent; the module reloads its server certificate and signing key when their files change; generated RGW certificates renewed before they expire.
  - Accepted (plan 04, 2026-11-03): a compromised mgr host, standby or active, is a compromised cluster; confirmations are not bound to the active incarnation against a lying standby, and the agents get no Ceph identity of their own.
  - Accepted for now: Talos has no conditional machine config apply, so the drift check and the apply are not atomic and a concurrent writer outside cephadm-talos can be overwritten. The request ([upstream/talos](upstream/talos/README.md), draft 01) is not filed; revisit if multi-writer setups without Omni matter.

### 5. Parity

- Service specs and the scheduler: `count`, `count_per_host`, `hosts`, `label`, `host_pattern`; apply and reconfig loop; `ceph orch ls/ps/apply/rm/daemon`.
- Hosts: add, remove, labels, maintenance, drain, `host ls --detail` from Talos resources.
- OSDs: one `RawVolumeConfig` partition per OSD with `ceph-volume raw` (after @hkraal), handed to an unprivileged OSD container as a device (PR #14775; caps CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID, `/run/udev` read-only, `--no-tmpfs`), Talos volume encryption with defined unlock and key recovery, device inventory, drive groups, a removal queue that waits for PGs to drain. Separate DB/WAL devices are deferred. Existing whole-device OSDs stay as they are; partitions come only with new provisioning or an evacuation. Operations are bound to disk identity, cluster fsid and OSD uuid; ambiguous matches are rejected.
- OSD provisioning records device, OSD uuid, allocated id and key before any irreversible step. Recovery reuses them, or runs a guarded `purge-new` after proving no initialized OSD exists. This addresses the stuck OSD after a reboot between `ceph osd new` and mkfs; crashes after each step are tested.
- Upgrade: cephadm order, `ok-to-stop` with retries, `noout`, wait for active+clean, staggered filters.
- Certificates: rotation of the RGW CA without dropping the VIP (the agent CA and the approval key are milestone 4; renewal is plan 04, ACME for the RGW serving certificate plan 05).
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
