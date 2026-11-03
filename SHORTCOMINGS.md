# Shortcomings

cephadm-talos is not ready for production. This file lists what is missing or wrong compared to cephadm, and what Talos does not (yet) make possible. The security gaps of the design itself (what a compromised mgr, agent or node can do) are in [docs/architecture.md](docs/architecture.md), "Known gaps". Items marked **(observed)** were hit while testing on a Talos QEMU cluster.

## Talos platform limits

- **Unreleased Talos features.** Exec into a container (PR #14781), one-shot containers with a restart policy and backoff (PR #14795), stop timeouts and the reverse `dependsOn` shutdown order (PR #14788, merged) and raw volumes as devices (PR #14775, merged) are not in a Talos release yet. Until they are, the nodes and `pkg/machinery` come from one combined build of those branches ([docs/support.md](docs/support.md)); a node on a plain pre-release misreads the new fields.
- **Workload isolation must be off on Ceph nodes (temporary).** The agent's `machinedAccess` calls are refused while workload isolation is on, because Talos records the container's PID in the wrong PID namespace (open Talos PR #14603). Until a release contains the fix, Ceph nodes need `SecurityProfileConfig` with `workloadIsolation: false` and a reboot; containerd then runs outside the `sandboxd` sandbox, a node-wide loss of that boundary (containers keep their own namespaces). See [docs/support.md](docs/support.md).
- **No stop or disable mode.** There is no way to stop a `ContainerConfig` container and keep it stopped. Maintenance therefore removes the host's daemon documents, and its exit renders them again from the cluster state. Each enter and exit is a machine config change, with the keyrings written again.
- **Shutdown stops every container at once, except for `dependsOn`.** On reboot, shutdown or upgrade outside the orchestrator, Talos stops the node's containers concurrently, in reverse `dependsOn` order where one is declared (PR #14788): an RGW drains for up to 130s, an OSD preparation job keeps running up to 4 minutes. Only the orchestrator's own maintenance sets `noout` and runs ok-to-stop first.
- **Plain `talosctl reboot`/`upgrade` is not Ceph-aware.** Without `ceph orch host maintenance enter` (or `ceph orch hardware powercycle`), a reboot sets no `noout` and runs no ok-to-stop. OSDs are marked out after `mon_osd_down_out_interval` (600s) and data starts moving. Rebooting two of three nodes at once, e.g. a too-fast rolling Talos upgrade, loses mon quorum. Talos's drain step only covers Kubernetes pods.
- **No cluster-wide stop/start.** cephadm has none either. The documented procedure is: set `noout`, `norecover`, `norebalance`, `nobackfill`, `nodown` and `pause` with `cephadm-talos shell`, then shut the nodes down.
- **Start ordering across nodes is not expressible.** `dependsOn` only covers the local node: network addresses, time sync, ceph.conf and the device. After a full power cycle, an OSD that starts before the mons have quorum fails, and Talos's restart backoff (5s up to 2 minutes) brings it up eventually. It works, but it is a crash loop rather than a dependency.
- **No sidecars or pod grouping.** Init containers are covered by `dependsOn` on a container that succeeded (PR #14795); sidecars (e.g. for iSCSI/NFS) and shared-namespace groups cannot be expressed (draft 07, held).
- **Only `restricted` or `privileged` profiles, no user namespaces.** OSDs and their preparation and zap jobs run fully privileged with host `/dev`. uid 0 in a container is root on the host. The OSD redesign in milestone 5 hands each OSD a raw volume as a device (PR #14775) for unprivileged OSDs.
- **Secrets live in the machine config in plaintext.** Keyrings are base64 env vars in `ContainerConfig` documents, and anyone with `os:admin` on a node's Talos API can read them (raw machine config is sensitive in the pinned Talos); agent and mgr TLS keys are in the agent's and the mgr's documents. A joining mon gets the `mon.` key only, as with cephadm; the bootstrap mon's document, which held `client.admin` and the first keys, is replaced by the joining template at the handoff, so after it no machine config holds `client.admin`. An OSD preparation job carries the bootstrap-osd key while it exists. There is no Talos "secret" document a container can mount (#14221, filed).
- **Every change is a machine config change.** Each daemon change grows the config history and goes through the full apply path. A typo in a document is rejected for the whole patch. Talos has no conditional apply, so an agent's drift check and its apply are not atomic: a concurrent writer outside cephadm-talos can be overwritten.

## Orchestration features missing vs. cephadm

- **`ceph orch` covers a subset.** Daemons, OSDs, hosts, maintenance, power cycles, upgrades and a keepalived-only ingress, each with a subset of its options; every row is in the [capability matrix](docs/capabilities.md), and anything else is refused. There are no service specs beyond the ingress (and host specs), no placement beyond the ingress's named hosts, no labels beyond storing them, no count-per-host and no reconciliation loop: daemons are placed one at a time, and nothing re-creates a daemon whose host disappears.
- **Certificates are not renewed after the handoff.** The CLI renewed the agent and mgr certificates on every command before the handoff; after it, nothing does until plan 04 moves renewal into the mgr. They are valid for 3 years; nothing is revoked.
- **No `orch host drain`, agent self-upgrade or enrollment by the leader** (plan 04). A new node is enrolled by the CLI (`cephadm-talos host add`), then added with `ceph orch host add`.
- Only mon, mgr, OSD, RGW and keepalived. No MDS/CephFS, NFS, iSCSI/NVMe-oF, monitoring stack (prometheus, grafana, alertmanager, node-exporter), crash collector or ceph-exporter.
- RGW is the default zone only: no realms, zonegroups or multisite, and no `rgw_dns_name` or virtual-hosted-style buckets. Users are created by hand with `cephadm-talos shell -- radosgw-admin`.
- The ingress is active/passive: keepalived without haproxy, so all S3 traffic goes to one RGW at a time and nothing balances load. It needs layer 2 between its hosts (VRRP unicast and gratuitous ARP), one VIP, and IPv4. Its keepalived runs with `NET_ADMIN`, `NET_RAW` and `NET_BROADCAST`, and the VRRP password is in the machine config. Talos's built-in VIP would avoid all of this, but it needs etcd for its election (observed). An upload through the VIP is cut when the VIP moves.
- A generated RGW certificate comes from a self-signed cluster CA; clients must trust it. A new certificate is rolled to every RGW one host at a time, the VIP moved away first; requests in flight on a restarting RGW are cut. Generated certificates are reissued when their names change, not before they expire (2 years).
- Each RGW restart registers a new instance (gid) in the Ceph service map, so after a few restarts `ceph -s` shows more RGW daemons than run (observed). They are cosmetic, but they make the RGW count in `ceph -s` unreliable.
- OSDs are one raw device per OSD: `ceph-volume raw`, bluestore only, no LVM. That means:
  - no separate DB/WAL devices;
  - no dm-crypt;
  - no drive groups or `ceph orch device ls` inventory;
  - no automatic "all available devices".
- The upgrade follows cephadm's order (standby mgrs, the active one after a failover, mons, OSDs, RGWs) with Ceph's `osd ok-to-stop` before each OSD, `mon ok-to-stop` before each mon only with more than two mons, a failover before the active mgr, the VIP moved off before an RGW, and the daemon back in Ceph after each, but it sets no `noout`, does not wait for active+clean between OSDs, and has no staggered or canary filters.
- `ceph orch osd rm status` reports the phase but no PG count; `osd rm --replace` is not supported.
- No host facts or metadata (`ceph orch host ls --detail`), no host checks or `prepare-host`: time sync, kernel modules and sysctls are not managed. On Talos they belong in machine config (`KernelModuleConfig` / `SysctlConfig`).
- No firewall management, no log rotation, and no per-cluster log files. Logs go to stderr and are kept by Talos in a bounded buffer per container.
- No adoption of existing (legacy or cephadm) daemons. Several clusters per host are possible in principle (all paths and names carry the fsid, the agents' records are per cluster) but untested.

## State and safety

- **Recovery after the handoff is limited to mons on their stores.** `cephadm-talos suspend`, `recover mons` and `resume` bring back mons whose stores and deployment markers survived; a lost majority (monmap surgery), a store rebuilt from OSDs, new or rotated credentials and a recovery that would change the cluster state (drop a mon, change an address) are not supported. One workstation runs one recovery at a time.
- **An uncertain operation needs the operator.** A job whose outcome is not known (started, no result) freezes further jobs on its node, and there is no command to resolve it yet.
- The workstation keeps the admin keyring, `ceph.conf`, the nodes' contacts (`local.json`) and the operator's approval signing key; losing them means no new approvals and no recovery from that workstation. Two operators cannot share them.
- `mon_host` in `/etc/ceph/ceph.conf` is updated on every host only after a mon joined or left. Running daemons pick up mon changes through the monmap, but anything started in between uses the old list.
- Removing a host does not clean `/var/mnt/ceph`, and its agent stays (owning nothing) until `rm-cluster`. Only `rm-cluster --zap` deletes `/var/mnt/ceph/<fsid>`; the agents' records volume stays.
- Zap runs `ceph-volume lvm zap` in a privileged job on the host. `talosctl wipe disk` (FAST) only clears the start of the disk; bluestore keeps label copies at 1G, 10G, 100G and 1000G, so an old OSD came back on the next deploy and crash-looped (observed). A disk whose zap failed keeps its label; a new preparation refuses it.
- The host name is the mon/mgr id. Renaming a Talos node breaks the mapping.
- Maintenance refuses hosts named like a number, `osd.<number>`, `all` or `any`: `ceph osd set-group noout <host>` would resolve those to OSD ids or keywords instead of the host's CRUSH bucket.
- Document names that are not valid Talos container names (uppercase, a trailing `-`, longer than 63 characters) are normalized and suffixed with a hash. The Ceph ids keep the raw hostname.
- **A crash inside an OSD preparation needs the operator.** A preparation job that started and left no result (a reboot inside `ceph-volume raw prepare`, after `ceph osd new` and before its label) is uncertain: the job does not run again, the agent runs no further job on that node, and an id `ceph osd new` allocated may be left behind (`cephadm-talos shell -- ceph osd purge-new osd.<id> --yes-i-really-mean-it`). There is no command yet to resolve the agent's uncertain job; ceph-volume's own rollback only covers failures it catches itself, not a crash.
- **Only the latest Ceph release.** Keys are always AES256KRB5 (v20.2.4+); older releases are refused.
- Clock skew warnings appear after the QEMU VMs were suspended (observed). They are not managed, because Talos owns time sync.

## Implementation shortcuts

- The CLI's own commands before the handoff (`deploy`, `rm`, `upgrade`, `host maintenance`) are the proof of concept's: a naive upgrade loop, OSD removal with a single `safe-to-destroy` check. After the handoff `ceph orch` replaces them.
- `--dry-run` does not persist state, so only `bootstrap` can be dry-run on a fresh setup.
- The integration suite (`go test -tags integration`) needs a QEMU cluster and does not run in CI; CI runs the unit tests, the mgr module's tests and the capability matrix check.

## Review scope

Every step went through Codex fix-or-refute rounds, each finding fixed or refuted with evidence, until a round came back clean; the recovery work (suspension, `recover mons`, `resume`, `rm-cluster` after the handoff) was reviewed for crash and retry paths too. Several simultaneous failures and races beyond the ones in the plan's tests have had less scrutiny.

## What was tested live

On the QEMU cluster (3 control planes, no Kubernetes, the combined Talos build v1.15.0-alpha.2-51-g8ee5a247e):

- bootstrap, handoff, enrollment of two nodes with `ceph orch host add`, mons and a standby mgr through `ceph orch`, 4 OSDs through `ceph orch daemon add osd` with the operator's disk approval;
- on v21.2.0: bootstrap, handoff, enrollment, mons, mgrs and 4 OSDs through `ceph orch`, a rolling upgrade through `ceph orch upgrade start` to the release's amd64 digest (every daemon on it), and an unplanned power loss of the whole cluster, after which every daemon came back to HEALTH_OK on its own;
- earlier rolling upgrades from v20.2.4 to v20.2.4 by another digest, and from v20.2.4 to v21.2.0 (all daemons on the new release, the orchestrator available after);
- `ceph orch hardware powercycle` of a mon+OSD host (maintenance, Talos reboot, back), and maintenance enter and exit;
- `suspend` during an OSD preparation (the receipt only after the job ended) and a `ceph orch` command refused while suspended;
- with one agent removed (its node suspended through Talos) and every mon document removed: `recover mons` back to quorum, `shell` into a mon, `resume` (the agent applied again, every agent re-adopting its node, both mgrs restarted), a new leader incarnation, and a `ceph orch daemon add` that landed;
- `rm-cluster --zap` during an OSD preparation, after which no document, container or label was left; `rm-cluster` without a quorum.

The proof of concept's CLI was tested earlier on Talos v1.15.0-alpha.1: RGW with TLS behind a keepalived VIP moving during maintenance, OSD removal and re-adding, mon removal and re-adding.
