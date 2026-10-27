# Shortcomings

cephadm-talos is a proof of concept. This file lists what is missing or wrong compared to cephadm, and what Talos does not (yet) make possible. Items marked **(observed)** were hit while testing on a Talos v1.15.0-alpha.1 QEMU cluster.

## Talos platform limits

- **No exec into containers.** Talos has no API to run a command in a `ContainerConfig` container. `talosctl debug` cannot use the `taloscontainers` namespace, privileged mode or host mounts. Every admin command therefore runs as a throw-away "job" `ContainerConfig`:
  1. patch the document in;
  2. wait for its output in `talosctl logs`;
  3. patch the document out.

  A `ceph -s` costs two machine config applies and several seconds. The job also carries the admin keyring in the machine config while it exists.
- **No one-shot containers.** Talos restarts every exited container 5s later, with no restart policy and no backoff. One-time work (mkfs, ceph-volume prepare) is folded into idempotent entrypoints. Jobs `sleep infinity` after finishing instead of exiting. Crash loops are slowed down by a 30s sleep in the entrypoint's EXIT trap, not by Talos.
- **No stop or disable mode.** There is no way to stop a `ContainerConfig` container and keep it stopped. `host maintenance enter` therefore removes the host's documents, and `exit` re-renders them from `state.json`. Each enter/exit is a machine config change, with the keyrings written again. See [UPSTREAM.md](UPSTREAM.md) for the feature request draft.
- **Shutdown is concurrent with a fixed 10s grace period.** On reboot, shutdown or upgrade, Talos stops all containers on the node at once, not in reverse `dependsOn` order, after Kubernetes pods and before EPHEMERAL is unmounted. Each gets SIGTERM, then SIGKILL after 10s, and the timeout can't be configured. ceph-mon and ceph-osd handle SIGTERM within that window. A shell entrypoint as PID 1 does not, unless it traps the signal: parked jobs used to always run into the SIGKILL (observed: 14s per `shell` command instead of 9s). They now trap TERM. During `ceph-volume raw prepare` the entrypoint ignores SIGTERM on purpose, so prepare gets the full 10s.
- **Plain `talosctl reboot`/`upgrade` is not Ceph-aware.** Without `cephadm-talos host maintenance enter` (or `host reboot`), a reboot sets no `noout` and runs no ok-to-stop. OSDs are marked out after `mon_osd_down_out_interval` (600s) and data starts moving. Rebooting two of three nodes at once, e.g. a too-fast rolling Talos upgrade, loses mon quorum. Talos's drain step only covers Kubernetes pods.
- **No cluster-wide stop/start.** cephadm has none either. The documented procedure is: set `noout`, `norecover`, `norebalance`, `nobackfill`, `nodown` and `pause` with `cephadm-talos shell`, then shut the nodes down. With cephadm-talos you can also `host maintenance enter` each host (OSD hosts first, mons last), but the last mon's ok-to-stop then needs `--force`.
- **Start ordering across nodes is not expressible.** `dependsOn` only covers the local node: network addresses, time sync, ceph.conf and the device. After a full power cycle, an OSD that starts before the mons have quorum fails, and the entrypoint's 30s restart backoff brings it up eventually. It works, but it is a crash loop rather than a dependency.
- **No init containers, sidecars or pod grouping.** cephadm's init containers, the sidecars (e.g. for iSCSI/NFS) and shared-namespace groups cannot be expressed.
- **Only `restricted` or `privileged` profiles, no user namespaces.** OSDs run fully privileged with host `/dev`. uid 0 in a container is root on the host.
- **Secrets live in the machine config in plaintext.** Keyrings are base64 env vars in `ContainerConfig` documents, and anyone with `os:reader` on the Talos API can see them. The mon document carries the admin and bootstrap keys, because they are needed for mkfs/join. There is no Talos "secret" document a container can mount.
- **Images are not digest-pinned automatically.** `talosctl validate` warns that the running image may change on restart when a tag is used. cephadm resolves tags to digests on upgrade; cephadm-talos does not. You can pass a digest reference yourself (`upgrade --image quay.io/ceph/ceph@sha256:...`), and that was tested.
- **Same-digest re-pins are a no-op (observed).** Talos only restarts a container when its resolved spec (digest, env, mounts) changes. An `upgrade` to a reference with the same digest therefore restarts nothing, which is correct but cannot exercise the restart path.
- **Job containers need a machine config apply each.** Admin commands take about 8s each on the QEMU cluster, so an `upgrade` of 8 daemons, with a `ceph -s` gate after each, took about 2 minutes.
- **Every change is a machine config change.** Each deploy/rm/job grows the config history and goes through the full apply path. A typo in a document is rejected for the whole patch.

## Orchestration features missing vs. cephadm

- No mgr `orchestrator` backend, so `ceph orch ...` and the dashboard's orchestrator pages do not work. All orchestration is client-side in the cephadm-talos CLI.
- No service specs, placement, labels, count-per-host or reconciliation loop. Daemons are placed by hand, and nothing re-creates a daemon whose host disappears.
- Only mon, mgr, OSD and RGW. No MDS/CephFS, NFS, iSCSI/NVMe-oF, monitoring stack (prometheus, grafana, alertmanager, node-exporter), crash collector or ceph-exporter.
- RGW is the default zone only: no realms, zonegroups or multisite, and no `rgw_dns_name` or virtual-hosted-style buckets. Users are created by hand with `cephadm-talos shell -- radosgw-admin`.
- The VIP is active/passive: keepalived without haproxy, so all S3 traffic goes to one rgw at a time and nothing balances load. It needs layer 2 between the vip hosts (VRRP unicast and gratuitous ARP), one VIP per cluster, and IPv4. Its keepalived runs with `NET_ADMIN`, `NET_RAW` and `NET_BROADCAST`, and the VRRP password is in the machine config. Talos's built-in VIP would avoid all of this, but it needs etcd for its election (observed).
- The generated RGW certificate comes from a self-signed cluster CA (`~/.cephadm-talos/<fsid>/rgw-ca.crt`); clients must trust it. The CA key and the server key are in `state.json` and, as a PEM bundle, in the rgw documents. Adding a host or the VIP reissues the certificate (only when its names change), and every rgw restarts, one host at a time. The VIP is moved away first, and each step waits until the rgw serves the new certificate (fingerprint check) and its keepalived is ready again. Under continuous S3 GETs through the VIP, a full rotation cost 1 failed request out of 325 (the VRRP handover); requests in flight on a restarting rgw are cut (observed). Certificates are not renewed (2 years).
- Each rgw restart registers a new instance (gid) in the Ceph service map. After a few certificate reissues `ceph -s` showed `rgw: 5 daemons active (2 hosts)` while exactly one radosgw process ran per host. The stale entries survived a mgr failover and were still listed after more than 10 minutes (observed). They are cosmetic, but they make the rgw count in `ceph -s` unreliable.
- OSDs are one raw device per OSD: `ceph-volume raw`, bluestore only, no LVM. That means:
  - no separate DB/WAL devices;
  - no dm-crypt;
  - no drive groups or `ceph orch device ls` inventory;
  - no automatic "all available devices".
- `host maintenance enter` follows cephadm: ok-to-stop for the host's OSDs and mon, no lone mgr, `osd set-group noout`, then stop the daemons. It does not drain anything. `rm` of an OSD only checks `safe-to-destroy` once; it does not wait for PGs to drain like `ceph orch osd rm` does.
- The upgrade is a naive loop: mon, mgr, then OSD, one at a time. The gate between steps is "the container runs the new image and `ceph -s` answers". It does not:
  - set `noout`;
  - check `ok-to-stop`;
  - wait for PGs to become active+clean;
  - support staggered or canary rollouts.
- No cephadm agent and no host facts or metadata (`ceph orch host ls --detail`).
- No host checks or `prepare-host`: time sync, kernel modules and sysctls are not managed. On Talos they belong in machine config (`KernelModuleConfig` / `SysctlConfig`).
- No firewall management, no log rotation, and no per-cluster log files. Logs go to stderr and are kept by Talos in a bounded buffer per container.
- No adoption of existing (legacy or cephadm) daemons. Several clusters per host are possible in principle (all paths and names carry the fsid) but untested.

## State and safety

- The inventory lives on the workstation (`~/.cephadm-talos/<fsid>/state.json`), not in the cluster. Losing it means re-deriving the state from the machine configs by hand. Two operators cannot share it.
- `mon_host` in `/etc/ceph/ceph.conf` is updated on every host only after a mon is added or removed. Running daemons pick up mon changes through the monmap, but anything started in between uses the old list.
- Removing a host does not clean `/var/mnt/ceph`. Removing the `UserVolumeConfig` does not wipe the directory either. Only `rm-cluster --zap` deletes `/var/mnt/ceph/<fsid>`.
- `rm --zap` and `rm-cluster --zap` run `ceph-volume lvm zap` in a privileged job on the host. `talosctl wipe disk` (FAST) was tried first, but it only clears the start of the disk; bluestore keeps label copies at 1G, 10G, 100G and 1000G, so the old OSD came back on the next deploy and crash-looped (observed).
- `ceph-volume raw` relies on the bluestore label to find an OSD again. If a device name changes (e.g. `/dev/vdb` becomes `/dev/vdc` after adding disks), the document still points at the old path. A by-id path or Talos `diskSelector` would be needed.
- The host name is the mon/mgr id. Renaming a Talos node breaks the mapping.
- `host maintenance` refuses hosts named like a number, `all` or `any`. `ceph osd set-group noout <host>` would resolve those to OSD ids or keywords instead of the host's CRUSH bucket.
- Document names that are not valid Talos container names (uppercase, a trailing `-`, longer than 63 characters) are normalized and suffixed with a hash. The Ceph ids keep the raw hostname.
- A forced `rm` while no mon is reachable only stops the container. The daemon stays in the inventory as `local_only`, and a later `rm` runs the cluster-side cleanup. `--zap` is refused in that case.
- **A reboot between `ceph osd new` and mkfs leaves the OSD stuck.** If the node reboots inside `ceph-volume raw prepare`, after the id was allocated but before the label was written, the restarted prepare reuses the same uuid with a new key, and Ceph rejects it ("exists but key does not match"). Recovery is manual: run `cephadm-talos shell -- ceph osd purge-new osd.<id> --yes-i-really-mean-it`, then `cephadm-talos redeploy`. ceph-volume's own rollback only covers failures it catches itself, not a crash.
- **CephX key type follows the image at bootstrap (observed).** v20.2.4 made AES256KRB5 (`aes256k`) the default, and fresh monmaps allow only that type, while v20.2.3 and older cannot parse such keys. `bootstrap --key-type auto` picks the type from the image tag; `aes` or `aes256k` can be forced.
- **Upgrading an AES cluster to v20.2.4 ends in HEALTH_ERR (observed).** Ceph's new checks flag the "insecure key types" and require rotating every cephx key to aes256k. cephadm-talos has no key rotation; the data path keeps working, as the v20.2.3 to v20.2.4 test showed.
- **`raw prepare --osd-fsid` is missing before v20.2.4 (observed).** For those releases the OSD falls back to a per-deploy pending marker under `/var/mnt/ceph/<fsid>/` to recognise its own label after a restart.
- Clock skew warnings appear after the QEMU VMs were suspended (observed). They are not managed, because Talos owns time sync.

## Implementation shortcuts

- cephadm-talos shells out to `talosctl` instead of using the Talos machinery Go API, so errors are parsed text.
- Waiting is polling: every 2-3s via `talosctl get containerstatus` and `talosctl logs`, rather than `talosctl get --watch`.
- The OSD id is discovered by scraping `CEPHADM-TALOS-OSD-ID=` from the container log.
- `--dry-run` does not persist state, so only `bootstrap` can be dry-run on a fresh setup.
- There are no integration tests in CI. Only unit tests and `talosctl validate` of the rendered documents are run.

## Review scope

The code went through repeated Codex review rounds, each finding fixed or refuted, until a round came back clean. The later rounds were limited to normal operation, meaning a healthy cluster or one node down, without `--force`. Behaviour under forced operations, several simultaneous failures and crash-timing races has had less scrutiny.

## What was tested live

On a `talosctl cluster create qemu` cluster running Talos v1.15.0-alpha.1 (1 control plane, 3 workers with an extra 10 GiB disk):

- bootstrap, 3 mons, 2 mgrs and 3 OSDs, reaching HEALTH_OK, then a rados put/get with matching md5, on v20 (20.2.4) and on v20.2.3;
- a rolling upgrade from v20.2.3 to v20.2.4, after which every daemon ran 20.2.4 and the data was intact;
- `rm` of an OSD: `safe-to-destroy` refused with 3 OSDs at size 3, then `rm --force --zap` and a redeploy on the same disk reused id 2 with a new uuid;
- `rm` of a mon and re-adding it on the same host (fresh store, quorum restored);
- `rm-cluster --zap`, which removed all documents, zapped the disks and deleted the data dirs;
- RGW with TLS on 2 nodes and a keepalived VIP: S3 bucket create, put and get with `curl --aws-sigv4 --cacert` through `https://<vip>`, with matching md5. During `host maintenance enter` of the VIP holder the VIP moved to the other node (gratuitous ARP seen on the client) and S3 kept working; after exit the VIP moved back to the preferred node;
- `host reboot` (maintenance enter, `talosctl reboot`, exit) of a mon+OSD host, which took about 2 minutes and ended with every daemon back and noout cleared; a second host entering maintenance at the same time was refused by `mon ok-to-stop`.
