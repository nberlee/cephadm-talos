# Talos feature requests

Feature requests for [siderolabs/talos](https://github.com/siderolabs/talos), following up on [#14220 (comment)](https://github.com/siderolabs/talos/issues/14220#issuecomment-6412486242), where smira quoted our requests (restart policy, a persistent stopped state, exec or run-once, stop timeout and order) and asked for them to be filed. They are written as Talos features that any non-Kubernetes workload can use, with Ceph as the worked use case. Each file is ready to paste into the Talos feature request template; `comment-*.md` files are comments for issues that already exist.

## Priority and filing order

P0 blocks a safe production orchestrator. P1 is needed for parity, least privilege, or for specific Ceph services. P2 has a workable workaround. P3 is small.

| Pri | File | Where | Summary |
|---|---|---|---|
| P2 | [01-config-compare-and-swap.md](01-config-compare-and-swap.md) | Not filing: Omni users do not hit it; the per-node agent is the single writer by convention | `expected_version` precondition on apply. Omni users do not hit this (Omni is the single writer to the node), so it matters only for multi-writer setups without Omni; for us a single-writer convention works meanwhile |
| P0 | [comment-14221-secret-volumes.md](comment-14221-secret-volumes.md) | #14221, [filed](https://github.com/siderolabs/talos/issues/14221#issuecomment-6439662907) 2026-10-27; [maintainer response](https://github.com/siderolabs/talos/issues/14221#issuecomment-6444599874): leaning towards optionally redactable config volumes (flag or separate kind) | Secret marking and redaction for the proposed config volumes |
| P0 | [comment-14733-restart-policy.md](comment-14733-restart-policy.md) | #14733, [filed](https://github.com/siderolabs/talos/issues/14733#issuecomment-6440031175) 2026-10-27; [PR #14795](https://github.com/siderolabs/talos/pull/14795) (draft) opened 2026-10-29 | Per-boot init vs durable jobs, terminal status with exit code, backoff, `dependsOn` succeeded |
| P0 | [comment-14733-reply.md](comment-14733-reply.md) | #14733, [filed](https://github.com/siderolabs/talos/issues/14733#issuecomment-6440668172) 2026-10-27 (posted shorter) | Reply to smira: drop durable one-shot (point 1), keep terminal status, backoff, `condition: succeeded` |
| P0 | [comment-14729-exec.md](comment-14729-exec.md) | #14729, [filed](https://github.com/siderolabs/talos/issues/14729#issuecomment-6445955564) 2026-10-27; [PR #14781](https://github.com/siderolabs/talos/pull/14781) opened 2026-10-29 | Exec into an existing container on top of `DebugService.ContainerRun`: separate stdout/stderr, exit status, audit (stays os:admin) |
| P1 | [04-container-stopped-state.md](04-container-stopped-state.md) | Not filing: the agent re-renders documents from desired state in Ceph, so delete and re-add works | `enabled: false` that keeps the document (host maintenance) |
| P1 | [05-container-pre-stop-hooks.md](05-container-pre-stop-hooks.md) | Not filing: the orchestrator sets `noout` for maintenance it starts; direct `talosctl reboot` is an operator choice | Pre-shutdown hooks for containers, like PR #14186 for extensions |
| P1 | [comment-14730-raw-volume-device.md](comment-14730-raw-volume-device.md) | #14730 (PR #14740), [filed](https://github.com/siderolabs/talos/issues/14730#issuecomment-6446999321) 2026-10-27; [maintainer response](https://github.com/siderolabs/talos/issues/14730#issuecomment-6467332527): accepted, but for Talos 1.16 (1.15 roadmap at capacity); we [offered to implement it](https://github.com/siderolabs/talos/issues/14730#issuecomment-6468776678); [PR #14775](https://github.com/siderolabs/talos/pull/14775) opened 2026-10-28, next to #14740 (filesystem mounts), merged 2026-10-30 | `devices` field handing a `RawVolumeConfig` to a container as a block device, without `privileged` (replaces draft 06) |
| P1 | [07-container-namespaces-init.md](07-container-namespaces-init.md) | Held: only blocks SMB (smb/winbind/ctdb sharing namespaces); file when SMB support is built | Host IPC/PID, shared namespaces (sidecars), `init: true` |
| P1 | [08-container-rlimits.md](08-container-rlimits.md) + [comment-14551-rlimit-nofile.md](comment-14551-rlimit-nofile.md) | Held: `nofile` is covered by #14551 (smira agreed to inherit the host limit). Talos raises only `RLIMIT_NOFILE` for machined ([tasks.go](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/startup/tasks.go#L136)), so `memlock` stays the kernel default; file when NVMe-oF (SPDK, `memlock=-1`) support is built. No `pids.max` is set for containers | Configurable rlimits and pids limit; +1 on the low default |
| P1 | [comment-14732-stop-timeout.md](comment-14732-stop-timeout.md) | Not filing: #14732 already covers timeout and order; stop signal is not needed for Ceph; [PR #14788](https://github.com/siderolabs/talos/pull/14788) opened 2026-10-29 | Stop timeout for every restart, stop signal, Ceph cases |
| P2 | [09-vip-without-etcd.md](09-vip-without-etcd.md) | Not filing: keepalived works | Layer-2 VIP election without etcd |
| P2 | [comment-14675-health-checks.md](comment-14675-health-checks.md) | Not filing: the agent checks admin sockets itself | exec checks, readiness in status, watchable |
| P3 | [10-container-status-aggregation.md](10-container-status-aggregation.md) | Not filing: small, the data exists across resources | Desired vs observed generation in `ContainerStatus` |

Decision 2026-10-27: only file what severely blocks the per-node agent design; rows marked "Not filing" or "Held" keep their drafts for reference.

Before filing: re-run the duplicate search (`gh search issues --repo siderolabs/talos <terms>`, discussions and open PRs), file the new issues first, then replace `#NNNN` in the comments with the new numbers. Ask for the new issues to be added as sub-issues of #14220.

## Not filed

- **Durable one-shot jobs** (a completed job not re-run after reboot). Rejected by smira in [#14733](https://github.com/siderolabs/talos/issues/14733#issuecomment-6440142915): jobs must be idempotent and detect their own previous run. Do not ask again elsewhere.

- **Persistent container logs.** Containers log through the same `LoggingManager.ServiceLog` as services ([containerd runner](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/system/runner/containerd/containerd.go#L204)), so the `/var/log` persistence from #11461 should cover them; the call alone does not prove persistence. Verify on a node before filing anything.
- **To validate on Talos before filing**: iSCSI (configfs, `iscsi_target_mod`), NVMe-oF (hugepages, VFIO, `SYS_NICE`), SELinux labels for Ceph daemons, kernel modules loaded from machine config. These may need more Talos features, or none.
- **Cross-node ordering** (an OSD waiting for mon quorum): stays with the orchestrator; only a docs note in #14732.
- **Scoped Talos API access for containers** (draft [03-container-api-access.md](03-container-api-access.md)). Cross-node credentials do not fit: Talos containers are node-local and nodes need not share a CA, so the orchestrator runs a per-node agent with full local `machinedAccess`. What remains, a role ceiling on `machinedAccess`, is generic least privilege we do not need ourselves.

## Evidence ledger

| Claim | Source | Status |
|---|---|---|
| `ApplyConfigurationRequest` has no version precondition; `applyConfigMu.TryLock` only | `api/machine/machine.proto` L127, `v1alpha1_server.go` L204 @ edbfe077 | read in source |
| `machinedAccess` lets a container request any role (`role.All`), local socket only | `system/services/machined.go` L239-243, PR #14206 @ edbfe077 | read in source |
| Secret marking exists: `config.SecretDocument`, applied by `Container.RedactSecrets`; implemented by RawVolume/UserVolume (encryption), RegistryAuth, Wireguard, SideroLink configs, not by `EtcFileConfig` or `ContainerConfig` | `config/config/document.go` L32-36, `config/container/container.go` L1243-1258, `types/*` `Redact()` @ edbfe077 | read in source |
| `talosctl debug` (`DebugService.ContainerRun`): new container from an image, `inmem`/`system` namespaces only, stdin/signal/TTY streaming, stdout only (no separate stderr), exit code, requires `os:admin` | `api/machine/debug.proto`, `cmd/talosctl/cmd/talos/debug.go` L61, `system/services/machined.go` L56 @ edbfe077 | read in source |
| Fixed 5s restart delay, no backoff | `controllers/containers/instance.go` L26-27 `RestartInterval` @ edbfe077 | read in source, observed |
| SIGTERM then SIGKILL after 10s, all containers asked to stop at once | `controllers/containers/containerd_runner.go` L44 `gracefulShutdownTimeout`, `controllers/containers/runtime.go` L531 `stopAll` @ edbfe077 | read in source, observed |
| `privileged` grants all grantable capabilities and allows all devices; `restricted` has none and a read-only rootfs | `adapters/containers/container_spec.go` L38-49 @ edbfe077 | read in source; device access under `restricted` not tested |
| `Layer2VIPConfig` needs etcd | `controllers/network/operator/vip.go` ~L155-250 @ edbfe077 | read in source, observed |
| Pre-shutdown hooks only for host extension services | PR #14186 (merged 2026-08-31) | read in PR |
| Container logs use `LoggingManager.ServiceLog` | `runner/containerd/containerd.go` L204 @ edbfe077 | read in source |

edbfe077 is Talos main as of 2026-10-26. All references to existing issues, PRs and discussions were checked against their text on 2026-10-27, and the cited source lines against edbfe077. "Observed" means seen on v1.15.0-alpha.1 with cephadm-talos.

## Credits

Henk Kraal ([@hkraal](https://github.com/hkraal), Exonet) describes the same direction in "Ceph on Talos without Kubernetes" (October 2026). His list of what is still missing (secrets, coordinated maintenance, device handover, day-2 access) maps onto the #14221 comment, 04/05, 06 and #14729 above, and is mentioned in those issues.
