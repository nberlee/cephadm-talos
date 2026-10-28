# Plan 01: Contract and Foundation (roadmap milestones 1 and 2)

Status: draft, awaiting sign-off.

## Goal

Fix what the project promises (supported versions, capability matrix, versioned state), then replace the `talosctl` shell-out with the Talos machinery Go client, without changing what the CLI does for a user. Nothing of the agent or mgr module is built here.

## Milestone 1: Contract

1. **Supported versions** in `docs/support.md`:
   - Talos 1.15 or later (`ContainerConfig` is new in 1.15). Until 1.15.0 is released, `pkg/machinery` and the test cluster track the latest Talos pre-release (today `v1.15.0-alpha.2`); afterwards the latest release. The QEMU test cluster is recreated at the same pre-release as the module before the integration suite runs (a user step: the cluster runs as root). `internal/spec` follows the machinery `ContainerConfig` types; PR #14740 (`userVolume` renamed to `volume`) is expected to land during this plan and break rendering once.
   - Ceph: only the latest release, today v20.2.4; the supported version moves with each new Ceph release once tested. No backwards compatibility before the first tagged release, so code for older releases is removed: key-type selection (`KeyTypeFor`, `--key-type`, the stored key type, the AES branch in `mon.sh`); keys are always AES256KRB5, and the tests follow. Correction found on the live cluster: `ceph-volume raw prepare` in v20.2.4 has no `--osd-fsid` (only Ceph main has it), so the `.pending` fallback in `osd.sh` stays; it is what the supported release uses.
   - amd64 only for now; arm64 follows later.
   - Version gates at operation boundaries, so shared job execution does not defeat the exceptions: bootstrap and deploy require a supported Talos node and a verified supported Ceph image; deploy on an older cluster is refused unless the testing override is set. Upgrade requires a supported current version and a verified supported candidate. The override skips the version checks only; it does not make older releases work. Removal (`rm`, `rm-cluster`, zap and forced paths) and recovery are not gated. Local commands (`conf`, inventory) are not gated. The override flag is separate from `--dry-run`, which stays offline.
2. **State schema**: `schema: 1` in `state.json`; any other or missing schema is refused. No migrations before the first release: PoC clusters are recreated, not adopted. From the first release on, the rule is a version field, refusal of unknown versions and explicit migrations, also for the later config-key schema and socket protocol.
3. **Capability matrix** in `docs/capabilities.md`, built from the Ceph v20.2.4 source (tag and commit recorded): public methods of the `Orchestrator` class (`orchestrator/_interface.py`), `ceph orch` commands (the command decorators in `orchestrator/module.py`), service types and spec fields, and the dashboard's orchestrator pages. Each row: implemented, planned in milestone N, or unsupported, plus the Talos blocker if any. Existing PoC CLI commands are listed separately; they do not count as an implemented `ceph orch` interface. A script reads the source with Python's `ast` module (no mgr runtime needed) and fails on missing, stale or duplicate rows; CI runs it against the pinned tag.

## Milestone 2: Foundation

Order: state and connections, then reads and watches, then patch, reboot and the rest, then digest pinning.

1. **Connections.** `state.Host` gets optional `talosconfig` and `context`. Precedence: CLI flags, then the host's fields, then the cluster defaults in state. Clients are cached per effective (talosconfig, context) and use `client.WithNode` per call. Dry-run returns before any client is built.
2. **Reads**: `ContainerStatuses`, `ImageStatus`, `HasInstances`, `InstanceGeneration`, `MachineConfig`, `Hostname`, `Version` read typed COSI resources and the version API instead of parsing `talosctl get` output. Missing resources, permission errors and transport errors are distinct errors.
3. **Watches** with `safe.StateWatch` through the node-scoped COSI client, seeded from a list, reconnecting within the existing deadlines: `ContainerStatus` for running, `ContainerImageStatus` plus `ContainerStatus` for the image wait, `ContainerInstanceSpec` plus status for "gone" (a status can disappear before the process exits, which `waitGone` already handles). Job results stay log markers in this milestone; result files and completion markers need the agent and move to milestone 3.
4. **Patch**: read the full active `MachineConfig`, apply the ordered patches with machinery's `configpatcher`, and send the complete result in one `NO_REBOOT` `ApplyConfiguration`. All unrelated documents are kept. The existing delete-then-add for `ContainerConfig` stays (strategic merge appends list fields). Keyrings stay in memory: no temporary files. Tests: unrelated documents kept, list replacement, deleting a missing document, apply errors.
5. **Logs, restart, reboot**: logs and restart use the `taloscontainers` namespace and the containerd driver. Reboot is node-scoped and the API call returns at once, so `Reboot` waits as `talosctl reboot --wait` did: it reads the node's boot id (COSI `runtime.BootID`) before rebooting, then waits for a different boot id and for `MachineStatus` to report stage `RUNNING` with `ready: true`, within the existing 20 minutes, before maintenance exit continues. A changed boot id with `ready: false` does not end the wait (tested). Stream errors and cancellation are handled.
6. **New thin wrappers** listed in the roadmap: Talos upgrade (`UpgradeWithOptions`) and disk inventory. No new CLI commands.
7. **Digest pinning**:
   - `bootstrap` and `upgrade` pull the candidate on one named node with `ImageServiceClient.Pull` in the `taloscontainers` namespace, which returns the canonical `name@digest` reference. Talos skips images it already has, so a floating tag is resolved once; `--refresh` removes the cached reference on that node (`ImageServiceClient.Remove`) and pulls again.
   - A new probe job runs `ceph --version` on that digest and reports through the existing log markers. It has no keyring, no `CEPH_ARGS`, no `/etc/ceph` mount and no `dependsOn` on `ceph.conf`, so it works before bootstrap. Deadlines for pull and probe.
   - Bootstrap order: resolve, probe, gate on the verified version, then generate keys and deploy. Upgrade probes the candidate digest, not the current image.
   - State stores the digest reference, the verified version and the platform it was probed on (amd64).
   - Dry-run stays offline: it prints the planned pull and probe, and records nothing.
8. **Tests**:
   - Unit tests against a fake machinery server: patch merge, resource decoding, watch seeding and reconnect, reboot wait, error kinds, schema refusal.
   - An `integration` build tag suite against an existing QEMU cluster (`TALOSCONFIG` and nodes from the environment): bootstrap, mon, mgr and OSDs, a job with a nonzero exit vs a transport failure, a cancelled job and its cleanup, delayed instance teardown, a reboot through `host reboot`, a rolling upgrade between two distinct digests of the supported Ceph release (instances must change; a same-digest re-pin is a separate no-op test), a stale cached tag with and without `--refresh`, offline dry-run, `rm-cluster --zap`, version gates tested at the gate (unsupported image or node refused, removal and recovery ungated, the override and dry-run separately; no older cluster needed), and the PoC's live scenarios on the supported release (without the v20.2.3 bootstrap and upgrade).
   - Upgrade fixtures: two amd64 images built `FROM` the digest-pinned supported Ceph image, differing only in a `LABEL`, pushed to a registry every QEMU node can reach. The test checks they have different digests and the same `ceph --version`, bootstraps with A, rolls to B and checks the instances changed. For the stale tag, a mutable tag points to A, then to B: without `--refresh` it resolves to A, with it to B.
   - The test cluster itself is created with `talosctl cluster create`; only the product avoids `talosctl`.

## Out of scope

The agent, the mgr module, config-key state, job result files, leadership and fencing (milestone 3), security changes (milestone 4), new services and OSD layouts (milestone 5). OSD identity stays a log line; the forced paths are not touched.

## Open points for sign-off

- Job result files and completion markers move from milestone 2 to 3 (`ROADMAP.md` updated accordingly): without an agent there is no way to delete them, `rm-cluster --zap` would remove them, and durable completion needs the journal. Recommended.
- State stays on the workstation until milestone 3?
- Existing PoC clusters are not migrated; they are recreated (no backwards compatibility before the first release).
