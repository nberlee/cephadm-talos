# Supported versions

| Component | Supported | Notes |
|---|---|---|
| Talos | the first release with Talos PRs #14775, #14781, #14788 and #14795 | `ContainerConfig` is new in 1.15. While the PRs are unmerged, `pkg/machinery` and the test cluster come from one combined build of their branches (always the same commit for both, as the branches renumber protobuf fields); afterwards the latest pre-release until 1.15.0. |
| Ceph | the latest release only, today v21.2.0 | The supported version moves with each new Ceph release once it is tested. |
| Architecture | amd64 with x86-64-v3 CPUs | Ceph 21's official builds need x86-64-v3 (AVX2, BMI2, FMA); a CPU without it crashes the daemons with SIGILL. arm64 follows later. |

## Workload isolation must be off (temporary)

The cephadm-talos agent reads Talos through the local machined socket (`machinedAccess`). With workload isolation on, Talos records the wrong PID for such a container and refuses its calls; open Talos PR [#14603](https://github.com/siderolabs/talos/pull/14603) fixes this. Until a release contains the fix, Ceph nodes need:

```yaml
apiVersion: v1alpha1
kind: SecurityProfileConfig
workloadIsolation: false
```

as the Talos maintainers suggest on the PR. Save it as `disable-workload-isolation.yaml`; on each Ceph node run `talosctl -n <node> patch machineconfig --mode auto --patch @disable-workload-isolation.yaml`, then `talosctl -n <node> reboot`. The setting only takes effect after a reboot (`--mode auto` applies it without one), so schedule the interruption; turning isolation back on later also needs a reboot.

This weakens isolation node-wide, including for unrelated workloads: CRI containerd runs in the host PID and mount namespaces, removing the extra `sandboxd` boundary that separates the container plane from `machined` and its file descriptors. Containers keep their own namespaces and security restrictions. Talos 1.15 enables isolation by default for new configs. Turn it back on once a release with the fix is supported.

## Version gates

Gates run at operation boundaries:

- `host add` needs a supported Talos version and an x86-64-v3 CPU on the node, and a lowercase hostname (Ceph 21 lowercases host names in its specs).
- `bootstrap` and `deploy` (mon, mgr, osd, rgw, vip) need a supported Talos version and an x86-64-v3 CPU on the target node and a verified supported Ceph image; `deploy` on a cluster whose image is older is refused.
- `upgrade` needs a supported current version and a verified supported candidate image. After the handoff, `ceph orch upgrade start` needs an image of the operator's approval; the leader probes it and refuses a downgrade, more than two majors up or another architecture.
- `rm`, `rm-cluster` (with `--zap` and `--force`), recovery (`host maintenance exit`), `host rm`, `ps`, `logs` and `conf` are not gated.
- `--skip-version-check` skips the CLI's checks for testing, not the leader's checks of an upgrade. It does not make older releases work, and it is separate from `--dry-run`, which reads the nodes and the cluster state but prints the patches instead of applying them.

## Compatibility

No migration or backwards compatibility is provided before the first tagged release. The cluster state (in the mons' config-key store), the agents' records, the CLI's `local.json` and recovery journal, and the wire protocol between CLI, agents and module carry a schema or version, and any other version is refused; clusters created by an earlier build are recreated, not adopted. From the first release on, state, the config-key schema and the socket protocol carry a version field, unknown versions are refused, and every change comes with an explicit migration.
