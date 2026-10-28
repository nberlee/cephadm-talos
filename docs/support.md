# Supported versions

| Component | Supported | Notes |
|---|---|---|
| Talos | 1.15 or later | `ContainerConfig` is new in 1.15. Until 1.15.0 is released, `pkg/machinery` and the test cluster track the latest pre-release (today v1.15.0-alpha.2). |
| Ceph | the latest release only, today v20.2.4 | The supported version moves with each new Ceph release once it is tested. |
| Architecture | amd64 | arm64 follows later. |

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

- `host add` needs a supported Talos version on the node.
- `bootstrap` and `deploy` (mon, mgr, osd, rgw, vip) need a supported Talos version on the target node and a verified supported Ceph image; `deploy` on a cluster whose image is older is refused.
- `upgrade` needs a supported current version and a verified supported candidate image.
- `rm`, `rm-cluster` (with `--zap` and `--force`), recovery (`host maintenance exit`), `host rm`, `ps`, `logs` and `conf` are not gated.
- `--skip-version-check` skips these checks for testing. It does not make older releases work, and it is separate from `--dry-run`, which never contacts a node.

## Compatibility

No migration or backwards compatibility is provided before the first tagged release. `state.json` carries a schema version, and any other version is refused; clusters created by an earlier build are recreated, not adopted. From the first release on, state, the config-key schema and the socket protocol carry a version field, unknown versions are refused, and every change comes with an explicit migration.
