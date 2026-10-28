# Supported versions

| Component | Supported | Notes |
|---|---|---|
| Talos | 1.15 or later | `ContainerConfig` is new in 1.15. Until 1.15.0 is released, `pkg/machinery` and the test cluster track the latest pre-release (today v1.15.0-alpha.2). |
| Ceph | the latest release only, today v20.2.4 | The supported version moves with each new Ceph release once it is tested. |
| Architecture | amd64 | arm64 follows later. |

## Version gates

Gates run at operation boundaries:

- `host add`, `bootstrap` and `deploy` need a supported Talos version on the target node and a verified supported Ceph image. `deploy` on a cluster whose image is older is refused.
- `upgrade` needs a supported current version and a verified supported candidate image.
- `rm`, `rm-cluster` (with `--zap` and `--force`), recovery (`host maintenance exit`) and local commands such as `conf` and `ps` are not gated.
- `--skip-version-check` skips these checks for testing. It does not make older releases work, and it is separate from `--dry-run`, which never contacts a node.

## Compatibility

No migration or backwards compatibility is provided before the first tagged release. `state.json` carries a schema version, and any other version is refused; clusters created by an earlier build are recreated, not adopted. From the first release on, state, the config-key schema and the socket protocol carry a version field, unknown versions are refused, and every change comes with an explicit migration.
