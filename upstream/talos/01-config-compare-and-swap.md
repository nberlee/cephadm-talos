Title: Machine config: compare-and-swap on apply

## Feature Request

### Description

`talosctl patch` [patches the machine config locally](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/cmd/talosctl/cmd/talos/patch.go#L74-L94) and submits the full result through `ApplyConfiguration`. [`ApplyConfigurationRequest`](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/api/machine/machine.proto#L127) has no version precondition. If two writers read the same config and apply one after the other, the later apply overwrites the earlier change, even when they modify different documents. PR #13430 serializes applies, but does not check for a stale read.

**In short, we would like to see:**

1. An optional `expected_version` on `ApplyConfigurationRequest`: an opaque revision returned with the config read, checked atomically with accepting the new config, `ABORTED` on mismatch. Without it, behaviour is unchanged. The revision should stay unambiguous across staged and active config, try-mode rollback and reboot.
2. The precondition in `pkg/machinery/client`, and `talosctl patch` rereading, re-patching and retrying (bounded) on `ABORTED`.

**Use cases**

- A node with more than one writer: an operator or GitOps pipeline owns the base config while a controller adds and removes documents (`ContainerConfig`, `EtcFileConfig`, `UserVolumeConfig`) at runtime. Kubernetes handles the same case with `resourceVersion` and a 409 on stale updates.

**Our case**: Ceph on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)), without Omni. A per-node agent adds and removes one `ContainerConfig` per Ceph daemon while the operator applies network or disk changes with `talosctl patch` on the same node. A stale apply can remove a mon's `ContainerConfig` or revert the operator's change. Routing all changes through one writer avoids this; checking the resource version before an unconditional apply does not.
