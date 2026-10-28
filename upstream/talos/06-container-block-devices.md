Title: Talos Containers: hand a block device or raw volume to a container without `privileged`

## Feature Request

### Description

Allow a container to use one specific block device, ideally a Talos-managed raw volume, without running `privileged`.

#### Problem

A container that needs one disk today must run `profile: privileged`, which grants all grantable capabilities and allows all devices ([adapter](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/adapters/containers/container_spec.go#L38-L49)). `restricted` defaults to no capabilities and a read-only root filesystem, and there is no device mount type. PR #14740 (for #14730) adds `ExternalVolume` and `ExistingVolume` mounts, not block-device passthrough.

Talos already selects, partitions and encrypts disks (`RawVolumeConfig`, `UserVolumeConfig` `disk`/`partition`, LUKS2 with TPM/KMS). What is missing is handing that one device to one container.

#### Use cases

- **Storage engines and databases on raw block devices** (direct IO), each getting only its assigned disk or partition.
- **VM or appliance containers** that need direct access to a host block device.
- Character devices (serial ports, GPUs, VFIO) would be a natural extension of the same mechanism, but are not the focus here.

#### Why we need it

A Ceph OSD owns one raw device. Today every OSD runs privileged with all of `/dev`, so one OSD bug can reach every disk on the node. With a `RawVolumeConfig` per OSD, Talos would also handle disk selection and encryption, and the OSD would see only its partition.

#### Proposal

```yaml
apiVersion: v1alpha1
kind: RawVolumeConfig
name: data-1
provisioning:
  diskSelector:
    match: disk.serial == "S4EWNX0R123456"
encryption:
  provider: luks2
  keys:
    - slot: 0
      tpm: {}
---
apiVersion: v1alpha1
kind: ContainerConfig
name: app
devices:
  - rawVolume: data-1           # or volume: / path: / diskSelector:
    destination: /dev/data-1
    permissions: rw             # cgroup rwm
```

- A device cgroup allow-rule and a device node for exactly that device, without `privileged`.
- For encrypted raw volumes, the container gets the unlocked dm-crypt device and starts only once it is unlocked.
- The container waits for the volume to be ready, and Talos holds the volume while a container uses it.
- A stable `destination` regardless of the kernel name (`/dev/vdb` can become `/dev/vdc` after adding a disk).
- A documented way to release and wipe the volume when the container and volume documents are removed.

#### Acceptance criteria

- A restricted container can do O_DIRECT IO to its assigned device and cannot open any other block device.
- Tested: disk renumbering, reboot with an encrypted raw volume, replacing the disk behind a selector.

#### Related

#14730 / PR #14740, #11778 / discussion #11804, #13906. "Device handover" in "Ceph on Talos without Kubernetes" by @hkraal (Exonet), whose proof of concept already backs OSDs with Talos raw volumes. Our use: [cephadm-talos](https://github.com/nberlee/cephadm-talos).
