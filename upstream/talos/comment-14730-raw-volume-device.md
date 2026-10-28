Target: comment on https://github.com/siderolabs/talos/issues/14730 (support more volume kinds in `ContainerConfig`, PR #14740)

---

Following up from #14220. With #14740 a `volume` mount can name a `UserVolumeConfig`, `ExistingVolumeConfig` or `ExternalVolumeConfig`, and the container waits for it to be mounted. A `RawVolumeConfig` has no filesystem to mount, so could `ContainerConfig` also get a separate `devices` field that hands a raw volume to the container as a block device?

```yaml
devices:
  - rawVolume: data-1
    destination: /dev/data-1
```

**In short, we would like to see:**

1. A device node at a stable `destination`, independent of kernel device names, and a device cgroup allow rule for that device only, without `profile: privileged` (which [allows all devices](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/adapters/containers/container_spec.go#L38-L49)).
2. The container waits for the raw volume to be ready; for an encrypted volume it gets the unlocked dm-crypt device.
3. The volume is held until the container has stopped, like the lifecycle protection for mounted volumes in #14740.

**Use cases**

- Storage engines and databases with their own on-disk format on a raw device, each limited to its assigned partition.
- VM or appliance containers that need one assigned block device.

**Our case**: Ceph OSDs on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)), each owning one raw partition for BlueStore. With a `RawVolumeConfig` per OSD, Talos handles disk selection and encryption, and the OSD no longer needs `privileged`. @hkraal backs OSDs with Talos raw volumes too ("Device handover" in "Ceph on Talos without Kubernetes").
