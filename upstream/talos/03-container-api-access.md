Title: Talos Containers: limit the roles granted by `machinedAccess`

## Feature Request

### Description

`security.machinedAccess: true` (#14078, PR #14155) lets a Talos container call the local machined socket. Its processes may request any role (`role.All`, PR #14206; [machined.go](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/system/services/machined.go#L239-L243)), so a read-only agent gets the same power as a node manager.

**In short, we would like to see:**

1. A role list on `machinedAccess`, for example `machinedAccess: {roles: [os:reader]}`, capping what the container's processes may request.
2. Default unchanged (`role.All`) for compatibility.

**Use cases**

- Metrics exporters and dashboards reading resources (`ContainerStatus`, disks, network) with `os:reader` only.
- Least privilege for anything that needs only part of the API.

**Our case**: Ceph on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)) runs a per-node agent that manages its own node through `machinedAccess` and needs full local access. We noticed the missing ceiling while designing it; we do not need it ourselves.

#### Related

#14078, PR #14155, PR #14206, PR #14603.
