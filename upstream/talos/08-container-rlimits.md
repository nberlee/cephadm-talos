Title: Talos Containers: configurable rlimits and pids limit

## Feature Request

### Description

Allow rlimits (`nofile`, `memlock`, ...) and the cgroup `pids.max` to be set per container.

#14551 addresses the low default `RLIMIT_NOFILE` and mentions an override as an alternative. This request adds configurable per-container limits, in particular `memlock` and `pids.max`, beyond correcting that default.

#### Problem

`resources.limits` covers `cpu`, `memory` and (on main) `swap`. Rlimits and `pids.max` cannot be set per container.

#### Use cases

- **Network servers, proxies and databases** (haproxy, nginx, postgres) that need a high `nofile`.
- **Software that locks or pins memory**: SPDK/DPDK with VFIO and applications using `mlock` need a `memlock` limit sized to their locked memory, or unlimited.
- **Containment**: capping `pids` for a less trusted container to stop a fork bomb.

#### Why we need it

Ceph OSDs and mons can need many file descriptors. cephadm sets `nofile=1048576` (Docker) and requests an unlimited pids limit for core Ceph daemons; its NVMe-oF gateway requests `memlock=-1:-1` and `nofile=10240`.

#### Proposal

```yaml
resources:
  limits:
    pids: 4096           # cgroup pids.max; unset = unlimited
  rlimits:
    nofile: {soft: 1048576, hard: 1048576}
    memlock: {soft: -1, hard: -1}   # -1 = unlimited
```

#### Acceptance criteria

- A container sees the configured rlimits in `/proc/self/limits` and its cgroup `pids.max`.

#### Related

#14551, discussion #13012 / PR #13027, #14282. Our use: [cephadm-talos](https://github.com/nberlee/cephadm-talos); cephadm [nvmeof.py](https://github.com/ceph/ceph/blob/tentacle/src/cephadm/cephadmlib/daemons/nvmeof.py).
