Target: comment on https://github.com/siderolabs/talos/issues/14551 (ContainerConfig keeps containerd's default RLIMIT_NOFILE 1024)

---

+1. A 1024 `nofile` default is low for most network servers and databases. Raising the default would help; per-container limits, including `memlock` and `pids.max`, are proposed separately in #NNNN.

Our case: Ceph OSDs and mons on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)) can exceed 1024 open file descriptors under load.
