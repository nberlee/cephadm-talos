Target: comment on https://github.com/siderolabs/talos/issues/14733 (restart policy for containers)

---

Following up from #14220, some thoughts on what makes this useful for one-shot work in general.

**In short, we would like to see:**

1. `never` meaning "run once per document generation": a container that completed is not run again after a reboot, until its spec changes.
2. A terminal state (`completed` / `failed`), exit code and generation in `ContainerStatus`, kept until the document changes or is removed.
3. Configurable backoff (`delay`, `maxDelay`) instead of the fixed 5s.
4. `dependsOn` with `condition: succeeded`, for init-style containers that run on every boot before the main one.

Details below.

**Two kinds of "run once"**

1. **Per-boot init.** Runs on every boot before the main container, must succeed, and the main container depends on it: preparing a directory, fixing ownership, activating a device, loading kernel state. After a reboot it must run again.
2. **Durable one-shot job.** Runs once for a given document generation and must not run again after a reboot once it completed: a schema migration, formatting a disk, a destructive cleanup. Re-running after a reboot is at best wasted work, at worst destructive.

`restart: never` covers (2) only if a completed job stays completed across reboots for the same spec. Otherwise every user has to delete the document before the next reboot, and a crash between "completed" and "deleted" re-runs it.

**Status**

- A terminal state (`completed` / `failed`) with the exit code in `ContainerStatus`, kept until the document changes or is removed, so a client can wait for a job and collect its result.
- The generation the result belongs to, so a client can tell "my job finished" from "the previous job finished".

**Backoff**

Today [`RestartInterval`](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/controllers/containers/instance.go#L26-L27) is a fixed 5s delay after an instance terminates, so a crash-looping client keeps reconnecting to its servers without any backoff. A sketch:

```yaml
restart:
  policy: always | on-failure | never
  maxRetries: 5          # on-failure only
  delay: 5s
  maxDelay: 5m           # exponential backoff up to this
```

**Dependencies on "succeeded"**

```yaml
dependsOn:
  containers:
    - name: app-init
      condition: succeeded   # proposed: exit code 0 for the current generation
```

**What stays the workload's job**

Talos cannot make a destructive side effect exactly-once: a crash after the work was done but before "completed" was recorded is ambiguous whatever Talos does. The workload has to be idempotent or detect its own previous run. Talos only needs to report outcomes reliably and not re-run completed jobs on its own.

**Our case**: we run Ceph on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)). OSD activation is a per-boot init; preparing a new OSD (mkfs) and wiping a disk are durable jobs. Today a job prints its result between markers and then sleeps forever, the client reads the logs and deletes the document: two config applies per admin command, and a crashed client leaves a job that re-runs on the next reboot.
