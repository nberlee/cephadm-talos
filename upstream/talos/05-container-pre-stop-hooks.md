Title: Talos Containers: pre-shutdown hooks on reboot, shutdown and upgrade

## Feature Request

### Description

PR #14186 added bounded pre-shutdown hooks for host extension services. This asks for the same for `ContainerConfig` containers: a bounded, best-effort command run inside the container before a graceful reboot, shutdown or upgrade.

This is not a request for Talos to wait for, or veto, a reboot or upgrade (see #9882). Coordination stays with a higher-level tool.

#### Problem

On reboot, shutdown and upgrade, all containers are asked to stop at once ([`stopAll`](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/controllers/containers/runtime.go#L531)) and get SIGKILL 10s after SIGTERM ([`gracefulShutdownTimeout`](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/controllers/containers/containerd_runner.go#L44)). #14732 tracks making that timeout configurable and stopping in reverse `dependsOn` order. There is no separate pre-shutdown hook for notifying peers before container termination begins; today this must be implemented in the workload's signal handler or coordinated externally.

#### Use cases

- **Clustered services** that should hand over leadership, drain connections or deregister before the node goes away: databases, message brokers, service discovery agents.
- **Planned vs unplanned downtime**: telling a cluster "this node will be back shortly, don't start recovering" avoids unnecessary data movement or failover.
- **Reboots by tools that do not know the workload**: a fleet-wide Talos upgrade, or someone running `talosctl reboot` directly.

#### Why we need it

Before a Ceph storage node reboots, `ceph osd set-group noout <host>` keeps Ceph from marking its OSDs out after 10 minutes and moving data. Our orchestrator does this when it runs the maintenance itself; the hook would cover reboots it did not start. It would run with a Ceph identity explicitly allowed to set flags, and the orchestrator clears the flag after recovery, including after a failed hook or an interrupted reboot.

#### Proposal

```yaml
apiVersion: v1alpha1
kind: ContainerConfig
name: app
lifecycle:
  preShutdown:
    exec: ["/usr/local/bin/leave-cluster"]
    timeout: 30s
    on: [reboot, shutdown, upgrade]   # default: all graceful paths
```

- Runs inside the container (same namespaces, mounts, credentials) while it and its network are still up, before containers are stopped.
- Bounded by `timeout`; a failure or timeout is logged and shutdown continues.
- Skipped on forced reboot, as for extension hooks.
- Hooks run in parallel, or in reverse `dependsOn` order if #14732 adds that.

#### Acceptance criteria

- A graceful reboot/upgrade runs the hook with the container's network still up.
- Hook failure never blocks the reboot.

#### Related

PR #14186, #9882, #4973, discussion #12518, #14732. "Coordinated maintenance" in "Ceph on Talos without Kubernetes" by @hkraal (Exonet). Our use: [cephadm-talos](https://github.com/nberlee/cephadm-talos).
