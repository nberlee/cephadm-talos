Target: comment on https://github.com/siderolabs/talos/issues/14732 (configurable stop timeout and shutdown order)

---

Following up from #14220, two additions.

**In short, we would like to see:**

1. Per-container stop timeout and stop signal settings, used for node shutdown, config-change restarts, explicit container restarts and document removal.
2. Reverse `dependsOn` order among containers stopped by the same operation, including updates and removals; documented as node-local.

**Details**

1. **Apply the configured stop timeout and signal to every managed stop**: node shutdown, config-change restarts, `talosctl restart --namespace taloscontainers`, and document removal. When an operation stops multiple containers, apply reverse `dependsOn` order among those containers. Containers managed by a controller are restarted for updates far more often than nodes reboot.
2. **Stop signal**: nginx uses SIGQUIT for graceful shutdown; PostgreSQL uses SIGTERM for smart and SIGINT for fast shutdown (SIGQUIT is an immediate stop that needs recovery on restart).

**Use cases**: databases flushing state and brokers draining work may need more time between the stop signal and SIGKILL.

Please document that dependency ordering is node-local; cross-node coordination remains with the user or an orchestrator.

**Our case**: we run Ceph on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)). The current 10s ([`gracefulShutdownTimeout`](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/controllers/containers/containerd_runner.go#L44)) was enough for ceph-mon and ceph-osd in our tests. Interrupting `ceph-volume raw prepare` (mkfs of a new OSD) can leave partially provisioned state that needs reconciliation. A longer timeout helps only if the process handles the stop signal and uses the grace period to finish or clean up; it does not make prepare atomic.
