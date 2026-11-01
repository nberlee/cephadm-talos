Target: comment on https://github.com/siderolabs/talos/issues/14675 (support for health checks)

---

Some additions to TCP/HTTP/gRPC:

- **exec checks.** Many daemons have no health port but do have a local CLI or unix socket that answers when they are alive. That needs a command run inside the container, with an exit code.
- **Readiness in `ContainerStatus`**, separate from "running", so a rolling update can wait until one container is ready before restarting the next.
- **Watchable**, so a client can wait on it with a COSI watch instead of polling.
- **Usable as a condition by other config**: an anycast VIP announced only while a container is healthy (#14033).

```yaml
healthCheck:
  exec: ["/usr/local/bin/healthcheck"]
  interval: 10s
  timeout: 5s
  failureThreshold: 3
```

**Our case**: we run Ceph on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)). `ceph daemon <name> version` tests that a daemon's local admin socket answers; it does not prove cluster readiness, which our orchestrator still checks before moving on. Today we check rgw readiness from outside by fetching its TLS certificate and comparing fingerprints. With an HTTPS check on the gateway, an anycast VIP (#14033) can follow its health. We can implement this.
