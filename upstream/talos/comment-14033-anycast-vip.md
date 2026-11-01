Target: comment on https://github.com/siderolabs/talos/issues/14033 (L3-only HA: BGP/anycast equivalent of the Layer 2 VIP)

---

+1 on `AnycastVIPConfig`, with the precondition generic: announce while named containers are running and healthy, with container health from #14675. That covers services on Talos containers on nodes without etcd or Kubernetes, next to kube-apiserver.

```yaml
apiVersion: v1alpha1
kind: AnycastVIPConfig
name: 10.3.4.5/32
link: lo
announceWhen:
  containers: [s3-gateway]   # all running and healthy (#14675)
```

In short, we would like to see:

1. The VIP originated by this document rather than by `advertise`, so the address can stay on the link while the route is withdrawn and packets still arriving are served locally.
2. On a planned stop or restart of a named container (including `talosctl restart`), withdrawal before the stop signal, like the reverse `dependsOn` stop order of #14732; the container's own health does not change in time for this.
3. The local announced or withdrawn state in a resource, so an orchestrator can wait for the withdrawal before it restarts the next node.

Use cases:

- kube-apiserver on control planes (this issue).
- An HTTP or S3 gateway, DNS or a proxy on several nodes behind one address, active/active through ECMP, with BFD for node loss.

**Our case**: we run Ceph's S3 gateway on Talos containers ([cephadm-talos](https://github.com/nberlee/cephadm-talos)) behind one address, today keepalived in a container with `NET_ADMIN`. An anycast VIP gated on the gateway's health replaces it without a privileged container and makes the gateways active/active. We can implement this, after or together with #14675.
