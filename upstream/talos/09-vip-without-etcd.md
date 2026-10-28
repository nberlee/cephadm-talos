Title: Layer-2 VIP on nodes without etcd

## Feature Request

### Description

Allow `Layer2VIPConfig` to elect its holder without etcd, so etcd-less nodes can share a floating IP.

#### Problem

`Layer2VIPConfig` elects the holder through etcd: the operator waits for the `etcd` service and runs an etcd election on `<EtcdRootTalosKey>:vip:election:<ip>` ([vip.go](https://github.com/siderolabs/talos/blob/edbfe07754a3dc6008cc8caa7b78782e99a81be2/internal/app/machined/pkg/controllers/network/operator/vip.go)). On nodes without etcd (Talos without Kubernetes, worker-only nodes) the VIP never comes up (observed on v1.15.0-alpha.1). The docs also limit it to control plane nodes.

With Talos Containers, etcd-less nodes are a real deployment shape that still needs floating IPs.

#### Use cases

- **An HA service on several etcd-less nodes behind one address**: a reverse proxy, DNS or an API gateway. (A database writer VIP would also need to follow primary election and fencing, which container health alone does not give.)
- **Floating IPs on worker nodes** for services, without running keepalived as a privileged container.
- **A VIP that follows service health** rather than node health (combined with #14675).

#### Why we need it

We serve Ceph's S3 gateway (rgw) from containers on several nodes behind one address that moves during maintenance or failure. Today that is keepalived in a container with `NET_ADMIN`, `NET_RAW` and `NET_BROADCAST` and the VRRP password in its environment. It works (tested: failover during maintenance; separately, a certificate rotation with rolling rgw restarts cost 1 failed request out of 325), but it is one more privileged container per node.

#### Proposal

```yaml
apiVersion: v1alpha1
kind: Layer2VIPConfig
name: 10.5.0.200
link: enp0s2
election:
  backend: vrrp          # etcd (default) | vrrp | discovery
  priority: 100
  peers: [10.5.0.3, 10.5.0.4]   # vrrp unicast
  healthCheck:                   # optional: only hold the VIP while this container is healthy
    container: proxy
```

Either built-in VRRP or an election through the discovery service.

#### Acceptance criteria

- A VIP on two or more etcd-less nodes fails over within a few seconds on node loss, with gratuitous ARP.

#### Related

#14033, #14222, #10959, #14675. Our use: [cephadm-talos](https://github.com/nberlee/cephadm-talos) `deploy vip`.
