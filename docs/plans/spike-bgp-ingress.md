# Spike: RGW ingress through Talos BGP

Status: planned for later, not signed off. To run before the RGW ingress design (roadmap milestone 5), or earlier when the test cluster is free. It needs its own sign-off before it runs.

## Goal

Find out whether Talos's native BGP can carry the RGW virtual IP instead of keepalived: every host with a healthy RGW announces the same /32, the routers balance across them with ECMP, and BFD detects a dead host fast. The spike answers the questions below with measurements; it writes no orchestrator code.

## What Talos has (from the source of the pinned build)

- `BGPInstanceConfig` documents (Talos 1.15, embedded GoBGP): local ASN, router id, optional VRF, neighbors with hold time and BFD, ECMP (`multipath`, `maxPaths`), imports between named instances, peer state in `BGPPeerStatus`.
- An instance announces the addresses that are on the links listed in `advertise`, with their prefix lengths (`internal/app/machined/pkg/controllers/network/internal/bgp/runtime.go`, `advertisedAddresses`). There is no health condition: every address on the link is announced, except loopback and link-local ones.
- BFD works only for the instance in the default routing domain; GoBGP's BFD listener is not VRF-aware.
- Without an explicit `routerID`, Talos derives the router id from an advertised IPv4 address (`runtime.go`, `routerID`). If the only advertised address is the gated VIP, removing it leaves no router id, and the controller keeps the running instance without withdrawing (`bgp.go`). The spike therefore sets `routerID` to each node's own address.
- Neighbors have no authentication: the neighbor schema and `BuildPeer` (`internal/bgp/bgp.go`) configure neither TCP-MD5 nor TCP-AO.
- Talos's `AddressSpecController` manages the addresses of its `AddressSpec` resources and does not remove addresses it did not create (`address_spec.go`), so an address added by another process stays on the link until that process removes it or the link is recreated.
- `talosctl cluster create --with-bgp` runs a GoBGP peer on the QEMU bridge gateway, but without BFD and without installing routes into the host's routing table, so it cannot test failover. `--with-bgp-clos` has both (BFD at 300 ms, routes installed on the host) but gives the nodes only unnumbered fabric uplinks.

## Questions

1. Health gating: a container on the host network with `NET_ADMIN` adds the VIP /32 to a dummy link from the machine config while the local RGW answers, and removes it when it does not. The source says Talos leaves such an address alone; the spike checks what happens when the link is recreated (a reboot, a config change of the link) and how long announcement and withdrawal take after the address is added or removed.
2. Failure of the gate itself: the address outlives the gating process, so a killed or hung gate keeps the VIP announced while BGP and BFD stay healthy. How long does a stale announcement last, what removes it (an init or stop hook, a watchdog in the agent), and how does the gate bound its own HTTPS probe so a hung RGW counts as down?
3. Failover times, each compared with today's keepalived VIP: the RGW stopped, the RGW hung (`SIGSTOP`), the node powered off, the node cut off from the network, and a planned restart where the VIP has to go before the RGW drains (the stop order keepalived has today through `dependsOn`). With the default hold time, with a short hold time, and with BFD.
4. ECMP: with two or three hosts announcing, does the peer install a multipath route, and do clients spread over the hosts? What happens to open connections when a host withdraws?
5. The alternative to question 1: our own speaker in a container announcing the VIP to a second Talos instance over a veth in a VRF, Talos peering passively and the container dialing it (it does not listen), its routes imported into the fabric instance. Talos's MetalLB test does this. The speaker's routes go when its session goes, so a dead speaker withdraws the VIP; is that worth its complexity, given that BFD does not work on that leg?
6. What the agent's admission policy would need: templates for `BGPInstanceConfig`, the dummy link and the gating container, and which parameters come from the cluster (ASN, neighbors, VIP) versus the operator.

## Setup

- A BGP peer on the workstation that does BFD and installs the VIP's routes with ECMP into the workstation's routing table: FRR (`bgpd`, `bfdd`, `zebra`) in a container on the host network, peering with every node on the QEMU bridge. The current test cluster stays as it is. If that does not work out, the QEMU cluster is recreated with `--with-bgp-clos` from the combined Talos build (`~/repo/talos-combined/_out/talosctl-linux-amd64`), which destroys and rebuilds the test cluster.
- A cluster bootstrapped with the CLI, RGWs on two or three hosts.
- Hand-applied documents (`talosctl patch`): a dummy link, a `BGPInstanceConfig` with `routerID` set to the node's address, peering with the workstation's FRR with BFD, advertising the dummy link.
- A throwaway gating container: a shell loop that checks the local RGW over HTTPS with a short timeout and adds or removes the VIP on the dummy link.
- A client loop on the workstation against the VIP that records every failed request and the time between failures.

## Steps

1. Baseline: today's keepalived VIP, each failure case of question 3, failover times recorded.
2. BGP without BFD: the same failure cases with the default and a short hold time.
3. BGP with BFD (for example 100 ms intervals, multiplier 3): the same failure cases.
4. ECMP with three announcing hosts: distribution, and a withdrawal with connections open.
5. Address ownership: reboot a node, change the dummy link's config, and check the gated address and its announcement each time.
6. Gate failure: kill the gating process, hang it (`SIGSTOP`), and restart it; record how long the VIP stays announced and what clears it.
7. Optionally the speaker of question 5, if questions 1 or 2 show a problem.

## Roles and security

- Who does what in the spike: the operator applies the dummy link, the `BGPInstanceConfig` and the gating container with `talosctl` (`os:admin`), by hand. In the product the agent would apply them on its own node, under its admission policy (question 6). The gating container holds no Talos or Ceph credential: it reads the local RGW over HTTPS and changes addresses on the node.
- The gating container needs `NET_ADMIN` on the host network. Compromised, it controls the node's networking, not only the dummy link: it can add and remove addresses on any interface, change routes and change packet filtering, so it can take the node off the network or redirect its traffic. Through the dummy link it can also make Talos announce any address, drawing traffic for addresses it does not own; the routers' prefix filters (accept only the VIPs from these nodes) limit what other hosts accept, not what happens on the node. The spike records the filters an operator has to configure. Keepalived today has the same `NET_ADMIN` on the host network, so the BGP mode adds the announcement risk, not the host one.
- Talos's native BGP has no neighbor authentication (no TCP-MD5 or TCP-AO). Anyone who can reach a node's BGP port on the peering network can try to peer, and a peer can send it routes, which Talos installs unless `installRoutes` is off; the peering network has to be trusted or filtered. The spike records this, and a Talos feature request is a candidate.
- No credential is added; the RGW TLS certificate stays as it is.

## Result

A report with the measurements and a decision for the RGW ingress design: whether a BGP mode goes in, which gating (question 1 or 5), the defaults for hold time and BFD, and the admission templates it needs. Talos feature requests found on the way go to `upstream/talos/` as usual.

## Out of scope

Orchestrator code, `ceph orch` specs for a BGP mode, router configuration beyond the test peer, IPv6 VIPs, multisite.
