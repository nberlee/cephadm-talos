# Spike: RGW ingress through Talos BGP

Status: planned for later, not signed off. To run before the RGW ingress design (roadmap milestone 5), or earlier when the test cluster is free. It needs its own sign-off before it runs.

## Goal

Find out whether Talos's native BGP can carry the RGW virtual IP instead of keepalived: every host with a healthy RGW announces the same /32, the routers balance across them with ECMP, and BFD detects a dead host fast. The spike answers the questions below with measurements; it writes no orchestrator code.

## What Talos has (from the source of the pinned build)

- `BGPInstanceConfig` documents (Talos 1.15, embedded GoBGP): local ASN, router id, optional VRF, neighbors with hold time and BFD, ECMP (`multipath`, `maxPaths`), imports between named instances, peer state in `BGPPeerStatus`.
- An instance announces the addresses that are on the links listed in `advertise`, with their prefix lengths (`internal/app/machined/pkg/controllers/network/internal/bgp/runtime.go`, `advertisedAddresses`). There is no health condition: every address on the link is announced, except loopback and link-local ones.
- BFD works only for the instance in the default routing domain; GoBGP's BFD listener is not VRF-aware.
- Without an explicit `routerID`, Talos derives the router id from an advertised IPv4 address (`runtime.go`, `routerID`). If the only advertised address is the gated VIP, removing it leaves no router id, and the controller keeps the running instance without withdrawing (`bgp.go`). The spike therefore sets `routerID` to each node's own address.
- Neighbor authentication with TCP-MD5 (RFC 2385): `authPassword` on a neighbor, in Talos main since 2026-10-30 (commit a1920121c, fixes #14568), not yet in our combined build. The password is redacted from the machine config for readers without `os:admin`. TCP-AO is not supported. The spike runs on a combined build that contains this commit.
- Talos's `AddressSpecController` manages the addresses of its `AddressSpec` resources and does not remove addresses it did not create (`address_spec.go`), so an address added by another process stays on the link until that process removes it or the link is recreated.
- `talosctl cluster create --with-bgp` runs a GoBGP peer on the QEMU bridge gateway, but without BFD and without installing routes into the host's routing table, so it cannot test failover. `--with-bgp-clos` has both (BFD at 300 ms, routes installed on the host) but gives the nodes only unnumbered fabric uplinks.

## Questions

1. Health gating. Talos does the BGP and announces what is on the advertised links; it does not know whether the RGW behind the VIP answers. Something has to take the VIP away when the local RGW is down, and none of these needs a new privileged container:
   - (a) The agent: it probes the local RGW over HTTPS with a short timeout and adds or removes the VIP in the dummy link's config, a document it owns. No new container or privilege, but a config apply for every change of health, with hysteresis against flapping, and a change the agent makes on its own, without a grant from the leader (a new kind of change for the admission and fencing design). How long from a failed probe to the withdrawal?
   - (b) Our own speaker in a container on the host network (question 5): it announces the VIP while the RGW answers and stops when it does not. It needs no `NET_ADMIN` for a plain TCP session; setting the TCP-MD5 key on its own socket needs no capability either.
   - (c) Talos itself: an announcement conditioned on a health check (a probe, or the status of a container). Not in Talos; a feature request candidate, the most native answer if the others are clumsy.
   - (d) For comparison only: a keepalived-like container with `NET_ADMIN` that adds and removes the address directly. The source says Talos leaves an address it did not create alone (see above).
   - For each option that is tried: what happens when the dummy link is recreated (a reboot, a config change of the link)?
2. Failure of the gate itself: with (a) and (d) the VIP outlives the gating process, so a killed or hung agent or gate keeps it announced while BGP and BFD stay healthy. How long does a stale announcement last and what removes it? With (b) the session ends with the speaker, so the announcement goes with it. How does each bound its HTTPS probe so a hung RGW counts as down?
3. Failover times, each compared with today's keepalived VIP: the RGW stopped, the RGW hung (`SIGSTOP`), the node powered off, the node cut off from the network, and a planned restart where the VIP has to go before the RGW drains (the stop order keepalived has today through `dependsOn`). With the default hold time, with a short hold time, and with BFD.
4. ECMP: with two or three hosts announcing, does the peer install a multipath route, and do clients spread over the hosts? What happens to open connections when a host withdraws?
5. Option (b) of question 1 in detail: our own speaker in a container announcing the VIP to a second Talos instance over a veth in a VRF, Talos peering passively and the container dialing it (it does not listen), its routes imported into the fabric instance. Talos's MetalLB test does this. The speaker's routes go when its session goes, so a dead speaker withdraws the VIP; is that worth its complexity, given that BFD does not work on that leg?
6. What the agent's admission policy would need: templates for `BGPInstanceConfig` and the dummy link (and a speaker container, if (b) is chosen), which parameters come from the cluster (ASN, neighbors, VIP) versus the operator, and where the MD5 password lives (a secret, like the VRRP password today).

## Setup

- A BGP peer on the workstation that does BFD and installs the VIP's routes with ECMP into the workstation's routing table: FRR (`bgpd`, `bfdd`, `zebra`) in a container on the host network, peering with every node on the QEMU bridge. The current test cluster stays as it is. If that does not work out, the QEMU cluster is recreated with `--with-bgp-clos` from the combined Talos build (`~/repo/talos-combined/_out/talosctl-linux-amd64`), which destroys and rebuilds the test cluster.
- A cluster bootstrapped with the CLI, RGWs on two or three hosts.
- A combined Talos build that contains commit a1920121c (`authPassword`), for the MD5 tests.
- Hand-applied documents (`talosctl patch`): a dummy link, a `BGPInstanceConfig` with `routerID` set to the node's address, peering with the workstation's FRR with BFD and an MD5 password, advertising the dummy link.
- Gating for option (a) without agent code: a script on the workstation that probes each RGW and patches the dummy link's address in or out with `talosctl`, which gives the apply-to-withdrawal time. Option (d) as a throwaway container, for comparison.
- A client loop on the workstation against the VIP that records every failed request and the time between failures.

## Steps

1. Baseline: today's keepalived VIP, each failure case of question 3, failover times recorded.
2. BGP without BFD: the same failure cases with the default and a short hold time.
3. BGP with BFD (for example 100 ms intervals, multiplier 3): the same failure cases.
4. ECMP with three announcing hosts: distribution, and a withdrawal with connections open.
5. Address ownership: reboot a node, change the dummy link's config, and check the gated address and its announcement each time.
6. Gate failure: stop the gating script of (a) and the container of (d), hang them (`SIGSTOP`), restart them; record how long the VIP stays announced and what clears it.
7. Optionally the speaker of question 5, if (a) is too slow or its stale announcements are too long.

## Roles and security

- Who does what in the spike: the operator applies the dummy link and the `BGPInstanceConfig` with `talosctl` (`os:admin`), by hand, and the gating script for (a) patches with the same talosconfig. In the product the agent would apply them on its own node, under its admission policy (question 6), with the `os:admin` it already has on its node; option (a) adds no credential or privilege.
- The BGP session belongs to Talos: no container needs `NET_ADMIN` for it. Only option (d) does, and it is in the spike for comparison: compromised, a container with `NET_ADMIN` on the host network controls the node's networking (addresses, routes, packet filtering), as keepalived does today. Moving the VIP to BGP with (a), (b) or (c) removes that privilege from the RGW hosts.
- What a compromised node can do with BGP: make Talos announce any address it puts on an advertised link, drawing traffic for addresses it does not own. The routers' prefix filters (accept only the VIPs from these nodes) are the boundary; the spike records the filters an operator has to configure.
- Neighbor authentication is TCP-MD5 with `authPassword`. MD5 is the common BGP practice but weak, and TCP-AO is not supported; without a password anyone who reaches a node's BGP port can try to peer, and a peer's routes are installed unless `installRoutes` is off. In the product the password is a secret: kept with the other secrets, rendered into the node's `BGPInstanceConfig` (redacted for readers without `os:admin`), released to the leader only for a host that announces.

## Result

A report with the measurements and a decision for the RGW ingress design: whether a BGP mode goes in, which gating (question 1 or 5), the defaults for hold time and BFD, and the admission templates it needs. Talos feature requests found on the way go to `upstream/talos/` as usual.

## Out of scope

Orchestrator code, `ceph orch` specs for a BGP mode, router configuration beyond the test peer, IPv6 VIPs, multisite.
