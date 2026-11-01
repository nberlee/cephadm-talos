# How cephadm-talos works: components, channels and security

This document describes what is built today (branch `plan-03-write-path`, plan 03 up to step 6a) so that its security can be judged. Where something is planned but not built, it says so. The plan is [plans/03-write-path.md](plans/03-write-path.md); fixes for the gaps listed at the end are on the [roadmap](../ROADMAP.md) (milestone 4).

## Components

| Component | Runs where | Holds | Can do |
|---|---|---|---|
| CLI (`cephadm-talos`) | the operator's workstation | a talosconfig per node (`os:admin`), the `client.admin` key, the operator certificate and key, the fsid | everything on every node through the Talos API, and anything in Ceph through `shell`. Before the handoff it writes the cluster state; after it, its own orchestration commands refuse to change anything, but `shell` (arbitrary commands with `client.admin`) and `rm-cluster` still work: the handoff changes who writes the state, not the operator's authority |
| Agent | one container per Ceph node: `restricted`, uid/gid 50, host network, `machinedAccess` (the local Talos socket), no Ceph binaries, no Ceph key, no talosconfig | its server and client certificate and key, the agent CA certificate, its records on the `cephadm-talos` volume | everything on its own node through the local socket. It reaches no other node's Talos API |
| Leader | code in the agent on the active mgr's host, only while that mgr's module heartbeats it | the cluster state it reads, which today includes private keys (see "Known gaps") | send revisions (grants) to every agent; read and write config-key below `mgr/cephadm/talos/` and read daemon keys through the bridge |
| mgr module (installed as `cephadm`) | Python in the active `ceph-mgr` | the mgr's CephX key, the mgr's TLS certificates and keys | Ceph commands with the mgr's caps; confirms that it is the active mgr; serves the bridge; polls every agent's status |
| Talos (machined) | every node | the node's machine config, including every keyring and TLS key of its containers | runs the containers the machine config describes |
| Daemons and jobs | containers on each node | see "Where daemon keys live" | talk to the mons |

## Trust domains and transports

| Connection | Transport | Authenticated by |
|---|---|---|
| CLI to Talos API, port 50000 | gRPC over TLS | the Talos CA and the talosconfig (`os:admin`) |
| Agent to its own Talos | gRPC over a Unix socket (no TLS) | machined identifies the calling process; `machinedAccess` containers may request any role, and the agent requests `os:admin`, so its role request does not limit a compromised agent |
| Agents, module, CLI among each other: ports 4721 (agent) and 4722 (module) | HTTPS, TLS 1.3, both on the host network on all interfaces | client and server certificates of the agent CA, checked by role, fsid and name in the URI SAN (never the common name) |
| Module, daemons and the CLI's exec'd commands to the mons | Ceph messenger | CephX. The generated `ceph.conf` does not require the encrypted messenger mode |
| S3 clients to RGW (through the VIP or directly) | HTTPS | a certificate of the separate RGW CA the CLI generated (2 years), or the user's own |
| keepalived between VIP hosts | unicast VRRP | a shared password (`PASS` authentication, 8 characters); its health check of the local RGW uses HTTPS without verifying the certificate (`curl -k`) |

## Identities

There is one agent CA per cluster (10 years). It issues certificates (3 years) with a URI SAN `cephadm-talos://<fsid>/<role>/<name>`. Before the handoff, every CLI command renews certificates that expire within 30 days; after the handoff nothing renews them yet (plan 04). Nothing revokes a certificate: removing a host or issuing a new certificate leaves the old one valid until it expires.

| Certificate | Role / name | Use | Issued by | Private key lives in |
|---|---|---|---|---|
| agent server | `agent/<host>` | the agent's HTTPS server (4721) | CLI | the agent's document (environment), so the node's machine config; and the published cluster state |
| agent client | `agent/<host>` | the agent as client: confirmations, the bridge, the leader's calls | CLI | same |
| mgr server | `mgr/<host>` | the module's HTTPS server (4722); its key signs confirmations | CLI | an `EtcFileConfig` on the mgr host (`/etc/ceph/talos/mgr-server.key`, mode 0600); the published cluster state |
| mgr client | `mgr/<host>` | the module as client: status polls and heartbeats | CLI | `/etc/ceph/talos/mgr-client.key` on the mgr host; the published cluster state |
| operator | `operator/admin` | the CLI: the handoff | CLI | the workstation only |
| agent CA key | | issuing all of the above | CLI | the published cluster state |

The module reads its client certificate and the CA for every status poll and heartbeat, but its server certificate, the CA it trusts as a server and its confirmation signing key only when it starts: a new server certificate takes effect at the next mgr restart.

## Where daemon keys live

| Kind | Key | Where |
|---|---|---|
| mon (joining) | `mon.` with `mon allow *` | its document's environment; the mon store on the ceph volume |
| bootstrap mon | `mon.`, `client.admin`, `client.bootstrap-osd`, the first mgr's key | its document's environment, until the document is replaced by the joining template (a redeploy does it; the handoff does not yet, see "Known gaps") |
| mgr | `mgr.<id>` (caps: `mon profile mgr`, `osd allow *`, `mds allow *`) | its document's environment, and a keyring file on the ceph volume |
| OSD | `osd.<n>` | not in its document: activation reads it from the OSD's own disk |
| RGW | `client.rgw.<id>` (`mon allow rw`, `osd allow rwx`, `mgr allow rw`) | its document's environment, and a keyring file on the ceph volume |
| OSD preparation job | `client.bootstrap-osd` | its document's environment while the job exists |
| zap, image probe | none | |

Mon, mgr, OSD and RGW containers share the ceph volume (`/var/lib/ceph`), writable, and mount `/etc/ceph` read-only, so a root compromise of one daemon container can read its siblings' key files there and change their data. OSDs, OSD preparation and zap jobs are privileged with the host's `/dev`; the image probe is restricted.

Who can read machine config secrets: `MachineConfig` is a sensitive Talos resource; reading it raw needs `os:admin` (in this Talos build, `os:reader` gets no raw machine config and only redacted forms of some resource types). Anyone with `os:admin` on a node, the CLI and every agent on its own node among them, reads every key in that node's documents.

## Channels

```mermaid
flowchart LR
  CLI["CLI (workstation)"]
  subgraph nodeA["mgr host"]
    MGR["mgr module :4722"]
    LA["agent + leader :4721"]
    TA["Talos (machined)"]
  end
  subgraph nodeB["other host"]
    AB["agent :4721"]
    TB["Talos (machined)"]
  end
  MONS["mons"]
  CLI -- "Talos API :50000, os:admin; exec" --> TA
  CLI -- "Talos API :50000, os:admin; exec" --> TB
  CLI -- "handoff (operator cert)" --> LA
  CLI -- "handoff (operator cert)" --> AB
  MGR -- "status polls (mgr cert)" --> AB
  MGR -- "status, heartbeat (mgr cert)" --> LA
  LA -- "bridge (cert of this host's agent)" --> MGR
  AB -- "confirm (agent cert)" --> MGR
  LA -- "node report, grant, abandon, close (agent cert)" --> AB
  LA -- "local socket, os:admin" --> TA
  AB -- "local socket, os:admin" --> TB
  MGR -- "CephX (mgr key)" --> MONS
  TA -. "exec'd ceph, client.admin" .-> MONS
```

### CLI to Talos, and through exec to the mons

The CLI applies machine config documents, reads resources (container status, disks, the machine config), files and logs, and runs commands in containers with `ContainerExec`. Every Ceph command of the CLI, also the ones that only read the cluster state when a command starts, runs in a Ceph container of a node: a mgr container, else a mon, an RGW or an OSD container. The CLI sends the `client.admin` key on stdin; the command's wrapper puts it into that command's `CEPH_ARGS` environment and runs `ceph` or a small Python/librados script, which connects to the mons as `client.admin`. So the key is never in an argument list, but it is in the environment of that process while it runs, readable to root in that container and on that node. Arguments the operator passes to `shell` are logged as given. Talos logs every exec with its arguments and the requested roles, and its exit code or error.

After the handoff the CLI's own changes are refused, and it pushes nothing to the nodes. `shell` still runs anything with `client.admin`. `rm-cluster` removes the cluster's containers and Ceph files from the nodes and the workstation's state; with `--zap` it also zaps the known OSD disks and deletes the cluster data directories. It leaves the agents' records volume and the volume declarations, and erases no credential copies elsewhere (config-key, config history).

### Agent to its own Talos (local socket)

The agent:

- reads container status, instances, images, disks and the machine config, every 30 seconds;
- applies its own node's cluster documents, only for a confirmed grant that passes its admission policy (below), and removes them on a confirmed grant;
- runs one read-only command through exec: `ceph --admin-daemon /var/run/ceph/ceph-<entity>.asok version`, for documents that pass its admission policy, up to three attempts per daemon instance until one answers.

### mgr module to agents (port 4721, mgr client certificate)

| Call | Who may call | What |
|---|---|---|
| `GET /status` | any mgr of the cluster | the agent's status record: the node's containers with states, exit codes and versions, its records' health, its ownership and drift |
| `POST /v1/heartbeat` | the mgr on the agent's own host only | every 5 seconds: the module's captured incarnation (gid and epoch). The agent is the leader while the last heartbeat names its own host and is at most 15 seconds old. The module sends heartbeats with the incarnation it captured once; it does not check every 5 seconds that it is still active |

### Agents to the module (port 4722, agent client certificate)

| Call | Who may call | What |
|---|---|---|
| `POST /v1/confirm` | any agent of the cluster, for its own host | the module answers only after a fresh `mgr dump` from the mons shows it is the active mgr, and signs the answer (ECDSA P-256 over the exact payload) with its mgr server key: fsid, mgr, gid, epoch, the agent's session, host, revision, operation id, inputs hash and the agent's challenge. It counts 10 seconds from the challenge. The module does not know whether the operation exists; it confirms leadership, not content |
| `POST /v1/bridge`, `GET /v1/bridge/<id>` | a client certificate `agent/<the mgr's host>`, from anywhere on the network (the leader itself dials loopback). The bridge checks that the module captured an incarnation once, not that it is still active | allowlisted mon commands with fixed argument shapes and a dispatch id: `status`, `health`, `mgr dump`; config-key list, get, set and rm anywhere below `mgr/cephadm/talos/` (all incarnations and `cli`, not only the module's own); the config-key entry limit; `auth get` for `mon.`, any `mgr.<id>`, `osd.<n>`, `client.rgw.<id>` and `client.bootstrap-osd` (never `client.admin`); `auth get-or-create` for `mgr.<id>` and `client.rgw.<id>` with caps fixed in the module. A deadline bounds the wait for the answer, not the command: a call that times out answers "unknown" and may still complete; outcomes are kept in memory for a while by dispatch id and are lost when the mgr restarts |

The bridge refuses `client.admin`, but the keys it does release are broad: `mon.` (`mon allow *`) and mgr keys (`mon profile mgr`, which may change mon auth). Whoever gets them can use them against the mons directly, outside the bridge's allowlist.

### Leader to agents (port 4721, agent client certificate)

| Call | What the agent checks | What |
|---|---|---|
| `GET /v1/node` | any agent certificate of the cluster | what the agent owns (hashes), its drift, the cluster's containers on its node and its disks |
| `GET /v1/operations/<id>` | any agent certificate of the cluster | the agent's record of a grant |
| `POST /v1/grant` | the sender's certificate name equals the grant's mgr; the grant's incarnation is not below the agent's session floor; a confirmation from that mgr, at the address the grant names, carries the same gid and epoch and is still valid when the configuration is sent; the admission policy; drift | apply a revision of documents (below) |
| `POST /v1/abandon` | the same, confirmed | give up a grant the agent has no record of: the agent raises a revision fence so that grant can never be applied |
| `POST /v1/close` | the same, confirmed | a new incarnation raises the agent's session floor: grants, abandons and closes of earlier incarnations are refused before anything is recorded |

The agent serves one grant, abandon or close at a time. A repeated grant with the same operation id and inputs (after the session floor check and reconciliation) returns the agent's record without a new confirmation, except a reserved or refused one, which tries again with a fresh confirmation and may then apply; other inputs under the same id are refused, and an abandoned operation never runs. A close at the current floor is accepted without a confirmation.

### CLI to agents (port 4721, operator certificate)

`POST /v1/handoff`: the agent takes ownership of its node's cluster documents as they are. Only the operator certificate may call it.

## The cluster state and incarnations

The cluster state (hosts, daemons, image, RGW settings, the agent and mgr certificates with their private keys, the agent CA with its key, the RGW CA, serving key and VRRP password, the module's inventory) is kept in config-key below `mgr/cephadm/talos/inc/<incarnation>/` as records plus a manifest. An incarnation is one leadership: a mgr process while it is active, identified by its gid and ordered by the mgrmap epoch at which the mons first confirmed it active (a standby promoted later can have a smaller gid). The CLI writes under `cli` until the handoff.

One writer at a time, by convention of the code (the bridge does not enforce it, and the operator's `shell` can write anything):

1. Before the handoff only the CLI writes, under `cli`.
2. `cephadm-talos handoff` records that it started (from then on the CLI changes nothing but the handoff), hands every node to its agent, and publishes its state one last time, sealed.
3. A leader takes its baseline from the sealed `cli` state, or from the newest earlier incarnation that published, copies it under its own incarnation, and writes only there.
4. Readers (the module's inventory, the CLI) read the active mgr's incarnation once it published, else the published one with the highest epoch, else `cli`.

The leader keeps its journal under `inc/<gid>/journal/`: requests (`req/<id>`) and its operations (`op/<id>`). The leader trusts a request because it is in the store; requests are not signed, so whoever can write that config-key can submit one. Rendered documents never go into the journal, only their hashes.

## What happens when

### A change to a node (today: a host revision)

Today this path runs when a host revision request is in the leader's journal (written with `ceph config-key set`, for tests); the `ceph orch` commands that will write requests come in step 6b.

```mermaid
sequenceDiagram
  participant M as module (active mgr)
  participant L as leader (agent on mgr host)
  participant A as agent of host X
  participant T as Talos on host X
  L->>M: bridge: read the state, auth get (keys)
  L->>A: GET /v1/node (owned hashes, disks)
  L->>L: render X, diff, pre-check policy, journal op = granting
  L->>A: POST /v1/grant (revision, documents)
  A->>A: record operation: reserved
  A->>M: POST /v1/confirm (challenge, inputs hash)
  M->>M: fresh mgr dump: am I active?
  M-->>A: signed confirmation (gid, epoch)
  A->>A: gid and epoch match, policy, drift check
  A->>A: write apply intent
  A->>T: ApplyConfiguration of the whole config (local socket), if still within the confirmation's 10 seconds
  A->>T: read the config back, must match exactly
  A->>A: ownership, operation: completed
  A-->>L: operation record
  L->>M: bridge: journal op = completed
```

"Completed" means Talos holds exactly the granted documents, not that the daemons run. Without a confirmation the agent changes nothing on its node. If the outcome of an apply is lost, the agent decides it later from the node's config: holding exactly what the apply would leave means completed; holding exactly what it held before, on another boot or 10 minutes after the apply was sent, means it did not happen; anything else stays uncertain, and the agent applies nothing more until it is resolved. This local reconciliation needs no confirmation: it only records what the node shows.

Talos has no conditional apply: the agent checks for drift, then sends the whole machine config. A writer outside cephadm-talos changing the config in between can be overwritten, also documents outside the cluster's.

### mgr failover (a new incarnation)

The new active mgr's module heartbeats its local agent, which becomes the leader. On its first ticks it closes the earlier incarnations' sessions on every agent (a confirmed close raises each agent's session floor), imports their unfinished operations (asking the agents for their outcome, or abandoning them with a fence), and publishes its baseline. A host whose session it could not close yet gets no grant.

### Quorum loss

Without the mons no new confirmation can be signed, so no new change starts. A confirmation signed just before still counts for its 10 seconds, and an apply already sent finishes. Bridge calls fail and are retried.

## Admission policy (agent)

Before applying, the agent checks every granted document and refuses anything else. It identifies the kind by the id that renders the document's name, checks each parameter's form (ids, fsid, IPs without zones, ports, keyrings holding exactly the kind's entity and a well-formed CephX key, images by digest from the repositories in the agent's own document, by-id devices of the node's disks with their serial, dependencies within the cluster on the node, mgr certificates of the agent CA for this host's mgr with the right use, an RGW certificate with its key), renders the template compiled into the agent and requires Talos's encoding of both to be identical.

What this fixes: the command, mounts, security profile, capabilities and environment of every document kind; no other image repository, no `client.admin` in a granted mon, no arbitrary file. What it does not:

- It checks the form of keys, not that a CephX key is the entity's real key in mon auth; a mgr private key only has to parse, not match its certificate; an RGW certificate is not checked for issuer or expiry; mon addresses and parameter values are not checked against the cluster state.
- Any digest of an allowed repository is admitted, not only the one the cluster runs, and the image's contents are trusted: the OSD and job templates are privileged with all of `/dev`, keepalived has network capabilities.
- A zap job needs only a disk of this node with a matching by-id link and serial; neither admission nor the zap script checks that it is an OSD of this cluster.
- Removals are not checked against templates: a confirmed grant can remove any of the node's cluster documents, including ceph.conf, mgr files and the ceph volume declaration, but not the agent, its records-init or their volume.

## Records on the node

The agent's records (ownership, operations, session floor, fence) are files of mode 0600 in a directory of uid/gid 50, mode 0700, on the `cephadm-talos` volume. They serve crash recovery and replay protection, not integrity against a compromised node: root on the node can change them, the privileged OSD preparation and zap jobs mount that volume, and OSDs, though they do not mount it, are privileged with the host's devices. Finished operation records are pruned; the bridge does not log requests.

## Security implications

- **A compromised agent is root on its node.** It can apply any config on its node, start privileged containers, read every keyring and TLS key in the node's documents, wipe disks and reboot. On its own it has no credential for other nodes' Talos APIs. For a change, other agents require a confirmation signed by the mgr identity of the sender's host with matching gid and epoch, plus admission and fencing; they cannot establish themselves that this mgr is active (see the next points). It can read other agents' node reports and operation records without a confirmation.
- **On a Talos control-plane node, a compromised agent reaches every node of that Talos cluster.** `os:admin` on the local socket allows `GenerateClientConfiguration`, which signs a talosconfig with the node's Talos CA. Use worker nodes, or nodes whose Talos CA is not shared, where that boundary matters.
- **A compromised mgr host, active or standby, can confirm.** A confirmation proves that the module holding `mgr/<host>`'s key says it is active; the agent cannot check the mgr map itself. Root on a host with a mgr has both that host's mgr and agent certificates, so it can run a confirming endpoint, become a leader for the agents and raise their session floor with an invented epoch. It also has that mgr's CephX key.
- **The leader and the active mgr hold the cluster.** The leader can grant every agent anything the admission policy admits (including removals and zaps), and through the bridge read config-key below `mgr/cephadm/talos/`, which today holds every TLS private key and the agent CA key, and daemon keys including `mon.` and the mgr keys. A compromised leader therefore has the mgr's Ceph access and can impersonate any agent or mgr. This is comparable to cephadm's mgr, which holds SSH root to every host.
- **Confirmations, fences and session floors protect correctness**: they stop a stale leader, not a malicious one with valid certificates.
- **The CLI's workstation holds full control**: `os:admin` on every node and `client.admin`, before and after the handoff, like a cephadm admin host.
- **`os:admin` on a node reads that node's secrets** in the machine config: daemon keyrings, the agent's TLS keys and, on a mgr host, the mgr's TLS keys.

## Known gaps

Each is on the [roadmap](../ROADMAP.md), milestone 4, with where it is fixed, unless it says it is accepted.

- **Private keys in the published cluster state**: the agent CA key, every host's agent and mgr TLS keys, the RGW CA and serving keys and the VRRP password. Whoever reads config-key below `mgr/cephadm/talos/` (the mgr, `client.admin`, the leader through the bridge) can issue certificates and impersonate agents and mgrs. Moving only the CA key would not be enough.
- **The bridge** listens on all interfaces, does not recheck that its incarnation is active, may write anywhere below `mgr/cephadm/talos/`, and releases `mon.` and mgr keys on request.
- **The bootstrap mon's document keeps `client.admin`** and the first keys until it is redeployed; the handoff does not replace it yet.
- **Confirmations are not bound to the active incarnation**: a mgr host's certificates are enough to confirm.
- **Admission** admits any digest of an allowed repository, does not match mgr keys to certificates or check RGW certificates, and admits a zap of any disk of the node.
- **No revocation** of certificates and no renewal after the handoff; the module reloads its server identity and signing key only on restart. Generated RGW certificates (2 years) are reissued when their names change, not before they expire.
- **No messenger encryption** is configured for Ceph.
- **Talos has no conditional apply**, so the drift check and the apply are not atomic. The feature request is drafted but not filed (Omni users do not need it); until then this is an accepted limitation of the single-writer convention, not scheduled for a fix.
- **Workload isolation must be off on Ceph nodes** until Talos PR #14603 is released.
- **The CLI assumes one workstation and one command at a time.**

## Not built yet

`ceph orch` commands that change the cluster and the module writing requests (step 6b on); the leader running jobs (OSD preparation and zap: the agents already admit their documents); control-plane safety (maintenance, reboot, upgrade through the leader); CLI request ids and suspension for recovery (step 7); enrollment of new nodes by the leader and certificate renewal (plan 04).
