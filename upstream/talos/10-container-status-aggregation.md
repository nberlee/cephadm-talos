Title: Talos Containers: desired vs observed generation in ContainerStatus

## Feature Request

### Description

Small, low priority. Let a client see in one resource whether the change it applied to a container is live, and how it ended.

#### Problem

To answer "is my last change to this container running, and did it succeed?", a client joins `ContainerStatus` (state, digest, restart count), `ContainerInstanceStatus` (phase, generation, start/finish time, exit code) and the image status. Nothing links the document a client applied to the instance that runs it.

#### Use cases

- **Rolling updates**: change one container, wait until exactly that change runs and is stable, then move to the next node.
- **CI/CD and GitOps tools** that apply a change and report when it is live.
- **Dashboards** showing which image reference (not just digest) runs where.

#### Why we need it

Our Ceph orchestrator upgrades daemons one at a time and needs per-daemon "upgraded and running" for `ceph orch ps` and `ceph orch upgrade`.

#### Proposal

In `ContainerStatus`:

- desired and observed generation identifiers that a client can correlate with the config it submitted, so it can wait for its generation to be observed and running, or learn that a later update superseded it;
- the start time and, with #14733, the terminal result of the last run;
- the requested image reference alongside the resolved digest.

#### Related

#14104, #14733. Our use: [cephadm-talos](https://github.com/nberlee/cephadm-talos) `ps` and `upgrade`.
