# cephadm-talos

> [!WARNING]
> **Not ready for your production data, nowhere near.** This is a proof of concept. Read [SHORTCOMINGS.md](SHORTCOMINGS.md) before you put anything on it that you care about.
>
> It also depends on Talos features that are still missing. The feature requests and their status are in [upstream/talos/README.md](upstream/talos/README.md); the plan towards production is in [ROADMAP.md](ROADMAP.md).

![demo: bootstrap a Ceph cluster on 3 Talos nodes without Kubernetes, watch the containers in talosctl dashboard, ceph -s](demo/demo.gif)

Also available as [SVG](demo/demo.svg) and as an [asciinema recording](demo/demo.cast) (`asciinema play demo/demo.cast`).

## Why

My main goal was to find out whether [Talos Linux](https://www.talos.dev) can replace the operating system of my dedicated Ceph cluster. That means Talos as an immutable, API-managed OS that runs Ceph directly, without Kubernetes and without Rook.

cephadm-talos is a small Go CLI that mimics cephadm's orchestration on top of Talos. It covers bootstrap, adding hosts, deploying mon/mgr/OSD daemons, `ps`, `shell`, upgrade, removal and host maintenance.

There is no SSH, no systemd and no python on the hosts. Each Ceph daemon is a Talos `ContainerConfig` machine config document (Talos 1.15+), applied through the Talos API (the machinery Go client, no `talosctl`) in no-reboot mode, and run by Talos itself in the containerd namespace `taloscontainers`.

The demo above runs on 3 Talos v1.15.0-alpha.1 nodes created with `--skip-etcd-k8s`. There is no Kubernetes and no etcd: the machine config's `cluster:` section is empty. The pauses in the recording, mostly image pulls, are shortened.

## Requirements

- Talos **1.15** or newer on the nodes, amd64, and the latest Ceph release (today v20.2.4); see [docs/support.md](docs/support.md). cephadm-talos needs `ContainerConfig`, `EtcFileConfig` and container logs and restart in the `taloscontainers` namespace.
- A talosconfig for the nodes (`--talosconfig`, `$TALOSCONFIG` or `~/.talos/config`). `talosctl` itself is not needed.
- Free raw disks on the nodes for OSDs. These must not be claimed by any Talos volume.
- No Ceph tooling on your workstation. `ceph` commands run in short-lived job containers on the nodes (`cephadm-talos shell`).

## How cephadm concepts map to Talos

| cephadm | cephadm-talos |
|---|---|
| SSH + `cephadm` python binary on the host | machine config patches through the Talos API |
| systemd unit `ceph-<fsid>@<daemon>` + `unit.run` | `ContainerConfig` `ceph-<fsid8>-<type>-<id>`, run by Talos in containerd namespace `taloscontainers` |
| `/var/lib/ceph/<fsid>` | `UserVolumeConfig` `ceph` (`volumeType: directory`, `/var/mnt/ceph`), mounted at `/var/lib/ceph` |
| `/etc/ceph/ceph.conf` written over SSH | `EtcFileConfig` `ceph/ceph.conf` |
| keyring files written over SSH | base64 env var in the document, written to the daemon dir by the entrypoint |
| `cephadm shell` / `cephadm ceph-volume` | `cephadm-talos shell`: a short-lived "job" `ContainerConfig`; its output is read from the container log, then the document is deleted |
| `ceph orch ps` / `cephadm ls` | `cephadm-talos ps`: inventory + `ContainerStatus` resources |
| `ceph orch daemon rm`, `ceph orch upgrade` | `cephadm-talos rm`, `cephadm-talos upgrade` |
| `ceph orch host maintenance enter/exit` (`systemctl disable --now ceph-<fsid>.target`) | `cephadm-talos host maintenance enter/exit` (documents removed and re-applied, as Talos has no stop/disable) |
| `cephadm rm-cluster` | `cephadm-talos rm-cluster` |
| `ceph orch apply rgw` (+ `ingress`: haproxy + keepalived) | `cephadm-talos deploy rgw` (HTTPS, generated CA) + `deploy vip` (keepalived only, no haproxy) |
| cluster state in mon config-key store | `~/.cephadm-talos/<fsid>/state.json` |

Every container entrypoint is idempotent. It does any first-start work (`ceph-mon --mkfs`, `ceph-volume raw prepare`), then `exec`s the daemon in the foreground. Talos restarts an exited container after 5s.

## Usage

```sh
go build -o cephadm-talos ./cmd/cephadm-talos

# create the cluster: 1 mon + 1 mgr
./cephadm-talos --talosconfig ./.talosconfig bootstrap --mon-node 10.5.0.2

# more hosts and daemons (talosconfig/context are remembered)
./cephadm-talos host add 10.5.0.3
./cephadm-talos host add 10.5.0.4
./cephadm-talos deploy mon cephadm-talos-controlplane-2
./cephadm-talos deploy mon cephadm-talos-controlplane-3
./cephadm-talos deploy mgr cephadm-talos-controlplane-2
./cephadm-talos deploy osd cephadm-talos-controlplane-1 /dev/sda
./cephadm-talos deploy osd cephadm-talos-controlplane-2 /dev/sda
./cephadm-talos deploy osd cephadm-talos-controlplane-3 /dev/sda

./cephadm-talos ps
./cephadm-talos shell -- ceph -s
./cephadm-talos shell -- 'ceph osd tree; ceph df'
./cephadm-talos logs -f mon.cephadm-talos-controlplane-1

# S3 over HTTPS behind a virtual IP (keepalived, VRRP unicast + gratuitous ARP)
./cephadm-talos deploy rgw cephadm-talos-controlplane-1            # beast on :443, cert from a generated cluster CA
./cephadm-talos deploy rgw cephadm-talos-controlplane-2
./cephadm-talos deploy vip cephadm-talos-controlplane-1 --vip 10.5.0.200/24
./cephadm-talos deploy vip cephadm-talos-controlplane-2
./cephadm-talos shell -- radosgw-admin user create --uid demo --display-name Demo
curl --cacert ~/.cephadm-talos/<fsid>/rgw-ca.crt https://10.5.0.200/

./cephadm-talos upgrade --image quay.io/ceph/ceph:v20.2.4
./cephadm-talos rm --zap osd.2
./cephadm-talos host maintenance enter cephadm-talos-controlplane-3   # ok-to-stop, noout, stop daemons
./cephadm-talos host maintenance exit cephadm-talos-controlplane-3
./cephadm-talos host reboot cephadm-talos-controlplane-3              # enter + Talos reboot + exit
./cephadm-talos rm-cluster --zap --yes-i-really-mean-it               # remove everything (like cephadm rm-cluster)
```

`deploy rgw --cert F --key F` uses your own certificate instead of the generated one. The generated server certificate covers the VIP, every host IP and hostname, and is reissued (and the rgws restarted) when a host or the VIP is added. `deploy vip` places keepalived (`quay.io/ceph/keepalived:2.2.4`, as cephadm's ingress uses). The VIP is held by the first vip host whose local rgw answers, and moves on failure or `host maintenance enter`. Talos's own VIP cannot be used here: it elects its holder through etcd.

`bootstrap` and `upgrade` pin the image to its digest: they pull it on one node, read the digest Talos resolved, and run `ceph --version` in it. Only the supported Ceph release is accepted (`--skip-version-check` for testing). A tag the node already has resolves to the digest it pulled before; `--refresh` pulls it again. cephx keys are always AES256KRB5 (`aes256k`).

`--dry-run` prints the machine config patches instead of applying them. `-v` prints every Talos API call. Both are global flags and go before the command.

## Local QEMU test cluster without Kubernetes

The demo cluster has 3 control planes, no Kubernetes and no etcd, and a 10 GiB spare disk per node for the OSD. `talosctl cluster create dev` uses the same QEMU provisioner as `cluster create qemu`, but it also offers `--skip-etcd-k8s` and `--extra-disks-on-controlplanes`:

```sh
mkdir -p .iso && curl -Lo .iso/metal-amd64.iso \
  https://factory.talos.dev/image/376567988ad370138ad8b2698212367b8edcb69b5fd68c80be1f2ec7d603b4ba/v1.15.0-alpha.2/metal-amd64.iso

sudo .bin/talosctl cluster create dev --name cephadm-talos \
  --state ./.clusters --talosconfig ./.talosconfig \
  --iso-path ./.iso/metal-amd64.iso --with-apply-config --skip-etcd-k8s \
  --controlplanes 3 --workers 0 --memory 4GiB --disk 10240 \
  --extra-disks 1 --extra-disks-size 10240 --extra-disks-on-controlplanes
sudo chown -R $USER .talosconfig .clusters
```

Notes:

- `--with-apply-config` is needed with `--iso-path`, or the nodes wait in maintenance mode forever.
- The extra disk is SATA (`/dev/sda`); Talos itself is installed on `/dev/vda`.
- A host firewall such as ufw has to allow the cluster network (DHCP, DNS and forwarding for 10.5.0.0/24).

## Recording the demo

```sh
asciinema rec --headless --window-size 120x32 --command "bash demo/record.sh" demo/demo.raw.cast
python3 demo/compress.py --segment 3=2.5 demo/demo.raw.cast demo/demo.cast   # cap pauses, fast-forward image pulls
agg --theme monokai --font-size 14 demo/demo.cast demo/demo.gif
asciinema convert -f asciicast-v2 demo/demo.cast /tmp/demo.v2.cast           # svg-term reads v2 only
npx svg-term-cli --in /tmp/demo.v2.cast --out demo/demo.svg --window
```

`demo/drive_dashboard.py` presses F3 (Containers) in `talosctl dashboard` during the recording.

## Layout

```
cmd/cephadm-talos    CLI
internal/orch        bootstrap/deploy/rm/upgrade/ps/shell/maintenance
internal/daemons     ContainerConfig per daemon type + embedded entrypoint scripts
internal/spec        Talos document types (minimal) and rendering
internal/talos       Talos API client (machinery)
internal/cephx       CephX key generation
internal/state       local inventory
demo/                asciinema recording scripts and output
upstream/talos       Talos feature requests and their status
```

## Credits

Henk Kraal ([@hkraal](https://github.com/hkraal), Exonet) explored the same direction in "Ceph on Talos without Kubernetes". The roadmap adopts his ideas: a Talos raw partition per OSD instead of LVM, digest-pinned images, restricted by default with OSDs as the only privileged daemons, and the cephadm monitoring stack on Talos.

## License

[MPL-2.0](LICENSE). cephadm-talos reimplements cephadm behaviour from the Ceph documentation; it contains no code from cephadm.
