#!/usr/bin/env bash
# Scripted demo session, recorded with:
#   asciinema rec --headless --window-size 120x32 --command demo/record.sh demo/demo.raw.cast
# Run from the repository root against a fresh 3-node Talos cluster without Kubernetes.
set -euo pipefail

export TALOSCONFIG=$PWD/.talosconfig
export PATH=$PWD:$PWD/.bin:$PATH
NODES=(10.5.0.2 10.5.0.3 10.5.0.4)
HOSTS=(cephadm-talos-controlplane-1 cephadm-talos-controlplane-2 cephadm-talos-controlplane-3)

# markers for demo/compress.py (OSC sequences, invisible in the recording)
fast_on()  { printf '\033]1337;demo-fast-on\007'; }
fast_off() { printf '\033]1337;demo-fast-off\007'; }

say() { printf '\n\033[1;36m# %s\033[0m\n' "$*"; sleep 1.2; }

# type a command at a fake prompt, then run it
run() {
	printf '\033[1;32m$\033[0m '
	local s="$*" i
	for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.03; done
	printf '\n'
	sleep 0.4
	eval "$@"
	sleep 1
}

clear
say "3 Talos v1.15 nodes, no Kubernetes, no etcd: only Talos' own services"
run "talosctl -n ${NODES[0]} services"

say "bootstrap a Ceph cluster: 1 mon + 1 mgr as Talos ContainerConfig documents"
fast_on
run "cephadm-talos --talosconfig \$TALOSCONFIG bootstrap --mon-node ${NODES[0]}"
fast_off

say "add the other nodes, 2 more mons and a standby mgr"
run "cephadm-talos host add ${NODES[1]} && cephadm-talos host add ${NODES[2]}"
fast_on
run "cephadm-talos deploy mon ${HOSTS[1]} && cephadm-talos deploy mon ${HOSTS[2]} && cephadm-talos deploy mgr ${HOSTS[1]}"
fast_off

say "one OSD per node on the spare disk, in the background, while we watch the containers"
run "for h in ${HOSTS[*]}; do cephadm-talos deploy osd \$h /dev/sda; done > /tmp/osd-deploy.log 2>&1 & echo \$! > /tmp/osd-deploy.pid"

say "talosctl dashboard, F3: the Containers screen"
sleep 0.5
fast_on
python3 "$(dirname "$0")/drive_dashboard.py" --pidfile /tmp/osd-deploy.pid -- \
	talosctl dashboard -n "$(IFS=,; echo "${NODES[*]}")"
fast_off
clear

say "every daemon runs as a Talos container"
run "cephadm-talos ps | cut -c1-110"

# wait (unrecorded time is compressed anyway) until the PGs settle
fast_on
for _ in $(seq 60); do
	cephadm-talos shell -- ceph health 2>/dev/null | grep -q HEALTH_OK && break
	sleep 5
done >/dev/null 2>&1
fast_off

say "and Ceph agrees"
run "cephadm-talos shell -- ceph -s"
sleep 4
