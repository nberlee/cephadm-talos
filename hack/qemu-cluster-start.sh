#!/usr/bin/env bash
# Restart the cephadm-talos QEMU cluster after a host reboot (talosctl has no "cluster start").
# Run as root: sudo bash hack/qemu-cluster-start.sh
set -eu
cd "$(dirname "$0")/.."
T=$PWD/.bin/talosctl
D=$PWD/.clusters/cephadm-talos
# stop $1.pid only if that PID still runs talosctl $2 (PIDs from before a reboot may be reused)
stop() { p=$(cat "$1.pid" 2>/dev/null) || return 0; grep -qa -- "$2" /proc/$p/cmdline 2>/dev/null && kill "$p" || true; }
# the bridge with the gateway address must exist before the launchers start
# (talosctl cluster create makes it through CNI; this is the same result)
if ! ip link show talos2620d064 >/dev/null 2>&1; then
	ip link add talos2620d064 type bridge
	ip link set talos2620d064 mtu 1500
	ip addr add 10.5.0.1/24 dev talos2620d064
fi
ip link set talos2620d064 up
sysctl -qw net.ipv4.ip_forward=1
for n in 1 2 3; do
	c=$D/cephadm-talos-controlplane-$n
	stop $c qemu-launch
	$T qemu-launch < $c.config >> $c.log 2>&1 &
	echo $! > $c.pid
done
stop $D/dhcpd dhcpd-launch
stop $D/dnsd dnsd-launch
$T dhcpd-launch --state-path $D --addr 10.5.0.1 --interface talos2620d064 --ipxe-next-handler "" >> $D/dhcpd.log 2>&1 &
echo $! > $D/dhcpd.pid
$T dnsd-launch --addr 10.5.0.1 --resolv-conf /etc/resolv.conf >> $D/dnsd.log 2>&1 &
echo $! > $D/dnsd.pid
echo started
