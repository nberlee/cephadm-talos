# Zap (plan 03, item 8), the command of a `never` job (job.sh): wipes an OSD
# device, bound to the disk's serial, checked right before the destructive step.
set -euo pipefail
log() { echo "cephadm-talos: $*" >&2; }

mkdir -p /run/lock/lvm

# $DEVICE is the disk's /dev/disk/by-id link, which carries its serial
serial=$(lsblk -dno SERIAL "$DEVICE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
if [ -z "$DISK_SERIAL" ] || [ "$serial" != "$DISK_SERIAL" ]; then
	log "$DEVICE has serial '$serial', not '$DISK_SERIAL': the disk changed, refusing"
	exit 66
fi

log "zapping $DEVICE (serial $serial)"
ceph-volume lvm zap "$DEVICE"
