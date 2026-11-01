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

# a disk is zapped only if it carries a BlueStore label of this cluster (and of
# the removed OSD), unless the operator approved zapping it as it is (plan 03, step 6c)
if [ "${ZAP_UNLABELLED:-}" != 1 ]; then
	if ! label=$(ceph-bluestore-tool show-label --dev "$DEVICE" 2>/dev/null); then
		log "$DEVICE has no readable BlueStore label: refusing without an approval to zap it"
		exit 67
	fi
	if ! printf '%s' "$label" | python3 -c '
import json, os, sys
d = json.load(sys.stdin)
labels = list(d.values()) if isinstance(d, dict) else []
ok = len(labels) == 1 and isinstance(labels[0], dict) and labels[0].get("ceph_fsid") == os.environ["FSID"]
uuid = os.environ.get("ZAP_OSD_UUID", "")
sys.exit(0 if ok and (not uuid or labels[0].get("osd_uuid") == uuid) else 1)'; then
		log "$DEVICE carries no BlueStore label of this cluster${ZAP_OSD_UUID:+ and OSD $ZAP_OSD_UUID}: refusing without an approval to zap it"
		exit 67
	fi
fi

log "zapping $DEVICE (serial $serial)"
ceph-volume lvm zap "$DEVICE"
