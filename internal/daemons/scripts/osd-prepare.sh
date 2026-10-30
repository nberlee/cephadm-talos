# OSD preparation (plan 03, item 8), the command of a `never` job (job.sh): it is
# bound to the disk's serial and the cluster, checked right before the
# destructive step, and reports the id and uuid ceph-volume chose. job.sh's
# records keep it from running twice; a prepare that fails or is interrupted is
# left for reconciliation, never repeated.
set -euo pipefail
log() { echo "cephadm-talos: $*" >&2; }

mkdir -p /var/lib/ceph/bootstrap-osd /run/lock/lvm /var/lib/ceph/osd
(umask 077 && echo "$CEPHADM_TALOS_KEYRING" | base64 -d > /var/lib/ceph/bootstrap-osd/ceph.keyring)
# ceph-volume chowns only the OSD dir itself; `ceph-osd --mkfs --setuser ceph` must traverse its parents
chmod 0755 /var/lib/ceph/osd

labels() { # the bluestore labels on $DEVICE: "<ceph fsid> <osd id> <osd uuid>" per line
	ceph-volume raw list "$DEVICE" --format json | python3 -c '
import json, sys
for osd in json.load(sys.stdin).values():
    print(osd.get("ceph_fsid", ""), osd.get("osd_id", ""), osd.get("osd_uuid", ""))
'
}

serial=$(lsblk -dno SERIAL "$DEVICE" | tr -d '[:space:]')
if [ -z "$DISK_SERIAL" ] || [ "$serial" != "$DISK_SERIAL" ]; then
	log "$DEVICE has serial '$serial', not '$DISK_SERIAL': the disk changed, refusing"
	exit 66
fi

before=$(labels)
if [ -n "$before" ]; then
	log "$DEVICE already holds an OSD ($before): zap it first, refusing"
	exit 67
fi

log "preparing $DEVICE (serial $serial) as a new bluestore OSD of $FSID"
ceph-volume raw prepare --bluestore --data "$DEVICE"

after=$(labels)
read -r fsid id uuid <<<"$after"
if [ "$(wc -l <<<"$after")" != 1 ] || [ "$fsid" != "$FSID" ] || [ -z "$id" ] || [ -z "$uuid" ]; then
	log "after prepare $DEVICE holds '$after': not exactly one OSD of this cluster, leaving it for reconciliation"
	exit 68
fi

echo "osd_id $id"
echo "osd_uuid $uuid"
