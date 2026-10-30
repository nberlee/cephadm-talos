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

# $DEVICE is the disk's /dev/disk/by-id link, which carries its serial: should
# the kernel name change, the link still leads to this disk or to none
serial=$(lsblk -dno SERIAL "$DEVICE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
if [ -z "$DISK_SERIAL" ] || [ "$serial" != "$DISK_SERIAL" ]; then
	log "$DEVICE has serial '$serial', not '$DISK_SERIAL': the disk changed, refusing"
	exit 66
fi

# ceph-volume reports an unreadable label as no label: the bluestore magic at the
# start of the device decides, and both must agree that the device is empty
magic=$(head -c 22 "$DEVICE" | tr -d '\0')
before=$(labels)
if [ -n "$before" ] || [ "$magic" = "bluestore block device" ]; then
	log "$DEVICE already holds an OSD (${before:-a bluestore label ceph-volume could not read}): zap it first, refusing"
	exit 67
fi

log "preparing $DEVICE (serial $serial) as a new bluestore OSD of $FSID"
prep=$(ceph-volume raw prepare --bluestore --data "$DEVICE" 2>&1 | tee /dev/stderr)

# the uuid this very run registered with `ceph osd new`; only that one is adopted
new=$(sed -n 's/.* osd new \([0-9a-f-]\{36\}\).*/\1/p' <<<"$prep" | tail -1)
after=$(labels)
read -r fsid id uuid <<<"$after"
if [ "$(wc -l <<<"$after")" != 1 ] || [ "$fsid" != "$FSID" ] || [ -z "$id" ] || [ -z "$uuid" ] || [ "$uuid" != "$new" ]; then
	log "after prepare $DEVICE holds '$after' (this run registered '$new'): not the OSD this run created, leaving it for reconciliation"
	exit 68
fi

if [ "$(lsblk -dno SERIAL "$DEVICE" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')" != "$DISK_SERIAL" ]; then
	log "$DEVICE changed its disk during prepare, leaving it for reconciliation"
	exit 68
fi

echo "osd_id $id"
echo "osd_uuid $uuid"
