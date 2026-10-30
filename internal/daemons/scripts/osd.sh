# ceph-osd on a raw device prepared by an osd-prepare job: activate and run.
# No LVM: nothing to activate on the host after a reboot, the device label is the source of truth.
keyring /var/lib/ceph/bootstrap-osd/ceph.keyring
mkdir -p /run/lock/lvm
chmod 0755 /var/lib/ceph/osd

# the label must still be this OSD's: a zapped or replaced disk must not start as it
label=$(ceph-volume raw list "$DEVICE" --format json | python3 -c '
import json, sys
for osd in json.load(sys.stdin).values():
    if osd.get("ceph_fsid") == sys.argv[1]:
        print(osd.get("osd_id"), osd.get("osd_uuid"))
' "$FSID")
if [ "$label" != "$OSD_ID $OSD_UUID" ]; then
	log "$DEVICE holds '$label', not osd.$OSD_ID ($OSD_UUID)"
	exit 1
fi

ceph-volume raw activate --device "$DEVICE" --osd-id "$OSD_ID" --osd-uuid "$OSD_UUID" --no-systemd
log "starting osd.$OSD_ID on $DEVICE"
exec ceph-osd -f --cluster ceph --id "$OSD_ID" --osd-data "/var/lib/ceph/osd/ceph-$OSD_ID" --default-log-to-file=false --default-log-to-stderr=true
