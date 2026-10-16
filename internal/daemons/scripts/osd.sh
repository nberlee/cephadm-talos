# ceph-osd on a raw device: ceph-volume raw prepare on first start, then activate and run.
# No LVM: nothing to activate on the host after a reboot, the device label is the source of truth.
keyring /var/lib/ceph/bootstrap-osd/ceph.keyring
mkdir -p /run/lock/lvm
# ceph-volume chowns only the OSD dir itself; `ceph-osd --mkfs --setuser ceph` must traverse its parents
chmod 0755 /var/lib/ceph/osd

osd_field() { # osd_field FIELD -> value for $DEVICE from `ceph-volume raw list`, empty if not an OSD
	ceph-volume raw list "$DEVICE" --format json 2>/dev/null | python3 -c '
import json, sys
fsid, field = sys.argv[1], sys.argv[2]
for osd in json.load(sys.stdin).values():
    if osd.get("ceph_fsid") == fsid:
        print(osd[field]); break
' "$FSID" "$1"
}

# OSD_UUID is chosen by cephadm-talos per deployment and passed to prepare, so a
# restart after an interrupted prepare recognises its own label. ceph-volume
# before v20.2.4 has no `raw prepare --osd-fsid`: then a pending marker on the
# host volume, written before prepare, identifies a label made by this deploy.
PENDING=/var/lib/ceph/$FSID/osd-$(basename "$DEVICE").pending
mkdir -p "/var/lib/ceph/$FSID"
OSD_ID=$(osd_field osd_id || true)
LABEL_UUID=$(osd_field osd_uuid || true)
if [ -z "$OSD_ID" ]; then
	echo "$DEPLOY_ID" > "$PENDING"
	if ceph-volume raw prepare --help 2>/dev/null | grep -q -- --osd-fsid; then
		log "preparing $DEVICE as a new bluestore OSD ($OSD_UUID)"
		ceph-volume raw prepare --bluestore --data "$DEVICE" --osd-fsid "$OSD_UUID"
	else
		log "preparing $DEVICE as a new bluestore OSD (this ceph-volume picks the uuid)"
		ceph-volume raw prepare --bluestore --data "$DEVICE"
	fi
	OSD_ID=$(osd_field osd_id)
	OSD_UUID=$(osd_field osd_uuid)
elif [ "$LABEL_UUID" != "$OSD_UUID" ] && [ "$(cat "$PENDING" 2>/dev/null)" = "$DEPLOY_ID" ]; then
	log "accepting $LABEL_UUID on $DEVICE, prepared by this deployment"
	OSD_UUID=$LABEL_UUID
elif [ "$LABEL_UUID" != "$OSD_UUID" ]; then
	# A label of this cluster from another deployment: most likely an OSD that was
	# removed without --zap, whose key and map entry are gone. Starting it would
	# only crash-loop, so refuse and park until the device is zapped.
	echo "CEPHADM-TALOS-OSD-ERROR=$DEPLOY_ID $DEVICE holds osd.$OSD_ID ($LABEL_UUID) from an earlier deployment; zap it first"
	park
fi
# tagged with the deploy id: Talos keeps the log buffer of a container name
# across delete/re-create, so older markers of the same name may be present
echo "CEPHADM-TALOS-OSD-ID=$DEPLOY_ID $OSD_ID $OSD_UUID"

ceph-volume raw activate --device "$DEVICE" --osd-id "$OSD_ID" --osd-uuid "$OSD_UUID" --no-systemd
log "starting osd.$OSD_ID on $DEVICE"
exec ceph-osd -f --cluster ceph --id "$OSD_ID" --osd-data "/var/lib/ceph/osd/ceph-$OSD_ID" --default-log-to-file=false --default-log-to-stderr=true
