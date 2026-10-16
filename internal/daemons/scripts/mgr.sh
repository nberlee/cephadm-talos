# ceph-mgr: the key is pre-registered by cephadm-talos (mon keyring at bootstrap, `auth import` later).
D=/var/lib/ceph/$FSID/mgr.$ID
keyring "$D/keyring"
log "starting mgr.$ID"
exec ceph-mgr -f -i "$ID" --mgr-data "$D" --default-log-to-file=false --default-log-to-stderr=true
