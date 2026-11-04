# ceph-mgr: the key is pre-registered by cephadm-talos (mon keyring at bootstrap, `auth import` later).
D=/var/lib/ceph/$FSID/mgr.$ID
keyring "$D/keyring"
log "starting mgr.$ID"
# a child, not exec'd: its SIGTERM waits 4s for the host's going-down report,
# the module's host_down and failover (plan 04, step 5, item 2b)
run_delayed 4 ceph-mgr -f -i "$ID" --mgr-data "$D" --default-log-to-file=false --default-log-to-stderr=true
