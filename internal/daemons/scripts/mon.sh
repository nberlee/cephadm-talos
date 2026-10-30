# ceph-mon: mkfs on first start (bootstrap or join), then run in the foreground.
D=/var/lib/ceph/$FSID/mon.$ID
# ADDRV is rendered by cephadm-talos (bracketed for IPv6)

# The marker holds the deploy id: a mon removed and later re-added on this host
# gets a new id, so its stale store (which the quorum no longer knows) is rebuilt.
if [ "$(cat "$D/cephadm-talos-done" 2>/dev/null)" != "$DEPLOY_ID" ]; then
	keyring /tmp/mon.keyring
	rm -rf "$D"
	mkdir -p "$D"
	if [ "$MODE" = bootstrap ]; then
		log "creating initial monmap for $ID $ADDRV"
		monmaptool --create --clobber --fsid "$FSID" --addv "$ID" "$ADDRV" /tmp/monmap
		ceph-mon --mkfs -i "$ID" --fsid "$FSID" --monmap /tmp/monmap --keyring /tmp/mon.keyring --mon-data "$D"
	else
		# as cephadm does: the store from ceph.conf's mon_host and the mon. key
		# alone; the new mon probes the quorum and joins it
		log "creating mon.$ID to join the quorum at mon_host"
		ceph-mon --mkfs -i "$ID" --fsid "$FSID" --keyring /tmp/mon.keyring --mon-data "$D" --public-addrv "$ADDRV"
	fi
	echo "$DEPLOY_ID" > "$D/cephadm-talos-done"
	rm -f /tmp/mon.keyring /tmp/monmap
fi

log "starting mon.$ID"
exec ceph-mon -f -i "$ID" --mon-data "$D" --public-addrv "$ADDRV" --default-log-to-file=false --default-log-to-stderr=true --default-mon-cluster-log-to-stderr=true
