# ceph-mon: mkfs on first start (bootstrap or join), then run in the foreground.
D=/var/lib/ceph/$FSID/mon.$ID
# ADDRV is rendered by cephadm-talos (bracketed for IPv6)

# The marker holds the deploy id: a mon removed and later re-added on this host
# gets a new id, so its stale store (which the quorum no longer knows) is rebuilt.
if [ "$(cat "$D/cephadm-talos-done" 2>/dev/null)" != "$DEPLOY_ID" ]; then
	keyring /tmp/mon.keyring
	if [ "${MODE:-join}" = bootstrap ]; then
		log "creating initial monmap for $ID $ADDRV"
		monmaptool --create --clobber --fsid "$FSID" --addv "$ID" "$ADDRV" /tmp/monmap
	else
		log "fetching monmap from the existing quorum"
		# the mon keyring we were given holds client.admin as well (see internal/orch)
		ceph -n client.admin -k /tmp/mon.keyring --connect-timeout 30 mon getmap -o /tmp/monmap
	fi
	rm -rf "$D"
	mkdir -p "$D"
	ceph-mon --mkfs -i "$ID" --fsid "$FSID" --monmap /tmp/monmap --keyring /tmp/mon.keyring --mon-data "$D"
	echo "$DEPLOY_ID" > "$D/cephadm-talos-done"
	rm -f /tmp/mon.keyring /tmp/monmap
fi

log "starting mon.$ID"
exec ceph-mon -f -i "$ID" --mon-data "$D" --public-addrv "$ADDRV" --default-log-to-file=false --default-log-to-stderr=true --default-mon-cluster-log-to-stderr=true
