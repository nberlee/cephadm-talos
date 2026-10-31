# radosgw with TLS: beast serves HTTPS only, the certificate+key come in as a PEM bundle.
# Its admin socket is named like the other daemons' (radosgw's own default
# carries its pid), where the agent asks it for its version.
D=/var/lib/ceph/$FSID/rgw.$ID
keyring "$D/keyring"
(umask 077 && echo "$TLS_PEM" | base64 -d > /tmp/rgw.pem)
log "starting rgw.$ID on https port $PORT"
exec radosgw -f -n "client.rgw.$ID" --keyring "$D/keyring" \
	--rgw-frontends "beast ssl_port=$PORT ssl_certificate=/tmp/rgw.pem" \
	--rgw_graceful_stop=true \
	--admin_socket="/var/run/ceph/ceph-client.rgw.$ID.asok" \
	--default-log-to-file=false --default-log-to-stderr=true
