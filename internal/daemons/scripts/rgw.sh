# radosgw with TLS: beast serves HTTPS only, the certificate+key come in as a PEM bundle.
D=/var/lib/ceph/$FSID/rgw.$ID
keyring "$D/keyring"
(umask 077 && echo "$TLS_PEM" | base64 -d > /tmp/rgw.pem)
log "starting rgw.$ID on https port $PORT"
exec radosgw -f -n "client.rgw.$ID" --keyring "$D/keyring" \
	--rgw-frontends "beast ssl_port=$PORT ssl_certificate=/tmp/rgw.pem" \
	--default-log-to-file=false --default-log-to-stderr=true
