# keepalived holding the RGW virtual IP: VRRP over unicast between the vip
# hosts, gratuitous ARPs on takeover, and a health check against the local RGW
# so the VIP moves when RGW stops.
IFACE=$(ip -o -4 addr show | awk -v ip="$ADDR" '{split($4, a, "/"); if (a[1] == ip) {print $2; exit}}')
if [ -z "$IFACE" ]; then
	log "no interface holds $ADDR"
	exit 1
fi

PEER_LINES=""
for p in $PEERS; do PEER_LINES="$PEER_LINES        $p
"; done

cat > /tmp/keepalived.conf <<CONF
global_defs {
    router_id $ID
    script_user root
    enable_script_security
    vrrp_garp_master_refresh 30
}

vrrp_script chk_rgw {
    script "/usr/bin/curl -skf -o /dev/null https://127.0.0.1:$PORT/"
    interval 2
    timeout 2
    fall 2
    rise 2
}

vrrp_instance rgw {
    state BACKUP
    interface $IFACE
    virtual_router_id $VRID
    priority $PRIORITY
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass $VRRP_PASS
    }
    unicast_src_ip $ADDR
    unicast_peer {
$PEER_LINES    }
    virtual_ipaddress {
        $VIP dev $IFACE
    }
    track_script {
        chk_rgw
    }
}
CONF

log "keepalived for $VIP on $IFACE, priority $PRIORITY, peers: ${PEERS:-none}"
# a unique line per start, so cephadm-talos can tell this instance's VRRP
# transitions from older ones in the (bounded) log buffer; on stderr like
# keepalived itself, as stdout and stderr are not ordered against each other
echo "CEPHADM-TALOS-VIP-START $(date +%s%N)-$$" >&2
exec keepalived --dont-fork --log-console --log-detail --use-file /tmp/keepalived.conf \
	--pid /run/keepalived.pid --vrrp_pid /run/keepalived-vrrp.pid --checkers_pid /run/keepalived-checkers.pid
