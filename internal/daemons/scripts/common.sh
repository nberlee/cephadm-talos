# Shared helpers, prepended to every entrypoint. Inputs come in as environment
# variables set in the ContainerConfig document (see internal/daemons).
set -euo pipefail

log() { echo "cephadm-talos: $*" >&2; }

# keyring FILE writes the base64 keyring from $CEPHADM_TALOS_KEYRING to FILE (0600)
# the umask is scoped to a subshell: directories created later must stay
# traversable for daemons that drop to the ceph user (ceph-osd --mkfs).
keyring() {
	mkdir -p "$(dirname "$1")"
	(umask 077 && echo "$CEPHADM_TALOS_KEYRING" | base64 -d > "$1")
}

mkdir -p /var/run/ceph /var/log/ceph

# run_delayed SECONDS CMD... runs a daemon as this container's child, not
# exec'd (plan 04, step 5, item 2b): Talos signals only the container's PID 1,
# which ignores a signal it has no handler for. On SIGTERM it waits SECONDS,
# so the agent's going-down report reaches the host's module before the
# daemon goes, then forwards SIGTERM once and waits for the daemon. The
# container exits with the daemon's status, also when the daemon exits by
# itself. HUP, USR1 and USR2 go to the daemon at once.
run_delayed() {
	local delay=$1 child="" status stop=0 forwarded=0
	shift
	# the delayed forward is scheduled from the handler itself (once), so a
	# SIGTERM that arrives before or between waits is never left unhandled
	forward() {
		if [ -n "$child" ] && [ "$forwarded" = 0 ]; then
			forwarded=1
			log "SIGTERM: the daemon stops in ${delay}s"
			(sleep "$delay"; kill -TERM "$child" 2>/dev/null) &
		fi
	}
	trap 'stop=1; forward' TERM
	trap 'kill -HUP "$child" 2>/dev/null || true' HUP
	trap 'kill -USR1 "$child" 2>/dev/null || true' USR1
	trap 'kill -USR2 "$child" 2>/dev/null || true' USR2
	"$@" &
	child=$!
	# a SIGTERM before the daemon was started
	if [ "$stop" = 1 ]; then forward; fi
	while :; do
		# wait returns early when a trapped signal arrives: the daemon is
		# gone only once kill -0 finds it no more (wait reaped it)
		status=0
		wait "$child" || status=$?
		if ! kill -0 "$child" 2>/dev/null; then
			exit "$status"
		fi
	done
}
