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
	local delay=$1 child="" status again stop=0 forwarded=0 sig=0
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
	# sig marks that a handler ran, so a wait may have returned the signal's
	# status (128 + n) instead of the daemon's
	trap 'sig=1; stop=1; forward' TERM
	trap 'sig=1; kill -HUP "$child" 2>/dev/null || true' HUP
	trap 'sig=1; kill -USR1 "$child" 2>/dev/null || true' USR1
	trap 'sig=1; kill -USR2 "$child" 2>/dev/null || true' USR2
	"$@" &
	child=$!
	# a SIGTERM before the daemon was started
	if [ "$stop" = 1 ]; then forward; fi
	while :; do
		# wait returns early when a trapped signal arrives: the daemon is
		# gone only once kill -0 finds it no more (wait reaped it)
		sig=0
		status=0
		wait "$child" || status=$?
		if kill -0 "$child" 2>/dev/null; then
			continue
		fi
		# gone; if a handler ran, status may be the signal's: wait again for
		# the saved status
		while [ "$sig" = 1 ]; do
			sig=0
			again=0
			wait "$child" 2>/tmp/run_delayed.wait || again=$?
			# 127 with bash's "not a child" message: the status was already
			# returned; a daemon's own 127 comes without the message
			if [ "$again" = 127 ] && [ -s /tmp/run_delayed.wait ]; then
				break
			fi
			status=$again
		done
		exit "$status"
	done
}
