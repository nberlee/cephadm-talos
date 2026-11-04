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

# run_delayed SECONDS CMD... runs a daemon as this container's grandchild, not
# exec'd (plan 04, step 5, item 2b): Talos signals only the container's PID 1,
# which ignores a signal it has no handler for. On SIGTERM it waits SECONDS,
# so the agent's going-down report reaches the host's module before the
# daemon goes, then forwards SIGTERM once to the daemon. HUP, USR1 and USR2
# go to the daemon at once. The daemon runs under a subshell that no signal
# reaches (signals go to PID 1, which sends them to the daemon itself), so
# its wait is never interrupted: it records the daemon's pid and exit status
# in /dev/shm (named by this shell's pid: 1 in a container, unique in tests;
# a subshell's $$ is its parent's), and the container exits with that status, also when the daemon
# exits by itself. (A wait in PID 1, interrupted by its own handlers, can lose
# the status in bash.)
run_delayed() {
	local delay=$1 daemon="" sub status stop=0 forwarded=0
	shift
	rm -f /dev/shm/run_delayed.$$.pid /dev/shm/run_delayed.$$.rc
	forward() {
		if [ -n "$daemon" ] && [ "$forwarded" = 0 ]; then
			forwarded=1
			log "SIGTERM: the daemon stops in ${delay}s"
			(sleep "$delay"; kill -TERM "$daemon" 2>/dev/null) &
		fi
	}
	pass() { if [ -n "$daemon" ]; then kill "-$1" "$daemon" 2>/dev/null || true; fi; }
	trap 'stop=1; forward' TERM
	trap 'pass HUP' HUP
	trap 'pass USR1' USR1
	trap 'pass USR2' USR2
	(
		"$@" &
		echo "$!" > /dev/shm/run_delayed.$$.pid
		status=0
		wait "$!" || status=$?
		echo "$status" > /dev/shm/run_delayed.$$.rc
	) &
	sub=$!
	while [ ! -s /dev/shm/run_delayed.$$.pid ] && kill -0 "$sub" 2>/dev/null; do
		sleep 0.05
	done
	daemon=$(cat /dev/shm/run_delayed.$$.pid 2>/dev/null || true)
	# a SIGTERM before the daemon's pid was known
	if [ "$stop" = 1 ]; then forward; fi
	while kill -0 "$sub" 2>/dev/null; do
		wait "$sub" || true
	done
	status=$(cat /dev/shm/run_delayed.$$.rc 2>/dev/null || echo 1)
	rm -f /dev/shm/run_delayed.$$.pid /dev/shm/run_delayed.$$.rc
	exit "$status"
}
