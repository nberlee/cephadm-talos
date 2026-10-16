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

# Talos restarts an exited container after 5s with no backoff: slow down
# crash loops so the log stays readable and the mons are not hammered.
trap 'rc=$?; if [ $rc -ne 0 ]; then log "exit $rc, sleeping 30s before restart"; sleep 30; fi' EXIT

# park waits until Talos stops the container. The shell is PID 1 here, and PID 1
# ignores signals it has no handler for: a bare `sleep infinity` would only end
# with the SIGKILL Talos sends 10s after SIGTERM.
park() {
	trap - EXIT
	trap 'exit 0' TERM INT
	sleep infinity &
	wait $!
}

mkdir -p /var/run/ceph /var/log/ceph
