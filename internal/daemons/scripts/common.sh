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
