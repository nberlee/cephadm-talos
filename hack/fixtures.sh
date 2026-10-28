#!/usr/bin/env bash
# Prepares the upgrade fixtures for the integration suite: two images of the
# supported Ceph release that differ only in a label, in a plain-HTTP registry
# the QEMU nodes can reach, and the RegistryMirrorConfig that lets Talos use it.
#
# usage: hack/fixtures.sh [registry]   (default 10.5.0.1:5000, the QEMU bridge)
#
# Start the registry first, e.g.: sudo docker run -d --name registry -p 5000:5000 registry:2
# Needs crane and .talosconfig; prints the env for `go test -tags integration`.
set -euo pipefail

REG=${1:-10.5.0.1:5000}
SRC=${CEPHADM_TALOS_IMAGE:-quay.io/ceph/ceph:v20.2.4}
TALOSCONFIG=${TALOSCONFIG:-.talosconfig}
NODES=${CEPHADM_TALOS_NODES:-10.5.0.2,10.5.0.3,10.5.0.4}

src=$(crane digest --platform linux/amd64 "$SRC")
# the repository: drop a digest, then a tag in the last path component (not a registry port)
repo=${SRC%@*}
last=${repo##*/}
[[ $last == *:* ]] && repo=${repo%:*}
base="$repo@$src"

for f in a b; do
	crane mutate --insecure --label "cephadm-talos.fixture=$f" --platform linux/amd64 -t "$REG/ceph:fixture-$f" "$base" >/dev/null
done

a="$REG/ceph@$(crane digest --insecure "$REG/ceph:fixture-a")"
b="$REG/ceph@$(crane digest --insecure "$REG/ceph:fixture-b")"

# plain HTTP: Talos uses the http endpoint for this registry
TALOSCONFIG=$TALOSCONFIG CEPHADM_TALOS_NODES=$NODES "$(dirname "$0")/test-registry.sh" "$REG" >/dev/null

cat <<OUT
export CEPHADM_TALOS_FIXTURE_A=$a
export CEPHADM_TALOS_FIXTURE_B=$b
export CEPHADM_TALOS_FIXTURE_TAG=$REG/ceph:fixture-moving
OUT
