#!/usr/bin/env bash
# Lets the QEMU nodes pull from a plain-HTTP registry on the host (for the
# agent image and the upgrade fixtures), by adding a RegistryMirrorConfig.
#
# usage: hack/test-registry.sh [registry]   (default 10.5.0.1:5000, the QEMU bridge)
#
# Start the registry first: docker run -d --name registry -p 5000:5000 registry:2
set -euo pipefail

REG=${1:-10.5.0.1:5000}
TALOSCONFIG=${TALOSCONFIG:-.talosconfig}
NODES=${CEPHADM_TALOS_NODES:-10.5.0.2,10.5.0.3,10.5.0.4}

cd "$(dirname "$0")/.."
.bin/talosctl --talosconfig "$TALOSCONFIG" -n "$NODES" patch machineconfig --mode no-reboot --patch "$(cat <<DOC
apiVersion: v1alpha1
kind: RegistryMirrorConfig
name: $REG
endpoints:
  - url: http://$REG
DOC
)"
