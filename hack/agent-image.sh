#!/usr/bin/env bash
# Builds the cephadm-talos agent image (Dockerfile.agent) and pushes it.
# Prints the pushed reference pinned to its digest, for bootstrap --agent-image.
#
# usage: hack/agent-image.sh [push-ref [pull-ref]]
#   push-ref  where docker pushes (default localhost:5000/cephadm-talos-agent:dev)
#   pull-ref  the same image as the nodes see it (default 10.5.0.1:5000/cephadm-talos-agent:dev,
#             the local test registry on the QEMU bridge)
set -euo pipefail

PUSH=${1:-localhost:5000/cephadm-talos-agent:dev}
PULL=${2:-10.5.0.1:5000/cephadm-talos-agent:dev}

cd "$(dirname "$0")/.."
docker build -q -f Dockerfile.agent -t "$PUSH" . >/dev/null
docker push -q "$PUSH" >/dev/null

echo "${PULL%:*}@$(crane digest --insecure "$PULL")"
