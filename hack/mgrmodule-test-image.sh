#!/usr/bin/env bash
# Runs the talos mgr module's unit tests with the Python, libraries and mgr
# code of a Ceph image, as the module runs there (hack/mgrmodule-test.sh uses
# the host's Python and a source tree).
# usage: hack/mgrmodule-test-image.sh [image]   (default quay.io/ceph/ceph:v21.2.0)
set -euo pipefail

IMAGE=${1:-quay.io/ceph/ceph:v21.2.0}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
exec docker run --rm --network none -v "$ROOT/internal/mgrmodule:/src:ro" --entrypoint bash "$IMAGE" -c \
	'cp -r /src /tmp/m && cd /tmp/m && PYTHONPATH="/tmp/m:/usr/share/ceph/mgr" exec python3 -m unittest test_talos test_bridge test_ledger'
