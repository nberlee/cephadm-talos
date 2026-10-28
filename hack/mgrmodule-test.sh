#!/usr/bin/env bash
# Runs the talos mgr module's unit tests against a Ceph source tree.
# usage: hack/mgrmodule-test.sh <ceph source dir>   (needs python3 with prettytable and pyyaml)
set -euo pipefail

CEPH=$(cd "$1" && pwd)
cd "$(dirname "$0")/../internal/mgrmodule"
PYTHONPATH="$PWD:$CEPH/src/pybind/mgr:$CEPH/src/pybind:$CEPH/src/python-common" exec python3 -m unittest -v test_talos
