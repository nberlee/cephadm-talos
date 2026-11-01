#!/usr/bin/env bash
# Runs the talos mgr module's unit tests against a Ceph source tree.
# usage: hack/mgrmodule-test.sh <ceph source dir>
# Needs python3 with prettytable, pyyaml and cryptography; uses .venv-mgrmodule when it exists:
#   python3 -m venv .venv-mgrmodule && .venv-mgrmodule/bin/pip install prettytable pyyaml cryptography
set -euo pipefail

CEPH=$(cd "$1" && pwd)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PY=python3
[ -x "$ROOT/.venv-mgrmodule/bin/python3" ] && PY=$ROOT/.venv-mgrmodule/bin/python3
cd "$ROOT/internal/mgrmodule"
PYTHONPATH="$PWD:$CEPH/src/pybind/mgr:$CEPH/src/pybind:$CEPH/src/python-common" exec "$PY" -m unittest -v test_talos test_bridge test_ledger
