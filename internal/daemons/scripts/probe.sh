# Image probe: reports the Ceph version and CPU architecture of an image.
# Runs before a cluster exists: no keyring, no ceph.conf, no cluster access.
trap - EXIT
echo "CEPHADM-TALOS-BEGIN $JOB"
set +e
ceph --version 2>&1
rc=$?
echo "arch $(uname -m)"
echo "CEPHADM-TALOS-END $JOB rc=$rc"
park
