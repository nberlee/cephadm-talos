# Image probe: prints the Ceph version and CPU architecture of an image and exits
# (restart policy never); cephadm-talos reads them from its log. Runs before a
# cluster exists: no keyring, no ceph.conf, no cluster access.
ceph --version
echo "arch $(uname -m)"
