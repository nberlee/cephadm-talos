# One-shot admin command. Talos restarts exited containers, so instead of exiting
# we print the result between markers and park; cephadm-talos reads the log and then
# deletes the document.
trap - EXIT
keyring /tmp/admin.keyring
export CEPH_ARGS="-n client.admin -k /tmp/admin.keyring"
echo "CEPHADM-TALOS-BEGIN $JOB"
set +e
bash -c "$CMD" 2>&1
rc=$?
echo "CEPHADM-TALOS-END $JOB rc=$rc"
park
