# The guard of a mgr (plan 04, step 5, item 2b): it depends on its mgr, so on
# its host's stop Talos stops it first and the mgr only after it exited. It
# exits 4 seconds after SIGTERM, which gives the agent's going-down report and
# the module's host_down and failover that time. Talos signals every process
# of the container: the wait starts in the trap, after the signal.
trap 'sleep 4; exit 0' TERM
while :; do
	sleep 3600 &
	wait $!
done
