# One-shot job (plan 03, item 8): a `never` container that claims its id, records
# that it started, runs its command and writes its result, each atomically in
# the jobs directory of the cephadm-talos volume. Talos runs it again after a
# reboot: a job that finds its result reports it and does nothing; one that
# finds only its started record reports "uncertain" and does not run again.
J="$JOBS/$FSID.$JOB"

# put FILE: write stdin to FILE atomically (temporary file, fsync, rename, fsync dir)
put() {
	local t
	t=$(mktemp "$JOBS/.tmp-XXXXXX") || return 1
	cat > "$t" && chmod 0644 "$t" && sync "$t" && mv -f "$t" "$1" && sync "$JOBS"
}

# create FILE: write stdin to FILE only if it does not exist yet, atomically and
# durably; fails if it exists (a hard link fails on an existing name)
create() {
	local t rc=0
	t=$(mktemp "$JOBS/.tmp-XXXXXX") || return 70
	cat > "$t" && chmod 0644 "$t" && sync "$t" || { unlink "$t"; return 70; }
	ln "$t" "$1" 2>/dev/null || rc=1
	unlink "$t"
	if [ "$rc" = 0 ] && ! sync "$JOBS"; then
		return 70 # created but maybe not durable: never act on it
	fi
	return "$rc"
}

# a job the leader acknowledged never runs again (plan 03, step 6c)
if [ -e "$J.tombstone" ]; then
	log "job $JOB is finished and acknowledged; refusing"
	exit 64
fi

# the claim binds the id to its inputs, before anything else is trusted
if [ -e "$J.claim" ]; then
	if [ "$(cat "$J.claim")" != "$JOB_INPUTS" ]; then
		log "job $JOB is claimed with other inputs; refusing"
		exit 65
	fi
else
	c=0
	printf '%s\n' "$JOB_INPUTS" | create "$J.claim" || c=$?
	case $c in
	0) ;;
	1)
		log "job $JOB was claimed meanwhile; refusing"
		exit 65
		;;
	*) exit 70 ;;
	esac
fi

if [ -e "$J.result" ]; then
	# a run that wrote it may still be syncing: report it only once it is durable
	sync "$J.result" && sync "$JOBS" || exit 70
	log "job $JOB already ran; its result:"
	cat "$J.result"
	exit 0
fi

# only one run ever gets past this point: started is created exclusively
c=0
echo started | create "$J.started" || c=$?
case $c in
0) ;;
1)
	log "job $JOB started before and left no result: its outcome is uncertain, it does not run again"
	exit 75
	;;
*) exit 70 ;;
esac

# Talos sends SIGTERM to every process of the container: a job that must not be
# cut short ignores it for its whole process tree (an ignored signal is
# inherited), so only the SIGKILL after its stop timeout ends it
if [ "${JOB_IGNORE_TERM:-}" = 1 ]; then
	trap '' TERM
fi

# the output kept in the result is bounded: its last 16 KiB
set +e
bash -c "$CMD" >/tmp/job.out 2>&1
rc=$?
set -e
out=$(tail -c 16384 /tmp/job.out)
{ echo "rc $rc"; echo "inputs $JOB_INPUTS"; printf '%s' "$out"; } | put "$J.result" || exit 70
printf '%s\n' "$out"
exit "$rc"
