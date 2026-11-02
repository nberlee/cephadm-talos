package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// RecordsReport is what a recovery job reads from an agent's records when the
// agent does not answer (plan 03, step 7 slice D, item 5): the receipt's
// fields, the open operations (whatever their kind), and the apply intent.
type RecordsReport struct {
	Version int `json:"version"`
	// Session is the suspension recorded, "" for none
	Session  string            `json:"session"`
	Revision int64             `json:"revision"`
	Fence    int64             `json:"fence"`
	Floor    int64             `json:"floor"`
	Owned    map[string]string `json:"owned"`
	// Open are the operations started or uncertain
	Open    []wire.Operation    `json:"open"`
	Intents []wire.BridgeIntent `json:"intents"`
	// Prepared are the serials of the disks preparation jobs used
	Prepared []string `json:"prepared,omitempty"`
	// ApplyBoot and ApplyAt are the apply intent's boot id and time
	// (UnixNano), empty without one
	ApplyBoot string `json:"apply_boot,omitempty"`
	ApplyAt   int64  `json:"apply_at,omitempty"`
}

// InspectRecords reads an agent's records; with session it first records the
// suspension (refused if another session is recorded). It never changes
// anything else.
func InspectRecords(recs *records.Store, session string) (RecordsReport, error) {
	g := &Granter{Records: recs}
	n := &Node{Records: recs}

	s, found, err := g.readSuspension()
	if err != nil {
		return RecordsReport{}, err
	}

	switch {
	case session != "" && found && s.Session != session:
		return RecordsReport{}, fmt.Errorf("suspended already for recovery session %s", s.Session)
	case session != "" && !found:
		if err := g.Suspend(context.Background(), session); err != nil {
			return RecordsReport{}, err
		}

		s = suspension{Session: session}
	}

	rep := RecordsReport{Version: wire.Version, Session: s.Session, Open: []wire.Operation{}}

	own, _, err := n.ownership()
	if err != nil {
		return RecordsReport{}, err
	}

	rep.Revision, rep.Owned = own.Revision, own.Docs

	if rep.Fence, err = n.fence(); err != nil {
		return RecordsReport{}, err
	}

	if rep.Floor, err = g.floor(); err != nil {
		return RecordsReport{}, err
	}

	var intent applyIntent

	if pending, err := n.readJSON(applyRecord, &intent); err != nil {
		return RecordsReport{}, err
	} else if pending {
		rep.ApplyBoot, rep.ApplyAt = intent.BootID, intent.At.UnixNano()
	}

	names, err := recs.List("op-")
	if err != nil {
		return RecordsReport{}, err
	}

	for _, name := range names {
		op, found, err := g.readOp(strings.TrimPrefix(name, "op-"))
		if err != nil {
			return RecordsReport{}, err
		}

		if found && (op.State == wire.OpStarted || op.State == wire.OpUncertain) {
			rep.Open = append(rep.Open, op)
		}
	}

	if rep.Intents, err = OpenIntents(recs); err != nil {
		return RecordsReport{}, err
	}

	if rep.Prepared, err = n.preparedSerials(); err != nil {
		return RecordsReport{}, err
	}

	return rep, nil
}

// preparedSerials are the serials of the disks preparation jobs used on the
// node, from the approval record's used disk entries (approval.Disk.Key:
// "<host>/<serial>/<action>/<since>"); read as recorded, not verified again.
func (n *Node) preparedSerials() ([]string, error) {
	var rec approvalStore

	if _, err := n.readJSON(approvalRecord, &rec); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	out := []string{}

	for key := range rec.Uses {
		parts := strings.Split(key, "/")
		if len(parts) == 4 && parts[2] == approval.Prepare && !seen[parts[1]] {
			seen[parts[1]] = true
			out = append(out, parts[1])
		}
	}

	sort.Strings(out)

	return out, nil
}

// WriteJobResult writes a job's result file in the jobs directory as job.sh
// does ("rc <n>", "inputs <hash>", then the output), atomically and synced.
func WriteJobResult(jobsDir, fsid, job, inputs string, rc int, out []byte) error {
	if job == "" || strings.ContainsAny(job, "/.") || strings.ContainsAny(inputs, "\n") {
		return errors.New("malformed job id or inputs")
	}

	path := filepath.Join(jobsDir, fsid+"."+job+".result")

	f, err := os.CreateTemp(jobsDir, "."+job+".result-")
	if err != nil {
		return err
	}

	defer os.Remove(f.Name()) //nolint:errcheck

	if _, err := fmt.Fprintf(f, "rc %d\ninputs %s\n%s", rc, inputs, out); err != nil {
		f.Close() //nolint:errcheck,gosec

		return err
	}

	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck,gosec

		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}

	d, err := os.Open(jobsDir)
	if err != nil {
		return err
	}

	defer d.Close() //nolint:errcheck

	return d.Sync()
}
