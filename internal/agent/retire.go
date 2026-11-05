package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// The agent's retirement (plan 04, step 6 part A). A retire grant, confirmed
// as any grant, has an agent that owns no document remove its own documents
// (its agent and records-init documents) through its own socket, under the
// apply intent every apply uses, marked as a retirement; Talos then stops its
// container. Only once that apply is decided completed, by the agent itself
// or on a later start from the intent, are its records retired: every serial
// of its server certificates the identity record lists gets a retirement mark
// and the set is moved aside under the latest (records.Retire). An agent
// started with a certificate whose serial has a mark refuses every grant and
// handoff and reports itself retired. The records job retires a set the same
// way when the agent could not finish it (RetireRecords).

// identityRecord lists the serials of the agent server certificates the
// records ran under, in the order they were first seen: a set names its
// generation, and a move aside is named by the latest.
const identityRecord = "identity"

type identity struct {
	Schema  int      `json:"schema"`
	Serials []string `json:"serials"`
}

// certSerialRe is a certificate serial as the agent names it: decimal, as the
// revocation entries do (cephadm-talos/revoked/<serial>).
var certSerialRe = regexp.MustCompile(`^[0-9]{1,64}$`)

// errRetired refuses what a retired agent does not do.
var errRetired = errors.New("the agent is retired")

// Retired reports whether the agent is retired.
func (g *Granter) Retired() bool { return g.retired.Load() }

// SetRetired marks the agent retired: started with a certificate whose
// serial has a retirement mark.
func (g *Granter) SetRetired() { g.retired.Store(true) }

func readIdentity(recs *records.Store) (identity, bool, error) {
	var id identity

	b, err := recs.Read(identityRecord)
	if errors.Is(err, records.ErrNotFound) {
		return id, false, nil
	}

	if err != nil {
		return id, false, err
	}

	if err := json.Unmarshal(b, &id); err != nil || id.Schema != ownershipSchema || len(id.Serials) == 0 {
		return identity{}, false, fmt.Errorf("record %s: damaged", identityRecord)
	}

	for _, s := range id.Serials {
		if !certSerialRe.MatchString(s) {
			return identity{}, false, fmt.Errorf("record %s: damaged", identityRecord)
		}
	}

	return id, true, nil
}

// RecordIdentity lists serial in the records' identity record if it is not
// listed yet, durably, before the agent serves anything under it.
func RecordIdentity(recs *records.Store, serial string) error {
	if !certSerialRe.MatchString(serial) {
		return fmt.Errorf("malformed serial %q", serial)
	}

	id, found, err := readIdentity(recs)
	if err != nil {
		return err
	}

	if found && slices.Contains(id.Serials, serial) {
		return nil
	}

	id.Schema = ownershipSchema
	id.Serials = append(id.Serials, serial)

	b, err := json.Marshal(id)
	if err != nil {
		return err
	}

	return recs.Write(identityRecord, b)
}

// retireSet marks every serial of the identity record and moves the set
// aside under the latest. Records without an identity record are refused.
func retireSet(recs *records.Store) error {
	id, found, err := readIdentity(recs)
	if err != nil {
		return err
	}

	if !found {
		return errors.New("the records have no identity record")
	}

	return records.Retire(recs.Dir, id.Serials)
}

// ResumeRetirement finishes a retirement in progress at start: when any
// serial the records' identity record lists has a retirement mark (a stop
// after some marks, before the move), every listed serial is marked and the
// set moved aside. It reports whether the records were retired so; then the
// agent runs retired, whatever serial it runs with.
func ResumeRetirement(recs *records.Store) (bool, error) {
	id, found, err := readIdentity(recs)
	if err != nil || !found {
		return false, err
	}

	for _, s := range id.Serials {
		marked, err := records.Marked(recs.Dir, s)
		if err != nil {
			return false, err
		}

		if marked {
			return true, records.Retire(recs.Dir, id.Serials)
		}
	}

	return false, nil
}

// RetireBefore removes the agent's own documents for a confirmed retire
// grant, under the checks of a self-update: handed over, owning no document,
// no undecided apply, the revision above the ownership and the fence, no
// drift (no cluster document on the node), the confirmation still counting.
// The intent, marked as a retirement, is recorded before the patch and the
// revision fenced; Talos stops the agent once its document is gone, so a
// later instance (if its documents come back) or the records job decides it.
// started reports whether the intent was recorded.
func (n *Node) RetireBefore(ctx context.Context, until time.Time, revision int64, operation string) (started bool, err error) {
	if err := n.lock(ctx); err != nil {
		return false, err
	}
	defer n.unlock()

	if err := n.Records.Check(); err != nil {
		return false, err
	}

	var intent applyIntent

	if pending, err := n.readJSON(applyRecord, &intent); err != nil || pending {
		if err == nil {
			err = fmt.Errorf("the apply of revision %d has an uncertain outcome", intent.Revision)
		}

		return false, err
	}

	own, found, err := n.ownership()
	if err != nil {
		return false, err
	}

	if !found {
		return false, errors.New("the node has not been handed over")
	}

	if len(own.Docs) > 0 {
		return false, fmt.Errorf("the agent still owns %d documents", len(own.Docs))
	}

	if _, found, err := readIdentity(n.Records); err != nil || !found {
		if err == nil {
			err = errors.New("the records have no identity record")
		}

		return false, err
	}

	floor, err := n.fence()
	if err != nil {
		return false, err
	}

	if revision <= max(own.Revision, floor) {
		return false, fmt.Errorf("revision %d is not newer than %d", revision, max(own.Revision, floor))
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return false, err
	}

	cur, err := parseDocs(cfg)
	if err != nil {
		return false, err
	}

	if d := n.drift(own, cur); len(d) > 0 {
		return false, fmt.Errorf("%w: %s", ErrDrift, strings.Join(d, ", "))
	}

	before, sent := map[string]string{}, map[string]string{}

	var dels bytes.Buffer

	agentKey, initKey := n.selfKeys()
	for _, k := range []string{agentKey, initKey} {
		if cur[k] == "" {
			continue // gone already
		}

		before[k], sent[k] = cur[k], ""

		kind, name, _ := strings.Cut(k, "/")

		del, err := yaml.Marshal(map[string]string{"apiVersion": "v1alpha1", "kind": kind, "name": name, "$patch": "delete"})
		if err != nil {
			return false, err
		}

		dels.WriteString("---\n")
		dels.Write(del)
	}

	if !until.IsZero() && !time.Now().Before(until) {
		return false, errors.New("the confirmation expired before the retirement")
	}

	boot, err := n.Talos.BootID(ctx, "")
	if err != nil {
		return false, err
	}

	intent = applyIntent{Schema: ownershipSchema, Revision: revision, Before: before, Sent: sent, BootID: boot, At: time.Now().UTC(), Self: true, Retire: true, Operation: operation}

	if floor < revision {
		if err := n.writeJSON(fenceRecord, fence{Schema: ownershipSchema, Revision: revision}); err != nil {
			return false, err
		}
	}

	// the documents are gone already: decided without a patch
	if len(sent) == 0 {
		return false, n.decideSelf(intent, wire.OpCompleted, "")
	}

	if err := n.writeJSON(applyRecord, intent); err != nil {
		return false, err
	}

	started = true

	pctx := ctx
	if !until.IsZero() {
		pctx = talos.WithApplyBefore(ctx, until)
	}

	if err := n.Talos.Patch(pctx, "", dels.Bytes()); errors.Is(err, talos.ErrApplyDeadline) {
		if rerr := n.Records.Remove(applyRecord); rerr != nil {
			return started, rerr
		}

		return false, err
	} else if err != nil {
		return started, fmt.Errorf("retirement %s: %w", operation, err)
	}

	// Talos stops this instance once its document is gone: from here on the
	// records job may be the one that decides the intent
	if cfg, err = n.Talos.MachineConfig(ctx, ""); err != nil {
		return started, err
	}

	now, err := parseDocs(cfg)
	if err != nil {
		return started, err
	}

	for k := range sent {
		if now[k] != "" {
			return started, fmt.Errorf("retirement %s: the node still holds %s afterwards", operation, k)
		}
	}

	return started, n.decideSelf(intent, wire.OpCompleted, "")
}

// retire runs a confirmed retire grant: recorded as started (a self apply)
// before anything is checked, decided as a self-update; once completed, the
// records are retired and the agent refuses everything from then on. One
// refused or failed leaves the agent unretired and answering.
func (g *Granter) retire(ctx context.Context, gr wire.Grant, op wire.Operation, until time.Time) (wire.Operation, error) {
	op.State, op.Self, op.Retire = wire.OpStarted, true, true
	if err := g.writeOp(op); err != nil {
		return wire.Operation{}, err
	}

	started, err := g.Node.RetireBefore(ctx, until, gr.Revision, gr.Operation)

	switch {
	case err == nil:
		op.State, op.Error = wire.OpCompleted, ""
	case !started:
		op.State, op.Error = wire.OpRefused, err.Error()
	default:
		op.State, op.Error = wire.OpUncertain, err.Error()
	}

	if err := g.writeOp(op); err != nil {
		return op, err
	}

	if err := g.prune(); err != nil {
		return op, err
	}

	if op.State != wire.OpCompleted {
		return op, nil
	}

	return op, g.finishRetire()
}

// finishRetire retires the records of a retirement decided completed; from
// then on the agent refuses everything.
func (g *Granter) finishRetire() error {
	if err := retireSet(g.Records); err != nil {
		return fmt.Errorf("retiring the records: %w", err)
	}

	g.retired.Store(true)

	return nil
}

// RetireRecords is the records job's --retire (plan 04, step 6): it retires
// a set as the agent does, for a node whose agent could not. The caller (the
// CLI) checks that no agent document of the cluster is on the node; the job
// checks the rest: the set has an identity record, which lists serial when
// one is given (the serial the leader journaled; another generation's records
// are refused), and an apply intent there has settled (boot is the node's
// boot id, "" when unknown: then only ApplySettle after it was sent counts).
// A retirement's intent is decided completed first (its documents are gone,
// the caller checked). It returns the retired report.
func RetireRecords(recs *records.Store, serial, boot string, now time.Time) (RecordsReport, error) {
	if serial != "" && !certSerialRe.MatchString(serial) {
		return RecordsReport{}, fmt.Errorf("malformed serial %q", serial)
	}

	if _, err := os.Stat(recs.Dir); err != nil {
		// a retry once the set is moved aside: retired already; without a
		// serial, no records of the cluster are left to retire
		if marked, merr := records.Marked(recs.Dir, serial); merr == nil && (marked || serial == "" && errors.Is(err, fs.ErrNotExist)) {
			return RetiredReport(), nil
		}

		return RecordsReport{}, fmt.Errorf("records: %w", err)
	}

	id, found, err := readIdentity(recs)
	if err != nil {
		return RecordsReport{}, err
	}

	if !found {
		return RecordsReport{}, errors.New("the records have no identity record: not retired")
	}

	if serial != "" && !slices.Contains(id.Serials, serial) {
		return RecordsReport{}, fmt.Errorf("the records do not list serial %s: another generation's", serial)
	}

	n := &Node{Records: recs}
	g := &Granter{Records: recs}

	var intent applyIntent

	pending, err := n.readJSON(applyRecord, &intent)
	if err != nil {
		return RecordsReport{}, err
	}

	if pending {
		settled := boot != "" && boot != intent.BootID || !now.Before(intent.At.Add(ApplySettle))
		if !settled {
			return RecordsReport{}, fmt.Errorf("the apply of revision %d may still land until %s", intent.Revision, intent.At.Add(ApplySettle).UTC().Format(time.RFC3339))
		}

		if intent.Retire {
			if op, found, err := g.readOp(intent.Operation); err != nil {
				return RecordsReport{}, err
			} else if found && op.State != wire.OpCompleted {
				op.State, op.Error = wire.OpCompleted, "decided by the records job: the agent's documents are gone"
				if err := g.writeOp(op); err != nil {
					return RecordsReport{}, err
				}
			}

			if err := n.decideSelf(intent, wire.OpCompleted, ""); err != nil {
				return RecordsReport{}, err
			}
		}
	}

	if err := records.Retire(recs.Dir, id.Serials); err != nil {
		return RecordsReport{}, err
	}

	return RetiredReport(), nil
}

// JobResultSaved reports whether a job's result file exists: a retirement
// left behind that runs again (a `never` job on the next boot) replays it and
// does not retire whatever the records are by then.
func JobResultSaved(jobsDir, fsid, job string) bool {
	if job == "" || strings.ContainsAny(job, "/.") {
		return false
	}

	_, err := os.Stat(filepath.Join(jobsDir, fsid+"."+job+".result"))

	return err == nil
}

// CheckRecordsSerial refuses current records that do not list serial (a host's
// journaled serial): another generation's, which a job must neither suspend nor
// settle. No serial asks nothing.
func CheckRecordsSerial(recs *records.Store, serial string) error {
	if serial == "" {
		return nil
	}

	id, _, err := readIdentity(recs)
	if err != nil {
		return err
	}

	if !slices.Contains(id.Serials, serial) {
		return fmt.Errorf("the records do not list serial %s: another generation's", serial)
	}

	return nil
}

// RetiredRecords is the records job's read of a host whose records are not
// there: retired if serial (its journaled serial) has a retirement mark.
func RetiredRecords(dir, serial string) (RecordsReport, bool, error) {
	if serial == "" {
		return RecordsReport{}, false, nil
	}

	if !certSerialRe.MatchString(serial) {
		return RecordsReport{}, false, fmt.Errorf("malformed serial %q", serial)
	}

	marked, err := records.Marked(dir, serial)
	if err != nil || !marked {
		return RecordsReport{}, false, err
	}

	return RetiredReport(), true, nil
}

// RetiredReport is a retired set's report: nothing owned, nothing open, no
// apply intent.
func RetiredReport() RecordsReport {
	return RecordsReport{Version: wire.Version, Owned: map[string]string{}, Open: []wire.Operation{}, Intents: []wire.BridgeIntent{}, Retired: true}
}
