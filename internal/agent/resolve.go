package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/wire"
)

// resolveTimeout bounds one resolve: the grant slot, the node's reads.
const resolveTimeout = time.Minute

// resolvedByOperator is the error and output of a job the operator failed.
const resolvedByOperator = "resolved by the operator"

// Resolve fails a job whose outcome is uncertain (plan 04, step 4), for the
// operator: under the grant slot, only once the job cannot still run (no
// apply intent open, its container ended), and only if its result is still
// missing after that; a result found is recorded as any outcome is. Only
// failed: a done preparation needs its result, which the operator cannot
// supply. The job's tombstone comes first, so it can never run.
func (g *Granter) Resolve(ctx context.Context, id string) (wire.Operation, error) {
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-ctx.Done():
		return wire.Operation{}, ctx.Err()
	}

	op, found, err := g.readOp(id)
	if err != nil {
		return wire.Operation{}, err
	}

	switch {
	case !found:
		return wire.Operation{}, fmt.Errorf("no operation %s", id)
	case op.Job == nil:
		return op, fmt.Errorf("operation %s is not a job's", id)
	case op.State != wire.OpUncertain && op.State != wire.OpStarted:
		return op, fmt.Errorf("operation %s is %s, not uncertain", id, op.State)
	}

	snap, err := g.Node.Snapshot(ctx)
	if err != nil {
		return op, err
	}

	if snap.Intent {
		return op, errors.New("an apply's outcome is still open on the node: the job's document may still change")
	}

	ended, err := g.Node.ended(ctx, op.Job.Doc)
	if err != nil {
		return op, err
	}

	if !ended {
		return op, fmt.Errorf("the job's container %s runs or may still start", op.Job.Doc)
	}

	// read again after it ended: the job writes its result right before it exits
	st, res, err := g.Node.JobOutcome(ctx, *op.Job)
	if err != nil {
		return op, err
	}

	switch st {
	case "":
		return op, fmt.Errorf("the job's container %s runs or may still start", op.Job.Doc)
	case wire.OpUncertain:
		if err := g.Records.Write(tombRecord+op.Job.ID, []byte(op.Job.Inputs)); err != nil {
			return op, err
		}

		if err := g.Node.writeJobFile(op.Job.ID, "tombstone", op.Job.Inputs); err != nil {
			return op, err
		}

		op.State, op.Result, op.Error = wire.OpFailed, &wire.JobResult{RC: -1, Output: resolvedByOperator}, resolvedByOperator
	default:
		op.State, op.Result, op.Error = st, res, "the job ended"
	}

	return op, g.writeOp(op)
}

// Unresolved lists the jobs whose outcome is not known yet, for the operator.
func (g *Granter) Unresolved() ([]wire.Operation, error) {
	names, err := g.Records.List("op-")
	if err != nil {
		return nil, err
	}

	out := []wire.Operation{}

	for _, n := range names {
		op, found, err := g.readOp(strings.TrimPrefix(n, "op-"))
		if err != nil {
			return nil, err
		}

		if found && op.Job != nil && (op.State == wire.OpStarted || op.State == wire.OpUncertain) {
			out = append(out, op)
		}
	}

	return out, nil
}

// HandleResolve serves POST /v1/resolve from the operator certificate, also
// while the agent is suspended or its revocation list is stale; GET lists the
// jobs it could resolve.
func (g *Granter) HandleResolve(w http.ResponseWriter, r *http.Request) {
	if err := g.operatorOf(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	if r.Method == http.MethodGet {
		ops, err := g.Unresolved()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ops)

		return
	}

	var req wire.Resolve

	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil || req.Version != wire.Version || req.FSID != g.Channel.Self.FSID || req.Host != g.Channel.Self.Name ||
		!operationRe.MatchString(req.Operation) {
		http.Error(w, "malformed resolve", http.StatusBadRequest)

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), resolveTimeout)
	defer cancel()

	op, err := g.Resolve(ctx, req.Operation)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(op)
}
