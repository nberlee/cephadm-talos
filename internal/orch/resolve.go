package orch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// listTimeout bounds asking one agent for its unresolved jobs (ps).
var listTimeout = 10 * time.Second

// Resolve asks a host's agent to fail a job whose outcome is uncertain (plan
// 04, step 4): the agent does it only once the job cannot still run, and
// records a result that appeared meanwhile instead. The leader's next query
// then finds the job ended and the operation it belongs to moves on.
func (o *Orch) Resolve(ctx context.Context, host, operation string) error {
	h, err := o.resolveHost(host)
	if err != nil {
		return err
	}

	var op wire.Operation
	if err := o.callOperator(ctx, h, "/v1/resolve", wire.Resolve{Version: wire.Version, FSID: o.St.FSID, Host: h.Name, Operation: operation}, &op); err != nil {
		return fmt.Errorf("%s: %w", h.Name, err)
	}

	rc := ""
	if op.Result != nil {
		rc = fmt.Sprintf(" (rc %d)", op.Result.RC)
	}

	o.printf("%s on %s: %s%s: %s\n", op.Operation, h.Name, op.State, rc, op.Error)

	return nil
}

// ListUnresolved prints the jobs of a host's agent whose outcome is not known.
func (o *Orch) ListUnresolved(ctx context.Context, host string) error {
	h, err := o.resolveHost(host)
	if err != nil {
		return err
	}

	ops, err := o.unresolvedJobs(ctx, h)
	if err != nil {
		return fmt.Errorf("%s: %w", h.Name, err)
	}

	if len(ops) == 0 {
		o.printf("%s: no job with an unknown outcome\n", h.Name)
	}

	for _, op := range ops {
		o.printf("%s on %s: %s, job %s (cephadm-talos resolve %s %s)\n", op.Operation, h.Name, op.State, op.Job.Doc, h.Name, op.Operation)
	}

	return nil
}

func (o *Orch) resolveHost(host string) (state.Host, error) {
	if o.St.Agent == nil {
		return state.Host{}, errors.New("the cluster has no agents")
	}

	h, ok := o.St.Host(host)
	if !ok {
		return state.Host{}, fmt.Errorf("no host %s", host)
	}

	return h, nil
}

// unresolvedJobs asks an agent for its jobs whose outcome is not known.
func (o *Orch) unresolvedJobs(ctx context.Context, h state.Host) ([]wire.Operation, error) {
	cl, err := o.operatorClient(h)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, agentURL(h, "/v1/resolve"), nil)
	if err != nil {
		return nil, err
	}

	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the agent answered %d", resp.StatusCode)
	}

	var ops []wire.Operation
	if err := json.Unmarshal(raw, &ops); err != nil {
		return nil, err
	}

	return ops, nil
}

// psUnresolved adds the agents' jobs whose outcome is not known to ps.
func (o *Orch) psUnresolved(ctx context.Context, w io.Writer) {
	if o.St.Agent == nil || !o.Managed() {
		return
	}

	for _, h := range o.St.Hosts {
		lctx, cancel := context.WithTimeout(ctx, listTimeout)
		ops, err := o.unresolvedJobs(lctx, h)

		cancel()

		if err != nil {
			fmt.Fprintf(w, "%s: the agent's unresolved jobs: %v\n", h.Name, err)

			continue
		}

		for _, op := range ops {
			fmt.Fprintf(w, "unresolved job: %s on %s, %s (cephadm-talos resolve %s %s)\n", op.Operation, h.Name, op.State, h.Name, op.Operation)
		}
	}
}
