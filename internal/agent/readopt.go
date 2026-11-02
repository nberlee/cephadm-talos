package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"sort"
	"strings"

	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// readoptRecord holds a re-adoption (plan 03, step 7 slice D, item 9): what
// the agent took for which session and changes, so the same request gives the
// same receipt, and whether the session's activation ended the suspension.
const readoptRecord = "readopt"

type readoption struct {
	Schema  int    `json:"schema"`
	Session string `json:"session"`
	// Changes is the hash of the request's changes
	Changes   string            `json:"changes"`
	Revision  int64             `json:"revision"`
	Docs      map[string]string `json:"docs"`
	Activated bool              `json:"activated,omitempty"`
}

// changesHash is the SHA-256 of the changes' JSON (its keys sorted).
func changesHash(changes map[string]string) (string, error) {
	if changes == nil {
		changes = map[string]string{}
	}

	b, err := json.Marshal(changes)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:]), nil
}

func (n *Node) readoption() (readoption, bool, error) {
	var r readoption

	found, err := n.readJSON(readoptRecord, &r)
	if err != nil || !found {
		return readoption{}, false, err
	}

	if r.Schema != ownershipSchema || r.Docs == nil || !uuidRe.MatchString(r.Session) {
		return readoption{}, false, fmt.Errorf("record %s: damaged", readoptRecord)
	}

	return r, true, nil
}

// Readopt takes ownership of the node's cluster documents again for a
// recovery session: only if they are exactly the retained ownership with the
// recovery's changes. The records stay as they are; the new revision is above
// the ownership, the fence and every operation's. The agent stays suspended.
func (g *Granter) Readopt(ctx context.Context, session string, changes map[string]string) (wire.ReadoptReceipt, error) {
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-ctx.Done():
		return wire.ReadoptReceipt{}, errors.New("the agent is busy")
	}

	s, found, err := g.readSuspension()
	if err != nil {
		return wire.ReadoptReceipt{}, err
	}

	if !found || s.Session != session {
		return wire.ReadoptReceipt{}, fmt.Errorf("the agent is not suspended for recovery session %s", session)
	}

	if err := g.reconcile(ctx); err != nil {
		return wire.ReadoptReceipt{}, err
	}

	// nothing it started may still change the node
	if _, waiting, err := g.unfinished(ctx); err != nil {
		return wire.ReadoptReceipt{}, err
	} else if len(waiting) > 0 {
		return wire.ReadoptReceipt{}, fmt.Errorf("still waiting for %s", strings.Join(waiting, ", "))
	}

	maxOp, err := g.maxOpRevision()
	if err != nil {
		return wire.ReadoptReceipt{}, err
	}

	r, err := g.Node.readopt(ctx, session, changes, maxOp)
	if err != nil {
		return wire.ReadoptReceipt{}, err
	}

	return wire.ReadoptReceipt{Version: wire.Version, Session: session, Host: g.Channel.Self.Name, Revision: r.Revision, Docs: r.Docs}, nil
}

// maxOpRevision is the highest revision of the agent's operation records.
func (g *Granter) maxOpRevision() (int64, error) {
	names, err := g.Records.List("op-")
	if err != nil {
		return 0, err
	}

	var top int64

	for _, name := range names {
		op, found, err := g.readOp(strings.TrimPrefix(name, "op-"))
		if err != nil {
			return 0, err
		}

		if found && op.Revision > top {
			top = op.Revision
		}
	}

	return top, nil
}

// readopt is Readopt's part on the node, under its lock.
func (n *Node) readopt(ctx context.Context, session string, changes map[string]string, maxOp int64) (readoption, error) {
	if err := n.lock(ctx); err != nil {
		return readoption{}, err
	}
	defer n.unlock()

	if err := n.Records.Check(); err != nil {
		return readoption{}, err
	}

	var intent applyIntent

	if pending, err := n.readJSON(applyRecord, &intent); err != nil || pending {
		if err == nil {
			err = fmt.Errorf("the apply of revision %d has an uncertain outcome", intent.Revision)
		}

		return readoption{}, err
	}

	own, found, err := n.ownership()
	if err != nil {
		return readoption{}, err
	}

	if !found {
		return readoption{}, errors.New("the agent owns nothing to adopt again: it was never handed its node")
	}

	hash, err := changesHash(changes)
	if err != nil {
		return readoption{}, err
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return readoption{}, err
	}

	docs, err := parseDocs(cfg)
	if err != nil {
		return readoption{}, err
	}

	actual := map[string]string{}

	for k, h := range docs {
		kind, name, _ := strings.Cut(k, "/")
		if n.cluster(kind, name) && !n.handoff(k) {
			actual[k] = h
		}
	}

	r, found, err := n.readoption()
	if err != nil {
		return readoption{}, err
	}

	// the same request again: the same receipt, while the node is unchanged
	if found && r.Session == session {
		switch {
		case r.Changes != hash:
			return readoption{}, errors.New("this session's re-adoption was made with other changes")
		case !maps.Equal(actual, r.Docs):
			return readoption{}, fmt.Errorf("the node changed since this session's re-adoption: %s", docDiff(r.Docs, actual))
		case own.Revision != r.Revision:
			own = Ownership{Schema: ownershipSchema, Revision: r.Revision, Docs: r.Docs, ApprovalSerial: own.ApprovalSerial}
			if err := n.writeJSON(ownershipRecord, own); err != nil {
				return readoption{}, err
			}
		}

		return r, nil
	}

	expected := maps.Clone(own.Docs)

	for k, h := range changes {
		if h == "" {
			delete(expected, k)
		} else {
			expected[k] = h
		}
	}

	if !maps.Equal(actual, expected) {
		return readoption{}, fmt.Errorf("the node's cluster documents are not the agent's with the recovery's changes: %s", docDiff(expected, actual))
	}

	fence, err := n.fence()
	if err != nil {
		return readoption{}, err
	}

	r = readoption{Schema: ownershipSchema, Session: session, Changes: hash, Revision: max(own.Revision, fence, maxOp) + 1, Docs: actual}

	// the record first: a retry finds it and writes the same ownership
	if err := n.writeJSON(readoptRecord, r); err != nil {
		return readoption{}, err
	}

	return r, n.writeJSON(ownershipRecord, Ownership{Schema: ownershipSchema, Revision: r.Revision, Docs: actual, ApprovalSerial: own.ApprovalSerial})
}

// docDiff names the documents that differ between want and have.
func docDiff(want, have map[string]string) string {
	var out []string

	for k, h := range want {
		switch hv, ok := have[k]; {
		case !ok:
			out = append(out, k+" missing")
		case hv != h:
			out = append(out, k+" changed")
		}
	}

	for k := range have {
		if _, ok := want[k]; !ok {
			out = append(out, k+" added")
		}
	}

	sort.Strings(out)

	return strings.Join(out, ", ")
}

// Activate ends the suspension of a re-adopted agent: the session's
// re-adoption at that revision, its ownership unchanged, and no open bridge
// intent after the epoch the resumption recorded before it restarted the
// mgrs (the others are released: no process that made them is left). The
// same call again succeeds.
func (g *Granter) Activate(ctx context.Context, a wire.Activate) error {
	select {
	case g.mu <- struct{}{}:
		defer func() { <-g.mu }()
	case <-ctx.Done():
		return errors.New("the agent is busy")
	}

	r, found, err := g.Node.readoption()
	if err != nil {
		return err
	}

	if !found || r.Session != a.Session || r.Revision != a.Revision {
		return fmt.Errorf("no re-adoption at revision %d for recovery session %s", a.Revision, a.Session)
	}

	s, suspended, err := g.readSuspension()
	if err != nil {
		return err
	}

	if !suspended {
		if r.Activated {
			return nil
		}

		return errors.New("the agent is not suspended")
	}

	if s.Session != a.Session {
		return fmt.Errorf("suspended for recovery session %s", s.Session)
	}

	own, _, err := g.Node.ownership()
	if err != nil {
		return err
	}

	if own.Revision != r.Revision {
		return fmt.Errorf("the ownership is at revision %d, not the re-adoption's %d", own.Revision, r.Revision)
	}

	intents, err := OpenIntents(g.Records)
	if err != nil {
		return err
	}

	for _, in := range intents {
		if in.Epoch > a.Epoch {
			return fmt.Errorf("the bridge call %s (dispatch %s) is of mgr map epoch %d, after the resumption's %d", in.Call, in.Dispatch, in.Epoch, a.Epoch)
		}
	}

	for _, in := range intents {
		if err := g.Records.Remove(intentRecord + in.Dispatch); err != nil && !errors.Is(err, records.ErrNotFound) {
			return err
		}
	}

	if !r.Activated {
		r.Activated = true
		if err := g.Node.writeJSON(readoptRecord, r); err != nil {
			return err
		}
	}

	if err := g.Records.Remove(suspensionRecord); err != nil && !errors.Is(err, records.ErrNotFound) {
		return err
	}

	return nil
}

// HandleReadopt serves POST /v1/readopt from the operator's certificate.
func (g *Granter) HandleReadopt(w http.ResponseWriter, r *http.Request) {
	if err := g.operatorOf(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	var req wire.Readopt

	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil || req.Version != wire.Version || req.FSID != g.Channel.Self.FSID || req.Host != g.Channel.Self.Name || !uuidRe.MatchString(req.Session) {
		http.Error(w, "malformed re-adoption", http.StatusBadRequest)

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), suspendWait)
	defer cancel()

	rec, err := g.Readopt(ctx, req.Session, req.Changes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

// HandleActivate serves POST /v1/activate from the operator's certificate.
func (g *Granter) HandleActivate(w http.ResponseWriter, r *http.Request) {
	if err := g.operatorOf(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)

		return
	}

	var req wire.Activate

	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil || req.Version != wire.Version || req.FSID != g.Channel.Self.FSID || req.Host != g.Channel.Self.Name || !uuidRe.MatchString(req.Session) || req.Revision < 1 {
		http.Error(w, "malformed activation", http.StatusBadRequest)

		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), suspendWait)
	defer cancel()

	if err := g.Activate(ctx, req); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}
