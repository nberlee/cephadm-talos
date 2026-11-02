package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/config/config"
	"github.com/siderolabs/talos/pkg/machinery/config/configloader"
	"github.com/siderolabs/talos/pkg/machinery/config/encoder"
	"github.com/siderolabs/talos/pkg/machinery/resources/block"
	"gopkg.in/yaml.v3"

	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// The agent is the only writer of its node's Ceph documents (plan 03, item 7).
// It records the hash of every document it owns; before it applies anything it
// checks that each owned document is unchanged and that no Ceph document it
// did not write has appeared. Talos has no conditional apply, so this is an
// operational rule: the check and the apply are not atomic.

// Record names in the agent's records directory.
const (
	ownershipRecord = "ownership"
	applyRecord     = "apply"
	// approvalRecord is the highest approval the agent verified, with the disk
	// entries jobs used (plan 03, step 6c); it is never pruned
	approvalRecord = "approval"
)

// ownershipSchema is the version of the ownership and apply records.
const ownershipSchema = 1

// Doc is one machine config document of a revision: its YAML, or a removal
// when YAML is nil.
type Doc struct {
	Kind string
	Name string
	YAML []byte
}

// Key is the document's identity in the records, "<kind>/<name>".
func (d Doc) Key() string { return d.Kind + "/" + d.Name }

// Ownership is what the agent owns on its node: the hash of every document,
// after the revision that last changed them.
type Ownership struct {
	Schema   int               `json:"schema"`
	Revision int64             `json:"revision"`
	Docs     map[string]string `json:"docs"` // key -> hash
	// ApprovalSerial is the highest approval the agent recorded: an approval
	// record missing or older than it blocks admission (plan 03, step 6c)
	ApprovalSerial int64 `json:"approval_serial,omitempty"`
}

// applyIntent is written before an apply and removed after its outcome is
// recorded; one left behind means the outcome is uncertain.
type applyIntent struct {
	Schema   int               `json:"schema"`
	Revision int64             `json:"revision"`
	Before   map[string]string `json:"before"` // the ownership it started from
	Sent     map[string]string `json:"sent"`   // key -> hash of the sent document, "" for a removal
	// BootID and At say when the apply was sent: on another boot, or after
	// ApplySettle, an apply that is not visible will not become visible
	BootID string    `json:"boot_id"`
	At     time.Time `json:"at"`
}

// ApplySettle is how long after an apply was sent its absence from the config
// counts as proof that it did not happen, on the same boot. Talos handles an
// apply synchronously and finishes it even when the caller is gone (its
// config update does not follow the caller's context), well within this.
const ApplySettle = 10 * time.Minute

// NodeStatus is the ownership part of the status record.
type NodeStatus struct {
	// State: "unowned" before the handoff, "owned", "drift" (changed, missing or
	// foreign documents: nothing is applied), "uncertain" (an apply whose
	// outcome was not recorded), or "error" (the config or records unreadable)
	State    string   `json:"state"`
	Revision int64    `json:"revision,omitempty"`
	Owned    int      `json:"owned,omitempty"`
	Drift    []string `json:"drift,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// maxDrift is how many drift entries the status lists.
const maxDrift = 32

// ErrNotApplied means Apply refused before anything reached Talos.
var ErrNotApplied = errors.New("not applied")

// ErrDrift means the node's documents are not the ones the agent recorded.
var ErrDrift = errors.New("drift")

// Node is the agent's own node: its Talos API through the local socket and
// its records.
type Node struct {
	Talos interface {
		MachineConfig(ctx context.Context, node string) (string, error)
		Patch(ctx context.Context, node string, patches ...[]byte) error
		Disks(ctx context.Context, node string) ([]*block.Disk, error)
		BootID(ctx context.Context, node string) (string, error)
		Instance(ctx context.Context, node, name string) (string, error)
		InstanceOwners(ctx context.Context, node string) ([]string, error)
		CurrentInstances(ctx context.Context, node string) (map[string]string, error)
		ContainerStatuses(ctx context.Context, node string) (map[string]containers.ContainerStatusSpec, error)
		RestartInstance(ctx context.Context, node, id string) error
		RebootNow(ctx context.Context, node string) error
		Hostname(ctx context.Context, node string) (string, error)
		Addresses(ctx context.Context, node string) ([]string, error)
		Logs(ctx context.Context, node, name string) (string, error)
	}
	Records *records.Store
	// JobsDir is where the node's jobs write their claims and results (the
	// cephadm-talos volume's jobs directory)
	JobsDir string
	// Policy admits the documents Apply applies; nil admits nothing
	Policy *Policy
	// FSID is the cluster's, Host the agent's host
	FSID string
	Host string

	// sem serializes Adopt, Apply, Fence, Status and Report: each reads and
	// writes the records and the config as one step; waiting for it ends with
	// the caller's context
	sem  chan struct{}
	once sync.Once
}

func (n *Node) lock(ctx context.Context) error {
	n.once.Do(func() { n.sem = make(chan struct{}, 1) })

	select {
	case n.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("the node is busy: %w", ctx.Err())
	}
}

func (n *Node) unlock() { <-n.sem }

func (n *Node) docName(typ string) string {
	return (&state.State{FSID: n.FSID}).DocName(state.Daemon{Type: typ, ID: n.Host})
}

// prefix is the name prefix of the cluster's ContainerConfig documents.
func (n *Node) prefix() string { return "ceph-" + (&state.State{FSID: n.FSID}).Short() + "-" }

// admit runs the admission policy over a revision's documents; without a
// policy nothing is applied. Errors name the document, never a value in it.
func (n *Node) admit(ctx context.Context, docs []Doc, typed map[string]typedDoc, cur, sent map[string]string) error {
	if n.Policy == nil {
		return errors.New("no admission policy: nothing is applied")
	}

	disks, err := n.Talos.Disks(ctx, "")
	if err != nil {
		return err
	}

	appr, err := n.approval()
	if err != nil {
		return err
	}

	uses := []diskUse{}
	f := facts{containers: map[string]bool{}, appr: appr, uses: &uses}

	for _, d := range disks {
		f.disks = append(f.disks, Disk{Serial: d.TypedSpec().Serial, Symlinks: d.TypedSpec().Symlinks})
	}

	// the node's containers after this revision: what it has and adds, minus removals
	for k := range cur {
		if name, ok := strings.CutPrefix(k, "ContainerConfig/"); ok {
			f.containers[name] = true
		}
	}

	for k, h := range sent {
		if name, ok := strings.CutPrefix(k, "ContainerConfig/"); ok {
			f.containers[name] = h != ""
		}
	}

	if err := n.Policy.check(docs, typed, f); err != nil {
		return err
	}

	// the whole revision passed: each job gets a disk entry of its own (one it
	// reserved before, on a retry, or one no job used), all checked before the
	// reservations are written, in one record, before anything is applied
	if len(uses) == 0 {
		return nil
	}

	_, rec, err := n.approvalRecord()
	if err != nil {
		return err
	}

	if rec.Uses == nil {
		rec.Uses = map[string]diskUseRecord{}
	}

	picked := map[string]bool{}

	for _, u := range uses {
		var pick string

		for _, e := range u.candidates {
			k := e.Key()
			if have, used := rec.Uses[k]; used && have.Job == u.job && have.Inputs == u.inputs && !picked[k] {
				pick = k // its own reservation

				break
			}
		}

		for _, e := range u.candidates {
			if _, used := rec.Uses[e.Key()]; pick == "" && !used && !picked[e.Key()] {
				pick = e.Key()
			}
		}

		if pick == "" {
			return fmt.Errorf("no unused approval to %s: every entry was used by another job", u.action)
		}

		picked[pick] = true
		rec.Uses[pick] = diskUseRecord{Entry: pick, Job: u.job, Inputs: u.inputs}
	}

	return n.writeJSON(approvalRecord, rec)
}

// diskUseRecord is a disk entry of an approval, reserved for the job that used it.
type diskUseRecord struct {
	Entry  string `json:"entry"`
	Job    string `json:"job"`
	Inputs string `json:"inputs"`
}

// approvalStore is the recorded highest approval and the disk entries jobs
// used, one record.
type approvalStore struct {
	Signed approval.Signed          `json:"signed"`
	Uses   map[string]diskUseRecord `json:"uses,omitempty"`
}

// approvalRecord reads the recorded approval, verified again, and checks it
// against the ownership's serial: a record missing or older than what the
// agent recorded before blocks, and never resets what was used.
func (n *Node) approvalRecord() (*approval.Approval, approvalStore, error) {
	var rec approvalStore

	if n.Policy == nil {
		return nil, rec, errors.New("no admission policy")
	}

	own, owned, err := n.ownership()
	if err != nil {
		return nil, rec, err
	}

	found, err := n.readJSON(approvalRecord, &rec)
	if err != nil {
		return nil, rec, err
	}

	if !found {
		if owned && own.ApprovalSerial > 0 {
			return nil, rec, fmt.Errorf("the approval record is missing (the agent recorded approval %d)", own.ApprovalSerial)
		}

		return nil, rec, nil
	}

	a, err := approval.Verify(n.Policy.ApprovalKey, rec.Signed, n.FSID)
	if err != nil {
		return nil, rec, fmt.Errorf("the recorded approval: %w", err)
	}

	if owned && a.Serial < own.ApprovalSerial {
		return nil, rec, fmt.Errorf("the recorded approval %d is older than %d", a.Serial, own.ApprovalSerial)
	}

	return &a, rec, nil
}

// approval returns the highest approval the agent verified, nil before any.
func (n *Node) approval() (*approval.Approval, error) {
	a, _, err := n.approvalRecord()

	return a, err
}

// Approval is the highest approval the agent verified, for checks outside a
// grant (the admin socket queries).
func (n *Node) Approval(ctx context.Context) (*approval.Approval, error) {
	if err := n.lock(ctx); err != nil {
		return nil, err
	}
	defer n.unlock()

	return n.approval()
}

// RecordApproval verifies an approval a grant carries and records it if it is
// higher than the agent's, keeping the entries jobs used; a lower one is
// refused: an agent never goes back.
func (n *Node) RecordApproval(ctx context.Context, s approval.Signed) error {
	if err := n.lock(ctx); err != nil {
		return err
	}
	defer n.unlock()

	if n.Policy == nil || n.Policy.ApprovalKey == "" {
		return errors.New("no approval key: the agent admits no approval")
	}

	a, err := approval.Verify(n.Policy.ApprovalKey, s, n.FSID)
	if err != nil {
		return err
	}

	cur, rec, err := n.approvalRecord()
	if err != nil {
		return err
	}

	if cur != nil && a.Serial < cur.Serial {
		return fmt.Errorf("approval %d is older than the agent's %d", a.Serial, cur.Serial)
	}

	if cur == nil || a.Serial > cur.Serial {
		rec.Signed = s
		if err := n.writeJSON(approvalRecord, rec); err != nil {
			return err
		}
	}

	// the ownership remembers the serial, so a lost record is noticed; an
	// equal one repairs a serial the ownership lost
	own, owned, err := n.ownership()
	if err != nil || !owned || own.ApprovalSerial >= a.Serial {
		return err
	}

	own.ApprovalSerial = a.Serial

	return n.writeJSON(ownershipRecord, own)
}

// handoff reports whether a document stays the CLI's: the agent's own
// document, its records-init and their volume (plan 03, item 11).
func (n *Node) handoff(key string) bool {
	switch key {
	case "ContainerConfig/" + n.docName("agent"),
		"ContainerConfig/" + n.docName("records-init"),
		"UserVolumeConfig/cephadm-talos":
		return true
	}

	return false
}

// cluster reports whether a document belongs to the cluster: what the agent
// owns after the handoff, or a foreign document if it does not own it.
func (n *Node) cluster(kind, name string) bool {
	switch kind {
	case "ContainerConfig":
		return strings.HasPrefix(name, n.prefix())
	case "EtcFileConfig":
		return strings.HasPrefix(name, "ceph/")
	case "UserVolumeConfig":
		return name == "ceph" || name == "cephadm-talos"
	}

	return false
}

// parseDocs reads a machine config's named documents through Talos's config
// types and hashes each in Talos's own encoding, keyed by kind/name. Talos
// re-encodes every document that way when it applies a patch, so a document
// nobody changed keeps its hash across applies of other documents.
func parseDocs(cfg string) (map[string]string, error) {
	docs, err := typedDocs([]byte(cfg))
	if err != nil {
		// the decoder's message may quote a value, a key among them
		return nil, errors.New("machine config: does not decode")
	}

	out := make(map[string]string, len(docs))
	for k, d := range docs {
		out[k] = d.hash
	}

	return out, nil
}

// typedDoc is one named document, decoded and in Talos's encoding.
type typedDoc struct {
	doc  config.Document
	yaml []byte
	hash string
}

// typedDocs decodes YAML through Talos's config loader, which knows every
// document kind, refuses unknown fields and `$patch` directives, and
// re-encodes each named document.
func typedDocs(data []byte) (map[string]typedDoc, error) {
	p, err := configloader.NewFromBytes(data)
	if err != nil {
		return nil, err
	}

	out := map[string]typedDoc{}

	for _, d := range p.Documents() {
		nd, ok := d.(config.NamedDocument)
		if !ok || nd.Name() == "" {
			continue // the v1alpha1 document and unnamed ones
		}

		b, err := encoder.NewEncoder(d, encoder.WithComments(encoder.CommentsDisabled)).Encode()
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", d.Kind(), nd.Name(), err)
		}

		var m map[string]any
		if err := yaml.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("%s %s: %w", d.Kind(), nd.Name(), err)
		}

		h, err := hashDoc(m)
		if err != nil {
			return nil, err
		}

		k := d.Kind() + "/" + nd.Name()
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("%s twice", k)
		}

		out[k] = typedDoc{doc: d, yaml: b, hash: h}
	}

	return out, nil
}

// errNotYAML is the error for a document that does not parse; the parser's
// message may quote the document.
var errNotYAML = errors.New("not YAML")

// checkDoc validates a revision's document: exactly one YAML document, of the
// kind and name the Doc says, in Talos's encoding.
func checkDoc(d Doc) (typedDoc, error) {
	n := 0

	dec := yaml.NewDecoder(bytes.NewReader(d.YAML))

	for {
		var v any

		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return typedDoc{}, errNotYAML
		}

		if v != nil {
			n++
		}
	}

	if n != 1 {
		return typedDoc{}, fmt.Errorf("%d YAML documents, want 1", n)
	}

	docs, err := typedDocs(d.YAML)
	if err != nil {
		// the decoder's message may quote a value, a key among them
		return typedDoc{}, errors.New("not a valid Talos document")
	}

	td, ok := docs[d.Key()]
	if len(docs) != 1 || !ok {
		return typedDoc{}, errors.New("the YAML is not this document")
	}

	return td, nil
}

// hashDoc hashes a document's canonical form: JSON with sorted keys.
func hashDoc(doc any) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:]), nil
}

// drift lists what differs from the ownership: owned documents changed or
// missing, and cluster documents the agent neither owns nor leaves to the CLI.
func (n *Node) drift(own Ownership, docs map[string]string) []string {
	var out []string

	for k, h := range own.Docs {
		switch cur, ok := docs[k]; {
		case !ok:
			out = append(out, "missing "+k)
		case cur != h:
			out = append(out, "changed "+k)
		}
	}

	for k := range docs {
		kind, name, _ := strings.Cut(k, "/")
		if _, owned := own.Docs[k]; !owned && n.cluster(kind, name) && !n.handoff(k) {
			out = append(out, "foreign "+k)
		}
	}

	sort.Strings(out)

	return out
}

func (n *Node) readJSON(name string, v any) (bool, error) {
	b, err := n.Records.Read(name)
	if errors.Is(err, records.ErrNotFound) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("record %s: %w", name, err)
	}

	return true, nil
}

func (n *Node) writeJSON(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	return n.Records.Write(name, b)
}

// ownership reads the ownership record; found is false before the handoff.
func (n *Node) ownership() (Ownership, bool, error) {
	var own Ownership

	found, err := n.readJSON(ownershipRecord, &own)
	if err != nil || !found {
		return Ownership{}, found, err
	}

	if own.Schema != ownershipSchema || own.Docs == nil {
		return Ownership{}, false, fmt.Errorf("record %s: schema %d, want %d", ownershipRecord, own.Schema, ownershipSchema)
	}

	return own, true, nil
}

// Status reports the node's ownership state.
func (n *Node) Status(ctx context.Context) NodeStatus {
	if err := n.lock(ctx); err != nil {
		return NodeStatus{State: "busy", Error: err.Error()}
	}
	defer n.unlock()

	st, _, _ := n.statusLocked(ctx)

	return st
}

// statusLocked derives the status, with the ownership and the config's
// documents it was derived from (nil when it could not read them).
func (n *Node) statusLocked(ctx context.Context) (NodeStatus, Ownership, map[string]string) {
	if err := n.Records.Check(); err != nil {
		return NodeStatus{State: "error", Error: err.Error()}, Ownership{}, nil
	}

	var intent applyIntent

	pending, err := n.readJSON(applyRecord, &intent)
	if err != nil {
		return NodeStatus{State: "error", Error: err.Error()}, Ownership{}, nil
	}

	own, found, err := n.ownership()
	if err != nil {
		return NodeStatus{State: "error", Error: err.Error()}, Ownership{}, nil
	}

	if pending {
		return NodeStatus{State: "uncertain", Revision: intent.Revision, Owned: len(own.Docs)}, own, nil
	}

	if !found {
		return NodeStatus{State: "unowned"}, own, nil
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return NodeStatus{State: "error", Revision: own.Revision, Owned: len(own.Docs), Error: err.Error()}, own, nil
	}

	docs, err := parseDocs(cfg)
	if err != nil {
		return NodeStatus{State: "error", Revision: own.Revision, Owned: len(own.Docs), Error: err.Error()}, own, nil
	}

	st := NodeStatus{State: "owned", Revision: own.Revision, Owned: len(own.Docs)}
	if d := n.drift(own, docs); len(d) > 0 {
		// the status record stays small (MaxRecord)
		if len(d) > maxDrift {
			d = append(d[:maxDrift], fmt.Sprintf("and %d more", len(d)-maxDrift))
		}

		st.State, st.Drift = "drift", d
	}

	return st, own, docs
}

// Report tells the leader what the node owns, its drift, the cluster's
// containers it has and its disks (wire.NodeReport).
func (n *Node) Report(ctx context.Context) (wire.NodeReport, error) {
	if err := n.lock(ctx); err != nil {
		return wire.NodeReport{}, err
	}
	defer n.unlock()

	// status, ownership and documents from one look at the records and the config
	st, own, cur := n.statusLocked(ctx)

	r := wire.NodeReport{Version: wire.Version, State: st.State, Revision: st.Revision, Drift: st.Drift, Owned: map[string]string{}, Containers: []string{}, Disks: []wire.Disk{}}

	if st.State == "error" {
		return r, errors.New(st.Error)
	}

	for k, h := range own.Docs {
		r.Owned[k] = h
	}

	for k := range cur {
		if name, ok := strings.CutPrefix(k, "ContainerConfig/"); ok && strings.HasPrefix(name, n.prefix()) {
			r.Containers = append(r.Containers, name)
		}
	}

	sort.Strings(r.Containers)

	// the cluster's containers that still have an instance: a removed daemon
	// is gone once its name is not here
	cur, err := n.Talos.CurrentInstances(ctx, "")
	if err != nil {
		return r, err
	}

	r.Current = map[string]string{}

	for name, id := range cur {
		if strings.HasPrefix(name, n.prefix()) {
			r.Instances, r.Current[name] = append(r.Instances, name), id
		}
	}

	sort.Strings(r.Instances)

	statuses, err := n.Talos.ContainerStatuses(ctx, "")
	if err != nil {
		return r, err
	}

	r.Running = map[string]string{}

	for name, s := range statuses {
		if strings.HasPrefix(name, n.prefix()) && s.State == containers.ContainerStateRunning {
			r.Running[name] = s.Image
		}
	}

	// a keepalived's VRRP state, from its own log (vip.sh marks each start)
	for name := range r.Running {
		if strings.HasPrefix(name, n.prefix()+"vip-") {
			logs, err := n.Talos.Logs(ctx, "", name)
			if err != nil {
				continue // unknown: not reported
			}

			if r.VRRP == nil {
				r.VRRP = map[string]wire.VRRP{}
			}

			r.VRRP[name] = vrrpState(logs)
		}
	}

	if r.BootID, err = n.Talos.BootID(ctx, ""); err != nil {
		return r, err
	}

	disks, err := n.Talos.Disks(ctx, "")
	if err != nil {
		return r, err
	}

	for _, d := range disks {
		r.Disks = append(r.Disks, wire.Disk{Serial: d.TypedSpec().Serial, Symlinks: d.TypedSpec().Symlinks, DevPath: d.TypedSpec().DevPath})
	}

	return r, nil
}

// Reconcile decides an apply whose outcome was not recorded (an intent left
// behind) from the machine config, which Talos persists before it answers:
// if the node holds exactly what the apply would have left, it happened
// (completed); if it holds exactly what it held before and the apply can no
// longer be in progress (another boot, or ApplySettle passed), it did not
// (refused); anything else stays uncertain and blocks every later apply. It returns ""
// when there is no such apply, the revision of the one it decided, and the
// ownership's revision afterwards, all from one look under the node lock.
func (n *Node) Reconcile(ctx context.Context) (outcome string, rev, owned int64, err error) {
	if err := n.lock(ctx); err != nil {
		return "", 0, 0, err
	}
	defer n.unlock()

	defer func() {
		if err == nil {
			own, _, oerr := n.ownership()
			owned, err = own.Revision, oerr
		}
	}()

	var intent applyIntent

	pending, err := n.readJSON(applyRecord, &intent)
	if err != nil || !pending {
		return "", 0, 0, err
	}

	// settlement first: the config read after it shows any apply that was
	// still being handled when it was established
	boot, err := n.Talos.BootID(ctx, "")
	if err != nil {
		return "", 0, 0, err
	}

	settled := boot != intent.BootID || time.Since(intent.At) >= ApplySettle

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return "", 0, 0, err
	}

	cur, err := parseDocs(cfg)
	if err != nil {
		return "", 0, 0, err
	}

	next := Ownership{Schema: ownershipSchema, Revision: intent.Revision, Docs: map[string]string{}}

	// what the agent knows of the operator's approvals is not the apply's to lose
	if prev, found, err := n.ownership(); err != nil {
		return "", 0, 0, err
	} else if found {
		next.ApprovalSerial = prev.ApprovalSerial
	}

	for k, h := range intent.Before {
		next.Docs[k] = h
	}

	for k, h := range intent.Sent {
		if h == "" {
			delete(next.Docs, k)
		} else {
			next.Docs[k] = h
		}
	}

	switch {
	case len(n.drift(next, cur)) == 0:
		if err := n.writeJSON(ownershipRecord, next); err != nil {
			return "", 0, 0, err
		}

		return "completed", intent.Revision, 0, n.Records.Remove(applyRecord)
	case len(n.drift(Ownership{Docs: intent.Before}, cur)) == 0:
		// not visible proves nothing while the apply may still be handled
		if !settled {
			return "uncertain", intent.Revision, 0, nil
		}

		return "refused", intent.Revision, 0, n.Records.Remove(applyRecord)
	}

	return "uncertain", intent.Revision, 0, nil
}

// fenceRecord holds the revision below which nothing is applied anymore.
const fenceRecord = "fence"

type fence struct {
	Schema   int   `json:"schema"`
	Revision int64 `json:"revision"`
}

// Fence makes every revision up to rev unappliable: the leader gave up a
// grant of that revision, which must not run if it arrives late.
func (n *Node) Fence(ctx context.Context, rev int64) error {
	return n.FenceBefore(ctx, time.Time{}, rev)
}

// FenceBefore is Fence that writes nothing unless it is before until (zero:
// no limit): the abandon's confirmation counts only that long.
func (n *Node) FenceBefore(ctx context.Context, until time.Time, rev int64) error {
	if err := n.lock(ctx); err != nil {
		return err
	}
	defer n.unlock()

	f, err := n.fence()
	if err != nil || f >= rev {
		return err
	}

	if !until.IsZero() && !time.Now().Before(until) {
		return errors.New("the confirmation expired before the fence")
	}

	return n.writeJSON(fenceRecord, fence{Schema: ownershipSchema, Revision: rev})
}

func (n *Node) fence() (int64, error) {
	var f fence

	found, err := n.readJSON(fenceRecord, &f)
	if err != nil || !found {
		return 0, err
	}

	if f.Schema != ownershipSchema || f.Revision < 0 {
		return 0, fmt.Errorf("record %s: damaged", fenceRecord)
	}

	return f.Revision, nil
}

// Adopt takes ownership of the cluster's documents on the node as they are,
// at the handoff (plan 03, item 11): everything but the CLI's own documents.
// It refuses if the agent already owns the node.
func (n *Node) Adopt(ctx context.Context, revision int64) (Ownership, error) {
	if err := n.lock(ctx); err != nil {
		return Ownership{}, err
	}
	defer n.unlock()

	if err := n.Records.Check(); err != nil {
		return Ownership{}, err
	}

	if _, found, err := n.ownership(); err != nil || found {
		if err == nil {
			err = errors.New("the node is already owned")
		}

		return Ownership{}, err
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return Ownership{}, err
	}

	docs, err := parseDocs(cfg)
	if err != nil {
		return Ownership{}, err
	}

	own := Ownership{Schema: ownershipSchema, Revision: revision, Docs: map[string]string{}}

	// an approval the agent recorded before the handoff counts from now on
	if a, err := n.approval(); err != nil {
		return Ownership{}, err
	} else if a != nil {
		own.ApprovalSerial = a.Serial
	}

	for k, h := range docs {
		kind, name, _ := strings.Cut(k, "/")
		if n.cluster(kind, name) && !n.handoff(k) {
			own.Docs[k] = h
		}
	}

	return own, n.writeJSON(ownershipRecord, own)
}

// Apply applies a revision's documents to the node: each one replaces the
// document of the same kind and name, or removes it. It refuses on drift, on
// an earlier apply whose outcome is uncertain, and for documents that are not
// the cluster's or are the CLI's. The intent is recorded before the apply and
// the new ownership, from the config read back, after it.
func (n *Node) Apply(ctx context.Context, revision int64, docs []Doc) (Ownership, error) {
	return n.ApplyBefore(ctx, time.Time{}, revision, docs)
}

// ApplyBefore is Apply that changes nothing unless the patch starts before
// until (zero: no limit): a confirmation counts only that long (plan 03,
// item 5), and the lock, the reads and the admission take time.
func (n *Node) ApplyBefore(ctx context.Context, until time.Time, revision int64, docs []Doc) (Ownership, error) {
	if err := n.lock(ctx); err != nil {
		return Ownership{}, fmt.Errorf("%w: %w", ErrNotApplied, err)
	}
	defer n.unlock()

	own, started, err := n.apply(ctx, until, revision, docs)
	if err != nil && !started {
		// refused before the intent was recorded: nothing reached Talos
		return Ownership{}, fmt.Errorf("%w: %w", ErrNotApplied, err)
	}

	return own, err
}

// apply is Apply under the lock; started reports whether the intent was
// recorded, after which an error leaves the outcome uncertain.
func (n *Node) apply(ctx context.Context, until time.Time, revision int64, docs []Doc) (own Ownership, started bool, err error) {

	if err := n.Records.Check(); err != nil {
		return Ownership{}, started, err
	}

	var intent applyIntent

	if pending, err := n.readJSON(applyRecord, &intent); err != nil || pending {
		if err == nil {
			err = fmt.Errorf("the apply of revision %d has an uncertain outcome", intent.Revision)
		}

		return Ownership{}, started, err
	}

	own, found, err := n.ownership()
	if err != nil {
		return Ownership{}, started, err
	}

	if !found {
		return Ownership{}, started, errors.New("the node has not been handed over")
	}

	floor, err := n.fence()
	if err != nil {
		return Ownership{}, started, err
	}

	if revision <= max(own.Revision, floor) {
		return Ownership{}, started, fmt.Errorf("revision %d is not newer than %d", revision, max(own.Revision, floor))
	}

	sent := map[string]string{}
	typed := map[string]typedDoc{}

	var dels, adds bytes.Buffer

	for _, d := range docs {
		k := d.Key()

		if !n.cluster(d.Kind, d.Name) || n.handoff(k) {
			return Ownership{}, started, fmt.Errorf("%s is not a document the agent applies", k)
		}

		if _, dup := sent[k]; dup {
			return Ownership{}, started, fmt.Errorf("%s twice in revision %d", k, revision)
		}

		sent[k] = ""

		// a removal, or the first half of a replacement: Talos merges documents
		// of the same name, the delete makes the new one replace the old
		del, err := yaml.Marshal(map[string]string{"apiVersion": "v1alpha1", "kind": d.Kind, "name": d.Name, "$patch": "delete"})
		if err != nil {
			return Ownership{}, started, err
		}

		dels.WriteString("---\n")
		dels.Write(del)

		if d.YAML != nil {
			td, err := checkDoc(d)
			if err != nil {
				return Ownership{}, started, fmt.Errorf("%s: %w", k, err)
			}

			// what is sent is Talos's own encoding of the checked document
			sent[k] = td.hash
			typed[k] = td

			adds.WriteString("---\n")
			adds.Write(td.yaml)
		}
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return Ownership{}, started, err
	}

	curTyped, err := typedDocs([]byte(cfg))
	if err != nil {
		return Ownership{}, started, errors.New("machine config: does not decode") // the message may quote a value
	}

	cur := make(map[string]string, len(curTyped))
	for k, d := range curTyped {
		cur[k] = d.hash
	}

	if d := n.drift(own, cur); len(d) > 0 {
		return Ownership{}, started, fmt.Errorf("%w: %s", ErrDrift, strings.Join(d, ", "))
	}

	// the mgr's keys and certificates as the node will hold them
	if err := mgrPairs(curTyped, typed, sent); err != nil {
		return Ownership{}, started, err
	}

	// and the RGW certificates, for this node (plan 03, step 6e)
	if n.Policy != nil {
		identity := func() (id NodeIdentity, err error) {
			if id.Hostname, err = n.Talos.Hostname(ctx, ""); err != nil {
				return id, err
			}

			id.Addrs, err = n.Talos.Addresses(ctx, "")

			return id, err
		}

		if err := n.Policy.rgwCerts(curTyped, typed, sent, identity, time.Now()); err != nil {
			return Ownership{}, started, err
		}
	}

	// every document must pass the admission policy (plan 03, item 13); disk
	// entries are reserved here, before the intent
	if err := n.admit(ctx, docs, typed, cur, sent); err != nil {
		return Ownership{}, started, err
	}

	// the mutation boundary: the confirmation must still count
	if !until.IsZero() && !time.Now().Before(until) {
		return Ownership{}, started, errors.New("the confirmation expired before the apply")
	}

	boot, err := n.Talos.BootID(ctx, "")
	if err != nil {
		return Ownership{}, started, err
	}

	if err := n.writeJSON(applyRecord, applyIntent{Schema: ownershipSchema, Revision: revision, Before: own.Docs, Sent: sent, BootID: boot, At: time.Now().UTC()}); err != nil {
		return Ownership{}, started, err
	}

	started = true

	patches := [][]byte{dels.Bytes()}
	if adds.Len() > 0 {
		patches = append(patches, adds.Bytes())
	}

	pctx := ctx
	if !until.IsZero() {
		pctx = talos.WithApplyBefore(ctx, until)
	}

	if err := n.Talos.Patch(pctx, "", patches...); errors.Is(err, talos.ErrApplyDeadline) {
		// nothing was sent: the intent goes, the outcome is certain
		if rerr := n.Records.Remove(applyRecord); rerr != nil {
			return Ownership{}, started, rerr
		}

		return Ownership{}, false, err
	} else if err != nil {
		// the intent stays: whether Talos took the config is not known
		return Ownership{}, started, fmt.Errorf("apply revision %d: %w", revision, err)
	}

	if cfg, err = n.Talos.MachineConfig(ctx, ""); err != nil {
		return Ownership{}, started, err
	}

	if cur, err = parseDocs(cfg); err != nil {
		return Ownership{}, started, err
	}

	next := Ownership{Schema: ownershipSchema, Revision: revision, Docs: map[string]string{}, ApprovalSerial: own.ApprovalSerial}
	for k, h := range own.Docs {
		next.Docs[k] = h
	}

	for k, h := range sent {
		if h == "" {
			delete(next.Docs, k)
		} else {
			next.Docs[k] = h
		}
	}

	// the node must now hold exactly what was sent and kept: anything else is
	// another writer between the patch and this read, and the intent stays
	if d := n.drift(next, cur); len(d) > 0 {
		return Ownership{}, started, fmt.Errorf("apply revision %d: %w afterwards: %s", revision, ErrDrift, strings.Join(d, ", "))
	}

	if err := n.writeJSON(ownershipRecord, next); err != nil {
		return Ownership{}, started, err
	}

	return next, started, n.Records.Remove(applyRecord)
}

// RestartBefore restarts the current instance of one daemon document the node
// owns with the given hash, under the same checks as an apply: handed over,
// no uncertain apply, the revision above the fence, no drift, the confirmation
// still counting. record is called with the instance and the boot before
// Talos is asked; started reports whether it was, after which an error leaves
// the outcome uncertain.
func (n *Node) RestartBefore(ctx context.Context, until time.Time, revision int64, r wire.GrantRestart, record func(instance, boot string) error) (started bool, err error) {
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

	floor, err := n.fence()
	if err != nil {
		return false, err
	}

	if revision <= max(own.Revision, floor) {
		return false, fmt.Errorf("revision %d is not newer than %d", revision, max(own.Revision, floor))
	}

	key := r.Kind + "/" + r.Name
	if r.Kind != "ContainerConfig" || !n.cluster(r.Kind, r.Name) || n.handoff(key) || own.Docs[key] == "" || own.Docs[key] != r.Hash {
		return false, fmt.Errorf("%s is not a document the agent owns with this content", key)
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return false, err
	}

	typed, err := typedDocs([]byte(cfg))
	if err != nil {
		return false, errors.New("machine config: does not decode") // the message may quote a key
	}

	cur := make(map[string]string, len(typed))
	for k, d := range typed {
		cur[k] = d.hash
	}

	if d := n.drift(own, cur); len(d) > 0 {
		return false, fmt.Errorf("%w: %s", ErrDrift, strings.Join(d, ", "))
	}

	if n.Policy == nil || !n.Policy.daemon(r.Name, typed[key]) {
		return false, fmt.Errorf("%s is not a daemon of the cluster", key)
	}

	instance, err := n.Talos.Instance(ctx, "", r.Name)
	if err != nil {
		return false, err
	}

	boot, err := n.Talos.BootID(ctx, "")
	if err != nil {
		return false, err
	}

	// the mutation boundary: the confirmation must still count
	if !until.IsZero() && !time.Now().Before(until) {
		return false, errors.New("the confirmation expired before the restart")
	}

	if err := record(instance, boot); err != nil {
		return false, err
	}

	// the revision is fenced like an applied one: the grant cannot run again
	// once its operation record is pruned
	if floor < revision {
		if err := n.writeJSON(fenceRecord, fence{Schema: ownershipSchema, Revision: revision}); err != nil {
			return false, err
		}
	}

	// and the confirmation must still count when the restart is sent
	if !until.IsZero() && !time.Now().Before(until) {
		return false, errors.New("the confirmation expired before the restart")
	}

	return true, n.Talos.RestartInstance(ctx, "", instance)
}

// vrrpState is the latest start marker vip.sh printed in a keepalived's log
// and the last VRRP transition after it ("" before any).
func vrrpState(logs string) wire.VRRP {
	const start = "CEPHADM-TALOS-VIP-START "

	i := strings.LastIndex(logs, start)
	if i < 0 {
		return wire.VRRP{}
	}

	marker, _, _ := strings.Cut(logs[i+len(start):], "\n")
	v, at := wire.VRRP{Start: strings.TrimSpace(marker)}, -1

	for _, s := range []string{"MASTER", "BACKUP", "FAULT"} {
		if j := strings.LastIndex(logs[i:], "Entering "+s+" STATE"); j > at {
			v.State, at = s, j
		}
	}

	return v
}

// RebootBefore reboots the node for a confirmed grant: only a node handed
// over that holds no daemon document of the cluster (its host is in
// maintenance), with the same checks as a restart. The operation is recorded
// with the boot before Talos is asked, and the revision fenced.
func (n *Node) RebootBefore(ctx context.Context, until time.Time, revision int64, record func(boot string) error) (started bool, err error) {
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

	typed, err := typedDocs([]byte(cfg))
	if err != nil {
		return false, errors.New("machine config: does not decode") // the message may quote a key
	}

	cur := make(map[string]string, len(typed))
	for k, d := range typed {
		cur[k] = d.hash
	}

	if d := n.drift(own, cur); len(d) > 0 {
		return false, fmt.Errorf("%w: %s", ErrDrift, strings.Join(d, ", "))
	}

	// what the node holds now, owned or not
	for key := range cur {
		kind, name, _ := strings.Cut(key, "/")
		if kind == "ContainerConfig" && n.cluster(kind, name) && !n.handoff(key) {
			return false, fmt.Errorf("the node still holds %s: only a node without daemons reboots", key)
		}
	}

	boot, err := n.Talos.BootID(ctx, "")
	if err != nil {
		return false, err
	}

	if !until.IsZero() && !time.Now().Before(until) {
		return false, errors.New("the confirmation expired before the reboot")
	}

	if err := record(boot); err != nil {
		return false, err
	}

	if floor < revision {
		if err := n.writeJSON(fenceRecord, fence{Schema: ownershipSchema, Revision: revision}); err != nil {
			return false, err
		}
	}

	if !until.IsZero() && !time.Now().Before(until) {
		return false, errors.New("the confirmation expired before the reboot")
	}

	return true, n.Talos.RebootNow(ctx, "")
}

// RestartOutcome decides a restart that is started or uncertain: "refused" on
// another boot (the call can no longer run), "completed" once a newer instance
// than the recorded one exists (Talos stopped the old one, within its stop
// timeout, and started the next), "refused" if the recorded one is still the
// current one after ApplySettle, "uncertain" if it is gone and no newer one
// came within ApplySettle, else "" (not known yet).
func (n *Node) RestartOutcome(ctx context.Context, instance, boot string, at time.Time) (string, error) {
	// a call of another boot can no longer run, whatever instances there are
	now, err := n.Talos.BootID(ctx, "")
	if err != nil {
		return "", err
	}

	if now != boot {
		return wire.OpRefused, nil
	}

	i := strings.LastIndex(instance, "-")
	if i <= 0 {
		return "", fmt.Errorf("instance %q has no generation", instance)
	}

	cur, err := n.Talos.Instance(ctx, "", instance[:i])
	if errors.Is(err, talos.ErrNotFound) {
		// the old instance is gone and no newer one exists yet (it may wait on
		// its dependencies): after the limit, nobody can tell
		if time.Since(at) > ApplySettle {
			return wire.OpUncertain, nil
		}

		return "", nil
	}

	if err != nil {
		return "", err
	}

	if cur != instance {
		return wire.OpCompleted, nil
	}

	if time.Since(at) > ApplySettle {
		return wire.OpRefused, nil
	}

	return "", nil
}

// jobFile is a file of a job in the jobs directory (job.sh: <fsid>.<job>.<what>).
func (n *Node) jobFile(job, what string) string {
	return filepath.Join(n.JobsDir, n.FSID+"."+job+"."+what)
}

// writeJobFile writes a job's file atomically (a tombstone).
func (n *Node) writeJobFile(job, what, contents string) error {
	if n.JobsDir == "" {
		return errors.New("no jobs directory")
	}

	tmp := n.jobFile(job, what) + ".tmp"

	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	if _, err := f.WriteString(contents + "\n"); err != nil {
		f.Close() //nolint:errcheck

		return err
	}

	if err := f.Sync(); err != nil {
		f.Close() //nolint:errcheck

		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmp, n.jobFile(job, what)); err != nil {
		return err
	}

	d, err := os.Open(n.JobsDir)
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck

	return d.Sync()
}

// maxJobOutput bounds the output a job's result keeps in its record.
const maxJobOutput = 16 << 10

// resultRCRe is the first line of a job's result (job.sh).
var resultRCRe = regexp.MustCompile(`^rc (0|-?[1-9][0-9]{0,4})$`)

// JobOutcome decides a job from its result file and its container: completed
// (rc 0) or failed with its result; refused if it left no started record or
// its result is for other inputs; uncertain if it started and left no result;
// "" while it runs.
func (n *Node) JobOutcome(ctx context.Context, job wire.JobRef) (string, *wire.JobResult, error) {
	// nothing is decided while the job's container runs: its result is
	// visible before the job synced and exited
	st, err := n.Talos.ContainerStatuses(ctx, "")
	if err != nil {
		return "", nil, err
	}

	s, ok := st[job.Doc]
	if !ok || (s.State != containers.ContainerStateCompleted && s.State != containers.ContainerStateFailed) {
		return "", nil, nil
	}

	b, err := os.ReadFile(n.jobFile(job.ID, "result"))
	if err == nil {
		head, rest, ok1 := strings.Cut(string(b), "\n")
		in, out, ok2 := strings.Cut(rest, "\n")

		m := resultRCRe.FindStringSubmatch(head)
		if !ok1 || !ok2 || m == nil {
			return wire.OpUncertain, nil, nil // a damaged result is no evidence
		}

		rc, _ := strconv.Atoi(m[1])

		if in != "inputs "+job.Inputs {
			return wire.OpRefused, nil, nil
		}

		if len(out) > maxJobOutput {
			out = out[len(out)-maxJobOutput:]
		}

		res := &wire.JobResult{RC: rc, Output: out}
		if rc != 0 {
			return wire.OpFailed, res, nil
		}

		return wire.OpCompleted, res, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return "", nil, err
	}

	if _, err := os.Stat(n.jobFile(job.ID, "started")); err == nil {
		return wire.OpUncertain, nil, nil
	}

	return wire.OpRefused, nil, nil
}

// cleanJob removes an acknowledged job's result and started record once its
// document and instance are gone; the claim and the tombstone stay.
func (n *Node) cleanJob(ctx context.Context, job wire.JobRef) error {
	owners, err := n.Talos.InstanceOwners(ctx, "")
	if err != nil || slices.Contains(owners, job.Doc) {
		return err
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return err
	}

	if cur, err := parseDocs(cfg); err != nil || cur["ContainerConfig/"+job.Doc] != "" {
		return err
	}

	for _, what := range []string{"result", "started"} {
		if err := os.Remove(n.jobFile(job.ID, what)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

// AckBefore admits a grant that only acknowledges a job: its revision must be
// newer than the node's and the fence, and is fenced, while the confirmation
// still counts.
func (n *Node) AckBefore(ctx context.Context, until time.Time, revision int64) error {
	if err := n.lock(ctx); err != nil {
		return err
	}
	defer n.unlock()

	own, found, err := n.ownership()
	if err != nil {
		return err
	}

	if !found {
		return errors.New("the node has not been handed over")
	}

	floor, err := n.fence()
	if err != nil {
		return err
	}

	if revision <= max(own.Revision, floor) {
		return fmt.Errorf("revision %d is not newer than %d", revision, max(own.Revision, floor))
	}

	if !until.IsZero() && !time.Now().Before(until) {
		return errors.New("the confirmation expired before the acknowledgement")
	}

	return n.writeJSON(fenceRecord, fence{Schema: ownershipSchema, Revision: revision})
}

// NodeSnapshot is the node's ownership, fence and whether an apply's outcome
// is still open, read together.
type NodeSnapshot struct {
	Own    Ownership
	Fence  int64
	Intent bool
	// IntentBoot and IntentAt say when the open apply was sent
	IntentBoot string
	IntentAt   time.Time
}

// Snapshot reads the ownership, the fence and the apply intent under the lock.
func (n *Node) Snapshot(ctx context.Context) (NodeSnapshot, error) {
	if err := n.lock(ctx); err != nil {
		return NodeSnapshot{}, err
	}
	defer n.unlock()

	own, _, err := n.ownership()
	if err != nil {
		return NodeSnapshot{}, err
	}

	f, err := n.fence()
	if err != nil {
		return NodeSnapshot{}, err
	}

	var intent applyIntent

	pending, err := n.readJSON(applyRecord, &intent)
	if err != nil {
		return NodeSnapshot{}, err
	}

	return NodeSnapshot{Own: own, Fence: f, Intent: pending, IntentBoot: intent.BootID, IntentAt: intent.At}, nil
}

// ended reports whether a container can no longer run: its status completed
// or failed, or neither its document nor any instance left (a missing status
// alone may be one not created yet, or an instance still exiting).
func (n *Node) ended(ctx context.Context, name string) (bool, error) {
	st, err := n.Talos.ContainerStatuses(ctx, "")
	if err != nil {
		return false, err
	}

	if s, ok := st[name]; ok {
		return s.State == containers.ContainerStateCompleted || s.State == containers.ContainerStateFailed, nil
	}

	owners, err := n.Talos.InstanceOwners(ctx, "")
	if err != nil || slices.Contains(owners, name) {
		return false, err
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return false, err
	}

	docs, err := parseDocs(cfg)
	if err != nil {
		return false, err
	}

	_, configured := docs["ContainerConfig/"+name]

	return !configured, nil
}

// DocHashes returns the hash of every document of a machine config, keyed
// "<kind>/<name>", as the agent records them (for the CLI's recovery journal).
func DocHashes(cfg string) (map[string]string, error) { return parseDocs(cfg) }
