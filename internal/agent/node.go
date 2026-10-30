package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/siderolabs/talos/pkg/machinery/config/config"
	"github.com/siderolabs/talos/pkg/machinery/config/configloader"
	"github.com/siderolabs/talos/pkg/machinery/config/encoder"
	"gopkg.in/yaml.v3"

	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/state"
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
}

// applyIntent is written before an apply and removed after its outcome is
// recorded; one left behind means the outcome is uncertain.
type applyIntent struct {
	Schema   int               `json:"schema"`
	Revision int64             `json:"revision"`
	Before   map[string]string `json:"before"` // the ownership it started from
	Sent     map[string]string `json:"sent"`   // key -> hash of the sent document, "" for a removal
}

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

// ErrDrift means the node's documents are not the ones the agent recorded.
var ErrDrift = errors.New("drift")

// Node is the agent's own node: its Talos API through the local socket and
// its records.
type Node struct {
	Talos interface {
		MachineConfig(ctx context.Context, node string) (string, error)
		Patch(ctx context.Context, node string, patches ...[]byte) error
	}
	Records *records.Store
	// FSID is the cluster's, Host the agent's host
	FSID string
	Host string

	// mu serializes Adopt, Apply and Status: each reads and writes the records
	// and the config as one step
	mu sync.Mutex
}

func (n *Node) docName(typ string) string {
	return (&state.State{FSID: n.FSID}).DocName(state.Daemon{Type: typ, ID: n.Host})
}

// prefix is the name prefix of the cluster's ContainerConfig documents.
func (n *Node) prefix() string { return "ceph-" + (&state.State{FSID: n.FSID}).Short() + "-" }

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
		return nil, fmt.Errorf("machine config: %w", err)
	}

	out := make(map[string]string, len(docs))
	for k, d := range docs {
		out[k] = d.hash
	}

	return out, nil
}

// typedDoc is one named document in Talos's encoding.
type typedDoc struct {
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

		out[k] = typedDoc{yaml: b, hash: h}
	}

	return out, nil
}

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
			return typedDoc{}, err
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
		return typedDoc{}, err
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
	n.mu.Lock()
	defer n.mu.Unlock()

	if err := n.Records.Check(); err != nil {
		return NodeStatus{State: "error", Error: err.Error()}
	}

	var intent applyIntent

	pending, err := n.readJSON(applyRecord, &intent)
	if err != nil {
		return NodeStatus{State: "error", Error: err.Error()}
	}

	own, found, err := n.ownership()
	if err != nil {
		return NodeStatus{State: "error", Error: err.Error()}
	}

	if pending {
		return NodeStatus{State: "uncertain", Revision: intent.Revision, Owned: len(own.Docs)}
	}

	if !found {
		return NodeStatus{State: "unowned"}
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return NodeStatus{State: "error", Revision: own.Revision, Owned: len(own.Docs), Error: err.Error()}
	}

	docs, err := parseDocs(cfg)
	if err != nil {
		return NodeStatus{State: "error", Revision: own.Revision, Owned: len(own.Docs), Error: err.Error()}
	}

	st := NodeStatus{State: "owned", Revision: own.Revision, Owned: len(own.Docs)}
	if d := n.drift(own, docs); len(d) > 0 {
		// the status record stays small (MaxRecord)
		if len(d) > maxDrift {
			d = append(d[:maxDrift], fmt.Sprintf("and %d more", len(d)-maxDrift))
		}

		st.State, st.Drift = "drift", d
	}

	return st
}

// Adopt takes ownership of the cluster's documents on the node as they are,
// at the handoff (plan 03, item 11): everything but the CLI's own documents.
// It refuses if the agent already owns the node.
func (n *Node) Adopt(ctx context.Context, revision int64) (Ownership, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

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
	n.mu.Lock()
	defer n.mu.Unlock()

	if err := n.Records.Check(); err != nil {
		return Ownership{}, err
	}

	var intent applyIntent

	if pending, err := n.readJSON(applyRecord, &intent); err != nil || pending {
		if err == nil {
			err = fmt.Errorf("the apply of revision %d has an uncertain outcome", intent.Revision)
		}

		return Ownership{}, err
	}

	own, found, err := n.ownership()
	if err != nil {
		return Ownership{}, err
	}

	if !found {
		return Ownership{}, errors.New("the node has not been handed over")
	}

	if revision <= own.Revision {
		return Ownership{}, fmt.Errorf("revision %d is not newer than %d", revision, own.Revision)
	}

	sent := map[string]string{}

	var dels, adds bytes.Buffer

	for _, d := range docs {
		k := d.Key()

		if !n.cluster(d.Kind, d.Name) || n.handoff(k) {
			return Ownership{}, fmt.Errorf("%s is not a document the agent applies", k)
		}

		if _, dup := sent[k]; dup {
			return Ownership{}, fmt.Errorf("%s twice in revision %d", k, revision)
		}

		sent[k] = ""

		// a removal, or the first half of a replacement: Talos merges documents
		// of the same name, the delete makes the new one replace the old
		del, err := yaml.Marshal(map[string]string{"apiVersion": "v1alpha1", "kind": d.Kind, "name": d.Name, "$patch": "delete"})
		if err != nil {
			return Ownership{}, err
		}

		dels.WriteString("---\n")
		dels.Write(del)

		if d.YAML != nil {
			td, err := checkDoc(d)
			if err != nil {
				return Ownership{}, fmt.Errorf("%s: %w", k, err)
			}

			// what is sent is Talos's own encoding of the checked document
			sent[k] = td.hash

			adds.WriteString("---\n")
			adds.Write(td.yaml)
		}
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return Ownership{}, err
	}

	cur, err := parseDocs(cfg)
	if err != nil {
		return Ownership{}, err
	}

	if d := n.drift(own, cur); len(d) > 0 {
		return Ownership{}, fmt.Errorf("%w: %s", ErrDrift, strings.Join(d, ", "))
	}

	if err := n.writeJSON(applyRecord, applyIntent{Schema: ownershipSchema, Revision: revision, Before: own.Docs, Sent: sent}); err != nil {
		return Ownership{}, err
	}

	patches := [][]byte{dels.Bytes()}
	if adds.Len() > 0 {
		patches = append(patches, adds.Bytes())
	}

	if err := n.Talos.Patch(ctx, "", patches...); err != nil {
		// the intent stays: whether Talos took the config is not known
		return Ownership{}, fmt.Errorf("apply revision %d: %w", revision, err)
	}

	if cfg, err = n.Talos.MachineConfig(ctx, ""); err != nil {
		return Ownership{}, err
	}

	if cur, err = parseDocs(cfg); err != nil {
		return Ownership{}, err
	}

	next := Ownership{Schema: ownershipSchema, Revision: revision, Docs: map[string]string{}}
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
		return Ownership{}, fmt.Errorf("apply revision %d: %w afterwards: %s", revision, ErrDrift, strings.Join(d, ", "))
	}

	if err := n.writeJSON(ownershipRecord, next); err != nil {
		return Ownership{}, err
	}

	return next, n.Records.Remove(applyRecord)
}
