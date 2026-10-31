// Package wire holds the messages of the agent channel between the mgr module
// and the agents (plan 03, items 1, 2 and 5), version 1. The mgr module's side
// is internal/mgrmodule/talos/bridge.py; both must change together.
package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Version is the wire format version.
const Version = 1

// Ports of the agent channel.
const (
	// AgentPort serves the agent's status and the module's heartbeats.
	AgentPort = 4721
	// ModulePort serves confirmations and the bridge, in the active mgr.
	ModulePort = 4722
)

// Heartbeat is what the module in the active mgr sends its local agent every 5
// seconds: the captured incarnation and the agent session it last saw.
type Heartbeat struct {
	Version int    `json:"version"`
	FSID    string `json:"fsid"`
	Mgr     string `json:"mgr"`
	GID     int64  `json:"gid"`
	Epoch   int64  `json:"epoch"`
	Session string `json:"session"`
}

// HeartbeatReply carries the agent's session nonce, new on every agent start.
type HeartbeatReply struct {
	Version int    `json:"version"`
	Session string `json:"session"`
}

// ConfirmRequest is an agent's challenge before it changes its node.
type ConfirmRequest struct {
	Version    int    `json:"version"`
	FSID       string `json:"fsid"`
	Session    string `json:"session"`
	Host       string `json:"host"`
	Revision   int64  `json:"revision"`
	Operation  string `json:"operation"`
	InputsHash string `json:"inputs_hash"`
	Challenge  string `json:"challenge"`
}

// ConfirmReply is the module's signed answer: Payload is the exact JSON of a
// Confirmation, signed with the mgr's server key (ECDSA P-256, SHA-256, ASN.1);
// both are base64.
type ConfirmReply struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Confirmation is what the module confirms: the captured gid was the active one
// when it answered this challenge.
type Confirmation struct {
	Version    int    `json:"version"`
	FSID       string `json:"fsid"`
	Mgr        string `json:"mgr"`
	GID        int64  `json:"gid"`
	Session    string `json:"session"`
	Host       string `json:"host"`
	Revision   int64  `json:"revision"`
	Operation  string `json:"operation"`
	InputsHash string `json:"inputs_hash"`
	Challenge  string `json:"challenge"`
}

// BridgeRequest is a call through the module with the mgr's credentials; only
// allowlisted calls with fixed argument shapes are accepted.
type BridgeRequest struct {
	Version    int            `json:"version"`
	Call       string         `json:"call"`
	Args       map[string]any `json:"args"`
	Deadline   float64        `json:"deadline"` // seconds
	DispatchID string         `json:"dispatch_id"`
}

// BridgeReply is a call's outcome: "done" with the command's result, or
// "unknown" when the deadline passed; the late result is fetched by dispatch id.
type BridgeReply struct {
	Outcome string `json:"outcome"`
	R       int    `json:"r"`
	Out     string `json:"out"`
	Outs    string `json:"outs"`
}

// Grant is a revision of one host's documents, sent by the leader to that
// host's agent (plan 03, items 5 and 7). The agent reserves the operation,
// asks the active mgr named here for a confirmation of the grant's inputs,
// admits and applies the documents, and answers with an Operation.
type Grant struct {
	Version   int    `json:"version"`
	FSID      string `json:"fsid"`
	Host      string `json:"host"`
	Mgr       string `json:"mgr"`      // the active mgr the leader runs beside
	MgrAddr   string `json:"mgr_addr"` // its host's address, for the confirmation
	GID       int64  `json:"gid"`      // the leader's incarnation: the mgr's gid
	Revision  int64  `json:"revision"`
	Operation string `json:"operation"`
	// Docs replace documents of the same kind and name, or remove them
	Docs []GrantDoc `json:"docs"`
}

// GrantDoc is one document of a grant: its YAML, or a removal when YAML is nil.
type GrantDoc struct {
	Kind string  `json:"kind"`
	Name string  `json:"name"`
	YAML *string `json:"yaml"`
}

// GrantInputs is the hash of what a grant changes, which the agent's
// confirmation carries: the same operation id with other inputs is refused.
func GrantInputs(g Grant) string {
	b, _ := json.Marshal(struct {
		FSID      string     `json:"fsid"`
		Host      string     `json:"host"`
		Revision  int64      `json:"revision"`
		Operation string     `json:"operation"`
		Docs      []GrantDoc `json:"docs"`
	}{g.FSID, g.Host, g.Revision, g.Operation, g.Docs})

	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// Operation states an agent records for a grant.
const (
	// OpReserved: recorded, not confirmed yet; nothing changed
	OpReserved = "reserved"
	// OpRefused: no confirmation, or refused by the agent before applying
	// (drift, admission, revision); nothing changed
	OpRefused = "refused"
	// OpStarted: confirmed and being applied
	OpStarted = "started"
	// OpCompleted: applied, and the node holds exactly the granted documents
	OpCompleted = "completed"
	// OpUncertain: the apply may or may not have happened; nothing more is
	// applied until it is reconciled
	OpUncertain = "uncertain"
	// OpAbandoned: the leader gave the operation up before the agent received
	// it; a later delivery of the same id is refused
	OpAbandoned = "abandoned"
)

// Operation is an agent's record of a grant, its answer to the grant and to a
// later lookup by operation id.
type Operation struct {
	Version    int    `json:"version"`
	Operation  string `json:"operation"`
	Revision   int64  `json:"revision"`
	InputsHash string `json:"inputs_hash"`
	GID        int64  `json:"gid"`
	State      string `json:"state"`
	Error      string `json:"error,omitempty"`
}

// Abandon is the leader giving up a grant whose outcome it does not know and
// that the agent has no record of. The agent confirms it like a grant, then
// records the operation as abandoned and fences its revision, so the grant
// cannot run if it arrives late.
type Abandon struct {
	Version   int    `json:"version"`
	FSID      string `json:"fsid"`
	Host      string `json:"host"`
	Mgr       string `json:"mgr"`
	MgrAddr   string `json:"mgr_addr"`
	GID       int64  `json:"gid"`
	Revision  int64  `json:"revision"`
	Operation string `json:"operation"`
}

// AbandonInputs is the hash the agent's confirmation of an abandon carries.
func AbandonInputs(a Abandon) string {
	b, _ := json.Marshal(struct {
		Abandon   bool   `json:"abandon"`
		FSID      string `json:"fsid"`
		Host      string `json:"host"`
		Revision  int64  `json:"revision"`
		Operation string `json:"operation"`
	}{true, a.FSID, a.Host, a.Revision, a.Operation})

	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// Handoff is the CLI's request that an agent take ownership of its node's
// cluster documents as they are (plan 03, item 11), with the operator
// certificate.
type Handoff struct {
	Version  int    `json:"version"`
	FSID     string `json:"fsid"`
	Host     string `json:"host"`
	Revision int64  `json:"revision"`
}

// HandoffReply is the ownership the agent took.
type HandoffReply struct {
	Version  int   `json:"version"`
	Revision int64 `json:"revision"`
	Owned    int   `json:"owned"`
}

// NodeReport is what an agent tells the leader about its node: what it owns,
// its drift, the cluster's containers it has and its disks, for the leader to
// skip documents the node already has and to check a revision before granting.
type NodeReport struct {
	Version    int               `json:"version"`
	State      string            `json:"state"` // the agent's NodeStatus state
	Revision   int64             `json:"revision"`
	Owned      map[string]string `json:"owned"` // "<kind>/<name>" -> hash of Talos's encoding
	Drift      []string          `json:"drift,omitempty"`
	Containers []string          `json:"containers"`
	Disks      []Disk            `json:"disks"`
}

// Disk is one of a node's disks as Talos reports it.
type Disk struct {
	Serial   string   `json:"serial"`
	Symlinks []string `json:"symlinks"`
}
