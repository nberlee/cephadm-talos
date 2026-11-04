// Package wire holds the messages of the agent channel between the mgr module
// and the agents (plan 03, items 1, 2 and 5), version 1. The mgr module's side
// is internal/mgrmodule/talos/bridge.py; both must change together.
package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/nberlee/cephadm-talos/internal/approval"
)

// Version is the wire format version.
const Version = 1

// Ports of the agent channel.
const (
	// AgentPort serves the agent's status and the module's heartbeats.
	AgentPort = 4721
	// ModulePort serves confirmations, in the active mgr, on all interfaces.
	ModulePort = 4722
	// BridgePort serves the bridge to the local agent, in the active mgr, on
	// loopback only.
	BridgePort = 4723
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
	Epoch      int64  `json:"epoch"` // the mgrmap epoch the incarnation was captured at: orders incarnations
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
	Epoch     int64  `json:"epoch"`    // and its captured mgrmap epoch, which orders incarnations
	Revision  int64  `json:"revision"`
	Operation string `json:"operation"`
	// Docs replace documents of the same kind and name, or remove them
	Docs []GrantDoc `json:"docs"`
	// Restart, instead of documents, restarts the current instance of one
	// daemon document the agent owns with this hash
	Restart *GrantRestart `json:"restart,omitempty"`
	// Reboot, instead of documents, reboots the agent's own node, which must
	// hold no daemon document of the cluster
	Reboot bool `json:"reboot,omitempty"`
	// Approval is the newest approval of the operator the leader has; the
	// agent verifies it and records it if it is higher than its own
	Approval *approval.Signed `json:"approval,omitempty"`
	// Ack acknowledges a job's recorded result; a grant that removes a job
	// document whose result is not acknowledged needs it
	Ack *JobAck `json:"ack,omitempty"`
	// SelfUpdate, instead of documents, has the agent render and apply its
	// own documents with these variable fields (plan 04, step 2)
	SelfUpdate *SelfUpdate `json:"self_update,omitempty"`
	// Pull, instead of documents, has the agent pull this image (by digest)
	// on its own node
	Pull string `json:"pull,omitempty"`
}

// SelfUpdate is what a self-update changes in the agent's own documents: its
// image, or its server and client certificates with their keys (all four or
// none); what it omits stays as the agent's current document has it. The
// pinned inputs (the agent CA, repositories, approval key) never change.
type SelfUpdate struct {
	Image      string `json:"image,omitempty"`
	Cert       string `json:"cert,omitempty"`
	Key        string `json:"key,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

// JobAck names a job's result the leader stored: the job, its inputs and its
// rc (-1 for an outcome without a result: refused or uncertain).
type JobAck struct {
	Job    string `json:"job"`
	Inputs string `json:"inputs"`
	RC     int    `json:"rc"`
}

// JobRef is the job a grant runs, recorded before anything is applied.
type JobRef struct {
	ID     string `json:"id"`
	Inputs string `json:"inputs"`
	Doc    string `json:"doc"` // its ContainerConfig name
}

// JobResult is a job's result as its result file had it, bounded.
type JobResult struct {
	RC     int    `json:"rc"`
	Output string `json:"output,omitempty"`
}

// GrantRestart names the daemon document a grant restarts.
type GrantRestart struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Hash string `json:"hash"`
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
		FSID      string           `json:"fsid"`
		Host      string           `json:"host"`
		Revision  int64            `json:"revision"`
		Operation string           `json:"operation"`
		Docs      []GrantDoc       `json:"docs"`
		Restart   *GrantRestart    `json:"restart,omitempty"`
		Reboot    bool             `json:"reboot,omitempty"`
		Approval  *approval.Signed `json:"approval,omitempty"`
		Ack       *JobAck          `json:"ack,omitempty"`
		Self      *SelfUpdate      `json:"self_update,omitempty"`
		Pull      string           `json:"pull,omitempty"`
	}{g.FSID, g.Host, g.Revision, g.Operation, g.Docs, g.Restart, g.Reboot, g.Approval, g.Ack, g.SelfUpdate, g.Pull})

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
	// OpFailed: the grant's job ran and its command failed (Result has the rc)
	OpFailed = "failed"
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
	// a restart records the instance it restarts, the boot and the time
	// (Unix nanoseconds) before it calls Talos, to decide a lost outcome
	Instance string `json:"instance,omitempty"`
	BootID   string `json:"boot_id,omitempty"`
	At       int64  `json:"at,omitempty"`
	// Reboot: the grant reboots the node; recorded with the boot before the
	// call, completed once the node runs another boot
	Reboot bool `json:"reboot,omitempty"`
	// Self: the grant updates the agent's own documents; decided from its
	// apply intent, or the self-update record it leaves
	Self bool `json:"self,omitempty"`
	// Pull: the grant pulls an image; one the agent's stop interrupted did
	// not finish
	Pull bool `json:"pull,omitempty"`
	// a job's grant: the job, its result once read, and whether the leader
	// acknowledged it (until then the record is kept)
	Job    *JobRef    `json:"job,omitempty"`
	Result *JobResult `json:"result,omitempty"`
	Acked  bool       `json:"acked,omitempty"`
	// AckBy is the operation whose grant acknowledges this job, recorded
	// before that grant is applied; once it completed, the job is acknowledged
	AckBy string `json:"ack_by,omitempty"`
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
	Epoch     int64  `json:"epoch"`
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

// Close is a new leader closing the sessions of earlier incarnations on an
// agent (plan 03, item 6): confirmed like a grant, it raises the agent's
// session floor to Epoch, below which no grant, abandon or close is admitted.
// Incarnations are ordered by their captured mgrmap epoch, not their gid: a
// standby promoted later may have a smaller gid.
type Close struct {
	Version int    `json:"version"`
	FSID    string `json:"fsid"`
	Host    string `json:"host"`
	Mgr     string `json:"mgr"`
	MgrAddr string `json:"mgr_addr"`
	GID     int64  `json:"gid"`
	Epoch   int64  `json:"epoch"`
}

// CloseInputs is the hash the agent's confirmation of a close carries.
func CloseInputs(c Close) string {
	b, _ := json.Marshal(struct {
		Close bool   `json:"close"`
		FSID  string `json:"fsid"`
		Host  string `json:"host"`
		GID   int64  `json:"gid"`
		Epoch int64  `json:"epoch"`
	}{true, c.FSID, c.Host, c.GID, c.Epoch})

	sum := sha256.Sum256(b)

	return hex.EncodeToString(sum[:])
}

// CloseReply is the agent's session floor after a close.
type CloseReply struct {
	Version int   `json:"version"`
	Floor   int64 `json:"floor"`
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

// Suspend is the CLI's request that an agent suspend for a recovery session
// (plan 03, step 7 slice D), with the operator certificate.
type Suspend struct {
	Version int    `json:"version"`
	FSID    string `json:"fsid"`
	Host    string `json:"host"`
	Session string `json:"session"`
}

// Resolve is the operator's request that an agent fail a job whose outcome is
// uncertain (plan 04, step 4), with the operator certificate: the agent's
// operation id, as the leader's journal names it (op-<hex>.prep).
type Resolve struct {
	Version   int    `json:"version"`
	FSID      string `json:"fsid"`
	Host      string `json:"host"`
	Operation string `json:"operation"`
}

// SuspendReceipt is a suspended agent's state once nothing it started runs:
// what the CLI must not touch, and what re-adoption keeps.
type SuspendReceipt struct {
	Version  int    `json:"version"`
	Session  string `json:"session"`
	Host     string `json:"host"`
	Revision int64  `json:"revision"` // the ownership's
	Fence    int64  `json:"fence"`
	Floor    int64  `json:"floor"` // the session floor
	// Unresolved are the operations whose outcome is uncertain, Intents the
	// bridge calls whose outcome the module did not give
	Unresolved []Operation `json:"unresolved"`
	// Prepared are the serials of the disks preparation jobs used on the host
	// (the approval's disk entries the agent recorded), for rm-cluster --zap
	Prepared []string          `json:"prepared,omitempty"`
	Intents  []BridgeIntent    `json:"intents"`
	Owned    map[string]string `json:"owned"` // "<kind>/<name>" -> hash
	// ApplyPending: an apply intent is left that the agent could not decide
	// (it settled, but the config matches neither its before nor its after):
	// the whole node is reserved
	ApplyPending bool `json:"apply_pending,omitempty"`
}

// SuspendState is the answer while an agent drains: Waiting says for what.
type SuspendState struct {
	Version int             `json:"version"`
	Session string          `json:"session"`
	Waiting []string        `json:"waiting,omitempty"`
	Receipt *SuspendReceipt `json:"receipt,omitempty"`
}

// Readopt is the CLI's request that a suspended agent take ownership of its
// node again at the resumption (plan 03, step 7 slice D, item 9): its
// ownership with the recovery's changes ("<kind>/<name>" -> hash, "" for a
// removal) must be exactly the node's cluster documents.
type Readopt struct {
	Version int               `json:"version"`
	FSID    string            `json:"fsid"`
	Host    string            `json:"host"`
	Session string            `json:"session"`
	Changes map[string]string `json:"changes"`
}

// ReadoptReceipt is the ownership a re-adoption took; the same request again
// gives the same receipt.
type ReadoptReceipt struct {
	Version  int               `json:"version"`
	Session  string            `json:"session"`
	Host     string            `json:"host"`
	Revision int64             `json:"revision"`
	Docs     map[string]string `json:"docs"`
}

// Activate ends a re-adopted agent's suspension. Epoch is the mgr map epoch
// the resumption recorded before it restarted every mgr: an open bridge
// intent of a later epoch refuses it, the others are released.
type Activate struct {
	Version  int    `json:"version"`
	FSID     string `json:"fsid"`
	Host     string `json:"host"`
	Session  string `json:"session"`
	Revision int64  `json:"revision"`
	Epoch    int64  `json:"epoch"`
}

// BridgeIntent is the leader's agent's record of a mutating bridge call made
// before the call (plan 03, step 7 slice D): until its outcome is known, it
// reserves the operation's daemon and host for the CLI's recovery.
type BridgeIntent struct {
	Version   int    `json:"version"`
	Dispatch  string `json:"dispatch"`
	Call      string `json:"call"`
	Operation string `json:"operation,omitempty"`
	// Daemon and Host are what the operation changes, as far as the leader
	// knew it when it made the call
	Daemon string `json:"daemon,omitempty"`
	Host   string `json:"host,omitempty"`
	GID    int64  `json:"gid"`
	Epoch  int64  `json:"epoch"`
	At     int64  `json:"at"`
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
	// Instances are the cluster's containers that have an instance, running or
	// not cleaned up yet
	Instances []string `json:"instances,omitempty"`
	// Current is the newest instance of each of them ("<name>-<generation>")
	Current map[string]string `json:"current,omitempty"`
	// Running is, for each of the cluster's containers that runs, the image
	// it runs (the resolved digest, "sha256:<hex>")
	Running map[string]string `json:"running,omitempty"`
	// VRRP is, for each running keepalived of the cluster, the latest start
	// its log shows and its VRRP state since (absent if the log was unreadable)
	VRRP  map[string]VRRP `json:"vrrp,omitempty"`
	Disks []Disk          `json:"disks"`
	// BootID is the node's boot id; it changes with every boot
	BootID string `json:"boot_id,omitempty"`
	// Addrs are the node's own IP addresses, as Talos reports them: a host's
	// move confirms the new one there (plan 04, step 5)
	Addrs []string `json:"addrs,omitempty"`
}

// VRRP is a keepalived's latest start marker (vip.sh prints one per start)
// and its VRRP state since: MASTER, BACKUP, FAULT, or "" before any. A
// replaced instance is ready once its marker differs from the one before.
type VRRP struct {
	Start string `json:"start"`
	State string `json:"state"`
}

// Disk is one of a node's disks as Talos reports it.
type Disk struct {
	Serial   string   `json:"serial"`
	Symlinks []string `json:"symlinks"`
	DevPath  string   `json:"dev_path,omitempty"`
}
