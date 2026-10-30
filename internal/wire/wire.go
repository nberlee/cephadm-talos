// Package wire holds the messages of the agent channel between the mgr module
// and the agents (plan 03, items 1, 2 and 5), version 1. The mgr module's side
// is internal/mgrmodule/talos/bridge.py; both must change together.
package wire

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
