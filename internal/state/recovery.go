package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nberlee/cephadm-talos/internal/wire"
)

// RecoverySchema is the version of the recovery journal.
const RecoverySchema = 1

// Phases of a recovery session (plan 03, step 7 slice D, item 1).
const (
	PhaseSuspending = "suspending"
	PhaseSuspended  = "suspended"
	PhaseRecovering = "recovering"
	PhaseResuming   = "resuming"
	PhaseResumed    = "resumed"
	PhaseRemoving   = "removing"
)

// Recovery is the CLI's journal of a recovery session, written before each of
// its effects: the agents' suspension receipts, the jobs it runs and the
// documents it changes. It is the workstation's, like local.json; one
// workstation runs one session at a time (the cluster's Lock).
type Recovery struct {
	Schema  int    `json:"schema"`
	FSID    string `json:"fsid"`
	Session string `json:"session"`
	Phase   string `json:"phase"`
	// Control is set once the control record is in config-key
	Control bool                     `json:"control"`
	Hosts   map[string]*RecoveryHost `json:"hosts"`
	// Jobs are the jobs the session allocated, by purpose: an id is recorded
	// before its document is applied, and a retry reuses it
	Jobs map[string]*RecoveryJob `json:"jobs"`
}

// RecoveryHost is one host's part of a session.
type RecoveryHost struct {
	// Addr is how the session reaches the host, recorded when it is first
	// found: a retry without the mons still knows every host it found
	Addr    string               `json:"addr"`
	Receipt *wire.SuspendReceipt `json:"receipt,omitempty"`
	// RemovingAgent: the agent did not answer and the CLI is removing its
	// document (recorded before the removal; the resumption applies the agent
	// again); AgentRemoved once every instance of it is gone
	RemovingAgent bool `json:"removing_agent,omitempty"`
	AgentRemoved  bool `json:"agent_removed,omitempty"`
}

// RecoveryJob is a job the session runs.
type RecoveryJob struct {
	ID     string `json:"id"`
	Host   string `json:"host"`
	Inputs string `json:"inputs"`
}

func recoveryPath(fsid string) string { return filepath.Join(Root(), fsid, "recovery.json") }

// LoadRecovery reads a cluster's open recovery session, nil without one.
func LoadRecovery(fsid string) (*Recovery, error) {
	b, err := os.ReadFile(recoveryPath(fsid))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var r Recovery
	if err := json.Unmarshal(b, &r); err != nil || r.Schema != RecoverySchema || r.FSID != fsid || r.Session == "" {
		return nil, fmt.Errorf("the recovery journal %s is damaged", recoveryPath(fsid))
	}

	if r.Hosts == nil {
		r.Hosts = map[string]*RecoveryHost{}
	}

	if r.Jobs == nil {
		r.Jobs = map[string]*RecoveryJob{}
	}

	return &r, nil
}

// Host returns a host's part of the session, created empty.
func (r *Recovery) Host(name string) *RecoveryHost {
	h, ok := r.Hosts[name]
	if !ok {
		h = &RecoveryHost{}
		r.Hosts[name] = h
	}

	return h
}

// Save writes the journal, synced, before the effect it records.
func (r *Recovery) Save() error {
	path := recoveryPath(r.FSID)

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}

	if err := writeSynced(path+".tmp", b); err != nil {
		return err
	}

	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}

	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}

	defer d.Close() //nolint:errcheck

	return d.Sync()
}

// Close removes the journal once its session ended.
func (r *Recovery) Close() error {
	err := os.Remove(recoveryPath(r.FSID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return err
}
