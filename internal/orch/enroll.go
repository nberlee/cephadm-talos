package orch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
)

// EnrollPrefix holds the enrollment records the CLI writes for `ceph orch host
// add` (plan 03, step 7): public, one per host, outside mgr/.
const EnrollPrefix = "cephadm-talos/enroll/"

// Enrollment is a node the CLI enrolled: its name and address and its agent's
// certificates (their keys are secrets of their own).
type Enrollment struct {
	Version         int    `json:"version"`
	Name            string `json:"name"`
	Addr            string `json:"addr"`
	AgentCert       string `json:"agent_cert"`
	AgentClientCert string `json:"agent_client_cert"`
}

// Enroll adds a node to a cluster its leader owns (plan 03, step 7): the node
// checked, its agent's certificates (an interrupted enrollment's, if their keys
// match, else new ones from the agent CA) with their keys as secrets and an
// enrollment record, the agent's own documents applied (no cluster document:
// ceph.conf comes with the leader's first revision), the node handed to its
// agent, then `ceph orch host add`. The CLI writes no cluster state. Every step
// can be repeated: an agent that owns its node already is taken as handed over.
func (o *Orch) Enroll(ctx context.Context, addr string) error {
	if o.St.Agent == nil {
		return errors.New("the cluster has no agents")
	}

	if err := o.checkTalos(ctx, addr); err != nil {
		return err
	}

	if o.Talos.DryRun {
		o.printf("# enroll %s: agent certificates from the agent CA, their keys as secrets, the enrollment record, the agent's documents, the handoff to its agent, then ceph orch host add\n", addr)

		return nil
	}

	name, err := o.Talos.Hostname(ctx, addr)
	if err != nil {
		return err
	}

	// the name is part of the host's certificate identities (plan 03, item 3)
	if err := pki.ValidName(name); err != nil {
		return err
	}

	if _, ok := o.St.Host(name); ok {
		return fmt.Errorf("%s is a host of the cluster already", name)
	}

	adm, err := o.confirmedAdminHost()
	if err != nil {
		return err
	}

	// the agent CA's key, and an earlier enrollment's keys of this host
	if err := o.openSecrets(ctx, adm.Addr); err != nil {
		return err
	}

	secret := func(n string) (string, error) {
		v, err := o.secrets.Get(ctx, store.SecretPrefix+n)
		if errors.Is(err, store.ErrNotFound) {
			return "", nil
		}

		return string(v), err
	}

	if o.St.Agent.CAKey, err = secret("agent-ca.key"); err != nil || o.St.Agent.CAKey == "" {
		return fmt.Errorf("the agent CA's key: %w", errors.Join(err, errors.New("not readable")))
	}

	records, err := o.enrollments(ctx, adm.Addr)
	if err != nil {
		return err
	}

	h := state.Host{Name: name, Addr: addr}

	if b, err := records.Get(ctx, EnrollPrefix+name); err == nil {
		var rec Enrollment
		if json.Unmarshal(b, &rec) == nil && rec.Name == name && rec.Addr == addr {
			h.AgentCert, h.AgentClientCert = rec.AgentCert, rec.AgentClientCert

			if h.AgentKey, err = secret(state.SecretHost(name, state.SecretAgentServer)); err != nil {
				return err
			}

			if h.AgentClientKey, err = secret(state.SecretHost(name, state.SecretAgentClient)); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	// new certificates unless the earlier ones are valid with their keys and
	// not about to expire
	if expiresSoon(h.AgentCert, time.Now()) || expiresSoon(h.AgentClientCert, time.Now()) {
		h.AgentCert, h.AgentKey, h.AgentClientCert, h.AgentClientKey = "", "", "", ""
	}

	if err := o.ensureAgentCert(&h); err != nil {
		return err
	}

	// the keys first: a record never names a certificate without its key
	if err := o.secrets.SetMany(ctx, []store.KV{
		{Key: store.SecretPrefix + state.SecretHost(name, state.SecretAgentServer), Value: []byte(h.AgentKey)},
		{Key: store.SecretPrefix + state.SecretHost(name, state.SecretAgentClient), Value: []byte(h.AgentClientKey)},
	}); err != nil {
		return err
	}

	b, err := json.Marshal(Enrollment{Version: 1, Name: name, Addr: addr, AgentCert: h.AgentCert, AgentClientCert: h.AgentClientCert})
	if err != nil {
		return err
	}

	if err := records.SetMany(ctx, []store.KV{{Key: EnrollPrefix + name, Value: b}}); err != nil {
		return err
	}

	o.printf("enrolling %s (%s)\n", name, addr)

	if err := o.apply(ctx, addr, o.agentDocs(h)...); err != nil {
		return err
	}

	// the agent answers once it runs
	deadline := time.Now().Add(3 * time.Minute)

	for {
		err := o.handOver(ctx, h)
		if err == nil {
			break
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("handing %s to its agent: %w", name, err)
		}

		if err := sleep(ctx, 5*time.Second); err != nil {
			return err
		}
	}

	res, err := o.Job(ctx, adm.Addr, "ceph orch host add "+shellQuote(name)+" "+shellQuote(addr), 2*time.Minute)
	o.printf("%s", res.Output)

	return err
}

// enrollments is the config-key namespace of the enrollment records.
func (o *Orch) enrollments(ctx context.Context, node string) (store.Backend, error) {
	if o.StoreBackend != nil {
		return o.StoreBackend, nil
	}

	return o.configKeys(ctx, node, EnrollPrefix)
}
