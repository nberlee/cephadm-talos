package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
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

	if err := hostName(name); err != nil {
		return err
	}

	// the fence: the published record as it is now, before anything is written
	if err := o.enrollFence(ctx, name, addr); err != nil {
		return err
	}

	adm, err := o.confirmedAdminHost()
	if err != nil {
		return err
	}

	if err := o.openSecrets(ctx, adm.Addr); err != nil {
		return err
	}

	records, err := o.enrollments(ctx, adm.Addr)
	if err != nil {
		return err
	}

	// an earlier enrollment of this host at this address, if any
	var earlier *Enrollment

	if b, err := records.Get(ctx, EnrollPrefix+name); err == nil {
		var rec Enrollment
		if json.Unmarshal(b, &rec) == nil && rec.Name == name && rec.Addr == addr {
			earlier = &rec
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	// a node of another generation is taken over before anything is written,
	// then it starts over: new certificates, a serial the old records never
	// listed, so a retirement mark never applies to the new agent
	cleaned, err := o.cleanNode(ctx, name, addr, earlier)
	if err != nil {
		return err
	}

	if cleaned {
		earlier = nil

		if err := o.enrollFence(ctx, name, addr); err != nil {
			return err
		}
	}

	// the agent CA's key, and an earlier enrollment's keys of this host

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

	h := state.Host{Name: name, Addr: addr}

	if earlier != nil {
		h.AgentCert, h.AgentClientCert = earlier.AgentCert, earlier.AgentClientCert

		if h.AgentKey, err = secret(state.SecretHost(name, state.SecretAgentServer)); err != nil {
			return err
		}

		if h.AgentClientKey, err = secret(state.SecretHost(name, state.SecretAgentClient)); err != nil {
			return err
		}
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

	err = o.adminCommand(ctx, "ceph orch host add "+shellQuote(name)+" "+shellQuote(addr))

	// whether the add was accepted or not: a mgr that died during an earlier
	// retirement of this name may have had a deletion still on its way (the
	// fence comment in the module's _retire_done), which erases what was just
	// written
	if lost := o.enrollmentLost(ctx, records, h, b); lost != nil {
		return errors.Join(err, fmt.Errorf("the enrollment of %s did not stay as written: %w; "+
			"if `ceph orch host ls` lists it: `ceph orch host rm %s`, wait until its retirement ended, then `cephadm-talos host add %s`; "+
			"if it does not: `cephadm-talos host add %s` again", name, lost, name, addr, addr))
	}

	return err
}

// enrollFence refuses a name that is a member or retiring, and an address a
// member or a retiring host has, from the published record read now: the
// removal's end deletes what its fold knew of the name, and a takeover of the
// node would stop a member's agent.
func (o *Orch) enrollFence(ctx context.Context, name, addr string) error {
	if err := o.Open(ctx); err != nil {
		return err
	}

	if h, ok := o.St.Host(name); ok && h.Name == name {
		return fmt.Errorf("%s is a host of the cluster already", name)
	}

	if _, _, ok := o.St.RetiringHost(name); ok {
		return fmt.Errorf("%s is being removed: it can be added again once its retirement ended (`ceph orch host ls`; `cephadm-talos host forget %s` if its agent does not retire)", name, name)
	}

	if h, ok := o.St.Host(addr); ok {
		return fmt.Errorf("%s has the address %s", h.Name, addr)
	}

	for n, r := range o.St.Retiring {
		if r != nil && r.Addr == addr {
			return fmt.Errorf("%s, which is being removed, has the address %s", n, addr)
		}
	}

	return nil
}

// cleanNode takes over a node that may hold the cluster's records of a
// generation before this enrollment (removed, forgotten, or its retirement
// ended before its agent moved them): the host is no member (the fence), so
// any such agent's documents go and the records are retired before anything
// of the new agent is written; a new agent never starts over an old set or a
// pending retirement apply. An agent document with the certificates of this
// host's enrollment record is that interrupted enrollment's own, which goes
// on (cleaned is false); so is a node that never had the records volume. A
// document of another host's agent that is a member or retiring refuses.
func (o *Orch) cleanNode(ctx context.Context, name, addr string, earlier *Enrollment) (cleaned bool, err error) {
	// whatever follows: a retirement left by a stopped run goes first
	if err := o.removeLeftRecordsJobs(ctx, state.Host{Name: name, Addr: addr}); err != nil {
		return false, err
	}

	docs, err := o.configuredDocs(ctx, addr, "ceph-"+o.St.Short()+"-agent-")
	if err != nil {
		return false, err
	}

	delete(docs, cephConfDoc)

	own := earlier != nil && len(docs) > 0

	for doc, d := range docs {
		cert := unb64(d.env[daemons.EnvCert])

		if c, err := pki.Parse(cert); err == nil {
			if id, err := pki.CertIdentity(c); err == nil && id.Name != name {
				if h, member := o.St.Host(id.Name); member && h.Name == id.Name {
					return false, fmt.Errorf("the node runs %s, the agent of %s, a host of the cluster", doc, id.Name)
				}

				if _, _, retiring := o.St.RetiringHost(id.Name); retiring {
					return false, fmt.Errorf("the node runs %s, the agent of %s, which is being removed", doc, id.Name)
				}
			}
		}

		if earlier == nil || cert != earlier.AgentCert {
			own = false
		}
	}

	if own {
		return false, nil
	}

	cfg, err := o.Talos.MachineConfig(ctx, addr)
	if err != nil {
		return false, err
	}

	held, err := agent.DocHashes(cfg)
	if err != nil {
		return false, err
	}

	if len(docs) == 0 && held["UserVolumeConfig/"+spec.RecordsVolumeName] == "" {
		return false, nil
	}

	o.printf("%s: taking over its node: any agent of the cluster goes and any records of the cluster are retired\n", name)

	if err := o.takeOverNode(ctx, state.Host{Name: name, Addr: addr}, ""); err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}

	return true, nil
}

// enrollmentLost reports what of an enrollment's keys and record differs from
// what was written, nil if nothing.
func (o *Orch) enrollmentLost(ctx context.Context, records store.Backend, h state.Host, record []byte) error {
	var lost []string

	for what, c := range map[string]struct {
		read func() ([]byte, error)
		want []byte
	}{
		"its agent's server key": {func() ([]byte, error) {
			return o.secrets.Get(ctx, store.SecretPrefix+state.SecretHost(h.Name, state.SecretAgentServer))
		}, []byte(h.AgentKey)},
		"its agent's client key": {func() ([]byte, error) {
			return o.secrets.Get(ctx, store.SecretPrefix+state.SecretHost(h.Name, state.SecretAgentClient))
		}, []byte(h.AgentClientKey)},
		"its enrollment record": {func() ([]byte, error) { return records.Get(ctx, EnrollPrefix+h.Name) }, record},
	} {
		got, err := c.read()

		switch {
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return fmt.Errorf("%s cannot be read back: %w", what, err)
		case err != nil || !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(c.want)):
			lost = append(lost, what)
		}
	}

	if len(lost) == 0 {
		return nil
	}

	slices.Sort(lost)

	return errors.New(strings.Join(lost, ", ") + " differ")
}

// enrollments is the config-key namespace of the enrollment records.
func (o *Orch) enrollments(ctx context.Context, node string) (store.Backend, error) {
	if o.StoreBackend != nil {
		return o.StoreBackend, nil
	}

	return o.configKeys(ctx, node, EnrollPrefix)
}
