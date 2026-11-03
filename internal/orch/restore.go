package orch

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

// RestoreAgent applies a host's agent documents (the CLI's own) inside a
// recovery session, while that host's agent is suspended (plan 04, step 2):
// rendered from the state's certificates (their keys through AgentKeys), the
// pinned inputs the suspension journaled or, without them, those of the
// agent's current document on the node, and the agents' image, or with
// previous the known good one (an unfinished agent upgrade's from-image,
// else the image the last one upgraded from); never an old document whole.
// An interrupted self-update's apply intent matches neither rendering and
// would block the re-adoption: once the documents are in the node's config,
// a records job settles it as failed, only a self-update's. The agent starts
// suspended from its records; the restore checks that it then runs the
// intended image and serves the state's certificate. `resume` ends the
// session as usual.
func (o *Orch) RestoreAgent(ctx context.Context, name string, previous bool) error {
	if o.Talos.DryRun {
		return errors.New("agent restore has no dry run")
	}

	if o.St.Agent == nil {
		return errors.New("the cluster has no agents")
	}

	unlock, err := state.Lock(o.St.FSID)
	if err != nil {
		return err
	}
	defer unlock()

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil {
		return err
	}

	if rec == nil {
		return errors.New("agent restore runs in a recovery session: run `cephadm-talos suspend` first")
	}

	// also while resuming, until the resumption re-adopted or activated an
	// agent: a restore it applied that cannot start is rolled back so
	resumed := slices.ContainsFunc(slices.Collect(maps.Values(rec.Hosts)), func(hr *state.RecoveryHost) bool { return hr.Readopt != nil || hr.Activated })
	if rec.Phase != state.PhaseSuspended && rec.Phase != state.PhaseRecovering && (rec.Phase != state.PhaseResuming || resumed) {
		return fmt.Errorf("recovery session %s is %s: agent restore runs while it is suspended, or resuming before any agent was re-adopted", rec.Session, rec.Phase)
	}

	hr := rec.Hosts[name]
	if hr == nil || hr.Receipt == nil {
		return fmt.Errorf("%s's agent is not suspended in this session: run `cephadm-talos suspend` again", name)
	}

	// the state's certificates and image
	if !o.opened {
		if err := o.Open(ctx); err != nil {
			return fmt.Errorf("agent restore needs the mons (run `cephadm-talos recover mons` first): %w", err)
		}
	}

	h := state.Host{Name: name, Addr: hr.Addr}
	if sh, ok := o.St.Host(name); ok && sh.Name == name {
		h = sh
	}

	ah, err := o.agentHost(ctx, h, hr)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	repos, approvalKey := hr.AgentRepos, hr.AgentApprovalKey
	if !hr.AgentPinned {
		doc := o.agentDocName(h)

		docs, err := o.configuredDocs(ctx, h.Addr, doc)
		if err != nil {
			return err
		}

		d, ok := docs[doc]
		if !ok {
			return fmt.Errorf("%s: its agent's pinned inputs are neither journaled nor in a document on the node", name)
		}

		repos, approvalKey = strings.Fields(d.env[daemons.EnvImageRepos]), d.env[daemons.EnvApprovalKey]
	}

	image := o.St.Agent.Image
	if previous {
		switch u := o.St.AgentUpgrade; {
		case u != nil && !u.Finished:
			image = u.From
		case o.St.Agent.PreviousImage != "":
			image = o.St.Agent.PreviousImage
		default:
			return errors.New("no earlier agent image is known: no agent upgrade ran")
		}
	}

	o.printf("%s: restoring its agent with %s\n", name, image)

	if err := o.agentReturn(ctx, rec, h, o.agentDocsWith(ah, image, repos, approvalKey)); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	// it answers, but on what: the intended image and the state's certificate
	st, err := o.Talos.ContainerStatuses(ctx, h.Addr)
	if err != nil {
		return err
	}

	_, digest, _ := strings.Cut(image, "@")
	if s, ok := st[o.agentDocName(h)]; !ok || s.State != containers.ContainerStateRunning || s.Image != digest {
		return fmt.Errorf("%s: its agent does not run %s", name, image)
	}

	if ok, err := o.agentServes(h, ah.AgentCert); err != nil || !ok {
		return fmt.Errorf("%s: its agent does not serve the state's certificate: %v", name, err)
	}

	o.printf("%s: its agent is restored and suspended; `cephadm-talos resume` ends the session\n", name)

	return nil
}

// agentReturn brings a suspended host's agent back with its documents (`agent
// restore`, the resumption; plan 04, step 2): the apply journaled first
// (AgentApply) and decided from the node's config, as the recovery's mon
// documents are; then, if the receipt has an apply intent the agent could not
// decide, a records job settles it if it is a self-update's, which neither
// rendering may match and which would block the re-adoption; then the agent
// must answer suspended for the session. An apply journaled before (a stop,
// a retry) is decided first: while it may still land, nothing is applied.
// Without docs, only a journaled apply that landed is finished.
func (o *Orch) agentReturn(ctx context.Context, rec *state.Recovery, h state.Host, docs []any) error {
	hr := rec.Hosts[h.Name]

	applied, err := o.agentApplied(ctx, rec, h)
	if err != nil {
		return err
	}

	if docs != nil {
		want, err := docHashes(docs)
		if err != nil {
			return err
		}

		// a journaled apply of another rendering (a retry with another image)
		// is replaced
		if !applied || !maps.Equal(hr.AgentApply.Hashes, want) {
			if err := o.applyAgentDocs(ctx, rec, h, want, docs); err != nil {
				return err
			}
		}
	} else if !applied {
		return nil
	}

	if hr.Receipt.ApplyPending {
		rep, err := o.settleJob(ctx, h, rec)
		if err != nil {
			return fmt.Errorf("settling its agent's self-update: %w", err)
		}

		if rep.Settled != "" {
			o.printf("%s: its agent's self-update %s is settled as failed\n", h.Name, rep.Settled)
		}
	}

	if err := o.awaitSuspended(ctx, rec, h); err != nil {
		return err
	}

	hr.AgentApply = nil
	if hr.RemovingAgent {
		hr.AgentRestored = true
	}

	return rec.Save()
}

// docHashes are documents' hashes as the agent computes them.
func docHashes(docs []any) (map[string]string, error) {
	b, err := spec.Render(docs...)
	if err != nil {
		return nil, err
	}

	return agent.DocHashes(string(b))
}

// agentApplyWithin bounds the dispatch of a journaled apply of an agent's
// documents: it is not sent after it, and its settlement counts from then.
const agentApplyWithin = 2 * time.Minute

// applyAgentDocs applies a host's agent documents, unless the node holds them
// already (recorded applied, nothing sent); else journaled first with the
// deadline of its dispatch. The node must hold them afterwards.
func (o *Orch) applyAgentDocs(ctx context.Context, rec *state.Recovery, h state.Host, hashes map[string]string, docs []any) error {
	hr := rec.Hosts[h.Name]

	held, err := o.holdsDocs(ctx, h, hashes)
	if err != nil {
		return err
	}

	if held {
		hr.AgentApply = &state.AgentApply{Hashes: hashes, At: time.Now().UTC(), Applied: true}

		return rec.Save()
	}

	boot, err := o.Talos.BootID(ctx, h.Addr)
	if err != nil {
		return err
	}

	at := time.Now().UTC()
	hr.AgentApply = &state.AgentApply{Hashes: hashes, BootID: boot, At: at, Before: at.Add(agentApplyWithin)}

	if err := rec.Save(); err != nil {
		return err
	}

	actx, cancel := context.WithDeadline(ctx, hr.AgentApply.Before)
	defer cancel()

	if err := o.apply(talos.WithApplyBefore(actx, hr.AgentApply.Before), h.Addr, docs...); errors.Is(err, talos.ErrApplyDeadline) {
		// nothing was sent: the journal entry goes
		hr.AgentApply = nil
		if serr := rec.Save(); serr != nil {
			return serr
		}

		return err
	} else if err != nil {
		return err
	}

	applied, err := o.agentApplied(ctx, rec, h)
	if err == nil && !applied {
		err = errors.New("its agent's documents are not in the node's config after their apply")
	}

	return err
}

// holdsDocs reports whether a node's config holds documents with these hashes.
func (o *Orch) holdsDocs(ctx context.Context, h state.Host, hashes map[string]string) (bool, error) {
	cfg, err := o.Talos.MachineConfig(ctx, h.Addr)
	if err != nil {
		return false, err
	}

	cur, err := agent.DocHashes(cfg)
	if err != nil {
		return false, err
	}

	for k, v := range hashes {
		if cur[k] != v {
			return false, nil
		}
	}

	return true, nil
}

// agentReserved refuses a node whose agent's documents a recovery apply
// journaled with no known outcome: decided first from the node's config, so
// one that settled no longer reserves it. Every writer of the recovery asks.
func (o *Orch) agentReserved(ctx context.Context, rec *state.Recovery, h state.Host) error {
	if rec == nil || rec.Hosts[h.Name] == nil || rec.Hosts[h.Name].AgentApply == nil {
		return nil
	}

	if _, err := o.agentApplied(ctx, rec, h); err != nil {
		return fmt.Errorf("the node is reserved: %w", err)
	}

	return nil
}

// agentApplied decides a journaled apply of a host's agent documents from the
// node's config: applied once the node holds every one (recorded); not, on
// another boot or once the apply settled (the journal entry goes); else its
// outcome is unknown, an error. Without one it reports false.
func (o *Orch) agentApplied(ctx context.Context, rec *state.Recovery, h state.Host) (bool, error) {
	hr := rec.Hosts[h.Name]

	a := hr.AgentApply
	if a == nil {
		return false, nil
	}

	if a.Applied {
		return true, nil
	}

	// settlement first: the config read after it shows an apply still handled
	// then; it counts from the dispatch's deadline
	boot, err := o.Talos.BootID(ctx, h.Addr)
	if err != nil {
		return false, err
	}

	sent := a.Before
	if sent.IsZero() {
		sent = a.At
	}

	settled := boot != a.BootID || time.Since(sent) >= agent.ApplySettle

	held, err := o.holdsDocs(ctx, h, a.Hashes)
	if err != nil {
		return false, err
	}

	switch {
	case held:
		a.Applied = true
	case settled:
		hr.AgentApply = nil
	default:
		return false, fmt.Errorf("the apply of its agent's documents may still land: run again after %s", sent.Add(agent.ApplySettle).Local().Format(time.TimeOnly))
	}

	return held, rec.Save()
}

// agentKeyNames are the secret names of a host's agent keys, for a host the
// state does not have (plan 04, step 2): those of the module's renewal whose
// server certificate, kept beside its key (issued/<op>/<attempt>/
// agent-server.crt), is the given one, else the CLI's (host/<host>/). The
// secrets are read through exec, as the CLI reads them.
func (o *Orch) agentKeyNames(ctx context.Context, host, certPEM string) (server, client string, err error) {
	adm, err := o.confirmedAdminHost()
	if err != nil {
		return "", "", err
	}

	if err := o.openSecrets(ctx, adm.Addr); err != nil {
		return "", "", err
	}

	keys, err := o.secrets.List(ctx, store.SecretPrefix+"issued/")
	if err != nil {
		return "", "", err
	}

	for _, k := range keys {
		ref, ok := strings.CutSuffix(strings.TrimPrefix(k, store.SecretPrefix+"issued/"), "/agent-server.crt")
		if !ok {
			continue
		}

		v, err := o.secrets.Get(ctx, k)
		if err != nil {
			return "", "", err
		}

		if strings.TrimSpace(string(v)) == strings.TrimSpace(certPEM) {
			return state.SecretIssued(ref, state.SecretAgentServer), state.SecretIssued(ref, state.SecretAgentClient), nil
		}
	}

	return state.SecretHost(host, state.SecretAgentServer), state.SecretHost(host, state.SecretAgentClient), nil
}

// settleJob runs the records job that settles an interrupted self-update's
// apply intent, under a new id of the session's journal (a job replays its
// result under the same id).
func (o *Orch) settleJob(ctx context.Context, h state.Host, rec *state.Recovery) (agent.RecordsReport, error) {
	if o.settleSelf != nil {
		return o.settleSelf(h)
	}

	var (
		purpose string
		j       *state.RecoveryJob
	)

	for n := 1; ; n++ {
		purpose = fmt.Sprintf("settle/%s/%d", h.Name, n)
		if j = rec.Jobs[purpose]; j == nil || !j.Done {
			break
		}
	}

	if j == nil {
		j = &state.RecoveryJob{ID: randHex(3), Host: h.Name, Inputs: jobInputs("records", h.Name, rec.Session, purpose)}
		rec.Jobs[purpose] = j

		if err := rec.Save(); err != nil {
			return agent.RecordsReport{}, err
		}
	}

	name := fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), j.ID)

	res, err := o.runJob(ctx, h.Addr, daemons.RecordsSettleJob(name, o.St.Agent.Image, o.St.FSID, j.ID, j.Inputs), j.ID, 5*time.Minute)
	if err != nil {
		return agent.RecordsReport{}, err
	}

	var rep agent.RecordsReport
	if err := json.Unmarshal([]byte(res.Output), &rep); err != nil {
		return agent.RecordsReport{}, fmt.Errorf("the records job's report: %w", err)
	}

	j.Done = true

	return rep, rec.Save()
}

// agentServes reports whether a host's agent answers a TLS handshake with a
// certificate.
func (o *Orch) agentServes(h state.Host, certPEM string) (bool, error) {
	want, err := pki.Parse(certPEM)
	if err != nil {
		return false, err
	}

	cfg, err := agent.ClientTLSConfig([]byte(o.St.Agent.CACert), []byte(o.St.Agent.OperatorCert), []byte(o.St.Agent.OperatorKey))
	if err != nil {
		return false, err
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", agentAddr(h), cfg)
	if err != nil {
		return false, err
	}
	defer conn.Close() //nolint:errcheck

	peers := conn.ConnectionState().PeerCertificates

	return len(peers) > 0 && peers[0].Equal(want), nil
}
