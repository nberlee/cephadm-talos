package orch

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
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

	if rec.Phase != state.PhaseSuspended && rec.Phase != state.PhaseRecovering {
		return fmt.Errorf("recovery session %s is %s: agent restore runs while it is suspended", rec.Session, rec.Phase)
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

	if err := o.apply(ctx, h.Addr, o.agentDocsWith(ah, image, repos, approvalKey)...); err != nil {
		return err
	}

	// an apply intent the suspension could not decide: settled if it is a
	// self-update's, now that the restored documents are in the config
	if hr.Receipt.ApplyPending {
		rep, err := o.settleJob(ctx, h, rec)
		if err != nil {
			return fmt.Errorf("%s: settling its agent's self-update: %w", name, err)
		}

		if rep.Settled != "" {
			o.printf("%s: its agent's self-update %s is settled as failed\n", name, rep.Settled)
		}
	}

	if err := o.awaitSuspended(ctx, rec, h); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	if hr.RemovingAgent {
		hr.AgentRestored = true
	}

	if err := rec.Save(); err != nil {
		return err
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
