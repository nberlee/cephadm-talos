package orch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// SuspensionKey is the control record while the cluster is suspended (plan
// 03, step 7 slice D, item 4): the module accepts nothing while it exists. It
// is outside mgr/, where the bridge cannot write.
const SuspensionKey = "cephadm-talos/suspension"

// SuspendOptions are the operator's choices for agents that do not answer.
type SuspendOptions struct {
	// Reboot reboots a node whose agent's last apply may still land, instead
	// of waiting until it settled
	Reboot bool
	// Force removes a job the agent started that still runs, instead of
	// waiting for it; its operation stays uncertain
	Force bool
}

// How long the CLI waits for what a suspension waits for, and how long an
// agent may not answer before it counts as not answering.
var (
	suspendTimeout   = 30 * time.Minute
	suspendPoll      = 5 * time.Second
	unreachableAfter = 30 * time.Second
	// the agent's own limits for a reboot and a restart (agent: rebootWithin,
	// restartWithin), for the outcome the CLI reads from Talos
	rebootLimit  = 20 * time.Minute
	restartLimit = 10 * time.Minute
)

// errUnreachable means an agent did not answer: the CLI suspends its node
// itself (item 5).
var errUnreachable = errors.New("the agent does not answer")

func newSession() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Suspend suspends every agent of the cluster for a recovery session (plan 03,
// step 7 slice D): the control record first when the mons answer, then each
// agent until it gives its receipt, or, for an agent that does not answer,
// the node through Talos. An interrupted suspension continues its session.
func (o *Orch) Suspend(ctx context.Context, opts SuspendOptions) (*state.Recovery, error) {
	if o.St.Agent == nil {
		return nil, errors.New("the cluster has no agents to suspend")
	}

	if o.Talos.DryRun {
		return nil, errors.New("suspend has no dry run: it suspends the agents themselves")
	}

	unlock, err := state.Lock(o.St.FSID)
	if err != nil {
		return nil, err
	}
	defer unlock()

	return o.suspendLocked(ctx, opts)
}

// suspendLocked is Suspend for a caller that holds the cluster's Lock.
func (o *Orch) suspendLocked(ctx context.Context, opts SuspendOptions) (*state.Recovery, error) {
	// what an offline suspension or recovery needs from the state (the agent
	// CA, the agent image, the hosts) is kept locally while it can be read
	if o.opened {
		if err := o.St.SaveLocked(); err != nil {
			return nil, err
		}
	}

	if o.St.Agent.CACert == "" || o.St.Agent.Image == "" {
		return nil, errors.New("this workstation has neither the cluster state nor a local copy of the agent CA and image: run a command while the mons answer first")
	}

	rec, err := state.LoadRecovery(o.St.FSID)
	if err != nil {
		return nil, err
	}

	if rec == nil {
		session, err := newSession()
		if err != nil {
			return nil, err
		}

		rec = &state.Recovery{Schema: state.RecoverySchema, FSID: o.St.FSID, Session: session, Phase: state.PhaseSuspending,
			Hosts: map[string]*state.RecoveryHost{}, Jobs: map[string]*state.RecoveryJob{}}
		if err := rec.Save(); err != nil {
			return nil, err
		}
	}

	if rec.Phase != state.PhaseSuspending && rec.Phase != state.PhaseSuspended {
		return nil, fmt.Errorf("recovery session %s is %s", rec.Session, rec.Phase)
	}

	o.printf("recovery session %s\n", rec.Session)

	if !rec.Control {
		if err := o.setControl(ctx, rec); err != nil {
			o.printf("warning: the control record is not written (%v); `resume` writes it once the mons answer\n", err)
		} else {
			rec.Control = true
			if err := rec.Save(); err != nil {
				return nil, err
			}
		}
	}

	// until no host is left without a receipt: an accepted `host add` may add
	// one while the others drain
	for {
		hosts, err := o.memberHosts(ctx)
		if err != nil {
			return rec, fmt.Errorf("the cluster's hosts: %w (the session stays open: run `cephadm-talos suspend` again)", err)
		}

		// every host found is journaled before any is suspended, and every
		// journaled host needs its receipt, also on a retry without the mons
		changed := false

		for _, h := range hosts {
			if hr := rec.Host(h.Name); hr.Addr == "" {
				hr.Addr, changed = h.Addr, true
			}
		}

		if changed {
			if err := rec.Save(); err != nil {
				return rec, err
			}
		}

		var pending []state.Host

		for name, hr := range rec.Hosts {
			if hr.Receipt == nil {
				pending = append(pending, state.Host{Name: name, Addr: hr.Addr})
			}
		}

		sort.Slice(pending, func(i, j int) bool { return pending[i].Name < pending[j].Name })

		if len(pending) == 0 {
			break
		}

		if err := o.suspendHosts(ctx, pending, rec, opts); err != nil {
			return rec, err
		}
	}

	rec.Phase = state.PhaseSuspended

	return rec, rec.Save()
}

// memberHosts are the hosts to suspend: those of the cluster state (read
// again while the mons answer), the workstation's contacts, and every node
// the CLI enrolled (an accepted `host add` may not be in the state yet).
func (o *Orch) memberHosts(ctx context.Context) ([]state.Host, error) {
	if !o.opened {
		return o.St.AllHosts(), nil
	}

	if err := o.Open(ctx); err != nil {
		return nil, err
	}

	hosts := o.St.AllHosts()

	adm, err := o.confirmedAdminHost()
	if err != nil {
		return nil, err
	}

	recs, err := o.enrollments(ctx, adm.Addr)
	if err != nil {
		return nil, err
	}

	keys, err := recs.List(ctx, EnrollPrefix)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		b, err := recs.Get(ctx, k)
		if err != nil {
			return nil, err
		}

		var e Enrollment
		if err := json.Unmarshal(b, &e); err != nil || e.Name == "" || e.Name != strings.TrimPrefix(k, EnrollPrefix) {
			return nil, fmt.Errorf("enrollment record %s: damaged", k)
		}

		if !slices.ContainsFunc(hosts, func(h state.Host) bool { return h.Name == e.Name }) {
			hosts = append(hosts, state.Host{Name: e.Name, Addr: e.Addr})
		}
	}

	return hosts, nil
}

// suspendHosts suspends each host: its agent, or the node itself when the
// agent does not answer, or when the CLI's operator certificate has expired
// (every agent would refuse it; read from its notAfter, never from a TLS
// error).
func (o *Orch) suspendHosts(ctx context.Context, hosts []state.Host, rec *state.Recovery, opts SuspendOptions) error {
	expired := o.operatorExpired(time.Now())
	if expired {
		o.printf("the operator certificate has expired: suspending every node through Talos\n")
	}

	for _, h := range hosts {
		hr := rec.Host(h.Name)

		var (
			receipt *wire.SuspendReceipt
			err     error
		)

		// an agent whose removal is not confirmed may answer again: asked first
		if !hr.AgentRemoved && !expired {
			receipt, err = o.suspendAgent(ctx, h, rec.Session)
		}

		if hr.AgentRemoved || expired || errors.Is(err, errUnreachable) {
			if err != nil {
				o.printf("%s: %v: suspending the node through Talos\n", h.Name, err)
			}

			receipt, err = o.suspendNode(ctx, h, rec, opts)
		}

		if err != nil {
			return fmt.Errorf("%s: %w (the session stays open: run `cephadm-talos suspend` again)", h.Name, err)
		}

		hr.Receipt = receipt
		if err := rec.Save(); err != nil {
			return err
		}

		o.printf("%s: suspended at revision %d, %d uncertain operations, %d open bridge calls\n", h.Name, receipt.Revision, len(receipt.Unresolved), len(receipt.Intents))
	}

	return nil
}

// setControl writes the control record through exec.
func (o *Orch) setControl(ctx context.Context, rec *state.Recovery) error {
	if !o.opened {
		return errors.New("the cluster state cannot be read")
	}

	keys, err := o.controlStore(ctx)
	if err != nil {
		return err
	}

	b, err := json.Marshal(map[string]string{"session": rec.Session})
	if err != nil {
		return err
	}

	return keys.SetMany(ctx, []store.KV{{Key: SuspensionKey, Value: b}})
}

// operatorClient is an HTTP client to one host's agent with the operator
// certificate, which checks the agent's certificate names that host.
func (o *Orch) operatorClient(h state.Host) (*http.Client, error) {
	cfg, err := agent.ClientTLSConfig([]byte(o.St.Agent.CACert), []byte(o.St.Agent.OperatorCert), []byte(o.St.Agent.OperatorKey))
	if err != nil {
		return nil, err
	}

	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no server certificate")
		}

		if _, err := pki.Require(cs.PeerCertificates[0], pki.Identity{FSID: o.St.FSID, Role: pki.RoleAgent, Name: h.Name}); err != nil {
			return err
		}

		// not an agent the revocation list names (plan 04, step 3)
		return o.checkAgent(cs.PeerCertificates[0])
	}

	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, Timeout: 2 * time.Minute}, nil
}

// agentAddr is where a host's agent listens; tests replace it.
var agentAddr = func(h state.Host) string { return net.JoinHostPort(h.Addr, strconv.Itoa(agent.Port)) }

func agentURL(h state.Host, path string) string { return "https://" + agentAddr(h) + path }

// suspendAgent asks one agent to suspend and waits for its receipt;
// errUnreachable when it does not answer for unreachableAfter.
func (o *Orch) suspendAgent(ctx context.Context, h state.Host, session string) (*wire.SuspendReceipt, error) {
	cl, err := o.operatorClient(h)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(wire.Suspend{Version: wire.Version, FSID: o.St.FSID, Host: h.Name, Session: session})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, suspendTimeout)
	defer cancel()

	var (
		silentSince time.Time
		last        string
		posted      bool
	)

	for {
		method, path, payload := http.MethodGet, "/v1/suspend", []byte(nil)
		if !posted {
			method, payload = http.MethodPost, body
		}

		st, code, err := callAgent(ctx, cl, method, agentURL(h, path), payload)

		switch {
		case err != nil && ctx.Err() != nil:
			return nil, fmt.Errorf("the agent's suspension did not end: %w", ctx.Err())
		case err != nil && (code != 0 || !unreachable(err)):
			// an agent that answers wrongly (its certificate, its TLS) is no
			// reason to take its node from it
			return nil, err
		case err != nil:
			if silentSince.IsZero() {
				silentSince = time.Now()
			}

			if time.Since(silentSince) >= unreachableAfter {
				return nil, fmt.Errorf("%w: %v", errUnreachable, err)
			}
		case code == http.StatusOK && st.Receipt != nil:
			if st.Receipt.Session != session || st.Receipt.Host != h.Name {
				return nil, fmt.Errorf("a receipt for session %s of %s", st.Receipt.Session, st.Receipt.Host)
			}

			return st.Receipt, nil
		case code == http.StatusAccepted:
			posted, silentSince = true, time.Time{}

			if w := strings.Join(st.Waiting, ", "); w != last {
				o.printf("%s: waiting for %s\n", h.Name, w)
				last = w
			}
		default:
			return nil, fmt.Errorf("the agent answered %d: %s", code, st.Error)
		}

		if err := sleep(ctx, suspendPoll); err != nil {
			return nil, fmt.Errorf("the agent's suspension did not end: %w", err)
		}
	}
}

// unreachable reports whether an error says the agent did not answer at
// all: no connection, or none within the deadline.
func unreachable(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}

	var ne net.Error

	return errors.As(err, &ne) && ne.Timeout() || errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)
}

// agentState is an agent's answer to a suspension: its state, or an error.
type agentState struct {
	wire.SuspendState
	Error string
}

func callAgent(ctx context.Context, cl *http.Client, method, url string, body []byte) (agentState, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return agentState{}, 0, err
	}

	resp, err := cl.Do(req)
	if err != nil {
		return agentState{}, 0, err
	}

	defer resp.Body.Close() //nolint:errcheck

	// an answer that started to arrive is never "no answer": its error names
	// no network failure (%v), so it cannot count as unreachable
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return agentState{}, resp.StatusCode, fmt.Errorf("the agent's answer (%d) could not be read: %v", resp.StatusCode, err)
	}

	var st agentState

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		if err := json.Unmarshal(raw, &st.SuspendState); err != nil {
			return agentState{}, resp.StatusCode, fmt.Errorf("the agent's answer: %v", err)
		}
	} else {
		st.Error = string(bytes.TrimSpace(raw))
	}

	return st, resp.StatusCode, nil
}

// suspendNode suspends a node whose agent does not answer (item 5): the
// agent's document goes, an apply it may have sent settles (or the node
// reboots), what it started ends, and a recovery job writes the suspension.
// The node stays reserved as a whole until then.
func (o *Orch) suspendNode(ctx context.Context, h state.Host, rec *state.Recovery, opts SuspendOptions) (*wire.SuspendReceipt, error) {
	hr := rec.Host(h.Name)
	doc := o.agentDocName(h)

	for attempt := 1; ; attempt++ {
		// recorded before the removal, so the resumption applies the agent
		// again whatever happened; confirmed once its instances are gone
		if !hr.RemovingAgent {
			// its certificates and pinned inputs, from its document while it
			// is there, and the secrets of its keys (plan 04, step 2)
			if hr.AgentCert == "" {
				docs, err := o.configuredDocs(ctx, h.Addr, doc)
				if err != nil {
					return nil, err
				}

				if d, ok := docs[doc]; ok {
					hr.AgentCert, hr.AgentClientCert = unb64(d.env[daemons.EnvCert]), unb64(d.env[daemons.EnvClientCert])
					hr.AgentPinned, hr.AgentRepos, hr.AgentApprovalKey = true, strings.Fields(d.env[daemons.EnvImageRepos]), d.env[daemons.EnvApprovalKey]
					hr.AgentCRLFailClosed = d.env[daemons.EnvCRLFailClosed] == "1"
				}

				// the state's AgentKeys; for a host the state does not have, the
				// renewal whose certificate the agent's document has, if the
				// secrets can be read (else the resumption finds them)
				if sh, ok := o.St.Host(h.Name); ok && sh.Name == h.Name {
					hr.AgentServerKey, hr.AgentClientKey = sh.AgentKeySecret(state.SecretAgentServer), sh.AgentKeySecret(state.SecretAgentClient)
				} else if hr.AgentCert != "" {
					if server, client, err := o.agentKeyNames(ctx, h.Name, hr.AgentCert); err == nil {
						hr.AgentServerKey, hr.AgentClientKey = server, client
					} else {
						o.printf("%s: the secrets of its agent's keys are not known yet: %v\n", h.Name, err)
					}
				}
			}

			hr.RemovingAgent = true
			if err := rec.Save(); err != nil {
				return nil, err
			}
		}

		o.printf("%s: removing its agent\n", h.Name)

		if err := o.remove(ctx, h.Addr, doc); err != nil {
			return nil, err
		}

		if err := o.waitGone(ctx, h.Addr, doc, 5*time.Minute); err != nil {
			return nil, err
		}

		if !hr.AgentRemoved {
			hr.AgentRemoved = true
			if err := rec.Save(); err != nil {
				return nil, err
			}
		}

		rep, err := o.recordsJob(ctx, h, rec, fmt.Sprintf("inspect/%s/%d", h.Name, attempt), "")
		if err != nil {
			return nil, err
		}

		if err := o.settleApply(ctx, h, rep, opts); err != nil {
			return nil, err
		}

		if err := o.awaitStarted(ctx, h, rec, rep, opts); err != nil {
			return nil, err
		}

		// an apply that landed meanwhile may have brought the agent back
		docs, err := o.configuredContainers(ctx, h.Addr, doc)
		if err != nil {
			return nil, err
		}

		if !slices.Contains(docs, doc) {
			break
		}

		o.printf("%s: its agent came back with an earlier apply\n", h.Name)
	}

	rep, err := o.recordsJob(ctx, h, rec, "suspend/"+h.Name, rec.Session)
	if err != nil {
		return nil, err
	}

	if rep.Session != rec.Session {
		return nil, fmt.Errorf("the records show session %q", rep.Session)
	}

	return &wire.SuspendReceipt{
		Version: wire.Version, Session: rec.Session, Host: h.Name, Revision: rep.Revision, Fence: rep.Fence, Floor: rep.Floor,
		Unresolved: rep.Open, Intents: rep.Intents, Owned: rep.Owned, Prepared: rep.Prepared, ApplyPending: rep.ApplyBoot != "",
	}, nil
}

// unb64 decodes a base64 value, "" if it is not one.
func unb64(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}

	return string(b)
}

// recordsJob runs the recovery job under the id the journal keeps for its
// purpose, allocated and recorded before its document is applied.
func (o *Orch) recordsJob(ctx context.Context, h state.Host, rec *state.Recovery, purpose, session string) (agent.RecordsReport, error) {
	j, ok := rec.Jobs[purpose]
	if !ok {
		j = &state.RecoveryJob{ID: randHex(3), Host: h.Name, Inputs: jobInputs("records", h.Name, rec.Session, purpose)}
		rec.Jobs[purpose] = j

		if err := rec.Save(); err != nil {
			return agent.RecordsReport{}, err
		}
	}

	name := fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), j.ID)

	res, err := o.runJob(ctx, h.Addr, daemons.RecordsJob(name, o.St.Agent.Image, o.St.FSID, j.ID, j.Inputs, session), j.ID, 5*time.Minute)
	if err != nil {
		return agent.RecordsReport{}, fmt.Errorf("reading the agent's records: %w", err)
	}

	var rep agent.RecordsReport
	if err := json.Unmarshal([]byte(res.Output), &rep); err != nil {
		return agent.RecordsReport{}, fmt.Errorf("the records job's report: %w", err)
	}

	return rep, nil
}

// settleApply waits until an apply the agent sent can no longer land: on
// another boot, or ApplySettle after it was sent; with Reboot it reboots the
// node instead of waiting.
func (o *Orch) settleApply(ctx context.Context, h state.Host, rep agent.RecordsReport, opts SuspendOptions) error {
	if rep.ApplyBoot == "" {
		return nil
	}

	boot, err := o.Talos.BootID(ctx, h.Addr)
	if err != nil {
		return err
	}

	until := time.Unix(0, rep.ApplyAt).Add(agent.ApplySettle)
	if boot != rep.ApplyBoot || !time.Now().Before(until) {
		return nil
	}

	if opts.Reboot {
		o.printf("%s: its agent's last apply may still land: rebooting the node\n", h.Name)

		return o.Talos.Reboot(ctx, h.Addr)
	}

	o.printf("%s: its agent's last apply may still land: waiting until %s (or run with --reboot)\n", h.Name, until.Format(time.TimeOnly))

	return sleep(ctx, time.Until(until))
}

// awaitStarted waits until what the agent started has ended: a job's
// container (or, with Force, removes it), a reboot (another boot) and a
// restart (a newer instance), each within the agent's own limits.
func (o *Orch) awaitStarted(ctx context.Context, h state.Host, rec *state.Recovery, rep agent.RecordsReport, opts SuspendOptions) error {
	for _, op := range rep.Open {
		switch {
		case op.Job != nil:
			// only a job whose apply the ownership shows and no apply intent
			// is left: one whose apply the agent did not record (or not
			// finish recording) is waited for, as its removal would make its
			// reconcile take the apply for refused
			if opts.Force && op.Revision <= rep.Revision && rep.ApplyBoot == "" {
				// a removal the re-adoption expects, journaled before it
				hr := rec.Host(h.Name)
				if v, ok := hr.Changes["ContainerConfig/"+op.Job.Doc]; !ok || v != "" {
					if hr.Changes == nil {
						hr.Changes = map[string]string{}
					}

					hr.Changes["ContainerConfig/"+op.Job.Doc] = ""
					if err := rec.Save(); err != nil {
						return err
					}
				}

				if err := o.remove(ctx, h.Addr, op.Job.Doc); err != nil {
					return err
				}

				if err := o.waitGone(ctx, h.Addr, op.Job.Doc, 5*time.Minute); err != nil {
					return err
				}

				continue
			}

			if err := o.waitEnded(ctx, h, op.Job.Doc); err != nil {
				return fmt.Errorf("job %s of operation %s: %w (or run with --force)", op.Job.ID, op.Operation, err)
			}
		case op.Reboot:
			until := time.Unix(0, op.At).Add(rebootLimit)

			for {
				boot, err := o.Talos.BootID(ctx, h.Addr)
				if err == nil && boot != op.BootID || !time.Now().Before(until) {
					break
				}

				if err := sleep(ctx, suspendPoll); err != nil {
					return err
				}
			}
		case op.Instance != "":
			doc := op.Instance[:max(strings.LastIndex(op.Instance, "-"), 0)]
			until := time.Unix(0, op.At).Add(restartLimit)

			// done once a newer instance exists or the node rebooted: between
			// the old instance and the new one there may be none at all
			for {
				cur, err := o.Talos.CurrentInstances(ctx, h.Addr)
				boot, berr := o.Talos.BootID(ctx, h.Addr)

				if err == nil && cur[doc] != "" && cur[doc] != op.Instance || berr == nil && op.BootID != "" && boot != op.BootID || !time.Now().Before(until) {
					break
				}

				if err := sleep(ctx, suspendPoll); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// waitEnded waits until a job's container completed or failed, or is gone.
func (o *Orch) waitEnded(ctx context.Context, h state.Host, name string) error {
	ctx, cancel := context.WithTimeout(ctx, suspendTimeout)
	defer cancel()

	for {
		if ended, err := o.ended(ctx, h, name); err == nil && ended {
			return nil
		}

		if err := sleep(ctx, suspendPoll); err != nil {
			return err
		}
	}
}

// KeepLocal saves the workstation's part of the state (local.json), with the
// agent CA and image an offline suspension needs.
func (o *Orch) KeepLocal() error {
	unlock, err := state.Lock(o.St.FSID)
	if err != nil {
		return err
	}
	defer unlock()

	return o.St.SaveLocked()
}

// ended reports whether a container can no longer run: completed or failed,
// or neither its document nor an instance left (a missing status alone may be
// one not created yet, or an instance still exiting).
func (o *Orch) ended(ctx context.Context, h state.Host, name string) (bool, error) {
	st, err := o.Talos.ContainerStatuses(ctx, h.Addr)
	if err != nil {
		return false, err
	}

	if s, ok := st[name]; ok {
		return s.State == containers.ContainerStateCompleted || s.State == containers.ContainerStateFailed, nil
	}

	if left, err := o.Talos.HasInstances(ctx, h.Addr, name); err != nil || left {
		return false, err
	}

	docs, err := o.configuredContainers(ctx, h.Addr, name)

	return err == nil && !slices.Contains(docs, name), err
}

// InRecovery reports whether a recovery session of the cluster is open on
// this workstation (its journal exists, not resumed).
func (o *Orch) InRecovery() bool {
	rec, err := state.LoadRecovery(o.St.FSID)

	return err != nil || rec != nil
}
