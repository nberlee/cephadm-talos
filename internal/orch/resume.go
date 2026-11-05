package orch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// How long the resumption waits for an agent applied again, for the mgrs
// after their restart, and for the new leader's takeover.
var (
	agentStartTimeout = 5 * time.Minute
	mgrTimeout        = 10 * time.Minute
	takeoverTimeout   = 10 * time.Minute
	mgrRestartAgain   = 2 * time.Minute
)

// Resume ends a recovery session (plan 03, step 7 slice D, item 10): the
// recovered mons and mgrs checked against the published state (first, so a
// refusal leaves the session open for recover mons), the control record and
// the removed agents back, every agent's re-adoption prepared,
// every mgr process replaced, then every agent activated and the control
// record removed. Each subphase is journaled before its effect; a retry
// continues where it stopped. It ends once a new leader published its
// takeover.
func (o *Orch) Resume(ctx context.Context) error {
	if o.Talos.DryRun {
		return errors.New("resume has no dry run")
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
		return errors.New("no recovery session to resume")
	}

	if rec.Phase != state.PhaseSuspended && rec.Phase != state.PhaseRecovering && rec.Phase != state.PhaseResuming {
		return fmt.Errorf("recovery session %s is %s: it resumes once suspended", rec.Session, rec.Phase)
	}

	// a quorum and the published state
	if !o.opened {
		if err := o.Open(ctx); err != nil {
			return fmt.Errorf("resume needs the mons (run `cephadm-talos recover mons` first): %w", err)
		}
	}

	// what an offline suspension took for retiring or left out, and the
	// published state has as a member: such a host joins the session here. A
	// failure stays pending in the journal, and a retry of resume asks again
	o.reconcileMembers(rec)

	pending, err := o.pendingSuspensions(ctx, rec)
	if err != nil {
		return err
	}

	if err := rec.Save(); err != nil {
		return err
	}

	if len(pending) > 0 {
		if err := o.suspendHosts(ctx, pending, rec, SuspendOptions{}); err != nil {
			return err
		}
	}

	// the session's hosts; once a re-adoption began, only the journaled ones
	// (the leader may add a host after an activation)
	hosts := o.removalHosts(rec)

	if slices.ContainsFunc(slices.Collect(maps.Values(rec.Hosts)), func(hr *state.RecoveryHost) bool { return hr.Readopt != nil }) {
		hosts = journaledHosts(rec)
	}

	for _, h := range hosts {
		if hr := rec.Hosts[h.Name]; hr == nil || hr.Receipt == nil {
			return fmt.Errorf("%s is not suspended in this session and its re-adoptions began: run `cephadm-talos resume` again", h.Name)
		}
	}

	// a host the published state now has retiring (its removal ran just before
	// the suspension) and not re-adopted yet is one too
	for name, hr := range rec.Hosts {
		if rh, r, ok := o.St.RetiringHost(name); ok && (!hr.Retiring || hr.RetireOp == "") && hr.Readopt == nil {
			journalRetiring(hr, rh, r)

			if err := rec.Save(); err != nil {
				return err
			}
		}
	}

	// one whose removal finished since it was journaled is no host to bring back
	for name, hr := range rec.Hosts {
		if sh, member := o.St.Host(name); hr.Retiring || hr.Readopt != nil || member && sh.Name == name {
			continue
		}

		// not published: enrolled, or gone
		members, err := o.publishedMembers(ctx)
		if err != nil {
			return fmt.Errorf("the cluster's hosts: %w", err)
		}

		if !slices.ContainsFunc(members, func(h state.Host) bool { return h.Name == name }) {
			o.printf("%s: no longer a host of the cluster: its node is taken over, not brought back\n", name)

			hr.Retiring = true

			if err := rec.Save(); err != nil {
				return err
			}
		}
	}

	// a retiring host is never re-adopted, activated or applied again (plan 04,
	// step 6): its node is taken over and the module told, below. It runs no
	// daemon, so nothing else of the resumption concerns it
	hosts = slices.DeleteFunc(hosts, func(h state.Host) bool {
		hr := rec.Hosts[h.Name]

		return hr.Retiring || hr.LeftOut
	})

	// (b) what the recovery changed is what the published state names; read
	// before the phase changes, so a refusal leaves `recover mons` open, and
	// again on a retry
	for _, h := range hosts {
		// a host re-adopted already is past the check: once activated, the
		// leader may have changed the state since
		if rec.Hosts[h.Name].Readopt != nil {
			continue
		}

		if err := o.checkChanges(ctx, rec, h); err != nil {
			return fmt.Errorf("%s: %w (resume changes no cluster state)", h.Name, err)
		}
	}

	// an apply of an agent's documents (agent restore, an earlier resumption)
	// whose outcome is not known yet refuses, before the phase moves on
	for _, h := range hosts {
		if hr := rec.Hosts[h.Name]; hr.AgentApply != nil && hr.Readopt == nil {
			if _, err := o.agentApplied(ctx, rec, h); err != nil {
				return fmt.Errorf("%s: %w", h.Name, err)
			}
		}
	}

	if rec.Phase != state.PhaseResuming {
		rec.Phase = state.PhaseResuming
		if err := rec.Save(); err != nil {
			return err
		}
	}

	o.printf("resuming recovery session %s\n", rec.Session)

	// (a) the control record, and the agents the suspension removed
	if !rec.Control {
		if err := o.setControl(ctx, rec); err != nil {
			return fmt.Errorf("the control record: %w", err)
		}

		rec.Control = true
		if err := rec.Save(); err != nil {
			return err
		}
	}

	for _, h := range hosts {
		// an apply that landed is finished as it was rendered (an agent
		// restore's image), not rendered again
		if hr := rec.Hosts[h.Name]; hr.AgentApply != nil && hr.Readopt == nil {
			if err := o.agentReturn(ctx, rec, h, nil); err != nil {
				return fmt.Errorf("%s: %w", h.Name, err)
			}
		}

		if hr := rec.Hosts[h.Name]; hr.RemovingAgent && !hr.AgentRestored && hr.Readopt == nil {
			if err := o.restoreAgent(ctx, rec, h); err != nil {
				return fmt.Errorf("%s: %w", h.Name, err)
			}
		}
	}

	// the retiring hosts' nodes taken over: their agents' suspension ends with
	// their documents
	for _, h := range retiringHosts(rec) {
		if err := o.finishRetiring(ctx, rec, h); err != nil {
			return fmt.Errorf("%s: finishing its retirement: %w", h.Name, err)
		}
	}

	// (c) every agent's re-adoption, bound to the journaled changes, once the
	// session's own jobs are gone from its node
	for _, h := range hosts {
		hr := rec.Hosts[h.Name]
		if hr.Readopt != nil {
			continue
		}

		if err := o.cleanJobs(ctx, rec, h); err != nil {
			return fmt.Errorf("%s: removing the recovery's jobs: %w", h.Name, err)
		}

		r, err := o.readopt(ctx, rec, h)
		if err != nil {
			return fmt.Errorf("%s: the re-adoption: %w", h.Name, err)
		}

		hr.Readopt = r
		if err := rec.Save(); err != nil {
			return err
		}

		o.printf("%s: its agent adopted %d documents again at revision %d\n", h.Name, len(r.Docs), r.Revision)
	}

	// (d) no mgr process of before is left
	if rec.Boundary == nil || rec.Boundary.GID == 0 {
		if err := o.drawBoundary(ctx, rec, hosts); err != nil {
			return fmt.Errorf("restarting the mgrs: %w", err)
		}
	}

	// (e) every agent activated, then the control record goes
	for _, h := range hosts {
		hr := rec.Hosts[h.Name]
		if hr.Activated {
			continue
		}

		if err := o.activate(ctx, rec, h); err != nil {
			return fmt.Errorf("%s: the activation: %w", h.Name, err)
		}

		hr.Activated = true
		if err := rec.Save(); err != nil {
			return err
		}

		o.printf("%s: its agent is active again\n", h.Name)
	}

	if rec.Control {
		if err := o.removeControl(ctx); err != nil {
			return fmt.Errorf("removing the control record: %w", err)
		}

		rec.Control = false
		if err := rec.Save(); err != nil {
			return err
		}
	}

	inc, err := waitTakeover(ctx, o, rec.Boundary.GIDs)
	if err != nil {
		return fmt.Errorf("the new leader's takeover: %w (run `cephadm-talos resume` again)", err)
	}

	o.printf("leader %s took over\n", inc)

	// the module accepts again: the retirements of the nodes taken over end
	for _, h := range retiringHosts(rec) {
		if err := o.retireTold(ctx, rec, h); err != nil {
			return fmt.Errorf("%s: telling the module: %w (run `cephadm-talos resume` again)", h.Name, err)
		}
	}

	rec.Phase = state.PhaseResumed
	if err := rec.Save(); err != nil {
		return err
	}

	return rec.Close()
}

// retireTold tells the module a retiring host's node was taken over, unless
// that removal's retirement ended meanwhile: another retirement of the name (a
// later enrollment and removal, from another workstation) is not this node's.
func (o *Orch) retireTold(ctx context.Context, rec *state.Recovery, h state.Host) error {
	hr := rec.Hosts[h.Name]
	if !hr.RetireFinished || hr.RetireTold {
		return nil
	}

	if err := o.Open(ctx); err != nil {
		return err
	}

	if _, r, ok := o.St.RetiringHost(h.Name); ok && r.Op == hr.RetireOp {
		if err := o.tellForgotten(ctx, h.Name, hr.RetireOp); err != nil {
			return err
		}
	}

	hr.RetireTold = true

	return rec.Save()
}

// journaledHosts are the hosts the session journaled, by name.
func journaledHosts(rec *state.Recovery) []state.Host {
	names := slices.Sorted(maps.Keys(rec.Hosts))
	hosts := make([]state.Host, 0, len(names))

	for _, n := range names {
		hosts = append(hosts, state.Host{Name: n, Addr: rec.Hosts[n].Addr})
	}

	return hosts
}

// controlStore is where the control record lives: config-key through exec.
func (o *Orch) controlStore(ctx context.Context) (store.Backend, error) {
	if o.StoreBackend != nil {
		return o.StoreBackend, nil
	}

	adm, err := o.confirmedAdminHost()
	if err != nil {
		return nil, err
	}

	return o.configKeys(ctx, adm.Addr, SuspensionKey)
}

// removeControl removes the control record: the module accepts again.
func (o *Orch) removeControl(ctx context.Context) error {
	keys, err := o.controlStore(ctx)
	if err != nil {
		return err
	}

	return keys.Remove(ctx, []string{SuspensionKey})
}

// restoreAgent applies a host's agent again with its certificates and keys
// from the cluster's secrets, and waits until it answers suspended for the
// session (it starts from its records).
func (o *Orch) restoreAgent(ctx context.Context, rec *state.Recovery, h state.Host) error {
	ah, err := o.agentHost(ctx, h, rec.Hosts[h.Name])
	if err != nil {
		return err
	}

	o.printf("%s: applying its agent again\n", h.Name)

	// with the pinned inputs its document had, if the suspension read them
	docs := o.agentDocs(ah)
	if hr := rec.Hosts[h.Name]; hr.AgentPinned {
		docs = o.agentDocsWith(ah, o.St.Agent.Image, hr.AgentRepos, hr.AgentApprovalKey, hr.AgentCRLFailClosed)
	}

	// journaled, and an interrupted self-update settled, as agent restore does
	return o.agentReturn(ctx, rec, h, docs)
}

// awaitSuspended waits until an agent applied again answers suspended for the
// session (it starts from its records), at the revision of its receipt or of
// an unresolved operation of it that it reconciled, and keeps its receipt.
func (o *Orch) awaitSuspended(ctx context.Context, rec *state.Recovery, h state.Host) error {
	ctx, cancel := context.WithTimeout(ctx, agentStartTimeout)
	defer cancel()

	for {
		r, err := o.suspendAgent(ctx, h, rec.Session)
		if err == nil {
			if old := rec.Hosts[h.Name].Receipt; r.Revision != old.Revision && !advanced(old, r.Revision) {
				return fmt.Errorf("its agent is at revision %d, the suspension's receipt at %d", r.Revision, old.Revision)
			}

			// its own receipt, after it reconciled what its records left open
			rec.Hosts[h.Name].Receipt = r

			return nil
		}

		if !errors.Is(err, errUnreachable) || ctx.Err() != nil {
			return err
		}
	}
}

// advanced reports whether a restored agent's revision is one an unresolved
// operation of its receipt left open: an apply it reconciled once it ran.
func advanced(receipt *wire.SuspendReceipt, revision int64) bool {
	return slices.ContainsFunc(receipt.Unresolved, func(op wire.Operation) bool { return op.Revision == revision })
}

// agentHost is a host with its agent's certificates and keys: the state's
// (its keys through AgentKeys), a retiring host's journaled identity and never
// anything else (plan 04, step 6), else the ones the suspension read from the
// agent's document before it removed it (a host the leader removed), else an
// enrollment record's; the keys from the cluster's secrets.
func (o *Orch) agentHost(ctx context.Context, h state.Host, hr *state.RecoveryHost) (state.Host, error) {
	adm, err := o.confirmedAdminHost()
	if err != nil {
		return state.Host{}, err
	}

	serverKey, clientKey := state.SecretHost(h.Name, state.SecretAgentServer), state.SecretHost(h.Name, state.SecretAgentClient)

	if rh, _, ok := o.St.RetiringHost(h.Name); ok {
		h = rh
		serverKey, clientKey = h.AgentKeySecret(state.SecretAgentServer), h.AgentKeySecret(state.SecretAgentClient)
	} else if sh, ok := o.St.Host(h.Name); ok {
		h = sh
		serverKey, clientKey = h.AgentKeySecret(state.SecretAgentServer), h.AgentKeySecret(state.SecretAgentClient)
	} else if hr != nil && hr.Retiring && hr.AgentCert == "" {
		return state.Host{}, errors.New("no agent certificates journaled for a retiring host")
	} else if hr != nil && hr.AgentCert != "" {
		h.AgentCert, h.AgentClientCert = hr.AgentCert, hr.AgentClientCert

		if hr.AgentServerKey != "" && hr.AgentClientKey != "" {
			serverKey, clientKey = hr.AgentServerKey, hr.AgentClientKey
		} else if serverKey, clientKey, err = o.agentKeyNames(ctx, h.Name, hr.AgentCert); err != nil {
			return state.Host{}, err
		}
	} else {
		recs, err := o.enrollments(ctx, adm.Addr)
		if err != nil {
			return state.Host{}, err
		}

		b, err := recs.Get(ctx, EnrollPrefix+h.Name)

		switch {
		case err == nil:
			var e Enrollment
			if err := json.Unmarshal(b, &e); err != nil || e.Name != h.Name {
				return state.Host{}, fmt.Errorf("enrollment record %s: damaged", h.Name)
			}

			h.AgentCert, h.AgentClientCert = e.AgentCert, e.AgentClientCert
		case !errors.Is(err, store.ErrNotFound):
			return state.Host{}, fmt.Errorf("its enrollment record: %w", err)
		}
	}

	if h.AgentCert == "" || h.AgentClientCert == "" {
		return state.Host{}, errors.New("no agent certificates")
	}

	if err := o.openSecrets(ctx, adm.Addr); err != nil {
		return state.Host{}, err
	}

	for name, dst := range map[string]*string{serverKey: &h.AgentKey, clientKey: &h.AgentClientKey} {
		v, err := o.secrets.Get(ctx, store.SecretPrefix+name)
		if err != nil {
			return state.Host{}, fmt.Errorf("its agent's key %s: %w", name, err)
		}

		*dst = string(v)
	}

	if _, err := tls.X509KeyPair([]byte(h.AgentCert), []byte(h.AgentKey)); err != nil {
		return state.Host{}, errors.New("its agent's server key does not match its certificate")
	}

	if _, err := tls.X509KeyPair([]byte(h.AgentClientCert), []byte(h.AgentClientKey)); err != nil {
		return state.Host{}, errors.New("its agent's keys do not match its certificates")
	}

	return h, nil
}

// checkChanges checks the documents the recovery applied or restarted on a
// host against the published state: each a mon or mgr the state names on
// that host, with its deployment id and the host's address, the host not in
// maintenance. A document still being applied, or a removal other than of a
// job, refuses.
func (o *Orch) checkChanges(ctx context.Context, rec *state.Recovery, h state.Host) error {
	hr := rec.Hosts[h.Name]

	if len(hr.Applying) > 0 {
		return errors.New("a document the recovery applied is not confirmed: run `cephadm-talos recover mons` again")
	}

	var names []string

	for key, hash := range hr.Changes {
		name, ok := strings.CutPrefix(key, "ContainerConfig/")

		switch {
		case ok && hash == "" && strings.HasPrefix(name, "ceph-"+o.St.Short()+"-job-"):
			continue // a job the suspension removed with --force
		case !ok || hash == "":
			return fmt.Errorf("the recovery changed %s, which no resumption adopts", key)
		}

		names = append(names, name)
	}

	for _, name := range hr.Restarted {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}

	if len(names) == 0 {
		return nil
	}

	sort.Strings(names)

	sh, ok := o.St.Host(h.Name)
	if !ok {
		return errors.New("the recovery changed a host the cluster state does not name")
	}

	docs, err := o.configuredDocs(ctx, sh.Addr, "ceph-"+o.St.Short()+"-")
	if err != nil {
		return err
	}

	for _, name := range names {
		i := slices.IndexFunc(o.St.Daemons, func(d state.Daemon) bool {
			return (d.Type == state.TypeMon || d.Type == state.TypeMgr) && o.St.DocName(d) == name
		})
		if i < 0 {
			return fmt.Errorf("%s is no mon or mgr of the cluster state", name)
		}

		d, cur := o.St.Daemons[i], docs[name]

		switch {
		case d.Host != h.Name:
			return fmt.Errorf("%s is of %s in the cluster state", name, d.Host)
		case sh.Maintenance:
			return fmt.Errorf("the cluster state has %s in maintenance, without its daemons", h.Name)
		case cur.env == nil:
			return fmt.Errorf("%s is not on the node", name)
		case cur.env["DEPLOY_ID"] != d.DeployID:
			return fmt.Errorf("%s has deployment %s, the cluster state %s", name, cur.env["DEPLOY_ID"], d.DeployID)
		case cur.env["ID"] != d.ID || cur.env["FSID"] != o.St.FSID:
			return fmt.Errorf("%s is not %s.%s of this cluster", name, d.Type, d.ID)
		case cur.env["ADDR"] != sh.Addr:
			return fmt.Errorf("%s has address %s, the cluster state %s", name, cur.env["ADDR"], sh.Addr)
		}
	}

	return nil
}

// cleanJobs removes the documents of the session's jobs on a host (a job
// whose removal a stop interrupted would otherwise be a document the agent
// does not own) and waits until their instances are gone.
func (o *Orch) cleanJobs(ctx context.Context, rec *state.Recovery, h state.Host) error {
	purposes := make([]string, 0, len(rec.Jobs))
	for p := range rec.Jobs {
		purposes = append(purposes, p)
	}

	sort.Strings(purposes)

	for _, p := range purposes {
		j := rec.Jobs[p]
		if j.Host != h.Name || j.Cleaned {
			continue
		}

		name := fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), j.ID)

		docs, err := o.configuredContainers(ctx, h.Addr, name)
		if err != nil {
			return err
		}

		if slices.Contains(docs, name) {
			if err := o.remove(ctx, h.Addr, name); err != nil {
				return err
			}
		}

		if err := o.waitGone(ctx, h.Addr, name, 5*time.Minute); err != nil {
			return err
		}

		j.Cleaned = true
		if err := rec.Save(); err != nil {
			return err
		}
	}

	return nil
}

// readopt prepares one host's re-adoption with the journaled changes.
func (o *Orch) readopt(ctx context.Context, rec *state.Recovery, h state.Host) (*wire.ReadoptReceipt, error) {
	changes := rec.Hosts[h.Name].Changes
	if changes == nil {
		changes = map[string]string{}
	}

	var r wire.ReadoptReceipt

	if err := o.callOperator(ctx, h, "/v1/readopt", wire.Readopt{Version: wire.Version, FSID: o.St.FSID, Host: h.Name, Session: rec.Session, Changes: changes}, &r); err != nil {
		return nil, err
	}

	if r.Session != rec.Session || r.Host != h.Name || r.Revision < 1 {
		return nil, fmt.Errorf("a receipt for session %s of %s", r.Session, r.Host)
	}

	return &r, nil
}

// activate ends one host's suspension at its re-adoption's revision.
func (o *Orch) activate(ctx context.Context, rec *state.Recovery, h state.Host) error {
	hr := rec.Hosts[h.Name]

	return o.callOperator(ctx, h, "/v1/activate", wire.Activate{
		Version: wire.Version, FSID: o.St.FSID, Host: h.Name, Session: rec.Session, Revision: hr.Readopt.Revision, Epoch: rec.Boundary.Epoch,
	}, nil)
}

// callOperator posts a request to a host's agent with the operator
// certificate and decodes its answer into out (nil: no body).
func (o *Orch) callOperator(ctx context.Context, h state.Host, path string, req, out any) error {
	cl, err := o.operatorClient(h)
	if err != nil {
		return err
	}

	body, err := json.Marshal(req)
	if err != nil {
		return err
	}

	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, agentURL(h, path), bytes.NewReader(body))
	if err != nil {
		return err
	}

	resp, err := cl.Do(hreq)
	if err != nil {
		return err
	}

	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("the agent answered %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
	}

	if out == nil {
		return nil
	}

	return json.Unmarshal(raw, out)
}

// mgrMap is what the boundary reads of the mgr map.
type mgrMap struct {
	Epoch     int64 `json:"epoch"`
	ActiveGID int64 `json:"active_gid"`
	Available bool  `json:"available"`
	Standbys  []struct {
		GID int64 `json:"gid"`
	} `json:"standbys"`
}

func (m mgrMap) gids() []int64 {
	var out []int64

	if m.ActiveGID != 0 {
		out = append(out, m.ActiveGID)
	}

	for _, s := range m.Standbys {
		out = append(out, s.GID)
	}

	return out
}

// mgrDump reads the mgr map; mgrFail fails a mgr by its gid. Tests replace them.
var (
	mgrDump = func(ctx context.Context, o *Orch) (mgrMap, error) {
		adm, err := o.adminHost()
		if err != nil {
			return mgrMap{}, err
		}

		res, err := o.jobInput(ctx, adm.Addr, "ceph mgr dump --format json 2>/dev/null", nil, time.Minute)
		if err != nil {
			return mgrMap{}, err
		}

		var m mgrMap
		if err := json.Unmarshal([]byte(res.Output), &m); err != nil {
			return mgrMap{}, fmt.Errorf("the mgr map: %w", err)
		}

		return m, nil
	}
	mgrFail = func(ctx context.Context, o *Orch, gid int64) error {
		adm, err := o.adminHost()
		if err != nil {
			return err
		}

		// by gid: a replacement active meanwhile is not failed
		_, err = o.jobInput(ctx, adm.Addr, fmt.Sprintf("ceph mgr fail %d", gid), nil, time.Minute)

		return err
	}
)

// drawBoundary replaces every mgr process while every agent is suspended
// (item 10 (d)): the mgr map's epoch and gids and every mgr container's
// instance are journaled, each container is restarted through Talos until a
// newer instance runs, the active mgr is failed while it is one of before,
// and the new active mgr's gid is journaled.
func (o *Orch) drawBoundary(ctx context.Context, rec *state.Recovery, hosts []state.Host) error {
	prefix := "ceph-" + o.St.Short() + "-" + state.TypeMgr + "-"

	if rec.Boundary == nil {
		m, err := mgrDump(ctx, o)
		if err != nil {
			return err
		}

		b := &state.Boundary{Epoch: m.Epoch, GIDs: m.gids(), Instances: map[string]string{}}

		for _, h := range hosts {
			cur, err := o.Talos.CurrentInstances(ctx, h.Addr)
			if err != nil {
				return fmt.Errorf("%s: %w", h.Name, err)
			}

			for c, inst := range cur {
				if strings.HasPrefix(c, prefix) {
					b.Instances[h.Name+"/"+c] = inst
				}
			}
		}

		rec.Boundary = b
		if err := rec.Save(); err != nil {
			return err
		}
	}

	b := rec.Boundary
	addr := map[string]string{}

	for _, h := range hosts {
		addr[h.Name] = h.Addr
	}

	ctx, cancel := context.WithTimeout(ctx, mgrTimeout)
	defer cancel()

	// a retry restarts only what still runs its instance of before; a restart
	// is asked again only after mgrRestartAgain (Talos stops the instance
	// within its stop timeout first)
	for key, inst := range b.Instances {
		host, c, _ := strings.Cut(key, "/")

		var asked time.Time

		for {
			cur, err := o.Talos.CurrentInstances(ctx, addr[host])
			if err != nil {
				return fmt.Errorf("%s: %w", host, err)
			}

			if cur[c] != "" && cur[c] != inst {
				break
			}

			if cur[c] == inst && time.Since(asked) >= mgrRestartAgain {
				o.printf("%s: restarting %s\n", host, c)

				if err := o.Talos.RestartInstance(ctx, addr[host], inst); err != nil {
					return err
				}

				asked = time.Now()
			}

			if err := sleep(ctx, suspendPoll); err != nil {
				return fmt.Errorf("%s on %s has no newer instance: %w", c, host, err)
			}
		}
	}

	failed := map[int64]bool{}

	for {
		m, err := mgrDump(ctx, o)

		switch {
		case err != nil:
		case m.Available && m.ActiveGID != 0 && !slices.Contains(b.GIDs, m.ActiveGID):
			b.GID, b.ActiveEpoch = m.ActiveGID, m.Epoch

			o.printf("mgr gid %d is active (mgr map epoch %d)\n", b.GID, b.ActiveEpoch)

			return rec.Save()
		case m.ActiveGID != 0 && slices.Contains(b.GIDs, m.ActiveGID) && !failed[m.ActiveGID]:
			o.printf("failing mgr gid %d of before\n", m.ActiveGID)

			if err := mgrFail(ctx, o, m.ActiveGID); err == nil {
				failed[m.ActiveGID] = true
			}
		}

		if err := sleep(ctx, suspendPoll); err != nil {
			return fmt.Errorf("no mgr of after is active: %w", err)
		}
	}
}

// waitTakeover waits until a leader of after the boundary published its
// state: the incarnation the CLI reads is the active mgr's, a gid not of
// before (not an older publication). Tests replace it.
var waitTakeover = func(ctx context.Context, o *Orch, before []int64) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, takeoverTimeout)
	defer cancel()

	for {
		adm, err := o.adminHost()
		if err == nil {
			m, merr := mgrDump(ctx, o)

			var inc string
			if inc, err = o.chooseIncarnation(ctx, adm.Addr); err == nil && merr == nil && m.Available &&
				inc == strconv.FormatInt(m.ActiveGID, 10) && !slices.Contains(before, m.ActiveGID) {
				return inc, nil
			}
		}

		if err := sleep(ctx, suspendPoll); err != nil {
			return "", err
		}
	}
}
