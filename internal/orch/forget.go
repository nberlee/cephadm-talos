package orch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// Taking a removed host's node over (plan 04, step 6): `host forget`, an
// enrollment over a non-member's node and the resumption of a retiring host
// do the same on the node, as a suspension does for an agent that does not
// answer: the cluster's agent documents go, their instances end, an apply
// intent settles (ApplySettle on that boot), what the agent started ends, no
// agent document came back, and the records job retires the records, always
// under a serial: the journaled one or the one the inspection read from the
// set's identity record, so a job left behind (a stop before its document was
// removed, running again on the next boot) finds another generation's records
// and refuses. A left job's document on the node is itself the record of it:
// every takeover removes those first, whichever workstation left them.

// nodeRecordsKind are the records jobs of a takeover.
const (
	recordsInspect = "inspect"
	recordsRetire  = "retire"
)

// certSerial is a certificate's serial as the records name it: decimal.
func certSerial(certPEM string) (string, error) {
	c, err := pki.Parse(certPEM)
	if err != nil {
		return "", err
	}

	return c.SerialNumber.String(), nil
}

// agentDocsOn are the cluster's agent and records-init documents on a node,
// the agent's first: whichever host they were rendered for.
func (o *Orch) agentDocsOn(ctx context.Context, addr string) ([]string, error) {
	all, err := o.configuredContainers(ctx, addr, "ceph-"+o.St.Short()+"-")
	if err != nil {
		return nil, err
	}

	agents := "ceph-" + o.St.Short() + "-agent-"
	inits := "ceph-" + o.St.Short() + "-records-init-"

	var first, then []string

	for _, n := range all {
		switch {
		case strings.HasPrefix(n, agents):
			first = append(first, n)
		case strings.HasPrefix(n, inits):
			then = append(then, n)
		}
	}

	return append(first, then...), nil
}

// removeLeftRecordsJobs removes the records jobs left on a node (only the CLI
// runs those) and waits until their instances are gone.
func (o *Orch) removeLeftRecordsJobs(ctx context.Context, h state.Host) error {
	docs, err := o.configuredDocs(ctx, h.Addr, "ceph-"+o.St.Short()+"-job-")
	if err != nil {
		return err
	}

	for _, name := range slices.Sorted(maps.Keys(docs)) {
		if !strings.HasPrefix(docs[name].env["CMD"], "records ") {
			continue
		}

		o.printf("%s: removing %s, a records job left behind\n", h.Name, name)

		if err := o.remove(ctx, h.Addr, name); err != nil {
			return err
		}

		if err := o.waitGone(ctx, h.Addr, name, 5*time.Minute); err != nil {
			return err
		}
	}

	return nil
}

// errNotThatNode refuses a takeover of a node that is not the host's generation:
// a reused node, whose replacement agent must not be touched.
var errNotThatNode = errors.New("not taking the node over")

// checkNodeIdentity refuses a node that is not the host, changing nothing: a
// member has the address, or the node calls itself something else.
func (o *Orch) checkNodeIdentity(ctx context.Context, h state.Host) error {
	if sh, member := o.St.Host(h.Addr); member && sh.Name != h.Name {
		return fmt.Errorf("%w: %s now has the address %s of %s", errNotThatNode, sh.Name, h.Addr, h.Name)
	}

	node, err := o.Talos.Hostname(ctx, h.Addr)
	if err != nil {
		return fmt.Errorf("the node of %s at %s: %w", h.Name, h.Addr, err)
	}

	if node != h.Name {
		return fmt.Errorf("%w: the node at %s calls itself %s, not %s", errNotThatNode, h.Addr, node, h.Name)
	}

	return nil
}

// clearRetiring drops a retirement's journaled identity from a host that is a
// member after all.
func clearRetiring(hr *state.RecoveryHost) {
	hr.Retiring, hr.RetireOp = false, ""
	hr.AgentCert, hr.AgentClientCert, hr.AgentServerKey, hr.AgentClientKey = "", "", "", ""
}

// reconcileMembers corrects, from the published state, what the journal says of
// a host that state has as a member and not retiring: an offline workstation's
// old retirement of a name enrolled again, or a cached host left out. Nothing
// of it was taken over, so it is a member of the session again: one that gave a
// real receipt is re-adopted as any other, and one left out, which was never
// suspended, loses its empty receipt so it is suspended now; it must not stay
// outside the session's restart of the mgrs and its resumption. It reports
// whether the journal changed.
func (o *Orch) reconcileMembers(rec *state.Recovery) bool {
	changed := false

	for _, name := range slices.Sorted(maps.Keys(rec.Hosts)) {
		hr := rec.Hosts[name]
		sh, member := o.St.Host(name)
		_, _, retiring := o.St.RetiringHost(name)

		if !member || sh.Name != name || retiring || !hr.Retiring && !hr.LeftOut || hr.Readopt != nil || hr.AgentRemoved || hr.RetireFinished {
			continue
		}

		o.printf("%s: a host of the cluster: a member of the session\n", name)

		changed = true

		if hr.LeftOut {
			hr.Receipt = nil
		}

		hr.LeftOut, hr.Addr = false, sh.Addr

		clearRetiring(hr)
		hr.AgentSerial = ""

		if s, err := certSerial(sh.AgentCert); err == nil {
			hr.AgentSerial = s
		}
	}

	return changed
}

// pendingSuspensions are the hosts a resumption still has to suspend: suspend
// itself refuses once recovery began, so this is where they end up, also after
// one failed. Every published member and every enrolled or retiring host
// without a receipt, not taken over; once a re-adoption began only the journaled
// ones (the leader may add a host after an activation). A journaled host that
// left the cluster leaves the journal.
func (o *Orch) pendingSuspensions(ctx context.Context, rec *state.Recovery) ([]state.Host, error) {
	readopting := slices.ContainsFunc(slices.Collect(maps.Values(rec.Hosts)), func(hr *state.RecoveryHost) bool { return hr.Readopt != nil })

	var pending []state.Host

	if !readopting {
		for _, h := range o.St.Hosts {
			if rec.Hosts[h.Name] == nil {
				rec.Host(h.Name).Addr = h.Addr

				if s, err := certSerial(h.AgentCert); err == nil {
					rec.Hosts[h.Name].AgentSerial = s
				}
			}
		}
	}

	for _, name := range slices.Sorted(maps.Keys(rec.Hosts)) {
		hr := rec.Hosts[name]
		if hr.Receipt != nil || hr.Readopt != nil || hr.RetireFinished {
			continue
		}

		if sh, member := o.St.Host(name); !member || sh.Name != name {
			members, err := o.publishedMembers(ctx)
			if err != nil {
				return nil, fmt.Errorf("the cluster's hosts: %w", err)
			}

			if !slices.ContainsFunc(members, func(h state.Host) bool { return h.Name == name }) {
				o.printf("%s: no longer a host of the cluster: left out of the session\n", name)
				delete(rec.Hosts, name)

				continue
			}
		}

		pending = append(pending, state.Host{Name: name, Addr: hr.Addr})
	}

	return pending, nil
}

// checkTakeover validates a takeover's target, changing nothing: no member has
// the address, the node calls itself the host, and with a journaled serial the
// records there list it (or are moved aside under it) and every agent document
// on the node carries a certificate of that host and generation. Without a
// serial (an enrollment, whose fence and cleanNode check the documents' names)
// there is no generation to hold the node to.
func (o *Orch) checkTakeover(ctx context.Context, h state.Host, serial string) error {
	if err := o.checkNodeIdentity(ctx, h); err != nil {
		return err
	}

	rep, err := o.nodeRecordsJob(ctx, h, recordsInspect, serial, "")

	switch {
	case err != nil && serial != "" && strings.Contains(err.Error(), "no records of cluster"):
		return fmt.Errorf("%w: it holds no records of %s and no retirement mark of serial %s", errNotThatNode, h.Name, serial)
	case err != nil && serial != "" && strings.Contains(err.Error(), "another generation"):
		return fmt.Errorf("%w: its records are another generation's than %s's serial %s", errNotThatNode, h.Name, serial)
	case err != nil:
		return err
	case serial == "":
		return nil
	case !rep.Retired && !slices.Contains(rep.Serials, serial):
		return fmt.Errorf("%w: its records (serials %v) are another generation's than %s's serial %s", errNotThatNode, rep.Serials, h.Name, serial)
	}

	docs, err := o.configuredDocs(ctx, h.Addr, "ceph-"+o.St.Short()+"-agent-")
	if err != nil {
		return err
	}

	delete(docs, cephConfDoc)

	for _, name := range slices.Sorted(maps.Keys(docs)) {
		c, err := pki.Parse(unb64(docs[name].env[daemons.EnvCert]))
		if err != nil {
			return fmt.Errorf("%w: the certificate of %s does not parse", errNotThatNode, name)
		}

		id, err := pki.CertIdentity(c)
		if err != nil || id.Name != h.Name {
			return fmt.Errorf("%w: %s is not the agent of %s", errNotThatNode, name, h.Name)
		}

		ds := c.SerialNumber.String()

		switch {
		case ds == serial:
		case !rep.Retired:
			if !slices.Contains(rep.Serials, ds) {
				return fmt.Errorf("%w: %s has serial %s, which the records do not list", errNotThatNode, name, ds)
			}
		default:
			// moved aside: every serial of that generation has its mark
			if other, err := o.nodeRecordsJob(ctx, h, recordsInspect, ds, ""); err != nil || !other.Retired {
				return fmt.Errorf("%w: %s has serial %s, of no retired generation", errNotThatNode, name, ds)
			}
		}
	}

	return nil
}

// takeOverNode takes a node over and retires the records on it, under serial
// when the caller knows the generation (a host's journaled serial; the job
// refuses records that do not list it), else under the serial the inspection
// read from the records there.
func (o *Orch) takeOverNode(ctx context.Context, h state.Host, serial string) error {
	// nothing is changed until the node is known to be this one
	if err := o.checkTakeover(ctx, h, serial); err != nil {
		return err
	}

	if err := o.removeLeftRecordsJobs(ctx, h); err != nil {
		return err
	}

	var last agent.RecordsReport

	for {
		docs, err := o.agentDocsOn(ctx, h.Addr)
		if err != nil {
			return err
		}

		for _, doc := range docs {
			o.printf("%s: removing %s\n", h.Name, doc)

			if err := o.remove(ctx, h.Addr, doc); err != nil {
				return err
			}
		}

		for _, doc := range docs {
			if err := o.waitGone(ctx, h.Addr, doc, 5*time.Minute); err != nil {
				return err
			}
		}

		rep, err := o.nodeRecordsJob(ctx, h, recordsInspect, serial, "")
		if err != nil {
			return err
		}

		if !rep.Retired {
			if err := o.settleApply(ctx, h, rep, SuspendOptions{noRebootHint: true}); err != nil {
				return err
			}

			if err := o.awaitStarted(ctx, h, nil, rep, SuspendOptions{}); err != nil {
				return err
			}
		}

		// an apply that landed meanwhile may have brought the agent back
		if docs, err = o.agentDocsOn(ctx, h.Addr); err != nil {
			return err
		}

		if len(docs) == 0 {
			last = rep

			break
		}

		o.printf("%s: its agent came back with an earlier apply\n", h.Name)
	}

	// no records left to retire: moved aside already, or none ever
	if last.Retired {
		return nil
	}

	if serial == "" {
		serial = last.Serial
	}

	if serial == "" {
		return fmt.Errorf("the records on %s have no identity record: not retired", h.Name)
	}

	boot, err := o.Talos.BootID(ctx, h.Addr)
	if err != nil {
		return err
	}

	rep, err := o.nodeRecordsJob(ctx, h, recordsRetire, serial, boot)
	if err != nil {
		return fmt.Errorf("retiring the records on %s: %w", h.Name, err)
	}

	if !rep.Retired {
		return fmt.Errorf("the records job on %s did not report them retired", h.Name)
	}

	return nil
}

// nodeRecordsJob runs a records job of a takeover under a new id: a job
// replays its result under the same id, and a retry must read the node again.
func (o *Orch) nodeRecordsJob(ctx context.Context, h state.Host, kind, serial, boot string) (agent.RecordsReport, error) {
	if o.nodeRecords != nil {
		return o.nodeRecords(h, kind, serial)
	}

	id := randHex(3)
	name, inputs := fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), id), jobInputs("records", h.Name, kind, serial, id)

	var doc *spec.ContainerConfig

	switch {
	case kind == recordsRetire:
		doc = daemons.RecordsRetireJob(name, o.St.Agent.Image, o.St.FSID, id, inputs, serial, boot)
	case serial == "":
		doc = daemons.RecordsProbeJob(name, o.St.Agent.Image, o.St.FSID, id, inputs)
	default:
		doc = daemons.RecordsJob(name, o.St.Agent.Image, o.St.FSID, id, inputs, "", serial)
	}

	res, err := o.runJob(ctx, h.Addr, doc, id, 5*time.Minute)
	if err != nil {
		return agent.RecordsReport{}, err
	}

	var rep agent.RecordsReport
	if err := json.Unmarshal([]byte(res.Output), &rep); err != nil {
		return agent.RecordsReport{}, fmt.Errorf("the records job's report: %w", err)
	}

	return rep, nil
}

// adminCommand runs a ceph command on the admin host and prints its output.
func (o *Orch) adminCommand(ctx context.Context, cmd string) error {
	if o.cephCommand != nil {
		return o.cephCommand(cmd)
	}

	adm, err := o.confirmedAdminHost()
	if err != nil {
		return err
	}

	res, err := o.Job(ctx, adm.Addr, cmd, 2*time.Minute)
	o.printf("%s", res.Output)

	return err
}

// tellForgotten tells the module a retiring host is forgotten: that removal's
// retirement, not whichever one of the name is current by then.
func (o *Orch) tellForgotten(ctx context.Context, name, operation string) error {
	return o.adminCommand(ctx, "ceph orch talos host forgotten "+shellQuote(name)+" --operation "+shellQuote(operation))
}

// HostForget ends the retirement of a removed host whose agent does not retire
// (plan 04, step 6): the node taken over, its records retired under the
// journaled serial, then the module told, whose leader ends the retirement.
// With nodeIsGone (the operator's statement: the node does not answer Talos
// and will not return) the module is only told. It needs the operator's
// certificate: the workstation of the cluster's operator, whoever else has
// the node's Talos credentials. Every step can be repeated.
func (o *Orch) HostForget(ctx context.Context, name string, nodeIsGone bool) error {
	if o.Talos.DryRun {
		return errors.New("host forget has no dry run")
	}

	if !o.Managed() {
		return errors.New("before the handoff `cephadm-talos host rm` removes a host")
	}

	if o.St.Agent == nil || o.St.Agent.OperatorCert == "" {
		return errors.New("host forget needs the operator certificate, which this workstation does not have")
	}

	unlock, err := state.Lock(o.St.FSID)
	if err != nil {
		return err
	}
	defer unlock()

	if rec, err := state.LoadRecovery(o.St.FSID); err != nil {
		return err
	} else if rec != nil {
		return fmt.Errorf("recovery session %s is open: `cephadm-talos resume` first (it takes retiring hosts' nodes over itself)", rec.Session)
	}

	// the record as it is now
	if err := o.Open(ctx); err != nil {
		return err
	}

	h, r, ok := o.St.RetiringHost(name)
	if !ok {
		if sh, member := o.St.Host(name); member && sh.Name == name {
			return fmt.Errorf("%s is a host of the cluster: `ceph orch host rm %s` removes it first", name, name)
		}

		return fmt.Errorf("%s is not retiring: its retirement ended, or no removal of it was accepted (a node left behind is cleaned by `cephadm-talos host add`)", name)
	}

	if !nodeIsGone {
		if h.Addr == "" {
			return fmt.Errorf("the retirement of %s journaled no address: nothing to take over; `host forget --node-is-gone %s`", name, name)
		}

		serial, err := certSerial(r.AgentCert)
		if err != nil {
			return fmt.Errorf("the journaled certificate of %s: %w", name, err)
		}

		if err := o.takeOverNode(ctx, h, serial); err != nil {
			return fmt.Errorf("%s: %w (if the node will not return: `host forget --node-is-gone %s`)", name, err, name)
		}

		o.printf("%s: its agent is gone and its records retired\n", name)
	}

	if err := o.tellForgotten(ctx, name, r.Op); err != nil {
		return fmt.Errorf("telling the module: %w (run `cephadm-talos host forget` again)", err)
	}

	o.printf("%s: its retirement ends with its credentials revoked and deleted (`ceph orch host ls`)\n", name)

	return nil
}

// journalRetiring journals a retiring host's identity from the state's record.
func journalRetiring(hr *state.RecoveryHost, h state.Host, r *state.Retiring) {
	hr.Retiring, hr.RetireOp, hr.Addr = true, r.Op, h.Addr
	hr.AgentCert, hr.AgentClientCert = h.AgentCert, h.AgentClientCert
	hr.AgentServerKey, hr.AgentClientKey = h.AgentKeySecret(state.SecretAgentServer), h.AgentKeySecret(state.SecretAgentClient)

	if s, err := certSerial(h.AgentCert); err == nil {
		hr.AgentSerial = s
	}
}

// retiringHosts are the session's retiring hosts to finish, by name.
func retiringHosts(rec *state.Recovery) []state.Host {
	return slices.DeleteFunc(journaledHosts(rec), func(h state.Host) bool {
		hr := rec.Hosts[h.Name]

		return !hr.Retiring || hr.LeftOut
	})
}

// finishRetiring is a retiring host's part of the resumption: the session's
// jobs gone from its node, then the node taken over and its records retired.
// A suspended retiring agent stays out of the re-adoption and the activation:
// its documents are gone, whatever step its retirement was at. A node that no
// longer answers Talos, is no longer this host's generation or whose generation
// is not known leaves its retirement waiting for `host forget`, untouched and
// without blocking the resumption.
func (o *Orch) finishRetiring(ctx context.Context, rec *state.Recovery, h state.Host) error {
	hr := rec.Hosts[h.Name]
	if hr.RetireFinished {
		return nil
	}

	if _, err := o.Talos.BootID(ctx, h.Addr); err != nil {
		o.printf("warning: %s: its node does not answer Talos (%v): its retirement waits for `cephadm-talos host forget %s`\n", h.Name, err, h.Name)

		hr.LeftOut = true

		return rec.Save()
	}

	if hr.AgentSerial == "" {
		o.printf("warning: %s: its agent's serial was never known: its node is not touched, its retirement waits for `cephadm-talos host forget %s`\n", h.Name, h.Name)

		hr.LeftOut = true

		return rec.Save()
	}

	if err := o.cleanJobs(ctx, rec, h); err != nil {
		return fmt.Errorf("removing the recovery's jobs: %w", err)
	}

	if err := o.takeOverNode(ctx, h, hr.AgentSerial); errors.Is(err, errNotThatNode) {
		o.printf("warning: %s: %v: its retirement waits for `cephadm-talos host forget %s`\n", h.Name, err, h.Name)

		hr.LeftOut = true

		return rec.Save()
	} else if err != nil {
		return err
	}

	hr.RetireFinished = true

	return rec.Save()
}
