package agent

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// ingressPlan is what an ingress apply keeps in the leader's journal (below
// "roll/<op>.plan"): the hosts with a keepalived before it, and whether the
// union of old and new is in the state.
type ingressPlan struct {
	Old     []string `json:"old"`
	Ordered bool     `json:"ordered,omitempty"`
}

// applyIngress converges the keepalived-only ingress (plan 03, step 6e): the
// ingress recorded in the state (VIP, router id, image, password secret), a
// generated certificate reissued and rolled first if the VIP is new to it,
// then the placement through the union of old and new hosts, so every running
// keepalived stays in one election: the running ones get the union as peers,
// the added hosts start, the departing ones are removed and retired, the
// remaining ones get the final peers. Each keepalived is ready before the
// next; every revision request waits meanwhile.
func (l *LeaderLoop) applyIngress(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	l.holding = holdAll

	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	if st.RGW == nil {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("no RGW to put the ingress in front of"))
	}

	// every host of the placement has its RGW (a removal may have run before)
	for _, h := range op.Hosts {
		if len(st.DaemonsOf(state.TypeRGW, h)) == 0 {
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s has no RGW", h))
		}
	}

	// the hosts with a keepalived before this apply, kept for the whole change
	planKey := rollKey(gid, op.ID+".plan")

	plan, found, err := l.readPlan(ctx, b, js, gid, op.ID)
	if err != nil {
		return err
	}

	if !found {
		plan.Old = []string{}
		for _, d := range st.DaemonsOf(state.TypeVIP, "") {
			plan.Old = append(plan.Old, d.Host)
		}

		if err := writeJSONKey(ctx, js, planKey, plan); err != nil {
			return err
		}
	}

	if st.RGW.VIP != op.VIP || st.RGW.VRID != op.VRID || st.RGW.KeepalivedImage != op.Image || op.NewPassword && st.RGW.VRRPSecret != "ingress/"+op.ID+"/vrrp" {
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			st.RGW.VIP, st.RGW.VRID, st.RGW.KeepalivedImage = op.VIP, op.VRID, op.Image
			if op.NewPassword {
				st.RGW.VRRPSecret = "ingress/" + op.ID + "/vrrp"
			}

			return nil
		}); err != nil {
			return err
		}

		return fmt.Errorf("%w: the ingress is recorded", errRetry)
	}

	// a generated certificate covers the VIP before a keepalived holds it
	vip, _, _ := strings.Cut(op.VIP, "/")

	if done, err := l.ingressCert(ctx, b, js, gid, epoch, op, st, vip); err != nil || !done {
		return err
	}

	added, departing := []string{}, []string{}

	for _, h := range op.Hosts {
		if !slices.Contains(plan.Old, h) {
			added = append(added, h)
		}
	}

	for _, h := range plan.Old {
		if !slices.Contains(op.Hosts, h) {
			departing = append(departing, h)
		}
	}

	// the union in the state, final placement first (priorities follow it)
	if !plan.Ordered {
		union := append(slices.Clone(op.Hosts), departing...)
		if len(union) > 15 {
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the change would place %d keepalived at once, at most 15", len(union)))
		}

		if err := l.vipOrder(ctx, b, gid, union); err != nil {
			return err
		}

		plan.Ordered = true
		if err := writeJSONKey(ctx, js, planKey, plan); err != nil {
			return err
		}
	}

	phases := []struct {
		name  string
		hosts []string
	}{{"k1", plan.Old}, {"k2", added}}

	for _, p := range phases {
		for _, h := range p.hosts {
			if done, err := l.vipStep(ctx, b, js, gid, epoch, op.ID+"."+p.name+"."+h, h); err != nil || !done {
				return err
			}
		}
	}

	for _, h := range departing {
		if done, err := l.vipRemove(ctx, b, js, gid, epoch, op, h); err != nil || !done {
			return err
		}
	}

	for _, h := range op.Hosts {
		if done, err := l.vipStep(ctx, b, js, gid, epoch, op.ID+".k4."+h, h); err != nil || !done {
			return err
		}
	}

	// keepalived the fold still has elsewhere (a failed apply left them, never
	// granted) are retired too; the module answers done for the others
	for _, h := range st.Hosts {
		if !slices.Contains(op.Hosts, h.Name) && len(vipDocs(st, h.Name)) == 0 {
			if err := b.RetireKeepalived(ctx, op.ID, "keepalived."+h.Name); err != nil {
				return err
			}
		}
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// ingressCert reissues a generated RGW certificate that does not cover the
// VIP and rolls it to every RGW (rollRGW) before any keepalived holds the VIP.
func (l *LeaderLoop) ingressCert(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp, st *state.State, vip string) (bool, error) {
	// an earlier roll that stopped halfway (an RGW's record set before it
	// served the certificate) is finished first, to the certificate it rolled,
	// an operator's included
	for _, d := range st.DaemonsOf(state.TypeRGW, "") {
		if parts := strings.Split(d.Cert, "/"); len(parts) >= 2 && parts[1] != op.ID {
			rec, found, err := l.readRoll(ctx, b, js, gid, parts[1]+".roll."+d.Host)
			if err != nil {
				return false, err
			}

			if found && !rec.Done {
				if done, err := l.rollRGW(ctx, b, js, gid, epoch, op, d.Cert, "recover"); err != nil || !done {
					return false, err
				}

				// finished: recorded under the roll it finished, for every host
				for _, x := range st.DaemonsOf(state.TypeRGW, "") {
					if err := writeJSONKey(ctx, js, rollKey(gid, parts[1]+".roll."+x.Host), rollRecord{Done: true}); err != nil {
						return false, err
					}
				}

				return false, fmt.Errorf("%w: an earlier roll is finished", errRetry)
			}
		}
	}

	// every RGW's certificate covers the VIP (an operator's counts as covering)
	covered := true

	for _, d := range st.DaemonsOf(state.TypeRGW, "") {
		if c, _, ok := st.RGWCertOf(d); ok && !c.User && !certCovers(c.Cert, vip) {
			covered = false
		}
	}

	issued := slices.ContainsFunc(st.RGW.Certs, func(c state.RGWCert) bool { return strings.HasPrefix(c.ID, "issued/"+op.ID+"/") })

	if !issued && covered {
		return true, nil
	}

	if !issued {
		c, err := b.RGWCert(ctx, op.ID)
		if err != nil {
			return false, err
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			id := "issued/" + op.ID + "/" + c.Attempt
			if !slices.ContainsFunc(st.RGW.Certs, func(x state.RGWCert) bool { return x.ID == id }) {
				st.RGW.Certs = append(st.RGW.Certs, state.RGWCert{ID: id, Cert: c.Cert})
			}

			return nil
		}); err != nil {
			return false, err
		}

		return false, fmt.Errorf("%w: a certificate for the VIP is recorded", errRetry)
	}

	var target string

	for _, c := range st.RGW.Certs {
		if strings.HasPrefix(c.ID, "issued/"+op.ID+"/") {
			target = c.ID
		}
	}

	if done, err := l.rollRGW(ctx, b, js, gid, epoch, op, target, "roll"); err != nil || !done {
		return false, err
	}

	return true, b.RGWCertDone(ctx, op.ID, target)
}

// vipOrder puts the keepalived daemons of the union into the state in its
// order (the ones of departing hosts last): priorities and peers follow it.
func (l *LeaderLoop) vipOrder(ctx context.Context, b *Bridge, gid int64, union []string) error {
	return l.changeState(ctx, b, gid, func(st *state.State) error {
		for _, d := range st.DaemonsOf(state.TypeVIP, "") {
			st.RemoveDaemon(d)
		}

		for _, h := range union {
			st.AddDaemon(state.Daemon{Type: state.TypeVIP, ID: h, Host: h})
		}

		return nil
	})
}

// vipStep grants a host's keepalived its revision (phase id) and waits until
// it is ready: running in MASTER or BACKUP, with a start marker other than
// before if its document changed.
func (l *LeaderLoop) vipStep(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, id, host string) (bool, error) {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return false, err
	}

	h, ok := st.Host(host)
	if !ok {
		return true, nil
	}

	name := st.DocName(state.Daemon{Type: state.TypeVIP, ID: host, Host: host})

	rec, recorded, err := l.readRoll(ctx, b, js, gid, id)
	if err != nil || rec.Done {
		return rec.Done, err
	}

	if !recorded {
		var rep wire.NodeReport
		if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			return false, err
		}

		rec.VRRP = map[string]string{name: rep.VRRP[name].Start}
		if err := writeJSONKey(ctx, js, rollKey(gid, id), rec); err != nil {
			return false, err
		}
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, id, host, revisionMode{})
	if err != nil || !done {
		return false, err
	}

	if !ok {
		return false, fmt.Errorf("the keepalived revision of %s did not apply", host)
	}

	s, err := l.journalState(ctx, b, js, gid, id)
	if err != nil {
		return false, err
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return false, err
	}

	v, reported := rep.VRRP[name]
	fresh := s != JournalNoChange

	if rep.Running[name] == "" || !reported || v.Start == "" || fresh && v.Start == rec.VRRP[name] || v.State != "MASTER" && v.State != "BACKUP" {
		return false, fmt.Errorf("%w: %s is not ready yet", errRetry, name)
	}

	rec.Done = true
	if err := writeJSONKey(ctx, js, rollKey(gid, id), rec); err != nil {
		return false, err
	}

	delete(l.failing, strings.SplitN(id, ".", 2)[0]) // 10 minutes per host

	return true, nil
}

// readPlan reads an ingress apply's plan: this incarnation's, else an earlier
// incarnation's (a takeover resumes from it).
func (l *LeaderLoop) readPlan(ctx context.Context, b *Bridge, js store.Backend, gid int64, op string) (ingressPlan, bool, error) {
	plan, found, err := readJSONKey[ingressPlan](ctx, js, rollKey(gid, op+".plan"))
	if err != nil || found {
		return plan, found, err
	}

	all, err := b.Store(ctx, store.Prefix+"inc/")
	if err != nil {
		return plan, false, err
	}

	keys, err := all.List(ctx, store.Prefix+"inc/")
	if err != nil {
		return plan, false, err
	}

	for _, k := range keys {
		if strings.HasSuffix(k, "/journal/roll/"+op+".plan") {
			p, ok, err := readJSONKey[ingressPlan](ctx, all, k)
			if err != nil {
				return plan, false, err
			}

			if ok && (!found || p.Ordered) {
				plan, found = p, true
			}
		}
	}

	if found {
		// kept by this incarnation from now on
		if err := writeJSONKey(ctx, js, rollKey(gid, op+".plan"), plan); err != nil {
			return plan, false, err
		}
	}

	return plan, found, nil
}

// ingressFailed is an ingress apply's cleanup when it fails: the keepalived of
// added hosts that were never granted (no k2 record) leave the state, so no
// later revision starts them outside the election's order.
func (l *LeaderLoop) ingressFailed(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	plan, _, err := l.readPlan(ctx, b, js, gid, op.ID)
	if err != nil {
		return err
	}

	var drop []string

	for _, h := range op.Hosts {
		if slices.Contains(plan.Old, h) {
			continue
		}

		s, err := l.journalState(ctx, b, js, gid, op.ID+".k2."+h)
		if err != nil {
			return err
		}

		if s == "" {
			drop = append(drop, h)
		}
	}

	if len(drop) == 0 {
		return nil
	}

	return l.changeState(ctx, b, gid, func(st *state.State) error {
		for _, h := range drop {
			if d, ok := st.Find(state.TypeVIP + "." + h); ok {
				st.RemoveDaemon(d)
			}
		}

		return nil
	})
}

// vipRemove takes a departing host's keepalived out (phase <op>.k3.<host>):
// out of the state, its document removed, its instance gone, then retired by
// the module.
func (l *LeaderLoop) vipRemove(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp, host string) (bool, error) {
	id := op.ID + ".k3." + host

	if rec, _, err := l.readRoll(ctx, b, js, gid, id); err != nil || rec.Done {
		return rec.Done, err
	}

	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return false, err
	}

	d := state.Daemon{Type: state.TypeVIP, ID: host, Host: host}
	name := st.DocName(d)

	// in the state until its document and instance are gone: a later apply
	// still finds it to remove
	if h, ok := st.Host(host); ok {
		done, ok, err := l.step(ctx, b, js, gid, epoch, id, host, revisionMode{stop: []string{"ContainerConfig/" + name}})
		if err != nil || !done {
			return false, err
		}

		if !ok {
			return false, fmt.Errorf("the removal of keepalived on %s did not apply", host)
		}

		if err := l.gone(ctx, h, []string{name}); err != nil {
			return false, err
		}
	}

	if x, ok := st.Find(state.TypeVIP + "." + host); ok {
		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			st.RemoveDaemon(x)

			return nil
		}); err != nil {
			return false, err
		}
	}

	if err := b.RetireKeepalived(ctx, op.ID, "keepalived."+host); err != nil {
		return false, err
	}

	return true, writeJSONKey(ctx, js, rollKey(gid, id), rollRecord{Done: true})
}
