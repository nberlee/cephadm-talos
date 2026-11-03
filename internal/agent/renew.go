package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// renewalThreshold is how long before its expiry a certificate is renewed
// (the module's daily check accepts a renewal from then on, plan 04 step 1).
const renewalThreshold = 30 * 24 * time.Hour

// mgrRenewal is what a mgr's renewal keeps in the leader's journal (below
// "roll/<op>.renew"): the host's certificates and keys before it, and whether
// it asks the module to retire the others, after which the new ones stay.
type mgrRenewal struct {
	ServerCert string `json:"server_cert"`
	ClientCert string `json:"client_cert"`
	Keys       string `json:"keys"`
	Retiring   bool   `json:"retiring,omitempty"`
}

// renewMgr renews a mgr's certificates (plan 04, step 1): the module issues
// them once per renewal; the ones before are journaled, the new ones recorded
// in the state and the host's revision granted (none on a host in
// maintenance: its exit renders them); on the active mgr's host the module
// serves the new server certificate (it loads it itself; a standby when it
// starts) before the module retires the others.
func (l *LeaderLoop) renewMgr(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	rec, found, err := l.readRenewal(ctx, b, js, gid, op.ID)
	if err != nil {
		return err
	}

	if !rec.Retiring {
		st, _, err := l.clusterState(ctx, b)
		if err != nil {
			return err
		}

		typ, id, _ := strings.Cut(op.Daemon, ".")
		_, exists := st.Find(op.Daemon)

		h, ok := st.Host(op.Host)
		if !ok || h.Name != op.Host || typ != state.TypeMgr || id != op.Host || !exists {
			return l.endRenewal(ctx, b, js, gid, op, fmt.Errorf("%s is not a mgr of %s in the cluster state", op.Daemon, op.Host))
		}

		if !strings.HasPrefix(h.MgrKeys, op.ID+"/") {
			certs, err := b.MgrCert(ctx, op.ID)
			if err != nil {
				return err
			}

			// the certificates before, journaled once, before the state changes
			if !found {
				rec = mgrRenewal{ServerCert: h.MgrServerCert, ClientCert: h.MgrClientCert, Keys: h.MgrKeys}
				if err := writeJSONKey(ctx, js, rollKey(gid, op.ID+".renew"), rec); err != nil {
					return err
				}
			}

			if err := l.changeState(ctx, b, gid, func(st *state.State) error {
				h, ok := st.Host(op.Host)
				if !ok {
					return fmt.Errorf("no host %s", op.Host)
				}

				h.MgrServerCert, h.MgrClientCert, h.MgrKeys = certs.ServerCert, certs.ClientCert, op.ID+"/"+certs.Attempt
				st.AddHost(h)

				return nil
			}); err != nil {
				return err
			}

			h.MgrServerCert = certs.ServerCert
		}

		if !h.Maintenance {
			done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".rev", h.Name, revisionMode{})
			if err != nil || !done {
				return err
			}

			if !ok {
				return l.endRenewal(ctx, b, js, gid, op, fmt.Errorf("the revision of %s did not apply", h.Name))
			}

			active, err := b.ActiveMgr(ctx)
			if err != nil {
				return err
			}

			if active == id && !l.servesCert(h.Addr, wire.ModulePort, h.MgrServerCert) {
				return fmt.Errorf("%w: the module on %s does not serve its new certificate yet", errRetry, h.Name)
			}
		}

		// from here the new certificates stay: the module is asked until it answers
		rec.Retiring = true
		if err := writeJSONKey(ctx, js, rollKey(gid, op.ID+".renew"), rec); err != nil {
			return err
		}
	}

	if err := b.MgrCertDone(ctx, op.ID, []string{rec.ServerCert, rec.ClientCert}); err != nil {
		return fmt.Errorf("%w: %v", errWait, err)
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// endRenewal ends a mgr's renewal failed, its certificates before restored.
func (l *LeaderLoop) endRenewal(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp, cause error) error {
	if err := l.renewMgrFailed(ctx, b, js, gid, op); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, JournalFailed, cause)
}

// renewMgrFailed is a mgr renewal's cleanup when it fails: before it asked the
// module to retire the others, the journaled certificates come back in the
// state (their keys still exist), so the module sees the installed ones
// again and renews anew; after, the module is asked once more.
func (l *LeaderLoop) renewMgrFailed(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	rec, found, err := l.readRenewal(ctx, b, js, gid, op.ID)
	if err != nil || !found {
		return err
	}

	if rec.Retiring {
		return b.MgrCertDone(ctx, op.ID, []string{rec.ServerCert, rec.ClientCert})
	}

	return l.changeState(ctx, b, gid, func(st *state.State) error {
		h, ok := st.Host(op.Host)
		if !ok || !strings.HasPrefix(h.MgrKeys, op.ID+"/") {
			return nil
		}

		h.MgrServerCert, h.MgrClientCert, h.MgrKeys = rec.ServerCert, rec.ClientCert, rec.Keys
		st.AddHost(h)

		return nil
	})
}

// readRenewal reads a mgr renewal's record: this incarnation's, else an
// earlier incarnation's (a takeover resumes from it).
func (l *LeaderLoop) readRenewal(ctx context.Context, b *Bridge, js store.Backend, gid int64, op string) (mgrRenewal, bool, error) {
	rec, found, err := readJSONKey[mgrRenewal](ctx, js, rollKey(gid, op+".renew"))
	if err != nil || found {
		return rec, found, err
	}

	all, err := b.Store(ctx, store.Prefix+"inc/")
	if err != nil {
		return rec, false, err
	}

	keys, err := all.List(ctx, store.Prefix+"inc/")
	if err != nil {
		return rec, false, err
	}

	for _, k := range keys {
		if strings.HasSuffix(k, "/journal/roll/"+op+".renew") {
			r, ok, err := readJSONKey[mgrRenewal](ctx, all, k)
			if err != nil {
				return rec, false, err
			}

			if ok && (!found || r.Retiring) {
				rec, found = r, true
			}
		}
	}

	if found {
		// kept by this incarnation from now on
		if err := writeJSONKey(ctx, js, rollKey(gid, op+".renew"), rec); err != nil {
			return rec, false, err
		}
	}

	return rec, found, nil
}

// removedCerts are a removed mgr's certificates, journaled (below
// "roll/<op>.certs") before the state drops them, for their revocation.
type removedCerts struct {
	ServerCert string `json:"server_cert,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
}

// readJournal reads a removal's journaled certificates: this incarnation's,
// else an earlier incarnation's (a takeover resumes from it).
func (l *LeaderLoop) readJournal(ctx context.Context, b *Bridge, js store.Backend, gid int64, name string) (removedCerts, bool, error) {
	rec, found, err := readJSONKey[removedCerts](ctx, js, rollKey(gid, name))
	if err != nil || found {
		return rec, found, err
	}

	all, err := b.Store(ctx, store.Prefix+"inc/")
	if err != nil {
		return rec, false, err
	}

	keys, err := all.List(ctx, store.Prefix+"inc/")
	if err != nil {
		return rec, false, err
	}

	for _, k := range keys {
		if strings.HasSuffix(k, "/journal/roll/"+name) {
			if rec, found, err = readJSONKey[removedCerts](ctx, all, k); err != nil || found {
				return rec, found, err
			}
		}
	}

	return rec, false, nil
}

// renewRGWCert renews the generated RGW certificate (plan 04, step 1): a new
// one from the module for every RGW host and the VIP, recorded in the state,
// rolled to every RGW (rollRGW), then the module retires the ones before. A
// roll a predecessor left half-done is finished first, to its certificate,
// while that is valid for longer than the renewal threshold; otherwise the
// renewal supersedes it and every RGW rolls to the new certificate.
func (l *LeaderLoop) renewRGWCert(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	l.holding = holdAll

	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	rgws := st.DaemonsOf(state.TypeRGW, "")
	if st.RGW == nil || len(rgws) == 0 {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("no RGW to renew a certificate for"))
	}

	issued := slices.ContainsFunc(st.RGW.Certs, func(c state.RGWCert) bool { return strings.HasPrefix(c.ID, "issued/"+op.ID+"/") })

	if !issued {
		for _, d := range rgws {
			parts := strings.Split(d.Cert, "/")
			if len(parts) < 2 || parts[1] == op.ID {
				continue
			}

			rec, found, err := l.readRoll(ctx, b, js, gid, parts[1]+".roll."+d.Host)
			if err != nil {
				return err
			}

			if !found || rec.Done {
				continue
			}

			// due itself: superseded, every RGW rolls to the new certificate
			c, _, ok := st.RGWCertOf(d)
			if leaf := leafOf(c.Cert); !ok || leaf == nil || leaf.NotAfter.Sub(l.clock()) <= renewalThreshold {
				continue
			}

			if done, err := l.rollRGW(ctx, b, js, gid, epoch, op, d.Cert, "recover"); err != nil || !done {
				return err
			}

			// finished: recorded under the roll it finished, for every host
			for _, x := range rgws {
				if err := writeJSONKey(ctx, js, rollKey(gid, parts[1]+".roll."+x.Host), rollRecord{Done: true}); err != nil {
					return err
				}
			}

			return fmt.Errorf("%w: an earlier roll is finished", errRetry)
		}

		// the operator's certificate is not renewed (a health warning names it)
		for _, d := range rgws {
			if c, _, ok := st.RGWCertOf(d); ok && c.User {
				return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("rgw.%s renders the operator's certificate, which is not renewed", d.ID))
			}
		}

		c, err := b.RGWCert(ctx, op.ID)
		if err != nil {
			return err
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			id := "issued/" + op.ID + "/" + c.Attempt
			if !slices.ContainsFunc(st.RGW.Certs, func(x state.RGWCert) bool { return x.ID == id }) {
				st.RGW.Certs = append(st.RGW.Certs, state.RGWCert{ID: id, Cert: c.Cert})
			}

			return nil
		}); err != nil {
			return err
		}

		return fmt.Errorf("%w: the renewed certificate is recorded", errRetry)
	}

	var target string

	for _, c := range st.RGW.Certs {
		if strings.HasPrefix(c.ID, "issued/"+op.ID+"/") {
			target = c.ID
		}
	}

	if done, err := l.rollRGW(ctx, b, js, gid, epoch, op, target, "roll"); err != nil || !done {
		return err
	}

	if err := b.RGWCertDone(ctx, op.ID, target); err != nil {
		return err
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}
