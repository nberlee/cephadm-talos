package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// rollRecord is what a host's step of an RGW roll or VIP-aware restart keeps
// in the leader's journal (below "roll/"): the RGW's instance and the
// keepalived start markers before, and whether the host is done.
type rollRecord struct {
	Instance string            `json:"instance,omitempty"`
	VRRP     map[string]string `json:"vrrp,omitempty"`
	Done     bool              `json:"done,omitempty"`
}

// leafOf is the first certificate of a PEM chain.
func leafOf(chain string) *x509.Certificate {
	for rest := []byte(chain); ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			return nil
		}

		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil
			}

			return c
		}
	}
}

// certCovers reports whether a certificate is for every name (address or DNS).
func certCovers(chain string, names ...string) bool {
	c := leafOf(chain)
	if c == nil {
		return false
	}

	for _, n := range names {
		if n != "" && c.VerifyHostname(n) != nil {
			return false
		}
	}

	return true
}

// servesCert reports whether an RGW answers a TLS handshake with the leaf of
// a certificate chain (LeaderLoop.serves replaces it in tests).
func (l *LeaderLoop) servesCert(addr string, port int, chain string) bool {
	if l.serves != nil {
		return l.serves(addr, port, chain)
	}

	want := leafOf(chain)
	if want == nil {
		return false
	}

	d := &net.Dialer{Timeout: 5 * time.Second}

	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the leaf is compared below
	if err != nil {
		return false
	}
	defer conn.Close() //nolint:errcheck

	peers := conn.ConnectionState().PeerCertificates

	return len(peers) > 0 && peers[0].Equal(want)
}

// vipDocs are the cluster's keepalived documents on a host.
func vipDocs(st *state.State, host string) []string {
	var out []string

	for _, d := range st.DaemonsOf(state.TypeVIP, host) {
		if !d.LocalOnly && !d.Purged {
			out = append(out, st.DocName(d))
		}
	}

	return out
}

func stopKeys(docs []string) []string {
	out := make([]string, 0, len(docs))
	for _, d := range docs {
		out = append(out, "ContainerConfig/"+d)
	}

	return out
}

// rollKey is the journal key of a host's step record.
func rollKey(gid int64, base string) string { return JournalPrefix(gid) + "roll/" + base }

// readRoll reads a host's step record: this incarnation's, else what earlier
// incarnations recorded (a takeover resumes from it).
func (l *LeaderLoop) readRoll(ctx context.Context, b *Bridge, js store.Backend, gid int64, base string) (rollRecord, bool, error) {
	rec, found, err := readJSONKey[rollRecord](ctx, js, rollKey(gid, base))
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
		if !strings.HasSuffix(k, "/journal/roll/"+base) {
			continue
		}

		r, ok, err := readJSONKey[rollRecord](ctx, all, k)
		if err != nil {
			return rec, false, err
		}

		if ok {
			found = true
			rec.Done = rec.Done || r.Done

			if rec.Instance == "" {
				rec.Instance = r.Instance
			}

			if rec.VRRP == nil {
				rec.VRRP = r.VRRP
			}
		}
	}

	return rec, found, nil
}

// restoring reports whether a host's keepalived is being granted back (its
// phase base.back has a record): from then on the step only finishes that.
func (l *LeaderLoop) restoring(ctx context.Context, b *Bridge, js store.Backend, gid int64, base string) (bool, error) {
	s, err := l.journalState(ctx, b, js, gid, base+".back")

	return s != "", err
}

// vipOff takes a host's keepalived off before its RGW restarts (phase
// base.vip): their start markers recorded, the documents removed, the
// instances gone, so the VIP is on a peer. Done reports that they are off.
func (l *LeaderLoop) vipOff(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, base string, h state.Host, vips []string) (bool, error) {
	if len(vips) == 0 {
		return true, nil
	}

	if back, err := l.restoring(ctx, b, js, gid, base); err != nil || back {
		return back, err // off before; coming back now
	}

	rec, _, err := l.readRoll(ctx, b, js, gid, base)
	if err != nil {
		return false, err
	}

	if rec.VRRP == nil {
		var rep wire.NodeReport
		if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			return false, err
		}

		rec.VRRP = map[string]string{}
		for _, v := range vips {
			rec.VRRP[v] = rep.VRRP[v].Start
		}

		if err := writeJSONKey(ctx, js, rollKey(gid, base), rec); err != nil {
			return false, err
		}
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, base+".vip", h.Name, revisionMode{stop: stopKeys(vips)})
	if err != nil || !done {
		return false, err
	}

	if !ok {
		return false, fmt.Errorf("keepalived on %s did not stop", h.Name)
	}

	return true, l.gone(ctx, h, vips)
}

// vipBack grants a host's keepalived back (phase base.back) and waits until
// each is ready: running with a start marker other than before (any, without
// a record of one), in MASTER or BACKUP.
func (l *LeaderLoop) vipBack(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, base string, h state.Host, vips []string) (bool, error) {
	if len(vips) == 0 {
		return true, nil
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, base+".back", h.Name, revisionMode{})
	if err != nil || !done {
		return false, err
	}

	if !ok {
		return false, fmt.Errorf("keepalived on %s did not come back", h.Name)
	}

	rec, _, err := l.readRoll(ctx, b, js, gid, base)
	if err != nil {
		return false, err
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return false, err
	}

	for _, v := range vips {
		s, ran := rep.VRRP[v]
		before, known := rec.VRRP[v]

		if rep.Running[v] == "" || !ran || s.Start == "" || known && s.Start == before || s.State != "MASTER" && s.State != "BACKUP" {
			return false, fmt.Errorf("%w: %s is not ready yet", errRetry, v)
		}
	}

	return true, nil
}

// rgwCertFor is the certificate a new RGW renders: the operator's from its
// add, else the one the RGWs render if it is the operator's or a generated
// one for this host and the VIP, else a new generated one from the module.
// isNew reports that this add brings it.
func (l *LeaderLoop) rgwCertFor(ctx context.Context, b *Bridge, st *state.State, op LedgerOp, h state.Host) (state.RGWCert, bool, error) {
	if op.Cert != "" {
		return state.RGWCert{ID: "user/" + op.ID, Cert: op.Cert, User: true}, true, nil
	}

	vip := ""
	if st.RGW != nil && st.RGW.VIP != "" {
		vip, _, _ = strings.Cut(st.RGW.VIP, "/")
	}

	for _, d := range st.DaemonsOf(state.TypeRGW, "") {
		if cur, _, ok := st.RGWCertOf(d); ok && (cur.User || certCovers(cur.Cert, h.Addr, h.Name, vip)) {
			return cur, false, nil
		}

		break // the one every RGW renders outside a roll
	}

	c, err := b.RGWCert(ctx, op.ID)
	if err != nil {
		return state.RGWCert{}, false, err
	}

	return state.RGWCert{ID: "issued/" + op.ID + "/" + c.Attempt, Cert: c.Cert}, true, nil
}

// addRGW deploys an RGW (plan 03, step 6e): its key, its certificate (rgwCertFor)
// recorded in the state, its host's revision, then, if the add brings a new
// certificate, the roll of every other RGW to it and the module's retirement
// of the ones before.
func (l *LeaderLoop) addRGW(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	_, id, _ := strings.Cut(op.Daemon, ".")

	h, ok := st.Host(op.Host)
	if !ok || id != op.Host || op.Port <= 0 {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("%s cannot be deployed on %s", op.Daemon, op.Host))
	}

	d, exists := st.Find(op.Daemon)

	if !exists {
		if st.RGW != nil && len(st.DaemonsOf(state.TypeRGW, "")) > 0 && st.RGW.Port != op.Port {
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the RGWs serve on port %d", st.RGW.Port))
		}

		if _, err := b.AuthGetOrCreate(ctx, "client.rgw."+id, op.ID); err != nil {
			return err
		}

		cert, isNew, err := l.rgwCertFor(ctx, b, st, op, h)
		if err != nil {
			return err
		}

		if err := l.changeState(ctx, b, gid, func(st *state.State) error {
			if st.RGW == nil {
				st.RGW = &state.RGW{}
			}

			if st.RGW.Port == 0 || len(st.DaemonsOf(state.TypeRGW, "")) == 0 {
				st.RGW.Port = op.Port
			}

			if isNew && !slices.ContainsFunc(st.RGW.Certs, func(c state.RGWCert) bool { return c.ID == cert.ID }) {
				st.RGW.Certs = append(st.RGW.Certs, cert)
			}

			ref := cert.ID
			if ref == "cli" {
				ref = ""
			}

			st.AddDaemon(st.Created(state.Daemon{Type: state.TypeRGW, ID: id, Host: h.Name, Cert: ref}))

			return nil
		}); err != nil {
			return err
		}

		if st, _, err = l.clusterState(ctx, b); err != nil {
			return err
		}

		d, _ = st.Find(op.Daemon)
	}

	done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".rev", h.Name, revisionMode{})
	if err != nil || !done {
		return err
	}

	if !ok {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the revision of %s did not apply", h.Name))
	}

	var rep wire.NodeReport
	if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
		return err
	}

	if rep.Running[st.DocName(d)] == "" {
		return fmt.Errorf("%w: %s is not running yet", errRetry, op.Daemon)
	}

	// the added RGW runs: the roll's hosts each get their own 10 minutes
	if _, started, err := l.readRoll(ctx, b, js, gid, op.ID+".added"); err != nil {
		return err
	} else if !started {
		delete(l.failing, op.ID)

		if err := writeJSONKey(ctx, js, rollKey(gid, op.ID+".added"), rollRecord{Done: true}); err != nil {
			return err
		}
	}

	// a certificate this add brought serves every RGW
	if d.Cert != "" && strings.Contains(d.Cert, op.ID) {
		if done, err := l.rollRGW(ctx, b, js, gid, epoch, op, d.Cert, "roll"); err != nil || !done {
			return err
		}

		if err := b.RGWCertDone(ctx, op.ID, d.Cert); err != nil {
			return err
		}
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// rollRGW moves every RGW to a certificate, one host at a time (journaled per
// host below base op.ID.<ns>.<host>, ns "roll", or "recover" for finishing an
// earlier roll): its keepalived off (vipOff), the RGW's
// record set to the certificate and its host's revision granted, the RGW
// running a newer instance and answering a TLS handshake with that
// certificate, then its keepalived back (vipBack). The leader holds every
// revision request meanwhile. Done reports that every RGW renders it.
func (l *LeaderLoop) rollRGW(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp, target, ns string) (bool, error) {
	l.holding = holdAll

	if err := l.notFailing(ctx, b, js, gid, op); err != nil {
		return false, err
	}

	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return false, err
	}

	rgws := st.DaemonsOf(state.TypeRGW, "")
	slices.SortFunc(rgws, func(a, b state.Daemon) int { return strings.Compare(a.Host, b.Host) })

	for _, d := range rgws {
		if d.LocalOnly || d.Purged {
			continue
		}

		h, ok := st.Host(d.Host)
		if !ok {
			continue
		}

		base := op.ID + "." + ns + "." + h.Name
		doc := st.DocName(d)

		rec, started, err := l.readRoll(ctx, b, js, gid, base)
		if err != nil {
			return false, err
		}

		if rec.Done {
			continue
		}

		// rendering it from the start (no step began), unless the roll that set
		// it stopped before this host served it
		if d.Cert == target && !started {
			prev, unfinished := strings.Split(target, "/"), false

			if len(prev) >= 2 && prev[1] != op.ID {
				r, found, err := l.readRoll(ctx, b, js, gid, prev[1]+".roll."+h.Name)
				if err != nil {
					return false, err
				}

				unfinished = found && !r.Done
			}

			if !unfinished {
				continue
			}
		}

		vips := vipDocs(st, h.Name)

		// keepalived already coming back: the RGW was checked before
		back, err := l.restoring(ctx, b, js, gid, base)
		if err != nil {
			return false, err
		}

		if back {
			if done, err := l.vipBack(ctx, b, js, gid, epoch, base, h, vips); err != nil || !done {
				return false, err
			}

			rec.Done = true
			if err := writeJSONKey(ctx, js, rollKey(gid, base), rec); err != nil {
				return false, err
			}

			delete(l.failing, op.ID) // 10 minutes per host

			continue
		}

		if done, err := l.vipOff(ctx, b, js, gid, epoch, base, h, vips); err != nil || !done {
			return false, err
		}

		if d.Cert != target {
			var rep wire.NodeReport
			if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
				return false, err
			}

			if rec, _, err = l.readRoll(ctx, b, js, gid, base); err != nil {
				return false, err
			}

			// recorded before the certificate changes: the record's presence marks the step
			rec.Instance = rep.Current[doc]
			if err := writeJSONKey(ctx, js, rollKey(gid, base), rec); err != nil {
				return false, err
			}

			if err := l.changeState(ctx, b, gid, func(st *state.State) error {
				x, ok := st.Find(state.TypeRGW + "." + d.ID)
				if ok {
					x.Cert = target
					st.AddDaemon(x)
				}

				return nil
			}); err != nil {
				return false, err
			}
		}

		done, ok, err := l.step(ctx, b, js, gid, epoch, base+".rev", h.Name, revisionMode{stop: stopKeys(vips)})
		if err != nil || !done {
			return false, err
		}

		if !ok {
			return false, fmt.Errorf("the revision of %s for its RGW did not apply", h.Name)
		}

		cert, _, ok := st.RGWCertOf(state.Daemon{Cert: target})
		if !ok {
			return false, fmt.Errorf("no certificate %s in the state", target)
		}

		var rep wire.NodeReport
		if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			return false, err
		}

		// a revision that changed nothing (the same certificate under a new id)
		// starts no new instance: serving the certificate is enough
		rs, err := l.journalState(ctx, b, js, gid, base+".rev")
		if err != nil {
			return false, err
		}

		fresh := rs != JournalNoChange

		if cur := rep.Current[doc]; cur == "" || fresh && cur == rec.Instance || rep.Running[doc] == "" || !l.servesCert(h.Addr, st.RGW.Port, cert.Cert) {
			return false, fmt.Errorf("%w: %s does not serve the new certificate yet", errRetry, doc)
		}

		if done, err := l.vipBack(ctx, b, js, gid, epoch, base, h, vips); err != nil || !done {
			return false, err
		}

		if rec, _, err = l.readRoll(ctx, b, js, gid, base); err != nil {
			return false, err
		}

		rec.Done = true
		if err := writeJSONKey(ctx, js, rollKey(gid, base), rec); err != nil {
			return false, err
		}

		delete(l.failing, op.ID) // 10 minutes per host
	}

	return true, nil
}

// rgwRestart restarts or redeploys an RGW on a host with a keepalived, the
// VIP moved first: keepalived off (vipOff), for a redeploy the host's
// revision, the restart (phase .rst), then keepalived back (vipBack).
func (l *LeaderLoop) rgwRestart(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp, h state.Host, vips []string) error {
	l.holding = holdAll

	if err := l.notFailing(ctx, b, js, gid, op); err != nil {
		return err
	}

	rst := op
	rst.ID, rst.Kind = op.ID+".rst", KindRestart

	// keepalived already coming back: only that is left
	if back, err := l.restoring(ctx, b, js, gid, op.ID); err != nil {
		return err
	} else if back {
		if done, err := l.vipBack(ctx, b, js, gid, epoch, op.ID, h, vips); err != nil || !done {
			return err
		}

		s, err := l.journalState(ctx, b, js, gid, rst.ID)
		if err != nil {
			return err
		}

		if s != wire.OpCompleted {
			return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the restart of %s ended %s", op.Daemon, s))
		}

		return finish(ctx, js, gid, op, wire.OpCompleted, nil)
	}

	if done, err := l.vipOff(ctx, b, js, gid, epoch, op.ID, h, vips); err != nil || !done {
		return err
	}

	if op.Kind == KindRedeploy {
		done, ok, err := l.step(ctx, b, js, gid, epoch, op.ID+".rev", h.Name, revisionMode{stop: stopKeys(vips)})
		if err != nil || !done {
			return err
		}

		if !ok {
			return fmt.Errorf("the revision of %s did not apply", h.Name)
		}
	}

	if err := l.restartOp(ctx, b, js, gid, epoch, rst); err != nil {
		return err
	}

	s, err := l.journalState(ctx, b, js, gid, rst.ID)
	if err != nil {
		return err
	}

	if !terminal(s) {
		return fmt.Errorf("%w: %s is restarting", errRetry, op.Daemon)
	}

	if done, err := l.vipBack(ctx, b, js, gid, epoch, op.ID, h, vips); err != nil || !done {
		return err
	}

	if s != wire.OpCompleted {
		return finish(ctx, js, gid, op, JournalFailed, fmt.Errorf("the restart of %s ended %s", op.Daemon, s))
	}

	return finish(ctx, js, gid, op, wire.OpCompleted, nil)
}

// notFailing refuses to advance an RGW operation whose cleanup began
// (restoreVIPs): it ends failed once its keepalived are back.
func (l *LeaderLoop) notFailing(ctx context.Context, b *Bridge, js store.Backend, gid int64, op LedgerOp) error {
	_, failing, err := l.readRoll(ctx, b, js, gid, op.ID+".failing")
	if err != nil {
		return err
	}

	if failing {
		return fmt.Errorf("%w: %s failed; its keepalived are coming back", errRetry, op.ID)
	}

	return nil
}

// restoreVIPs is an RGW operation's cleanup when it fails: every keepalived
// it took off (phase base.vip ended) and did not bring back (base.back) is
// granted back, as far as that can be granted now; the failure says which
// could not.
func (l *LeaderLoop) restoreVIPs(ctx context.Context, b *Bridge, js store.Backend, gid, epoch int64, op LedgerOp) error {
	// from now on the operation only fails: its phases no longer advance it
	if err := writeJSONKey(ctx, js, rollKey(gid, op.ID+".failing"), rollRecord{Done: true}); err != nil {
		return err
	}

	st, _, err := l.clusterState(ctx, b)
	if err != nil {
		return err
	}

	bases := map[string]string{op.ID: op.Host}
	for _, h := range st.Hosts {
		bases[op.ID+".roll."+h.Name], bases[op.ID+".recover."+h.Name] = h.Name, h.Name
	}

	var lost []string

	for base, host := range bases {
		off, err := l.journalState(ctx, b, js, gid, base+".vip")
		if err != nil {
			return err
		}

		if off != wire.OpCompleted {
			continue
		}

		back, err := l.journalState(ctx, b, js, gid, base+".back")
		if err != nil {
			return err
		}

		h, _ := st.Host(host)
		vips := vipDocs(st, host)

		if back != wire.OpCompleted && back != JournalNoChange {
			done, ok, err := l.step(ctx, b, js, gid, epoch, base+".back", host, revisionMode{})

			// a restoration whose outcome is not known keeps the operation
			if s, serr := l.journalState(ctx, b, js, gid, base+".back"); serr != nil || s == JournalGranting || s == wire.OpUncertain || err == nil && !done {
				return fmt.Errorf("%w: keepalived on %s is coming back", errRetry, host)
			}

			if err != nil || !ok {
				lost = append(lost, host)

				continue
			}
		}

		// back once each runs a new instance (in any VRRP state: its RGW may be
		// what failed); a host that cannot be asked is named
		rec, _, err := l.readRoll(ctx, b, js, gid, base)
		if err != nil {
			return err
		}

		var rep wire.NodeReport
		if _, err := l.call(ctx, h, http.MethodGet, "/v1/node", nil, &rep); err != nil {
			lost = append(lost, host)

			continue
		}

		for _, v := range vips {
			cur, reported := rep.VRRP[v]
			if before, known := rec.VRRP[v]; rep.Running[v] == "" || !reported || cur.Start == "" || known && cur.Start == before {
				return fmt.Errorf("%w: %s is starting", errRetry, v)
			}
		}
	}

	if len(lost) > 0 {
		return failNote("keepalived not restored on " + strings.Join(lost, ", ") + ": grant it back with a revision of that host")
	}

	return nil
}
