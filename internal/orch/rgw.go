package orch

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"gopkg.in/yaml.v3"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// DefaultKeepalivedImage is the image cephadm's ingress uses for keepalived.
const DefaultKeepalivedImage = "quay.io/ceph/keepalived:2.2.4"

// RGWOptions are the settings of `deploy rgw`.
type RGWOptions struct {
	Port     int    // HTTPS port; only honoured for the first rgw
	CertFile string // optional PEM certificate (chain) instead of the generated one
	KeyFile  string
}

// DeployRGW places a radosgw serving HTTPS on a host.
func (o *Orch) DeployRGW(ctx context.Context, hostName string, opts RGWOptions) error {
	if err := o.gateCluster(); err != nil {
		return err
	}

	h, err := o.deployHost(ctx, hostName)
	if err != nil {
		return err
	}

	d := state.Daemon{Type: state.TypeRGW, ID: h.Name, Host: h.Name}
	if _, ok := o.St.Find("rgw." + h.Name); ok {
		// a repeated deploy finishes an earlier, interrupted one
		o.printf("rgw.%s already exists, re-applying\n", h.Name)
	}

	if o.St.RGW == nil {
		port := opts.Port
		if port == 0 {
			port = 443
		}

		o.St.RGW = &state.RGW{Port: port}
	}

	if opts.CertFile != "" {
		cert, err := os.ReadFile(opts.CertFile)
		if err != nil {
			return err
		}

		key, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return err
		}

		if _, err := tls.X509KeyPair(cert, key); err != nil {
			return fmt.Errorf("certificate and key do not match: %w", err)
		}

		o.St.RGW.Cert, o.St.RGW.Key, o.St.RGW.UserCert = string(cert), string(key), true
	}

	// (re)issue the generated certificate so it also covers this host
	if err := o.ensureRGWCert(); err != nil {
		return err
	}

	entity := "client.rgw." + h.Name

	k, err := o.newKey(entity)
	if err != nil {
		return err
	}

	if err := o.importKey(ctx, daemons.Keyring(entity, k, "mon", "allow rw", "osd", "allow rwx", "mgr", "allow rw")); err != nil {
		return err
	}

	o.St.AddDaemon(d)

	if err := o.save(); err != nil {
		return err
	}

	// all rgws share one certificate: this host first, then everyone else
	if err := o.applyRGWAndVIP(ctx, h.Name); err != nil {
		return err
	}

	o.printf("rgw.%s serving https://%s (CA: %s/rgw-ca.crt)\n", h.Name, net.JoinHostPort(h.Addr, fmt.Sprint(o.St.RGW.Port)), o.St.Dir())

	return nil
}

// DeployVIP places a keepalived holding the RGW virtual IP on a host. The host
// should run an rgw: keepalived only holds the VIP while its local rgw answers.
func (o *Orch) DeployVIP(ctx context.Context, hostName, vip, image string) error {
	if err := o.gateCluster(); err != nil {
		return err
	}

	h, err := o.deployHost(ctx, hostName)
	if err != nil {
		return err
	}

	if o.St.RGW == nil {
		return fmt.Errorf("deploy an rgw first")
	}

	r := o.St.RGW

	if vip != "" && r.VIP != "" && vip != r.VIP {
		return fmt.Errorf("the cluster already uses VIP %s", r.VIP)
	}

	if r.VIP == "" {
		if vip == "" {
			return fmt.Errorf("the first vip needs --vip <ip>/<prefix>")
		}

		if _, _, err := net.ParseCIDR(vip); err != nil {
			return fmt.Errorf("--vip must be an address with prefix length, e.g. 10.5.0.200/24: %w", err)
		}

		r.VIP, r.VRID, r.VRRPPass = vip, 51, randHex(4)
	}

	if image != "" {
		r.KeepalivedImage = image
	}

	if r.KeepalivedImage == "" {
		r.KeepalivedImage = DefaultKeepalivedImage
	}

	if _, ok := o.St.Find("vip." + h.Name); ok {
		o.printf("vip.%s already exists, re-applying\n", h.Name)
	}

	if len(o.St.DaemonsOf(state.TypeRGW, h.Name)) == 0 {
		o.printf("warning: no rgw on %s; its keepalived will never hold the VIP\n", h.Name)
	}

	d := state.Daemon{Type: state.TypeVIP, ID: h.Name, Host: h.Name}
	o.St.AddDaemon(d)

	// the certificate must now include the VIP; rgws get the reissued one
	if err := o.ensureRGWCert(); err != nil {
		return err
	}

	if err := o.save(); err != nil {
		return err
	}

	// every keepalived lists all the others as unicast peers: re-render them all,
	// this host first (its rgw with the reissued certificate before its keepalived)
	if err := o.applyRGWAndVIP(ctx, h.Name); err != nil {
		return err
	}

	if err := o.waitRunning(ctx, h.Addr, o.St.DocName(d), 10*time.Minute); err != nil {
		return err
	}

	o.printf("vip.%s running; the VIP %s is held by one keepalived at a time\n", h.Name, r.VIP)

	return nil
}

// applyRGWAndVIP re-applies every rgw and vip document (new certificate, new
// peers), one apply per host with the rgw before the keepalived. The given host
// goes first. Unreachable hosts don't stop the others: they are remembered in
// RGWPending and retried by the next command (RetryPendingRGW).
func (o *Orch) applyRGWAndVIP(ctx context.Context, first string) error {
	hosts := []state.Host{}

	if h, ok := o.St.Host(first); ok {
		hosts = append(hosts, h)
	}

	for _, h := range o.St.Hosts {
		if h.Name != first {
			hosts = append(hosts, h)
		}
	}

	var failed []string

	pending := slices.Clone(o.St.RGWPending)

	for i, h := range hosts {
		if h.Maintenance {
			continue
		}

		applied, err := o.rollRGWHost(ctx, h, o.St.Image, rollOpts{verify: slices.Contains(pending, h.Name)})
		if err == nil {
			continue
		}

		if !applied {
			// unreachable: the others can still be updated, this one is retried later
			o.printf("warning: rgw/vip on %s not updated: %v\n", h.Name, err)
			failed = append(failed, h.Name)

			continue
		}

		// applied but not serving: stop, continuing could restart the last working gateway
		for _, rest := range hosts[i:] {
			if !rest.Maintenance {
				failed = append(failed, rest.Name)
			}
		}

		o.St.RGWPending = failed
		if serr := o.save(); serr != nil {
			return serr
		}

		return fmt.Errorf("stopped the rgw roll at %s, %s pending: %w", h.Name, strings.Join(failed, ", "), err)
	}

	o.St.RGWPending = failed

	if err := o.save(); err != nil {
		return err
	}

	if len(failed) > 0 {
		if slices.Contains(failed, first) {
			return fmt.Errorf("rgw/vip documents could not be applied on %s; retried on the next command", strings.Join(failed, ", "))
		}

		o.printf("warning: rgw/vip documents outdated on %s; retried on the next command\n", strings.Join(failed, ", "))
	}

	return nil
}

// waitRGWServing waits until a host's rgw serves the intended certificate over HTTPS.
func (o *Orch) waitRGWServing(ctx context.Context, h state.Host, d state.Daemon) error {
	if o.Talos.DryRun {
		return nil
	}

	fp, err := certFingerprint(o.St.RGW.Cert)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(h.Addr, fmt.Sprint(o.St.RGW.Port))
	check := fmt.Sprintf(`for i in $(seq 90); do
  got=$(openssl s_client -connect %[1]s </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
  [ "$got" = %[2]q ] && curl -skf -o /dev/null https://%[1]s/ && exit 0
  sleep 2
done
echo "rgw.%[3]s does not serve the expected certificate (got ${got:-nothing})" >&2
exit 1`, addr, fp, d.ID)

	_, err = o.Job(ctx, h.Addr, check, 5*time.Minute)

	return err
}

// rollRGWHost brings one host's rgw and keepalived documents up to date. It is
// the only way an rgw is restarted (deploy, certificate change, upgrade):
//
//  1. compare the rendered documents with the node's machine config; nothing
//     changed means nothing restarts;
//  2. if the rgw changes and another vip host has a serving rgw, stop the local
//     keepalived first, so the VIP moves at once (priority 0 advert);
//  3. apply, wait for the new container generation, then for HTTPS with the
//     intended certificate;
//  4. restore keepalived and wait until it can hold the VIP again.
//
// applied reports whether anything was applied before an error.
// rollOpts: verify checks readiness even when nothing changed (a host left
// pending by a failed roll); force replaces the instances (explicit redeploy).
type rollOpts struct {
	verify bool
	force  string // state.TypeRGW or state.TypeVIP: replace those instances
}

func (o *Orch) rollRGWHost(ctx context.Context, h state.Host, image string, opts rollOpts) (applied bool, err error) {
	var rgwDocs, vipDocs []*spec.ContainerConfig

	var rgws []state.Daemon

	for _, d := range o.St.DaemonsOf(state.TypeRGW, h.Name) {
		if d.LocalOnly {
			continue
		}

		doc, err := o.redeployDoc(d, h, image)
		if err != nil {
			return false, err
		}

		rgwDocs, rgws = append(rgwDocs, doc), append(rgws, d)
	}

	for _, d := range o.St.DaemonsOf(state.TypeVIP, h.Name) {
		if d.LocalOnly {
			continue
		}

		doc, err := o.redeployDoc(d, h, image)
		if err != nil {
			return false, err
		}

		vipDocs = append(vipDocs, doc)
	}

	if len(rgwDocs)+len(vipDocs) == 0 || o.Talos.DryRun {
		if o.Talos.DryRun {
			return false, o.apply(ctx, h.Addr, append(asAny(rgwDocs), asAny(vipDocs)...)...)
		}

		return false, nil
	}

	current, err := o.Talos.MachineConfig(ctx, h.Addr)
	if err != nil {
		return false, err
	}

	rgwChanged, vipChanged := docsChanged(current, rgwDocs), docsChanged(current, vipDocs)
	forceRGW := opts.force == state.TypeRGW && len(rgwDocs) > 0
	forceVIP := opts.force == state.TypeVIP && len(vipDocs) > 0
	rgwChanged = rgwChanged || forceRGW
	vipChanged = vipChanged || forceVIP

	if !rgwChanged {
		if !vipChanged {
			if opts.verify {
				// "applied" so a failure stops the roll: this host may be the one
				// that never came up
				for _, d := range rgws {
					if err := o.waitRGWServing(ctx, h, d); err != nil {
						return true, err
					}
				}
			}

			return false, nil
		}

		if forceVIP {
			// same document: replace the instance by removing it first
			for _, doc := range vipDocs {
				if err := o.remove(ctx, h.Addr, doc.MetaName); err != nil {
					return false, err
				}

				if err := o.waitGone(ctx, h.Addr, doc.MetaName, 2*time.Minute); err != nil {
					return true, err
				}
			}
		}

		before := o.vrrpTransitions(ctx, h)

		vgens := map[string]uint64{}

		for _, doc := range vipDocs {
			g, err := o.Talos.InstanceGeneration(ctx, h.Addr, doc.MetaName)
			if err != nil {
				return false, err
			}

			vgens[doc.MetaName] = g
		}

		if err := o.apply(ctx, h.Addr, asAny(vipDocs)...); err != nil {
			return false, err
		}

		// a forced replacement is new by construction (the old one was removed)
		if forceVIP {
			return true, o.waitVRRPReady(ctx, h, before)
		}

		// a new keepalived must show it can hold the VIP; one Talos kept (same
		// digest) already could
		for _, doc := range vipDocs {
			replaced, err := o.waitGeneration(ctx, h, doc.MetaName, vgens[doc.MetaName], doc.ContainerImage)
			if err != nil {
				return true, err
			}

			if replaced {
				return true, o.waitVRRPReady(ctx, h, before)
			}
		}

		return true, nil
	}

	gens := map[string]uint64{}

	for _, d := range rgws {
		g, err := o.Talos.InstanceGeneration(ctx, h.Addr, o.St.DocName(d))
		if err != nil {
			return false, err
		}

		gens[o.St.DocName(d)] = g
	}

	drain := false

	// a drained keepalived is always put back, also when the roll fails
	defer func() {
		if drain && err != nil {
			if rerr := o.apply(context.WithoutCancel(ctx), h.Addr, asAny(vipDocs)...); rerr != nil {
				err = fmt.Errorf("%w (and keepalived on %s could not be restored: %v)", err, h.Name, rerr)
			}
		}
	}()

	if len(vipDocs) > 0 {
		if drain = o.peerServing(ctx, h); drain {
			o.printf("moving the VIP away from %s while its rgw restarts\n", h.Name)

			for _, doc := range vipDocs {
				if err := o.remove(ctx, h.Addr, doc.MetaName); err != nil {
					return false, err
				}

				if err := o.waitGone(ctx, h.Addr, doc.MetaName, 2*time.Minute); err != nil {
					return true, err
				}
			}
		} else {
			o.printf("warning: no other vip host with a serving rgw; S3 through the VIP is interrupted while rgw on %s restarts\n", h.Name)

			// keepalived depends on the rgw, which Talos does not let go first:
			// for a forced replacement it stops too and comes back after
			if forceRGW {
				for _, doc := range vipDocs {
					if err := o.remove(ctx, h.Addr, doc.MetaName); err != nil {
						return false, err
					}

					if err := o.waitGone(ctx, h.Addr, doc.MetaName, 2*time.Minute); err != nil {
						return true, err
					}
				}

				drain = true
			}
		}
	}

	if forceRGW {
		// same document: replace the instance by removing it first
		for _, doc := range rgwDocs {
			if err := o.remove(ctx, h.Addr, doc.MetaName); err != nil {
				return true, err
			}

			if err := o.waitGone(ctx, h.Addr, doc.MetaName, 5*time.Minute); err != nil {
				return true, err
			}
		}
	}

	vipBefore := o.vrrpTransitions(ctx, h)

	if forceVIP && !drain {
		// the keepalived replacement asked for must still happen
		for _, doc := range vipDocs {
			if err := o.remove(ctx, h.Addr, doc.MetaName); err != nil {
				return true, err
			}

			if err := o.waitGone(ctx, h.Addr, doc.MetaName, 2*time.Minute); err != nil {
				return true, err
			}
		}
	}

	docs := asAny(rgwDocs)
	if !drain {
		docs = append(docs, asAny(vipDocs)...)
	}

	if err := o.apply(ctx, h.Addr, docs...); err != nil {
		return drain, err
	}

	// the old instance keeps serving until Talos has replaced it
	for i, d := range rgws {
		// after a forced removal only the new instance can answer at all
		if !forceRGW {
			if _, err := o.waitGeneration(ctx, h, o.St.DocName(d), gens[o.St.DocName(d)], rgwDocs[i].ContainerImage); err != nil {
				return true, err
			}
		}

		if err := o.waitRGWServing(ctx, h, d); err != nil {
			return true, err
		}
	}

	if drain {
		before := o.vrrpTransitions(ctx, h)

		if err := o.apply(ctx, h.Addr, asAny(vipDocs)...); err != nil {
			return true, fmt.Errorf("keepalived on %s not restored: %w", h.Name, err)
		}

		drain = false // restored

		if err := o.waitVRRPReady(ctx, h, before); err != nil {
			return true, err
		}
	} else if forceVIP {
		if err := o.waitVRRPReady(ctx, h, vipBefore); err != nil {
			return true, err
		}
	}

	return true, nil
}

// peerServing reports whether another vip host (not in maintenance) has an rgw answering HTTPS.
func (o *Orch) peerServing(ctx context.Context, h state.Host) bool {
	var urls []string

	for _, d := range o.St.DaemonsOf(state.TypeVIP, "") {
		ph, ok := o.St.Host(d.Host)
		if !ok || ph.Name == h.Name || ph.Maintenance || len(o.St.DaemonsOf(state.TypeRGW, ph.Name)) == 0 {
			continue
		}

		urls = append(urls, "https://"+net.JoinHostPort(ph.Addr, fmt.Sprint(o.St.RGW.Port))+"/")
	}

	if len(urls) == 0 {
		return false
	}

	check := "for u in " + strings.Join(urls, " ") + "; do curl -skf --max-time 5 -o /dev/null \"$u\" && exit 0; done; exit 1"
	_, err := o.Job(ctx, h.Addr, check, 2*time.Minute)

	return err == nil
}

// waitGeneration waits until Talos runs a newer instance of a container than
// gen. Talos only replaces an instance when its resolved spec changes: a new
// image reference with the same digest keeps the old one. So once the requested
// image is resolved and the instance runs that digest, no replacement within
// a grace period means none is needed.
func (o *Orch) waitGeneration(ctx context.Context, h state.Host, name string, gen uint64, image string) (replaced bool, err error) {
	deadline := time.Now().Add(5 * time.Minute)

	var settled time.Time

	for time.Now().Before(deadline) {
		if g, err := o.Talos.InstanceGeneration(ctx, h.Addr, name); err == nil && g > gen {
			return true, nil
		}

		img, err := o.Talos.ImageStatus(ctx, h.Addr, name)
		st, serr := o.Talos.ContainerStatuses(ctx, h.Addr)

		if s, ok := st[name]; err == nil && serr == nil && ok && img.Phase == containers.ContainerImagePhaseReady && sameImage(img.Image, image) && s.State == containers.ContainerStateRunning && s.Image == img.Digest {
			if settled.IsZero() {
				settled = time.Now()
			} else if time.Since(settled) > 20*time.Second {
				return false, nil
			}
		} else {
			settled = time.Time{}
		}

		if err := sleep(ctx, 2*time.Second); err != nil {
			return false, err
		}
	}

	return false, fmt.Errorf("%s was not restarted by Talos", name)
}

// docsChanged reports whether any document differs from (or is missing in) the
// current machine config.
func docsChanged(current string, docs []*spec.ContainerConfig) bool {
	have := map[string]any{}

	dec := yaml.NewDecoder(strings.NewReader(current))

	for {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			break
		}

		if m["kind"] == "ContainerConfig" {
			if name, ok := m["name"].(string); ok {
				have[name] = m
			}
		}
	}

	for _, doc := range docs {
		b, err := yaml.Marshal(doc)
		if err != nil {
			return true
		}

		var want map[string]any
		if err := yaml.Unmarshal(b, &want); err != nil {
			return true
		}

		if !reflect.DeepEqual(have[doc.MetaName], want) {
			return true
		}
	}

	return false
}

func asAny(docs []*spec.ContainerConfig) []any {
	out := make([]any, len(docs))
	for i, d := range docs {
		out[i] = d
	}

	return out
}

// vrrpTransitions returns, per keepalived on a host, the marker of its latest
// start (printed by vip.sh). Talos keeps one bounded log per container name,
// so counting lines is unreliable; the newest lines are always there.
func (o *Orch) vrrpTransitions(ctx context.Context, h state.Host) map[string]string {
	out := map[string]string{}

	for _, d := range o.St.DaemonsOf(state.TypeVIP, h.Name) {
		logs, _ := o.Talos.Logs(ctx, h.Addr, o.St.DocName(d))
		out[d.ID], _ = lastVIPStart(logs)
	}

	return out
}

// lastVIPStart returns the latest start marker and whether a VRRP BACKUP or
// MASTER transition was logged after it.
func lastVIPStart(logs string) (marker string, ready bool) {
	const start = "CEPHADM-TALOS-VIP-START "

	i := strings.LastIndex(logs, start)
	if i < 0 {
		return "", false
	}

	rest := logs[i+len(start):]
	marker, after, _ := strings.Cut(rest, "\n")

	return marker, strings.Contains(after, "Entering BACKUP STATE") || strings.Contains(after, "Entering MASTER STATE")
}

// waitVRRPReady waits until each keepalived on a host started anew (a marker
// other than before) and reached BACKUP or MASTER after that start.
func (o *Orch) waitVRRPReady(ctx context.Context, h state.Host, before map[string]string) error {
	if o.Talos.DryRun {
		return nil
	}

	deadline := time.Now().Add(2 * time.Minute)

	for time.Now().Before(deadline) {
		ready := true

		for _, d := range o.St.DaemonsOf(state.TypeVIP, h.Name) {
			logs, _ := o.Talos.Logs(ctx, h.Addr, o.St.DocName(d))

			marker, ok := lastVIPStart(logs)
			if marker == "" || marker == before[d.ID] || !ok {
				ready = false
			}
		}

		if ready {
			return nil
		}

		if err := sleep(ctx, time.Second); err != nil {
			return err
		}
	}

	return fmt.Errorf("keepalived on %s did not become ready", h.Name)
}

// RetryPendingRGW re-applies rgw/vip documents an earlier run left behind.
func (o *Orch) RetryPendingRGW(ctx context.Context) error {
	if len(o.St.RGWPending) == 0 || o.Talos.DryRun {
		return nil
	}

	o.printf("retrying the rgw/vip update for %s\n", strings.Join(o.St.RGWPending, ", "))

	return o.applyRGWAndVIP(ctx, "")
}

// deployHost resolves a host for a deploy, adding an unknown address on the fly.
func (o *Orch) deployHost(ctx context.Context, hostName string) (state.Host, error) {
	h, ok := o.St.Host(hostName)
	if !ok {
		var err error

		if h, err = o.AddHost(ctx, hostName); err != nil {
			return h, err
		}
	}

	if h.Maintenance {
		return h, fmt.Errorf("host %s is in maintenance, run `cephadm-talos host maintenance exit %s` first", h.Name, h.Name)
	}

	if err := o.checkTalos(ctx, h.Addr); err != nil {
		return h, err
	}

	return h, nil
}
