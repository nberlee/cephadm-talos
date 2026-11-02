package orch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/resources/containers"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// quorumTimeout bounds how long recover mons waits for a quorum.
var quorumTimeout = 10 * time.Minute

// RecoverMons brings the mons of a suspended cluster back on their existing
// stores (plan 03, step 7 slice D, item 7), from the nodes' documents, the
// agents' receipts and the stores alone: never the cluster state, mon auth,
// mkfs, a monmap injection or a new key. A running mon is left alone; a mon
// whose document is there is restarted, and one whose document went missing
// (its agent still owned it) is applied again with its store's deployment id,
// each only if its document, its store and its marker check out. Then it
// waits for a quorum.
func (o *Orch) RecoverMons(ctx context.Context, image string) error {
	if o.Talos.DryRun {
		return errors.New("recover has no dry run")
	}

	if image != "" && !digestRe.MatchString(image) {
		return fmt.Errorf("--image %s: an image by digest (<repository>@sha256:<hex>)", image)
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

	if rec == nil || rec.Phase != state.PhaseSuspended && rec.Phase != state.PhaseRecovering {
		return errors.New("no suspended recovery session: run `cephadm-talos suspend` first")
	}

	// every host it may touch, also one found since the suspension
	for _, h := range o.removalHosts(rec) {
		if hr := rec.Hosts[h.Name]; hr == nil || hr.Receipt == nil {
			return fmt.Errorf("%s is not suspended in this session: run `cephadm-talos suspend` again", h.Name)
		}
	}

	if rec.Phase != state.PhaseRecovering {
		rec.Phase = state.PhaseRecovering
		if err := rec.Save(); err != nil {
			return err
		}
	}

	var failed []string

	for _, h := range o.removalHosts(rec) {
		if err := o.recoverMon(ctx, rec, h, image); err != nil {
			o.printf("mon.%s: %v\n", h.Name, err)
			failed = append(failed, h.Name)
		}
	}

	if err := o.waitQuorum(ctx, rec); err != nil {
		return errors.Join(err, failedMons(failed))
	}

	return failedMons(failed)
}

var (
	// digestRe is an image reference by digest
	digestRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}$`)
	// markerRe is a deployment id as mon.sh compares it
	markerRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// cephConfDoc is the key configuredDocs gives ceph.conf.
const cephConfDoc = "EtcFileConfig/ceph/ceph.conf"

// confFSID is the fsid line of a ceph.conf.
func confFSID(conf string) string {
	for _, line := range strings.Split(conf, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "fsid" {
			return strings.TrimSpace(v)
		}
	}

	return ""
}

func failedMons(hosts []string) error {
	if len(hosts) == 0 {
		return nil
	}

	return fmt.Errorf("the mons of %s were not recovered", strings.Join(hosts, ", "))
}

// checkMonDoc checks that a mon's document is the session's mon of that
// host on its Ceph volume: the store the inspection reads is the one it runs.
func (o *Orch) checkMonDoc(h state.Host, d configuredDoc) error {
	switch {
	case d.env["FSID"] != o.St.FSID:
		return fmt.Errorf("its document is of cluster %q", d.env["FSID"])
	case d.env["ID"] != h.Name:
		return fmt.Errorf("its document is mon.%s", d.env["ID"])
	case d.volumes["/var/lib/ceph"] != spec.VolumeName:
		return fmt.Errorf("its document does not run on the %s volume", spec.VolumeName)
	case !storeMountOnly(d.mounts):
		return errors.New("its document mounts something over, under or beside its store's volume, or at a path that is not clean")
	case !digestRe.MatchString(d.image):
		return fmt.Errorf("its document's image %s is not by digest", d.image)
	}

	return nil
}

// storeMountOnly reports whether /var/lib/ceph is mounted exactly once and
// nothing else is mounted at an ancestor or a descendant of it, every path
// clean: what the inspection reads is what the mon sees.
func storeMountOnly(mounts []string) bool {
	const store = "/var/lib/ceph"

	n := 0

	for _, m := range mounts {
		switch {
		case m != path.Clean(m):
			return false
		case m == store:
			n++
		case strings.HasPrefix(m, store+"/"), m == "/", strings.HasPrefix(store, m+"/"):
			return false
		}
	}

	return n == 1
}

// recoverMon recovers the mon of one host, if it has one.
func (o *Orch) recoverMon(ctx context.Context, rec *state.Recovery, h state.Host, image string) error {
	prefix := "ceph-" + o.St.Short() + "-"
	doc := o.St.DocName(state.Daemon{Type: state.TypeMon, ID: h.Name, Host: h.Name})
	key := "ContainerConfig/" + doc
	hr := rec.Host(h.Name)

	docs, err := o.configuredDocs(ctx, h.Addr, prefix)
	if err != nil {
		return err
	}

	cur, configured := docs[doc]

	owned := false
	if hr.Receipt != nil {
		_, owned = hr.Receipt.Owned[key]
	}

	if !configured && !owned {
		return nil // no mon on this host
	}

	// the full fsid: ceph.conf's and every document's that names one
	if conf, ok := docs[cephConfDoc]; !ok || conf.env["FSID"] != o.St.FSID {
		return fmt.Errorf("the node's ceph.conf is not of cluster %s", o.St.FSID)
	}

	for name, d := range docs {
		if fsid, ok := d.env["FSID"]; ok && name != cephConfDoc && fsid != o.St.FSID {
			return fmt.Errorf("the document %s is of cluster %s", name, fsid)
		}
	}

	if err := reservedMon(rec, h.Name, doc); err != nil {
		return err
	}

	// a document applied before a stop: it is the one the journal says, or an error
	if _, ok := hr.Applying[key]; ok && configured {
		if err := o.journalHash(ctx, rec, h, key); err != nil {
			return err
		}
	}

	if configured {
		if err := o.checkMonDoc(h, cur); err != nil {
			return err
		}
	}

	// before anything else, also for a mon that runs again by now
	if err := o.cleanInspections(ctx, rec, h); err != nil {
		return err
	}

	st, err := o.Talos.ContainerStatuses(ctx, h.Addr)
	if err != nil {
		return err
	}

	if s, ok := st[doc]; ok && s.State == containers.ContainerStateRunning {
		o.printf("mon.%s: running\n", h.Name)

		return nil
	}

	// the Ceph image: the mon's own, else a mgr's or an OSD's on the node (a
	// keepalived runs another image), else --image; by digest
	img := cur.image

	for _, typ := range []string{state.TypeMgr, state.TypeOSD} {
		for name, d := range docs {
			if img == "" && strings.HasPrefix(name, prefix+typ+"-") {
				img = d.image
			}
		}
	}

	if img == "" {
		img = image
	}

	if !digestRe.MatchString(img) {
		return fmt.Errorf("no Ceph image by digest on the node (%q): pass --image", img)
	}

	marker, err := o.monMarker(ctx, rec, h, img)
	if err != nil {
		return err
	}

	switch {
	case marker == "":
		return errors.New("its store has no deployment marker, or there is no store: not recovered (nothing rebuilds a store)")
	case configured && marker != cur.env["DEPLOY_ID"]:
		return fmt.Errorf("its store's marker %s is not the document's deployment id %s: not started (the entrypoint would rebuild the store)", marker, cur.env["DEPLOY_ID"])
	case configured:
		o.printf("mon.%s: restarting it on its store\n", h.Name)

		return o.Talos.Restart(ctx, h.Addr, doc)
	}

	// the document went missing while its agent owned it: applied again with
	// the store's deployment id, joining, without a key (the store has it);
	// what it is goes into the journal first
	c := daemons.Mon(daemons.Params{Name: doc, Image: img, FSID: o.St.FSID, ID: h.Name, Addr: h.Addr, DeployID: marker, Mode: "join", Addrv: daemons.MonAddrv(h.Addr)})

	// its hash as the agent will compute it from the node's config
	b, err := spec.Render(c)
	if err != nil {
		return err
	}

	hashes, err := agent.DocHashes(string(b))
	if err != nil || hashes[key] == "" {
		return fmt.Errorf("the mon's document does not hash: %v", err)
	}

	if hr.Applying == nil {
		hr.Applying = map[string]state.Applying{}
	}

	hr.Applying[key] = state.Applying{Hash: hashes[key], DeployID: marker, Image: img}

	if err := rec.Save(); err != nil {
		return err
	}

	o.printf("mon.%s: applying its document again on its store (deployment %s)\n", h.Name, marker)

	if err := o.apply(ctx, h.Addr, c); err != nil {
		return err
	}

	return o.journalHash(ctx, rec, h, key)
}

// journalHash records the hash of a document the recovery applied, as the
// agent will see it at the re-adoption.
func (o *Orch) journalHash(ctx context.Context, rec *state.Recovery, h state.Host, key string) error {
	cfg, err := o.Talos.MachineConfig(ctx, h.Addr)
	if err != nil {
		return err
	}

	hashes, err := agent.DocHashes(cfg)
	if err != nil {
		return err
	}

	hash, ok := hashes[key]
	if !ok {
		return fmt.Errorf("%s is not in the node's config after its apply", key)
	}

	hr := rec.Host(h.Name)

	// exactly the document the recovery rendered, or an error
	if want := hr.Applying[key]; hash != want.Hash {
		return fmt.Errorf("the node's %s is not the document the recovery applied (deployment %s, image %s)", key, want.DeployID, want.Image)
	}
	if hr.Changes == nil {
		hr.Changes = map[string]string{}
	}

	hr.Changes[key] = hash
	delete(hr.Applying, key)

	return rec.Save()
}

// reservedMon refuses a mon an uncertain operation or an open bridge intent
// may still change: on its node, an apply's or a reboot's documents are not
// known, so it reserves the node, and a restart reserves its daemon's
// document (a job changes no mon document); a bridge intent, on whichever
// host the leader made it, reserves its daemon, or with no daemon its host.
func reservedMon(rec *state.Recovery, host, doc string) error {
	if hr := rec.Hosts[host]; hr != nil && hr.Receipt != nil {
		for _, op := range hr.Receipt.Unresolved {
			switch {
			case op.Job != nil:
			case op.Instance != "":
				if strings.HasPrefix(op.Instance, doc+"-") {
					return fmt.Errorf("its restart in operation %s has no known outcome", op.Operation)
				}
			default:
				return fmt.Errorf("operation %s on the node has no known outcome: the node is reserved", op.Operation)
			}
		}
	}

	for _, hr := range rec.Hosts {
		if hr.Receipt == nil {
			continue
		}

		for _, in := range hr.Receipt.Intents {
			if in.Daemon == "mon."+host || in.Daemon == "" && in.Host == host {
				return fmt.Errorf("the bridge call %s of operation %s has no known outcome", in.Call, in.Operation)
			}
		}
	}

	return nil
}

// monMarker runs the journaled inspection of a mon's store: its deployment
// marker, "" without a store or a marker.
func (o *Orch) monMarker(ctx context.Context, rec *state.Recovery, h state.Host, image string) (string, error) {
	if o.inspectMon != nil {
		return o.inspectMon(h)
	}

	if err := o.cleanInspections(ctx, rec, h); err != nil {
		return "", err
	}

	j, err := inspectionJob(rec, h)
	if err != nil {
		return "", err
	}

	dir := "/var/lib/ceph/" + o.St.FSID + "/mon." + h.Name
	// the marker exactly as mon.sh compares it ($(cat ...)), in base64
	cmd := fmt.Sprintf(`D=%s; if [ -d "$D/store.db" ] && [ -s "$D/cephadm-talos-done" ]; then printf 'marker %%s\n' "$(printf '%%s' "$(cat "$D/cephadm-talos-done")" | base64 -w0)"; else echo marker; fi`, shellQuote(dir))
	doc := daemons.HostJob(daemons.Params{Name: fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), j.ID), Image: image, FSID: o.St.FSID, ID: "job"}, j.ID, j.Inputs, cmd)

	res, err := o.runJob(ctx, h.Addr, doc, j.ID, 5*time.Minute)

	// used once, whatever happened: the next run inspects the store again,
	// and removes this one first unless its cleanup is known to be done
	var cleanup *JobCleanupError

	j.Done, j.Cleaned = true, !errors.As(err, &cleanup)
	if serr := rec.Save(); serr != nil {
		return "", errors.Join(err, serr)
	}

	if err != nil {
		return "", fmt.Errorf("inspecting its store: %w", err)
	}

	return parseMarker(res.Output)
}

// cleanInspections removes the inspections of a host an earlier run left
// (their cleanup not known to be done): they may have ended unseen, are
// read-only, and no cluster document may stay behind for the re-adoption.
func (o *Orch) cleanInspections(ctx context.Context, rec *state.Recovery, h state.Host) error {
	for purpose, prev := range rec.Jobs {
		if !strings.HasPrefix(purpose, "inspect-mon/"+h.Name+"/") || prev.Cleaned {
			continue
		}

		name := fmt.Sprintf("ceph-%s-job-%s", o.St.Short(), prev.ID)
		if err := o.remove(ctx, h.Addr, name); err != nil {
			return err
		}

		if err := o.waitGone(ctx, h.Addr, name, 5*time.Minute); err != nil {
			return err
		}

		prev.Done, prev.Cleaned = true, true
		if err := rec.Save(); err != nil {
			return err
		}
	}

	return nil
}

// inspectionJob is the job of a mon store's inspection: the last one again
// while its result was not read, else a new one, journaled (a job replays its
// result, which would be the store as it was).
func inspectionJob(rec *state.Recovery, h state.Host) (*state.RecoveryJob, error) {
	for n := 1; ; n++ {
		purpose := fmt.Sprintf("inspect-mon/%s/%d", h.Name, n)

		j := rec.Jobs[purpose]
		if j != nil && j.Done {
			continue
		}

		if j == nil {
			j = &state.RecoveryJob{ID: randHex(3), Host: h.Name, Inputs: jobInputs("inspect-mon", h.Name, rec.Session, purpose)}
			rec.Jobs[purpose] = j

			if err := rec.Save(); err != nil {
				return nil, err
			}
		}

		return j, nil
	}
}

// parseMarker reads the inspection's output: "marker" without a store or a
// marker, "marker <base64>" with one, which must be a deployment id as is.
func parseMarker(out string) (string, error) {
	for _, line := range strings.Split(out, "\n") {
		if line == "marker" {
			return "", nil
		}

		v, ok := strings.CutPrefix(line, "marker ")
		if !ok {
			continue
		}

		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil || !markerRe.Match(b) {
			return "", fmt.Errorf("the store's marker %q is not a deployment id", b)
		}

		return string(b), nil
	}

	return "", errors.New("the inspection printed no marker")
}

// waitQuorum waits until the mons answer with a quorum, through exec into a
// mon container (no mgr needs to run).
func (o *Orch) waitQuorum(ctx context.Context, rec *state.Recovery) error {
	ctx, cancel := context.WithTimeout(ctx, quorumTimeout)
	defer cancel()

	for {
		for _, h := range o.removalHosts(rec) {
			if !o.runsMgrOrMon(ctx, h) {
				continue
			}

			res, err := o.jobInput(ctx, h.Addr, "timeout 20 ceph quorum_status --format json", nil, 30*time.Second)
			if err != nil || res.RC != 0 {
				continue
			}

			var q struct {
				Quorum []string `json:"quorum_names"`
			}

			if json.Unmarshal([]byte(res.Output), &q) == nil && len(q.Quorum) > 0 {
				o.printf("quorum: %s\n", strings.Join(q.Quorum, ", "))

				return nil
			}
		}

		if err := sleep(ctx, 10*time.Second); err != nil {
			return fmt.Errorf("no quorum within %s", quorumTimeout)
		}
	}
}

// offlineExecHost is a host with a running mgr or mon container of the
// cluster, for exec without the cluster state.
func (o *Orch) offlineExecHost(ctx context.Context, rec *state.Recovery) (state.Host, error) {
	for _, h := range o.removalHosts(rec) {
		if o.runsMgrOrMon(ctx, h) {
			return h, nil
		}
	}

	return state.Host{}, errors.New("no node with a running mgr or mon container of the cluster")
}

// runsMgrOrMon reports whether a node runs a mgr or mon container of the cluster.
func (o *Orch) runsMgrOrMon(ctx context.Context, h state.Host) bool {
	targets, err := o.execTargets(ctx, h.Addr)

	return err == nil && slices.ContainsFunc(targets, func(t string) bool {
		return strings.Contains(t, "-mgr-") || strings.Contains(t, "-mon-")
	})
}

// configuredDoc is a cluster container configured on a node.
type configuredDoc struct {
	image string
	env   map[string]string
	// volumes maps a mount destination to its volume; mounts are the
	// destinations of every mount
	volumes map[string]string
	mounts  []string
}
