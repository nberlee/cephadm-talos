package orch

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/state"
)

// MaintenanceEnter puts a host into maintenance like `ceph orch host maintenance
// enter`: check that its daemons can be stopped, set noout for the host, and stop
// them. cephadm stops and disables ceph-<fsid>.target; Talos has no stop or
// disable for ContainerConfig, so the documents are removed and re-applied from
// the inventory on exit. They stay down across reboots until then.
func (o *Orch) MaintenanceEnter(ctx context.Context, name string, force bool) error {
	h, ok := o.St.Host(name)
	if !ok {
		return fmt.Errorf("unknown host %q", name)
	}

	// `osd set-group noout <host>` resolves numbers (osd ids) and all/any before
	// CRUSH bucket names, so such a host name would flag the wrong OSDs
	if _, err := strconv.Atoi(h.Name); err == nil || h.Name == "all" || h.Name == "any" {
		return fmt.Errorf("host name %q is ambiguous for `ceph osd set-group noout`; maintenance is not supported for it", h.Name)
	}

	daemons := o.hostDaemons(h)

	// Every enter runs the full sequence, also when resuming an interrupted one:
	// an earlier ok-to-stop reserves nothing (another host may have been stopped
	// since) and an earlier set-group may never have run.
	for i, d := range daemons {
		if d.Type == state.TypeOSD {
			// ok-to-stop only checks the ids it is given: every OSD's identity must be known
			if err := o.ensureOSDID(ctx, &daemons[i], h, false, false); err != nil {
				return err
			}
		}
	}

	st, err := o.Talos.ContainerStatuses(ctx, h.Addr)
	if err != nil {
		return err
	}

	var running []state.Daemon

	for _, d := range daemons {
		if _, ok := st[o.St.DocName(d)]; ok {
			running = append(running, d)
		}
	}

	// prefer another host's mon for the checks; fall back to this one while its
	// mon still runs, whatever its maintenance flag says (resume on single-mon clusters)
	adm, err := o.adminHostExcept(h.Name)
	if err != nil {
		for _, d := range running {
			if d.Type == state.TypeMon {
				adm, err = h, nil
			}
		}

		if err != nil {
			return err
		}
	}

	if err := o.okToStop(ctx, adm, h, running, force); err != nil {
		return err
	}

	// Recorded before the flag is set, so exit always knows to clear it.
	// Unsetting a group flag that was never set is harmless.
	h.Maintenance = true
	h.NoOut = h.NoOut || len(o.hostOSDs(daemons)) > 0
	o.St.AddHost(h)

	if err := o.save(); err != nil {
		return err
	}

	if h.NoOut {
		o.printf("setting noout for %s\n", h.Name)

		// idempotent; must succeed before any OSD is stopped
		if _, err := o.Job(ctx, adm.Addr, "ceph osd set-group noout "+shellQuote(h.Name), 5*time.Minute); err != nil {
			return fmt.Errorf("%w (%s is marked in maintenance; run enter again to finish, or exit to undo)", err, h.Name)
		}
	}

	// all documents are deleted and waited for, not only those with a status left:
	// a status vanishes with its document before the process has exited

	for _, d := range daemons {
		o.printf("stopping %s\n", displayName(d))

		if err := o.remove(ctx, h.Addr, o.St.DocName(d)); err != nil {
			return err
		}
	}

	for _, d := range daemons {
		if err := o.waitGone(ctx, h.Addr, o.St.DocName(d), 5*time.Minute); err != nil {
			return err
		}
	}

	o.printf("host %s is in maintenance\n", h.Name)

	return nil
}

// MaintenanceExit restarts a host's daemons and clears its noout flag.
func (o *Orch) MaintenanceExit(ctx context.Context, name string) error {
	h, ok := o.St.Host(name)
	if !ok {
		return fmt.Errorf("unknown host %q", name)
	}

	if !h.Maintenance {
		return fmt.Errorf("host %s is not in maintenance", h.Name)
	}

	daemons := o.hostDaemons(h)

	// mons first, so the OSDs find a local mon again
	for _, typ := range []string{state.TypeMon, state.TypeMgr, state.TypeOSD, state.TypeRGW, state.TypeVIP} {
		for _, d := range daemons {
			if d.Type != typ {
				continue
			}

			doc, err := o.redeployDoc(d, h, o.St.Image)
			if err != nil {
				return err
			}

			o.printf("starting %s\n", displayName(d))

			if err := o.apply(ctx, h.Addr, doc); err != nil {
				return err
			}

			if err := o.waitRunning(ctx, h.Addr, o.St.DocName(d), 10*time.Minute); err != nil {
				return err
			}
		}
	}

	// the host stays "in maintenance" until its OSDs are back and noout is gone,
	// so a failed exit can simply be repeated
	// its mon runs again, so the host itself is eligible for the jobs (single-mon clusters)
	h.Maintenance = false
	o.St.AddHost(h)
	adm, err := o.adminHost()
	h.Maintenance = true
	o.St.AddHost(h)

	if err != nil {
		return err
	}

	for _, d := range daemons {
		if d.Type == state.TypeOSD && d.OSDID != nil {
			if _, err := o.Job(ctx, adm.Addr, osdUpLoop(*d.OSDID, d.OSDUUID), 10*time.Minute); err != nil {
				return fmt.Errorf("%s did not come back up, %s stays in maintenance: %w", displayName(d), h.Name, err)
			}
		}
	}

	if h.NoOut {
		o.printf("clearing noout for %s\n", h.Name)

		if _, err := o.Job(ctx, adm.Addr, "ceph osd unset-group noout "+shellQuote(h.Name), 5*time.Minute); err != nil {
			return err
		}
	}

	h.Maintenance, h.NoOut = false, false
	o.St.AddHost(h)

	if err := o.save(); err != nil {
		return err
	}

	o.printf("host %s left maintenance\n", h.Name)

	return nil
}

// HostReboot is maintenance enter, Talos reboot, maintenance exit.
func (o *Orch) HostReboot(ctx context.Context, name string, force bool) error {
	if err := o.MaintenanceEnter(ctx, name, force); err != nil {
		return err
	}

	h, _ := o.St.Host(name)
	o.printf("rebooting %s\n", h.Name)

	if err := o.Talos.Reboot(ctx, h.Addr); err != nil {
		return fmt.Errorf("reboot of %s failed; it stays in maintenance: %w", h.Name, err)
	}

	return o.MaintenanceExit(ctx, name)
}

// mgrElsewhere reports whether a mgr runs on another host that is not in maintenance.
func (o *Orch) mgrElsewhere(host string) bool {
	for _, d := range o.St.DaemonsOf(state.TypeMgr, "") {
		if h, ok := o.St.Host(d.Host); ok && d.Host != host && !h.Maintenance {
			return true
		}
	}

	return false
}

// adminHostExcept is adminHost preferring hosts other than the given one; the
// excluded host is still used as a last resort while it runs a mon.
func (o *Orch) adminHostExcept(host string) (state.Host, error) {
	if h, ok := o.St.Host(host); ok && !h.Maintenance {
		h.Maintenance = true
		o.St.AddHost(h)
		adm, err := o.adminHost()
		h.Maintenance = false
		o.St.AddHost(h)

		if err == nil {
			return adm, nil
		}
	}

	return o.adminHost()
}

// hostDaemons returns the daemons placed on a host, except half removed OSDs.
func (o *Orch) hostDaemons(h state.Host) []state.Daemon {
	var out []state.Daemon

	for _, d := range o.St.Daemons {
		if d.Host == h.Name && !d.Purged && !d.LocalOnly {
			out = append(out, d)
		}
	}

	return out
}

func (o *Orch) hostOSDs(daemons []state.Daemon) []int {
	var ids []int

	for _, d := range daemons {
		if d.Type == state.TypeOSD && d.OSDID != nil {
			ids = append(ids, *d.OSDID)
		}
	}

	return ids
}

// okToStop mirrors cephadm's _host_ok_to_stop: every daemon on the host must be stoppable.
func (o *Orch) okToStop(ctx context.Context, adm, h state.Host, daemons []state.Daemon, force bool) error {
	var checks []string

	if ids := o.hostOSDs(daemons); len(ids) > 0 {
		s := make([]string, len(ids))
		for i, id := range ids {
			s[i] = fmt.Sprint(id)
		}

		checks = append(checks, "ceph osd ok-to-stop "+strings.Join(s, " "))
	}

	for _, d := range daemons {
		switch d.Type {
		case state.TypeMon:
			checks = append(checks, "ceph mon ok-to-stop "+shellQuote(d.ID))
		case state.TypeMgr:
			// like cephadm: another mgr must be up, judged from the live mgr map, not the
			// inventory (a mgr on a host that is down or in maintenance does not count)
			if !o.mgrElsewhere(h.Name) && !force {
				return fmt.Errorf("mgr.%s is the only mgr; deploy another one first or use --force", d.ID)
			}

			checks = append(checks, fmt.Sprintf(`ceph mgr dump --format json | python3 -c 'import json,sys; m=json.load(sys.stdin); up=([m["active_name"]] if m.get("available") else [])+[s["name"] for s in m.get("standbys",[])]; sys.exit(0 if any(n!=%q for n in up) else 1)' || { echo "no other mgr is up" >&2; exit 1; }`, d.ID))
		}
	}

	if len(checks) == 0 {
		return nil
	}

	if force {
		// `osd ok-to-stop` needs an active mgr; --force must also work without one
		o.printf("warning: skipping ok-to-stop for %s (--force)\n", h.Name)

		return nil
	}

	o.printf("checking that the daemons on %s can be stopped\n", h.Name)

	res, err := o.Job(ctx, adm.Addr, strings.Join(checks, " && "), 5*time.Minute)
	if err != nil {
		if force && forceable(res, err) {
			o.printf("warning: ignoring failed ok-to-stop (--force):\n%s", res.Output)

			return nil
		}

		return fmt.Errorf("not ok to stop %s (use --force to override): %w", h.Name, err)
	}

	return nil
}
