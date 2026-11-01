package orch

import (
	"context"
	"os"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
)

// ApprovalPrefix holds the operator's approvals in config-key, one per serial,
// outside mgr/ (plan 03, step 6c). The leader reads the newest; the agents
// verify it against the key they pin.
const ApprovalPrefix = "cephadm-talos/approvals/"

// ApprovalChange is what `cephadm-talos approve` changes.
type ApprovalChange struct {
	AddImages, DropImages []string
	// Prepare and Zap are "<host>:<serial>" or "<host>:/dev/<disk>";
	// Drop is "<host>:<serial>:<action>"
	Prepare, Zap, Drop []string
}

func (c ApprovalChange) empty() bool {
	return len(c.AddImages)+len(c.DropImages)+len(c.Prepare)+len(c.Zap)+len(c.Drop) == 0
}

// lastApproval is the last approval this workstation signed, nil before any.
func (o *Orch) lastApproval() (*approval.Approval, *approval.Signed, error) {
	a := o.St.Agent
	if a == nil || a.ApprovalPriv == "" || a.ApprovalKey == "" {
		return nil, nil, errors.New("this workstation has no approval key for the cluster")
	}

	if a.Approval == "" {
		return nil, nil, nil
	}

	var s approval.Signed
	if err := json.Unmarshal([]byte(a.Approval), &s); err != nil {
		return nil, nil, fmt.Errorf("the last approval: %w", err)
	}

	appr, err := approval.Verify(a.ApprovalKey, s, o.St.FSID)
	if err != nil {
		return nil, nil, fmt.Errorf("the last approval: %w", err)
	}

	return &appr, &s, nil
}

// Approve signs the next approval from the last one this workstation signed
// and publishes it; with no change, it publishes the last one again if it is
// not the newest in config-key yet (a publication that had no answer). The
// workstation's copy is the authority: config-key is only where the leader
// finds it, and a newer approval there than this workstation signed is refused.
func (o *Orch) Approve(ctx context.Context, c ApprovalChange) (approval.Approval, error) {
	// one approve at a time per cluster, from the history as it is on disk
	unlock, err := state.Lock(o.St.FSID)
	if err != nil {
		return approval.Approval{}, err
	}
	defer unlock()

	if o.St.Agent != nil {
		if disk, err := state.LastApproval(o.St.FSID); err == nil {
			o.St.Agent.Approval = disk
		} else if !errors.Is(err, os.ErrNotExist) {
			return approval.Approval{}, err
		}
	}

	prev, prevSigned, err := o.lastApproval()
	if err != nil {
		return approval.Approval{}, err
	}

	keys, err := o.approvals(ctx)
	if err != nil {
		return approval.Approval{}, err
	}

	have, err := keys.List(ctx, ApprovalPrefix)
	if err != nil {
		return approval.Approval{}, err
	}

	var newest int64

	for _, k := range have {
		if n, err := strconv.ParseInt(strings.TrimPrefix(k, ApprovalPrefix), 10, 64); err == nil && n > newest {
			newest = n
		}
	}

	var last int64
	if prev != nil {
		last = prev.Serial
	}

	if newest > last {
		return approval.Approval{}, fmt.Errorf("config-key has approval %d, newer than the last this workstation signed (%d): refusing", newest, last)
	}

	publish := func(a approval.Approval, s approval.Signed) error {
		b, err := json.Marshal(s)
		if err != nil {
			return err
		}

		return keys.SetMany(ctx, []store.KV{{Key: fmt.Sprintf("%s%020d", ApprovalPrefix, a.Serial), Value: b}})
	}

	// the last one first, if its publication had no answer
	if prev != nil && newest < last {
		if err := publish(*prev, *prevSigned); err != nil {
			return approval.Approval{}, err
		}
	}

	if c.empty() {
		if prev == nil {
			return approval.Approval{}, errors.New("nothing to approve")
		}

		return *prev, nil
	}

	next := approval.Approval{Version: approval.Version, FSID: o.St.FSID, Serial: last + 1}
	if prev != nil {
		next.Images, next.Disks = slices.Clone(prev.Images), slices.Clone(prev.Disks)
	}

	if err := o.change(ctx, &next, c); err != nil {
		return approval.Approval{}, err
	}

	if err := next.Check(o.St.FSID); err != nil {
		return approval.Approval{}, err
	}

	s, err := approval.Sign(o.St.Agent.ApprovalPriv, next)
	if err != nil {
		return approval.Approval{}, err
	}

	b, err := json.Marshal(s)
	if err != nil {
		return approval.Approval{}, err
	}

	// one that the mons would refuse is not recorded: it would block every later approve
	if limit := approvalLimit(keys); len(b) > limit {
		return approval.Approval{}, fmt.Errorf("the approval is %d bytes, more than one config-key entry takes (%d)", len(b), limit)
	}

	// recorded (synced) before it is published: never two contents under one serial
	o.St.Agent.Approval = string(b)
	if err := o.St.SaveLocked(); err != nil {
		return approval.Approval{}, err
	}

	return next, publish(next, s)
}

// approvalLimit is the largest approval one config-key entry takes.
func approvalLimit(b store.Backend) int {
	if l, ok := b.(interface{ EntryLimit() int }); ok && l.EntryLimit() > 0 {
		return l.EntryLimit()
	}

	return 64 << 10 // mon_config_key_max_entry_size by default
}

// approvals is the config-key namespace of the approvals, through exec in a
// Ceph container (the tests' store backend in tests).
func (o *Orch) approvals(ctx context.Context) (store.Backend, error) {
	if o.StoreBackend != nil {
		return o.StoreBackend, nil
	}

	adm, err := o.confirmedAdminHost()
	if err != nil {
		return nil, err
	}

	return o.configKeys(ctx, adm.Addr, ApprovalPrefix)
}

// change applies an ApprovalChange to the next approval.
func (o *Orch) change(ctx context.Context, a *approval.Approval, c ApprovalChange) error {
	for _, img := range c.AddImages {
		if !slices.Contains(a.Images, img) {
			a.Images = append(a.Images, img)
		}
	}

	a.Images = slices.DeleteFunc(a.Images, func(i string) bool { return slices.Contains(c.DropImages, i) })

	for _, add := range []struct {
		action string
		disks  []string
	}{{approval.Prepare, c.Prepare}, {approval.Zap, c.Zap}} {
		for _, d := range add.disks {
			host, serial, err := o.diskOf(ctx, d)
			if err != nil {
				return err
			}

			// a new entry, also for a disk approved before: each is used once
			a.Disks = append(a.Disks, approval.Disk{Host: host, Serial: serial, Action: add.action, Since: a.Serial})
		}
	}

	for _, d := range c.Drop {
		parts := strings.Split(d, ":")
		if len(parts) != 3 {
			return fmt.Errorf("--drop %q: want <host>:<serial>:<action>", d)
		}

		n := len(a.Disks)
		a.Disks = slices.DeleteFunc(a.Disks, func(e approval.Disk) bool {
			return e.Host == parts[0] && e.Serial == parts[1] && e.Action == parts[2]
		})

		if len(a.Disks) == n {
			return fmt.Errorf("--drop %q: no such disk entry", d)
		}
	}

	return nil
}

// diskOf resolves "<host>:<serial>" or "<host>:/dev/<disk>" to a host of the
// cluster and a disk serial (from Talos, for a device path).
func (o *Orch) diskOf(ctx context.Context, d string) (string, string, error) {
	host, disk, ok := strings.Cut(d, ":")
	if !ok || host == "" || disk == "" {
		return "", "", fmt.Errorf("%q: want <host>:<serial> or <host>:/dev/<disk>", d)
	}

	h, ok := o.St.Host(host)
	if !ok {
		return "", "", fmt.Errorf("no host %s", host)
	}

	if !strings.HasPrefix(disk, "/dev/") {
		return h.Name, disk, nil
	}

	serial, _, err := o.diskIdentity(ctx, h.Addr, disk)

	return h.Name, serial, err
}

// ShowApproval prints the last approval this workstation signed.
func (o *Orch) ShowApproval() error {
	a, _, err := o.lastApproval()
	if err != nil {
		return err
	}

	if a == nil {
		o.printf("no approval yet\n")

		return nil
	}

	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}

	o.printf("%s\n", b)

	return nil
}
