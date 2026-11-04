package orch

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// mismatchedKeys are the certificates in the state whose keys are not theirs.
func (o *Orch) mismatchedKeys() []string {
	var bad []string

	check := func(what, cert, key string) {
		if cert == "" {
			return
		}

		if _, err := tls.X509KeyPair([]byte(cert), []byte(key)); err != nil {
			bad = append(bad, what)
		}
	}

	if r := o.St.RGW; r != nil {
		check("rgw", r.Cert, r.Key)
	}

	for _, h := range o.St.Hosts {
		check("agent server "+h.Name, h.AgentCert, h.AgentKey)
		check("agent client "+h.Name, h.AgentClientCert, h.AgentClientKey)
		check("mgr server "+h.Name, h.MgrServerCert, h.MgrServerKey)
		check("mgr client "+h.Name, h.MgrClientCert, h.MgrClientKey)
	}

	return bad
}

// Handoff hands the cluster to its agents and their leader (plan 03, item
// 11): every node's agent takes ownership of its node's documents as they
// are, then the CLI publishes its state one last time, sealed. The leader
// takes its baseline only from a sealed state, so the CLI and the leader never
// both write it; from then on the CLI only reads. The handoff is recorded
// before the first node is handed over: a node whose agent does not answer
// stops it before the seal, the CLI then changes nothing but runs the handoff
// again.
func (o *Orch) Handoff(ctx context.Context) error {
	if o.sealed || o.incarnation != "" && o.incarnation != Incarnation {
		return errors.New("the cluster is already handed over")
	}

	o.handoff = true
	defer func() { o.handoff = false }()

	if o.St.Agent == nil {
		return errors.New("the cluster has no agents to hand over to")
	}

	// what the CLI still owes a node would not reach it anymore
	if len(o.St.ConfPending)+len(o.St.RGWPending)+len(o.St.Published.MgrRestart) > 0 {
		return fmt.Errorf("documents are still to be pushed (ceph.conf %v, rgw %v, mgr restart %v): run `cephadm-talos ps` first", o.St.ConfPending, o.St.RGWPending, o.St.Published.MgrRestart)
	}

	// from here the CLI changes nothing but this handoff, also when it stops
	// half-way: a node handed over must not see the CLI again
	if !o.St.HandingOver {
		// the leader renders no key that is not its certificate's, and only the
		// CLI can repair one (a crash between writing the secrets and publishing)
		if bad := o.mismatchedKeys(); len(bad) > 0 {
			return fmt.Errorf("keys that do not match their certificates: %v; `deploy rgw` again (with --cert and --key for your own certificate) first", bad)
		}

		o.St.HandingOver = true

		if err := o.save(); err != nil {
			return err
		}

		o.handingOver = true
	}

	for _, h := range o.St.Hosts {
		// no machine config keeps the bootstrap keyring (plan 03, step 7)
		if err := o.joinMons(ctx, h); err != nil {
			return fmt.Errorf("%s: %w (not sealed: run `cephadm-talos handoff` again)", h.Name, err)
		}

		if err := o.handOver(ctx, h); err != nil {
			return fmt.Errorf("%s: %w (not sealed: run `cephadm-talos handoff` again)", h.Name, err)
		}
	}

	// the operator's first approval: the cluster's images and the agents'
	// image (plan 04, step 2), no disks (plan 03, step 6c); without it the
	// agents admit no image from the leader
	if last, _, err := o.lastApproval(); err != nil {
		return err
	} else if last == nil {
		imgs := []string{o.St.Image}
		if o.St.RGW != nil && o.St.RGW.KeepalivedImage != "" {
			imgs = append(imgs, o.St.RGW.KeepalivedImage)
		}

		if o.St.Agent != nil && o.St.Agent.Image != "" {
			imgs = append(imgs, o.St.Agent.Image)
		}

		if _, err := o.Approve(ctx, ApprovalChange{AddImages: imgs}); err != nil {
			return fmt.Errorf("the first approval: %w (not sealed: run `cephadm-talos handoff` again)", err)
		}
	} else if _, err := o.Approve(ctx, ApprovalChange{}); err != nil { // published, if it was not yet
		return fmt.Errorf("the approval: %w (not sealed: run `cephadm-talos handoff` again)", err)
	}

	// the module warns from the public copy before the operator's certificate expires
	if err := o.publishOperatorCert(ctx); err != nil {
		return fmt.Errorf("the operator certificate's public copy: %w (not sealed: run `cephadm-talos handoff` again)", err)
	}

	o.St.Sealed = true

	if err := o.save(); err != nil {
		o.St.Sealed = false

		return err
	}

	o.sealed = true
	o.printf("the cluster is handed over: its leader writes the state from now on\n")

	return nil
}

// joinMons replaces a host's mon documents rendered for bootstrap (with
// client.admin, client.bootstrap-osd and the first mgr's key) by the joining
// template the leader renders (only the mon. key, the same deploy id): the mon
// restarts once on its existing store, and the handoff waits until it is back
// in the quorum. A mon with that rendering already is left alone.
func (o *Orch) joinMons(ctx context.Context, h state.Host) error {
	mons := o.St.DaemonsOf(state.TypeMon, h.Name)
	if len(mons) == 0 || o.Talos.DryRun {
		return nil
	}

	current, err := o.Talos.MachineConfig(ctx, h.Addr)
	if err != nil {
		return err
	}

	for _, d := range mons {
		doc, err := o.redeployDoc(d, h, o.St.Image)
		if err != nil {
			return err
		}

		name := o.St.DocName(d)

		// the apply only while the node has another rendering; then, every time
		// (also on a resumed handoff), the newest instance must run with the
		// joining template, not merely be running
		if docsChanged(current, []*spec.ContainerConfig{doc}) {
			o.printf("%s: mon.%s gets the joining template (no bootstrap keyring)\n", h.Name, d.ID)

			if err := o.apply(ctx, h.Addr, doc); err != nil {
				return err
			}
		}

		if err := o.waitJoined(ctx, h, name); err != nil {
			return fmt.Errorf("mon.%s: %w", d.ID, err)
		}

		if err := o.waitRunning(ctx, h.Addr, name, 10*time.Minute); err != nil {
			return err
		}

		adm, err := o.adminHost()
		if err != nil {
			return err
		}

		quorum := fmt.Sprintf(`for i in $(seq 100); do ceph quorum_status --format json | python3 -c 'import json,sys; sys.exit(0 if %q in json.load(sys.stdin)["quorum_names"] else 1)' && exit 0; sleep 3; done; echo "mon.%s is not in the quorum" >&2; exit 1`, d.ID, d.ID)
		if _, err := o.Job(ctx, adm.Addr, quorum, 10*time.Minute); err != nil {
			return err
		}
	}

	return nil
}

// waitJoined waits until a mon's newest instance runs with the joining
// template (MODE=join in its environment, which is compared, never printed).
func (o *Orch) waitJoined(ctx context.Context, h state.Host, name string) error {
	deadline := time.Now().Add(5 * time.Minute)

	for time.Now().Before(deadline) {
		if env, err := o.Talos.InstanceEnvironment(ctx, h.Addr, name); err == nil && slices.Contains(env, "MODE=join") {
			return nil
		}

		if err := sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}

	return errors.New("its instance still runs the bootstrap rendering")
}

// handOver asks one node's agent to take ownership, with the operator
// certificate; an agent that already owns its node is handed over.
func (o *Orch) handOver(ctx context.Context, h state.Host) error {
	if o.Talos.DryRun {
		o.printf("# hand %s to its agent\n", h.Name)

		return nil
	}

	cfg, err := agent.ClientTLSConfig([]byte(o.St.Agent.CACert), []byte(o.St.Agent.OperatorCert), []byte(o.St.Agent.OperatorKey))
	if err != nil {
		return err
	}

	// by its identity, not its address (plan 04, step 5)
	cfg = agent.WithPeer(cfg, func(c *x509.Certificate) error {
		if _, err := pki.Require(c, pki.Identity{FSID: o.St.FSID, Role: pki.RoleAgent, Name: h.Name}); err != nil {
			return err
		}

		// not an agent the revocation list names (plan 04, step 3)
		return o.checkAgent(c)
	})

	body, err := json.Marshal(wire.Handoff{Version: wire.Version, FSID: o.St.FSID, Host: h.Name, Revision: 1})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+net.JoinHostPort(h.Addr, strconv.Itoa(agent.Port))+"/v1/handoff", bytes.NewReader(body))
	if err != nil {
		return err
	}

	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}}

	resp, err := cl.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close() //nolint:errcheck

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	switch {
	case resp.StatusCode == http.StatusOK:
		var r wire.HandoffReply
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}

		o.printf("%s: its agent owns %d documents\n", h.Name, r.Owned)

		return nil
	case resp.StatusCode == http.StatusConflict && bytes.Contains(raw, []byte("already owned")):
		o.printf("%s: its agent owns it already\n", h.Name)

		return nil
	}

	return fmt.Errorf("agent answered %d: %s", resp.StatusCode, bytes.TrimSpace(raw))
}
