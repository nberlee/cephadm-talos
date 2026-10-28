package orch

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
)

// Agent certificate lifetimes and renewal, cephadm's defaults: root CA 10
// years, certificate_duration_days 3 years, certificate_renewal_threshold_days 30.
const (
	agentCAYears   = 10
	agentCertYears = 3
	agentRenewal   = 30 * 24 * time.Hour
)

// agentDocName is the ContainerConfig name of a host's agent.
func (o *Orch) agentDocName(h state.Host) string {
	return o.St.DocName(state.Daemon{Type: "agent", ID: h.Name})
}

// setupAgent creates the agent CA and the mgr's client certificate, and pins
// the agent image to the digest Talos pulls on node.
func (o *Orch) setupAgent(ctx context.Context, node, image string, refresh bool) error {
	a := &state.Agent{Image: image}

	if !o.Talos.DryRun {
		o.printf("pulling the agent image %s on %s\n", image, node)

		pinned, err := o.Talos.PullImage(ctx, node, image, refresh)
		if err != nil {
			return fmt.Errorf("agent image: %w", err)
		}

		a.Image = pinned
	}

	var err error

	if a.CACert, a.CAKey, err = pki.NewCA("cephadm-talos agent CA "+o.St.Short(), agentCAYears); err != nil {
		return err
	}

	o.St.Agent = a

	return o.issueMgrCert()
}

// issueMgrCert (re)issues the mgr's client certificate for the agents.
func (o *Orch) issueMgrCert() error {
	a := o.St.Agent

	c, k, err := pki.Issue(a.CACert, a.CAKey, pki.Leaf{CommonName: "mgr", Usage: x509.ExtKeyUsageClientAuth, Years: agentCertYears})
	if err != nil {
		return err
	}

	a.MgrCert, a.MgrKey = c, k

	return nil
}

// ensureAgentCert gives a host a server certificate for its address and name,
// or a new one if those changed.
func (o *Orch) ensureAgentCert(h *state.Host) error {
	if o.St.Agent == nil {
		return nil
	}

	if h.AgentCert != "" && certCovers(h.AgentCert, []string{h.Addr}, []string{h.Name}) {
		return nil
	}

	return o.issueAgentCert(h)
}

func (o *Orch) issueAgentCert(h *state.Host) error {
	a := o.St.Agent

	c, k, err := pki.Issue(a.CACert, a.CAKey, pki.Leaf{
		CommonName: "agent " + h.Name, IPs: []string{h.Addr}, Names: []string{h.Name},
		Usage: x509.ExtKeyUsageServerAuth, Years: agentCertYears,
	})
	if err != nil {
		return err
	}

	h.AgentCert, h.AgentKey = c, k

	return nil
}

// agentDocs is the agent of a host, if the cluster has agents.
func (o *Orch) agentDocs(h state.Host) []any {
	if o.St.Agent == nil || h.AgentCert == "" {
		return nil
	}

	return []any{daemons.Agent(o.agentDocName(h), o.St.Agent.Image, o.St.Agent.CACert, h.AgentCert, h.AgentKey)}
}

// expiresSoon reports whether a certificate is due for renewal.
func expiresSoon(certPEM string, now time.Time) bool {
	t, err := pki.NotAfter(certPEM)

	return err != nil || t.Sub(now) <= agentRenewal
}

// RenewAgentCerts reissues agent and mgr certificates with 30 days or less
// left and pushes them like ceph.conf, so a failed push is retried by the next
// command. Until plan 03, this only happens when the CLI runs.
func (o *Orch) RenewAgentCerts(ctx context.Context) error {
	if o.St.Agent == nil || o.Talos.DryRun {
		return nil
	}

	now := time.Now()

	var renewed []string

	for i := range o.St.Hosts {
		h := &o.St.Hosts[i]
		if h.AgentCert == "" || !expiresSoon(h.AgentCert, now) {
			continue
		}

		if err := o.issueAgentCert(h); err != nil {
			return err
		}

		renewed = append(renewed, h.Name)
	}

	if expiresSoon(o.St.Agent.MgrCert, now) {
		if err := o.issueMgrCert(); err != nil {
			return err
		}

		renewed = append(renewed, "mgr")
	}

	if len(renewed) == 0 {
		return nil
	}

	o.printf("renewing agent certificates: %v\n", renewed)

	// saved before any node is patched: an interrupted push is retried
	for _, h := range o.St.Hosts {
		if !slices.Contains(o.St.ConfPending, h.Name) {
			o.St.ConfPending = append(o.St.ConfPending, h.Name)
		}
	}

	if err := o.St.Save(); err != nil {
		return err
	}

	return o.pushConf(ctx)
}

// removeAgent removes a host's agent and waits until its process is gone.
func (o *Orch) removeAgent(ctx context.Context, h state.Host) error {
	if o.St.Agent == nil {
		return nil
	}

	name := o.agentDocName(h)

	if err := o.remove(ctx, h.Addr, name); err != nil {
		return err
	}

	return o.waitGone(ctx, h.Addr, name, 5*time.Minute)
}
