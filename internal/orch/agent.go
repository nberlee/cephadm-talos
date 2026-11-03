package orch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
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

// setupAgent creates the agent CA and the operator's client certificate, and
// pins the agent image to the digest Talos pulls on node.
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

	// the operator's approvals: the private key never leaves the workstation
	if a.ApprovalPriv, a.ApprovalKey, err = approval.NewKey(); err != nil {
		return err
	}

	o.St.Agent = a

	return o.issueOperatorCert()
}

// identity is a role's identity in this cluster (plan 03, item 3).
func (o *Orch) identity(role pki.Role, name string) pki.Identity {
	return pki.Identity{FSID: o.St.FSID, Role: role, Name: name}
}

// issue signs a certificate for one identity and usage with the agent CA.
func (o *Orch) issue(id pki.Identity, usage x509.ExtKeyUsage, ips, names []string) (string, string, error) {
	a := o.St.Agent

	return pki.Issue(a.CACert, a.CAKey, pki.Leaf{
		CommonName: string(id.Role) + " " + id.Name, IPs: ips, Names: names,
		Usage: usage, Years: agentCertYears, Identity: &id,
	})
}

// issueOperatorCert (re)issues the CLI's client certificate.
func (o *Orch) issueOperatorCert() error {
	c, k, err := o.issue(o.identity(pki.RoleOperator, "admin"), x509.ExtKeyUsageClientAuth, nil, nil)
	if err != nil {
		return err
	}

	o.St.Agent.OperatorCert, o.St.Agent.OperatorKey = c, k

	return nil
}

// certValid reports whether a certificate carries the identity and, for a
// server certificate, exactly these addresses and names.
func certValid(certPEM, keyPEM string, id pki.Identity, server bool, ips, names []string) bool {
	// a key that is not the certificate's, e.g. after a save that wrote the
	// secrets but did not publish, gets a new certificate
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return false
	}

	c, err := pki.Parse(certPEM)
	if err != nil {
		return false
	}

	if _, err := pki.Require(c, id); err != nil {
		return false
	}

	return !server || certCovers(certPEM, ips, names)
}

// ensureAgentCert gives a host its agent's server certificate (for its address
// and name) and client certificate, or new ones if they no longer match.
func (o *Orch) ensureAgentCert(h *state.Host) error {
	if o.St.Agent == nil {
		return nil
	}

	id := o.identity(pki.RoleAgent, h.Name)
	ips, names := []string{h.Addr}, []string{h.Name}

	if !certValid(h.AgentCert, h.AgentKey, id, true, ips, names) {
		if err := o.issueAgentServerCert(h); err != nil {
			return err
		}
	}

	if !certValid(h.AgentClientCert, h.AgentClientKey, id, false, nil, nil) {
		return o.issueAgentClientCert(h)
	}

	return nil
}

func (o *Orch) issueAgentServerCert(h *state.Host) (err error) {
	h.AgentCert, h.AgentKey, err = o.issue(o.identity(pki.RoleAgent, h.Name), x509.ExtKeyUsageServerAuth, []string{h.Addr}, []string{h.Name})

	return err
}

func (o *Orch) issueAgentClientCert(h *state.Host) (err error) {
	h.AgentClientCert, h.AgentClientKey, err = o.issue(o.identity(pki.RoleAgent, h.Name), x509.ExtKeyUsageClientAuth, nil, nil)

	return err
}

// ensureMgrCerts gives a host its mgr's server and client certificates, or new
// ones if they no longer match; without a mgr they are dropped.
func (o *Orch) ensureMgrCerts(h *state.Host, withMgr bool) error {
	if o.St.Agent == nil || !withMgr {
		h.MgrServerCert, h.MgrServerKey, h.MgrClientCert, h.MgrClientKey = "", "", "", ""

		return nil
	}

	id := o.identity(pki.RoleMgr, h.Name)

	if !certValid(h.MgrServerCert, h.MgrServerKey, id, true, []string{h.Addr}, []string{h.Name}) {
		if err := o.issueMgrServerCert(h); err != nil {
			return err
		}
	}

	if !certValid(h.MgrClientCert, h.MgrClientKey, id, false, nil, nil) {
		return o.issueMgrClientCert(h)
	}

	return nil
}

func (o *Orch) issueMgrServerCert(h *state.Host) (err error) {
	h.MgrServerCert, h.MgrServerKey, err = o.issue(o.identity(pki.RoleMgr, h.Name), x509.ExtKeyUsageServerAuth, []string{h.Addr}, []string{h.Name})

	return err
}

func (o *Orch) issueMgrClientCert(h *state.Host) (err error) {
	h.MgrClientCert, h.MgrClientKey, err = o.issue(o.identity(pki.RoleMgr, h.Name), x509.ExtKeyUsageClientAuth, nil, nil)

	return err
}

// recordsInitDocName is the ContainerConfig name of a host's records-init.
func (o *Orch) recordsInitDocName(h state.Host) string {
	return o.St.DocName(state.Daemon{Type: "records-init", ID: h.Name})
}

// agentDocs are the agent of a host and its records-init, if the cluster has agents.
func (o *Orch) agentDocs(h state.Host) []any {
	if o.St.Agent == nil || h.AgentCert == "" {
		return nil
	}

	init := o.recordsInitDocName(h)

	return []any{
		spec.RecordsVolume(),
		daemons.RecordsInit(init, o.St.Agent.Image),
		daemons.Agent(o.agentDocName(h), init, o.St.Agent.Image, o.imageRepos(), o.St.Agent.ApprovalKey, o.St.Agent.CACert, h.AgentCert, h.AgentKey, h.AgentClientCert, h.AgentClientKey),
	}
}

// imageRepos are the repositories of the cluster's images, which the agents'
// admission policy allows (plan 03, item 13).
func (o *Orch) imageRepos() []string {
	// keepalived's always: an ingress may come after the handoff (plan 03, step
	// 6e), and the operator's approval admits its digests one by one
	refs := []string{o.St.Image, DefaultKeepalivedImage}
	if o.St.RGW != nil {
		refs = append(refs, o.St.RGW.KeepalivedImage)
	}

	var repos []string

	for _, r := range refs {
		if repo, err := daemons.ImageRepository(r); err == nil && !slices.Contains(repos, repo) {
			repos = append(repos, repo)
		}
	}

	return repos
}

// operatorRenewal is how long before its expiry the CLI renews its operator
// certificate; the module warns from then on (plan 04, step 1).
const operatorRenewal = 60 * 24 * time.Hour

// OperatorCertKey is the public copy of the CLI's operator certificate in
// config-key, from which the module warns before it expires. It is outside
// mgr/, where the bridge cannot write.
const OperatorCertKey = "cephadm-talos/operator.crt"

// operatorDue reports whether the CLI's operator certificate is renewed: not
// this cluster's operator's with its key, or within operatorRenewal of its end.
func (o *Orch) operatorDue(now time.Time) bool {
	a := o.St.Agent
	if !certValid(a.OperatorCert, a.OperatorKey, o.identity(pki.RoleOperator, "admin"), false, nil, nil) {
		return true
	}

	t, err := pki.NotAfter(a.OperatorCert)

	return err != nil || t.Sub(now) <= operatorRenewal
}

// operatorExpired reports whether the CLI's operator certificate has expired,
// from its notAfter: an agent's TLS error says nothing about it.
func (o *Orch) operatorExpired(now time.Time) bool {
	t, err := pki.NotAfter(o.St.Agent.OperatorCert)

	return err != nil || !now.Before(t)
}

// EnsureOperatorCert renews the CLI's operator certificate when it is due, on
// any command, also after the handoff (plan 04, step 1): the agent CA's key
// from the secrets through exec, as enrollment reads it, the certificate
// issued and saved in local.json. Then the public copy in config-key is made
// equal to the CLI's certificate, renewed or not, so a copy a failed write
// left behind is corrected by the next command.
func (o *Orch) EnsureOperatorCert(ctx context.Context) error {
	if o.St.Agent == nil || o.Talos.DryRun {
		return nil
	}

	if o.operatorDue(time.Now()) {
		if o.St.Agent.CAKey == "" {
			adm, err := o.confirmedAdminHost()
			if err != nil {
				return err
			}

			if err := o.openSecrets(ctx, adm.Addr); err != nil {
				return err
			}

			v, err := o.secrets.Get(ctx, store.SecretPrefix+state.SecretAgentCA)
			if err != nil || len(v) == 0 {
				return fmt.Errorf("the agent CA's key: %w", errors.Join(err, errors.New("not readable")))
			}

			o.St.Agent.CAKey = string(v)
		}

		if err := o.issueOperatorCert(); err != nil {
			return err
		}

		o.printf("renewed the operator certificate\n")

		if err := o.KeepLocal(); err != nil {
			return err
		}
	}

	return o.publishOperatorCert(ctx)
}

// publishOperatorCert makes the public copy of the operator certificate in
// config-key equal to the CLI's: written only when it differs.
func (o *Orch) publishOperatorCert(ctx context.Context) error {
	keys := o.StoreBackend

	if keys == nil {
		adm, err := o.confirmedAdminHost()
		if err != nil {
			return err
		}

		snap, err := o.configKeys(ctx, adm.Addr, OperatorCertKey)
		if err != nil {
			return err
		}

		keys = snap
	}

	cur, err := keys.Get(ctx, OperatorCertKey)
	if err == nil && string(cur) == o.St.Agent.OperatorCert {
		return nil
	}

	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}

	return keys.SetMany(ctx, []store.KV{{Key: OperatorCertKey, Value: []byte(o.St.Agent.OperatorCert)}})
}

// expiresSoon reports whether a certificate is due for renewal.
func expiresSoon(certPEM string, now time.Time) bool {
	t, err := pki.NotAfter(certPEM)

	return err != nil || t.Sub(now) <= agentRenewal
}

// RenewAgentCerts reissues agent and mgr certificates with 30 days or less
// left, and the operator's when it is due (operatorDue), and pushes them like
// ceph.conf, so a failed push is retried by the next command. Until plan 03,
// this only happens when the CLI runs.
func (o *Orch) RenewAgentCerts(ctx context.Context) error {
	if o.St.Agent == nil || o.Talos.DryRun {
		return nil
	}

	now := time.Now()

	var renewed []string

	for i := range o.St.Hosts {
		h := &o.St.Hosts[i]
		before := *h

		// certificates a host lacks or that no longer match it (identity, address,
		// name, a mgr placed or removed) are issued anew
		if err := o.ensureAgentCert(h); err != nil {
			return err
		}

		if err := o.ensureMgrCerts(h, o.hasMgr(*h)); err != nil {
			return err
		}

		if !reflect.DeepEqual(*h, before) {
			renewed = append(renewed, "missing or changed "+h.Name)
		}

		for _, c := range []struct {
			cert  string
			issue func(*state.Host) error
			what  string
		}{
			{h.AgentCert, o.issueAgentServerCert, "agent server"},
			{h.AgentClientCert, o.issueAgentClientCert, "agent client"},
			{h.MgrServerCert, o.issueMgrServerCert, "mgr server"},
			{h.MgrClientCert, o.issueMgrClientCert, "mgr client"},
		} {
			if c.cert == "" || !expiresSoon(c.cert, now) {
				continue
			}

			if err := c.issue(h); err != nil {
				return err
			}

			renewed = append(renewed, c.what+" "+h.Name)
		}
	}

	if o.operatorDue(now) {
		if err := o.issueOperatorCert(); err != nil {
			return err
		}

		renewed = append(renewed, "operator")
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

	if err := o.save(); err != nil {
		return err
	}

	return o.pushConf(ctx)
}

// removeAgent removes a host's agent and waits until its process is gone.
func (o *Orch) removeAgent(ctx context.Context, h state.Host) error {
	if o.St.Agent == nil {
		return nil
	}

	// the agent first: it depends on records-init
	for _, name := range []string{o.agentDocName(h), o.recordsInitDocName(h)} {
		if err := o.remove(ctx, h.Addr, name); err != nil {
			return err
		}

		if err := o.waitGone(ctx, h.Addr, name, 5*time.Minute); err != nil {
			return err
		}
	}

	return nil
}
