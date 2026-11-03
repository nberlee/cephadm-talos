package orch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
)

// The agent CA's revocation list as the module publishes it (revocation.py):
// chunks and a manifest outside mgr/ (plan 04, step 3).
const (
	CRLPrefix   = "cephadm-talos/crl/"
	CRLManifest = CRLPrefix + "manifest"
)

// crlManifest is the published list's manifest.
type crlManifest struct {
	Schema int      `json:"schema"`
	Number string   `json:"number"`
	Chunks []string `json:"chunks"`
	SHA256 string   `json:"sha256"`
	Size   int      `json:"size"`
}

// crlFile is the highest list the CLI saw, kept in the cluster directory for
// when the mons do not answer (suspension, recovery).
func (o *Orch) crlFile() crl.File { return crl.File(filepath.Join(o.St.Dir(), "crl.der")) }

// CRL is the CLI's installed list: the highest it saw, checked as an agent
// checks one. Its clients refuse an agent whose server certificate it names.
func (o *Orch) CRL() *crl.Holder {
	if o.crl == nil {
		ca := ""
		if o.St.Agent != nil {
			ca = o.St.Agent.CACert
		}

		o.crl = &crl.Holder{CA: ca, Persist: o.crlFile()}
		if ca != "" {
			if err := o.crl.Load(); err != nil {
				o.printf("warning: the saved revocation list: %v\n", err)
			}
		}
	}

	return o.crl
}

// RefreshCRL reads the published list through exec, as the state, and keeps
// it if it is newer than the one the CLI holds (plan 04, step 3).
func (o *Orch) RefreshCRL(ctx context.Context) error {
	if o.St.Agent == nil || o.St.Agent.CACert == "" || o.Talos.DryRun {
		return nil
	}

	keys := o.StoreBackend
	if keys == nil {
		adm, err := o.confirmedAdminHost()
		if err != nil {
			return err
		}

		snap, err := o.configKeys(ctx, adm.Addr, CRLPrefix)
		if err != nil {
			return err
		}

		keys = snap
	}

	der, err := publishedCRL(ctx, keys)
	if err != nil || der == nil {
		return err
	}

	if _, err := o.CRL().Install(der); err != nil && !errors.Is(err, crl.ErrNotNewer) {
		return fmt.Errorf("the published revocation list: %w", err)
	}

	return nil
}

// publishedCRL reads the published list from its manifest and chunks, nil
// before the first.
func publishedCRL(ctx context.Context, keys store.Backend) ([]byte, error) {
	raw, err := keys.Get(ctx, CRLManifest)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	var m crlManifest
	if err := json.Unmarshal(raw, &m); err != nil || m.Schema != 1 || len(m.Chunks) == 0 {
		return nil, errors.New("the revocation list's manifest is malformed")
	}

	var enc strings.Builder

	for _, c := range m.Chunks {
		if !strings.HasPrefix(c, CRLPrefix+m.Number+"/") {
			return nil, fmt.Errorf("chunk %q outside its list", c)
		}

		part, err := keys.Get(ctx, c)
		if err != nil {
			return nil, fmt.Errorf("chunk %s: %w", c, err)
		}

		enc.Write(part)
	}

	der, err := base64.StdEncoding.DecodeString(enc.String())
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != m.SHA256 || len(der) != m.Size {
		return nil, errors.New("the revocation list does not match its manifest")
	}

	return der, nil
}

// checkAgent refuses an agent's server certificate the CLI's list names. The
// operator certificate is never refused by the CLI itself.
func (o *Orch) checkAgent(c *x509.Certificate) error {
	return o.CRL().Check(c)
}

// pendingRevoke records the operator certificate a renewal replaces, so
// later commands revoke it until the module accepts it (plan 04, step 3).
// Before the handoff nothing is revoked: no list exists yet.
func (o *Orch) pendingRevoke(old string) {
	if !o.Managed() || old == "" {
		return
	}

	c, err := pki.Parse(old)
	if err != nil {
		return
	}

	o.St.Agent.OperatorRevoke = append(o.St.Agent.OperatorRevoke, state.PendingRevoke{Serial: c.SerialNumber.String(), NotAfter: c.NotAfter.UTC()})
}

// RevokePending runs `ceph orch talos revoke` for the operator certificate a
// renewal replaced, on every command until it succeeds, then clears it.
func (o *Orch) RevokePending(ctx context.Context) error {
	if o.St.Agent == nil || len(o.St.Agent.OperatorRevoke) == 0 || o.Talos.DryRun {
		return nil
	}

	revoke := o.RevokeCert
	if revoke == nil {
		revoke = o.revokeThroughExec
	}

	for len(o.St.Agent.OperatorRevoke) > 0 {
		p := o.St.Agent.OperatorRevoke[0]
		if err := revoke(ctx, p.Serial, p.NotAfter); err != nil {
			return fmt.Errorf("the previous operator certificate (serial %s) is not revoked yet: %w", p.Serial, err)
		}

		o.St.Agent.OperatorRevoke = o.St.Agent.OperatorRevoke[1:]
		if err := o.KeepLocal(); err != nil {
			return err
		}
	}

	return nil
}

func (o *Orch) revokeThroughExec(ctx context.Context, serial string, until time.Time) error {
	adm, err := o.confirmedAdminHost()
	if err != nil {
		return err
	}

	var out, errb bytes.Buffer

	rc, _, err := o.execAdmin(ctx, adm.Addr, []string{"ceph", "orch", "talos", "revoke", serial, "--until", until.UTC().Format(time.RFC3339)}, nil, &out, &errb)
	if err != nil {
		return err
	}

	if rc != 0 {
		return fmt.Errorf("rc %d: %s", rc, strings.TrimSpace(errb.String()))
	}

	return nil
}

// SetCRLPolicy changes the agents' revocation list policy (plan 04, step 3):
// an approval the operator signs with the `crl` field, sent to every agent
// with the operator certificate; documents the CLI renders afterwards agree.
func (o *Orch) SetCRLPolicy(ctx context.Context, policy string) error {
	if policy != approval.CRLClosed && policy != approval.CRLOpen {
		return fmt.Errorf("crl-policy %s|%s", approval.CRLClosed, approval.CRLOpen)
	}

	a, err := o.Approve(ctx, ApprovalChange{CRL: policy})
	if err != nil {
		return err
	}

	s, err := approval.Sign(o.St.Agent.ApprovalPriv, a)
	if err != nil {
		return err
	}

	// kept before it is sent: the documents the CLI renders carry it
	o.St.Agent.CRLFailClosed = policy == approval.CRLClosed
	if err := o.KeepLocal(); err != nil {
		return err
	}

	body, err := json.Marshal(s)
	if err != nil {
		return err
	}

	var failed []string

	for _, h := range o.St.AllHosts() {
		if err := o.postPolicy(ctx, h, body); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", h.Name, err))

			continue
		}

		o.printf("%s: revocation list policy %s\n", h.Name, policy)
	}

	if len(failed) > 0 {
		return fmt.Errorf("not set on every agent (run it again): %s", strings.Join(failed, "; "))
	}

	return nil
}

func (o *Orch) postPolicy(ctx context.Context, h state.Host, body []byte) error {
	cl, err := o.operatorClient(h)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, agentURL(h, "/v1/policy"), bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := cl.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		var b bytes.Buffer
		_, _ = b.ReadFrom(http.MaxBytesReader(nil, resp.Body, 1024))

		return fmt.Errorf("agent answered %d: %s", resp.StatusCode, strings.TrimSpace(b.String()))
	}

	return nil
}
