package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/distribution/reference"
	"gopkg.in/yaml.v3"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/talos"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// The agent's own documents (plan 04, step 2): a self-update grant carries
// only their variable fields, the image and the certificates with their keys.
// The agent renders its agent and records-init documents itself from those
// and the pinned inputs of its current document (the agent CA, the
// repositories, the approval key), which no grant changes, and applies them
// under the apply intent every apply uses, marked as a self-update: an
// undecided one blocks every later apply. Talos replaces the agent's instance
// once they are in the node's config, so the next instance often decides it,
// from the config. The documents stay out of the agent's ownership.

// selfRecord is the self-update the agent decided last: written before its
// intent is removed, so its operation record follows it after a stop.
const selfRecord = "self-update"

type selfUpdateRecord struct {
	Schema    int               `json:"schema"`
	Operation string            `json:"operation"`
	Revision  int64             `json:"revision"`
	Outcome   string            `json:"outcome"`
	Error     string            `json:"error,omitempty"`
	Sent      map[string]string `json:"sent"` // key -> hash of the applied document
}

// selfKeys are the keys of the agent's own documents.
func (n *Node) selfKeys() (agentKey, initKey string) {
	return "ContainerConfig/" + n.docName("agent"), "ContainerConfig/" + n.docName("records-init")
}

// ownDoc is the agent's current document in the node's config: its image and
// its environment.
type ownDoc struct {
	image string
	env   map[string]string
}

func (n *Node) ownDoc(typed map[string]typedDoc) (ownDoc, error) {
	key, _ := n.selfKeys()

	td, ok := typed[key]
	if !ok {
		return ownDoc{}, errors.New("the agent's own document is not in the node's config")
	}

	c, ok := td.doc.(*spec.ContainerConfig)
	if !ok {
		return ownDoc{}, errors.New("the agent's own document is not a ContainerConfig")
	}

	env, err := envMap(c.ContainerEnvironment)
	if err != nil {
		return ownDoc{}, fmt.Errorf("the agent's own document: %w", err)
	}

	return ownDoc{image: c.ContainerImage, env: env}, nil
}

// pemOf is a base64 PEM of the agent's environment.
func (d ownDoc) pemOf(name string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(d.env[name])
	if err != nil || len(b) == 0 {
		return "", fmt.Errorf("the agent's own document: %s is not a base64 PEM", name)
	}

	return string(b), nil
}

// selfImage checks an image the agent's documents get that is not the one
// they have: by digest, in the operator's approval, and from the repository
// of the agent's current image (the agent image is not one of the cluster's
// repositories).
func selfImage(ref, current string, appr *approval.Approval) error {
	if appr == nil || !appr.Image(ref) {
		return errors.New("image: not approved by the operator")
	}

	n, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return errors.New("image: not a reference")
	}

	if _, ok := n.(reference.Canonical); !ok {
		return errors.New("image: not pinned to a digest")
	}

	if _, ok := n.(reference.Tagged); ok {
		return errors.New("image: a tag next to the digest")
	}

	repo, err := daemons.ImageRepository(current)
	if err != nil || n.Name() != repo {
		return errors.New("image: not from the repository of the agent's image")
	}

	return nil
}

// selfCert checks one of the agent's certificates with its key: one PEM
// certificate the agent CA issued for this use to this host's agent, within
// its validity, and the key its own.
func (n *Node) selfCert(caPEM, certPEM, keyPEM string, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("not one PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("not a certificate")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errors.New("no agent CA")
	}

	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		return nil, errors.New("not issued by the agent CA for this use")
	}

	if _, err := pki.Require(cert, pki.Identity{FSID: n.FSID, Role: pki.RoleAgent, Name: n.Host}); err != nil {
		return nil, errors.New("not this host's agent's certificate")
	}

	if n.Policy != nil && n.Policy.CRL.Current().Names(cert) {
		return nil, errors.New("revoked")
	}

	if err := privateKey(keyPEM); err != nil {
		return nil, err
	}

	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return nil, errors.New("the key does not match its certificate")
	}

	return cert, nil
}

// selfDocs renders the agent's own documents for a self-update from its
// current document and the grant's variable fields, after checking them: an
// image other than the current one (selfImage), certificates of the agent CA
// for agent/<host> with their keys, the server certificate covering the
// host's name and one of its addresses.
func (n *Node) selfDocs(ctx context.Context, typed map[string]typedDoc, su wire.SelfUpdate, appr *approval.Approval) ([]Doc, error) {
	cur, err := n.ownDoc(typed)
	if err != nil {
		return nil, err
	}

	pems := map[string]string{}

	for _, name := range []string{daemons.EnvCA, daemons.EnvCert, daemons.EnvKey, daemons.EnvClientCert, daemons.EnvClientKey} {
		if pems[name], err = cur.pemOf(name); err != nil {
			return nil, err
		}
	}

	image := cur.image
	if su.Image != "" && su.Image != cur.image {
		if err := selfImage(su.Image, cur.image, appr); err != nil {
			return nil, err
		}

		image = su.Image
	}

	certs := []string{su.Cert, su.Key, su.ClientCert, su.ClientKey}
	if given := len(strings.Join(certs, "")) > 0; given {
		for _, c := range certs {
			if c == "" {
				return nil, errors.New("certificates: the server and client certificates and their keys come together")
			}
		}

		server, err := n.selfCert(pems[daemons.EnvCA], su.Cert, su.Key, x509.ExtKeyUsageServerAuth)
		if err != nil {
			return nil, fmt.Errorf("server certificate: %w", err)
		}

		if _, err := n.selfCert(pems[daemons.EnvCA], su.ClientCert, su.ClientKey, x509.ExtKeyUsageClientAuth); err != nil {
			return nil, fmt.Errorf("client certificate: %w", err)
		}

		addrs, err := n.Talos.Addresses(ctx, "")
		if err != nil {
			return nil, err
		}

		covered := false
		for _, a := range addrs {
			covered = covered || server.VerifyHostname(a) == nil
		}

		if server.VerifyHostname(n.Host) != nil || !covered {
			return nil, errors.New("server certificate: not for this host's name and address")
		}

		pems[daemons.EnvCert], pems[daemons.EnvKey], pems[daemons.EnvClientCert], pems[daemons.EnvClientKey] = su.Cert, su.Key, su.ClientCert, su.ClientKey
	}

	init := n.docName("records-init")
	// the pinned inputs as the current document has them: repositories, approval key, revocation list policy
	agent := daemons.Agent(n.docName("agent"), init, image, strings.Fields(cur.env[daemons.EnvImageRepos]), cur.env[daemons.EnvApprovalKey], cur.env[daemons.EnvCRLFailClosed] == "1",
		pems[daemons.EnvCA], pems[daemons.EnvCert], pems[daemons.EnvKey], pems[daemons.EnvClientCert], pems[daemons.EnvClientKey])

	var docs []Doc

	for _, c := range []*spec.ContainerConfig{daemons.RecordsInit(init, image), agent} {
		y, err := spec.Render(c)
		if err != nil {
			return nil, err
		}

		docs = append(docs, Doc{Kind: "ContainerConfig", Name: c.MetaName, YAML: y})
	}

	return docs, nil
}

// SelfUpdateBefore applies the agent's own documents for a confirmed
// self-update grant, rendered by selfDocs, under the same checks as an apply:
// handed over, no undecided apply, the revision above the ownership and the
// fence, no drift, the confirmation still counting. The intent, marked as a
// self-update, is recorded before the patch and the revision fenced; after
// it the agent may be replaced at any moment, and its next instance decides
// the intent (Reconcile). started reports whether the intent was recorded,
// after which an error leaves the outcome uncertain.
func (n *Node) SelfUpdateBefore(ctx context.Context, until time.Time, revision int64, operation string, su wire.SelfUpdate) (started bool, err error) {
	if err := n.lock(ctx); err != nil {
		return false, err
	}
	defer n.unlock()

	if err := n.Records.Check(); err != nil {
		return false, err
	}

	var intent applyIntent

	if pending, err := n.readJSON(applyRecord, &intent); err != nil || pending {
		if err == nil {
			err = fmt.Errorf("the apply of revision %d has an uncertain outcome", intent.Revision)
		}

		return false, err
	}

	own, found, err := n.ownership()
	if err != nil {
		return false, err
	}

	if !found {
		return false, errors.New("the node has not been handed over")
	}

	floor, err := n.fence()
	if err != nil {
		return false, err
	}

	if revision <= max(own.Revision, floor) {
		return false, fmt.Errorf("revision %d is not newer than %d", revision, max(own.Revision, floor))
	}

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return false, err
	}

	typed, err := typedDocs([]byte(cfg))
	if err != nil {
		return false, errors.New("machine config: does not decode") // the message may quote a value
	}

	cur := make(map[string]string, len(typed))
	for k, d := range typed {
		cur[k] = d.hash
	}

	// Talos patches the whole config: nobody else's change is overwritten
	if d := n.drift(own, cur); len(d) > 0 {
		return false, fmt.Errorf("%w: %s", ErrDrift, strings.Join(d, ", "))
	}

	appr, err := n.approval()
	if err != nil {
		return false, err
	}

	docs, err := n.selfDocs(ctx, typed, su, appr)
	if err != nil {
		return false, err
	}

	before, sent := map[string]string{}, map[string]string{}

	var dels, adds bytes.Buffer

	for _, d := range docs {
		td, err := checkDoc(d)
		if err != nil {
			return false, fmt.Errorf("%s: %w", d.Key(), err)
		}

		k := d.Key()
		if cur[k] == td.hash {
			continue // unchanged: not sent, so Talos leaves its container alone
		}

		before[k], sent[k] = cur[k], td.hash

		del, err := yaml.Marshal(map[string]string{"apiVersion": "v1alpha1", "kind": d.Kind, "name": d.Name, "$patch": "delete"})
		if err != nil {
			return false, err
		}

		dels.WriteString("---\n")
		dels.Write(del)
		adds.WriteString("---\n")
		adds.Write(td.yaml)
	}

	// the mutation boundary: the confirmation must still count
	if !until.IsZero() && !time.Now().Before(until) {
		return false, errors.New("the confirmation expired before the self-update")
	}

	boot, err := n.Talos.BootID(ctx, "")
	if err != nil {
		return false, err
	}

	intent = applyIntent{Schema: ownershipSchema, Revision: revision, Before: before, Sent: sent, BootID: boot, At: time.Now().UTC(), Self: true, Operation: operation}

	// the revision is fenced like an applied one: the grant cannot run again
	// once its operation record is pruned
	if floor < revision {
		if err := n.writeJSON(fenceRecord, fence{Schema: ownershipSchema, Revision: revision}); err != nil {
			return false, err
		}
	}

	// the documents are what they would become: decided without a patch
	if len(sent) == 0 {
		return false, n.decideSelf(intent, wire.OpCompleted, "")
	}

	if err := n.writeJSON(applyRecord, intent); err != nil {
		return false, err
	}

	started = true

	pctx := ctx
	if !until.IsZero() {
		pctx = talos.WithApplyBefore(ctx, until)
	}

	if err := n.Talos.Patch(pctx, "", dels.Bytes(), adds.Bytes()); errors.Is(err, talos.ErrApplyDeadline) {
		// nothing was sent: the intent goes, the outcome is certain
		if rerr := n.Records.Remove(applyRecord); rerr != nil {
			return started, rerr
		}

		return false, err
	} else if err != nil {
		// the intent stays: whether Talos took the config is not known
		return started, fmt.Errorf("self-update %s: %w", operation, err)
	}

	// Talos replaces this instance once the documents are in the config: from
	// here on the next instance may be the one that decides the intent
	if cfg, err = n.Talos.MachineConfig(ctx, ""); err != nil {
		return started, err
	}

	now, err := parseDocs(cfg)
	if err != nil {
		return started, err
	}

	for k, h := range sent {
		if now[k] != h {
			return started, fmt.Errorf("self-update %s: the node does not hold %s afterwards", operation, k)
		}
	}

	return started, n.decideSelf(intent, wire.OpCompleted, "")
}

// reconcileSelf decides a self-update's intent from the agent's own documents
// in the node's config, as an apply's: all as sent, completed; all as before
// once the apply settled, refused; anything else stays uncertain.
func (n *Node) reconcileSelf(intent applyIntent, cur map[string]string, settled bool) (string, error) {
	holds := func(want map[string]string) bool {
		for k, h := range want {
			if cur[k] != h {
				return false
			}
		}

		return true
	}

	switch {
	case holds(intent.Sent):
		return wire.OpCompleted, n.decideSelf(intent, wire.OpCompleted, "")
	case holds(intent.Before) && settled:
		return wire.OpRefused, n.decideSelf(intent, wire.OpRefused, "the self-update did not reach the node's config")
	}

	return "uncertain", nil
}

// decideSelf records a self-update's outcome, then removes its intent.
func (n *Node) decideSelf(intent applyIntent, outcome, msg string) error {
	if err := n.writeJSON(selfRecord, selfUpdateRecord{Schema: ownershipSchema, Operation: intent.Operation, Revision: intent.Revision, Outcome: outcome, Error: msg, Sent: intent.Sent}); err != nil {
		return err
	}

	return n.Records.Remove(applyRecord)
}

// selfDecided is the self-update the agent decided last, if any.
func (n *Node) selfDecided() (selfUpdateRecord, bool, error) {
	var rec selfUpdateRecord

	found, err := n.readJSON(selfRecord, &rec)
	if err != nil || !found {
		return rec, false, err
	}

	switch rec.Outcome {
	case wire.OpCompleted, wire.OpRefused, wire.OpFailed:
	default:
		return rec, false, fmt.Errorf("record %s: damaged", selfRecord)
	}

	if rec.Schema != ownershipSchema || rec.Operation == "" {
		return rec, false, fmt.Errorf("record %s: damaged", selfRecord)
	}

	return rec, true, nil
}

// CheckPull checks an image a pull grant names, as a self-update checks a new
// image (selfImage): by digest, approved, from the agent image's repository.
func (n *Node) CheckPull(ctx context.Context, ref string) error {
	if err := n.lock(ctx); err != nil {
		return err
	}
	defer n.unlock()

	cfg, err := n.Talos.MachineConfig(ctx, "")
	if err != nil {
		return err
	}

	typed, err := typedDocs([]byte(cfg))
	if err != nil {
		return errors.New("machine config: does not decode")
	}

	cur, err := n.ownDoc(typed)
	if err != nil {
		return err
	}

	appr, err := n.approval()
	if err != nil {
		return err
	}

	return selfImage(ref, cur.image, appr)
}

// selfUpdate runs a confirmed self-update grant: the operation is recorded as
// started before the documents are rendered and checked, so a stop before its
// intent leaves a record reconcile refuses; its outcome follows the intent.
func (g *Granter) selfUpdate(ctx context.Context, gr wire.Grant, op wire.Operation, until time.Time) (wire.Operation, error) {
	op.State, op.Self = wire.OpStarted, true
	if err := g.writeOp(op); err != nil {
		return wire.Operation{}, err
	}

	started, err := g.Node.SelfUpdateBefore(ctx, until, gr.Revision, gr.Operation, *gr.SelfUpdate)

	switch {
	case err == nil:
		op.State, op.Error = wire.OpCompleted, ""
	case !started:
		op.State, op.Error = wire.OpRefused, err.Error()
	default:
		op.State, op.Error = wire.OpUncertain, err.Error()
	}

	if err := g.writeOp(op); err != nil {
		return op, err
	}

	return op, g.prune()
}

// pull runs a confirmed pull grant: the image checked (CheckPull), then
// pulled through the agent's own socket within the grant. A pull changes no
// document: one that failed, or that a stop interrupted, is refused and may
// be granted again.
func (g *Granter) pull(ctx context.Context, gr wire.Grant, op wire.Operation, until time.Time) (wire.Operation, error) {
	refuse := func(err error) (wire.Operation, error) {
		op.State, op.Error = wire.OpRefused, err.Error()
		if err := g.writeOp(op); err != nil {
			return op, err
		}

		return op, g.prune()
	}

	if err := g.Node.CheckPull(ctx, gr.Pull); err != nil {
		return refuse(err)
	}

	if !g.now().Before(until) {
		return refuse(errors.New("the confirmation expired before the pull"))
	}

	op.State, op.Pull = wire.OpStarted, true
	if err := g.writeOp(op); err != nil {
		return wire.Operation{}, err
	}

	if _, err := g.Node.Talos.PullImage(ctx, "", gr.Pull, false); err != nil {
		return refuse(fmt.Errorf("pull: %w", err))
	}

	op.State, op.Error = wire.OpCompleted, ""
	if err := g.writeOp(op); err != nil {
		return op, err
	}

	return op, g.prune()
}

// SettleSelfUpdate settles an interrupted self-update's intent for `agent
// restore` (plan 04, step 2), run by the records job once the restored
// documents are in the node's config: the self-update's operation is
// recorded as failed, superseded by the restore, its revision fenced and its
// intent removed, so the re-adoption is not blocked. Only an intent marked as
// a self-update is settled, never a cluster apply's. It returns the operation
// it settled, "" for none.
func SettleSelfUpdate(recs *records.Store) (string, error) {
	g := &Granter{Records: recs}
	n := &Node{Records: recs}

	var intent applyIntent

	pending, err := n.readJSON(applyRecord, &intent)
	if err != nil || !pending || !intent.Self {
		return "", err
	}

	// a retirement's intent is decided completed once its documents are gone
	// (RetireRecords), never failed by a restore (plan 04, step 6)
	if intent.Retire {
		return "", fmt.Errorf("the apply intent of operation %s is a retirement: a retiring agent is not restored", intent.Operation)
	}

	const superseded = "superseded by agent restore"

	op, found, err := g.readOp(intent.Operation)
	if err != nil {
		return "", err
	}

	if found && (op.State == wire.OpStarted || op.State == wire.OpUncertain || op.State == wire.OpReserved) {
		op.State, op.Error = wire.OpFailed, superseded
		if err := g.writeOp(op); err != nil {
			return "", err
		}
	}

	f, err := n.fence()
	if err != nil {
		return "", err
	}

	if f < intent.Revision {
		if err := n.writeJSON(fenceRecord, fence{Schema: ownershipSchema, Revision: intent.Revision}); err != nil {
			return "", err
		}
	}

	return intent.Operation, n.decideSelf(intent, wire.OpFailed, superseded)
}
