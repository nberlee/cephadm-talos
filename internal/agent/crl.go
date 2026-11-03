package agent

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/nberlee/cephadm-talos/internal/approval"
	"github.com/nberlee/cephadm-talos/internal/crl"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
)

// The agent's records of the revocation list (plan 04, step 3).
const (
	crlRecord       = "crl"
	crlPolicyRecord = "crl-policy"
)

// recordCRL keeps the installed list in the agent's records.
type recordCRL struct{ recs *records.Store }

func (r recordCRL) Read() ([]byte, error) {
	b, err := r.recs.Read(crlRecord)
	if errors.Is(err, records.ErrNotFound) {
		return nil, nil
	}

	return b, err
}

func (r recordCRL) Write(der []byte) error { return r.recs.Write(crlRecord, der) }

// NewCRLHolder is the agent's installed list, kept in its records.
func NewCRLHolder(caPEM string, recs *records.Store) *crl.Holder {
	h := &crl.Holder{CA: caPEM}
	if recs != nil {
		h.Persist = recordCRL{recs}
	}

	return h
}

// crlPolicy is the agent's record of its revocation list policy: Serial is
// the operator's approval that last set it, 0 when only a document did.
type crlPolicy struct {
	Closed bool  `json:"closed"`
	Serial int64 `json:"serial,omitempty"`
}

// CRLPolicy is the agent's own fail-closed setting (plan 04, step 3): from
// its document (EnvCRLFailClosed) and its records. A setting the operator
// signed wins over the document's both ways, also after a restart; without
// one, a document can only make the recorded setting stricter.
type CRLPolicy struct {
	Records     *records.Store
	ApprovalKey string
	FSID        string

	mu  sync.Mutex
	rec crlPolicy
}

// LoadCRLPolicy reads the record and takes the document's setting into it
// when that is stricter and the operator signed none.
func LoadCRLPolicy(recs *records.Store, docClosed bool, approvalKey, fsid string) (*CRLPolicy, error) {
	p := &CRLPolicy{Records: recs, ApprovalKey: approvalKey, FSID: fsid}

	b, err := recs.Read(crlPolicyRecord)

	switch {
	case errors.Is(err, records.ErrNotFound):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &p.rec); err != nil {
			return nil, errors.New("record crl-policy: damaged")
		}
	}

	if docClosed && !p.rec.Closed && p.rec.Serial == 0 {
		if err := p.write(crlPolicy{Closed: true}); err != nil {
			return nil, err
		}
	}

	return p, nil
}

func (p *CRLPolicy) write(r crlPolicy) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}

	if err := p.Records.Write(crlPolicyRecord, b); err != nil {
		return err
	}

	p.rec = r

	return nil
}

// Closed reports whether the agent fails closed on a stale list.
func (p *CRLPolicy) Closed() bool {
	if p == nil {
		return false
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.rec.Closed
}

// Set records a setting from an approval the operator signed, if its serial
// is above the one the record holds.
func (p *CRLPolicy) Set(s approval.Signed) (bool, error) {
	a, err := approval.Verify(p.ApprovalKey, s, p.FSID)
	if err != nil {
		return false, err
	}

	if a.CRL == "" {
		return false, errors.New("the approval sets no revocation list policy")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if a.Serial == p.rec.Serial && (a.CRL == approval.CRLClosed) == p.rec.Closed {
		return p.rec.Closed, nil // sent again
	}

	if a.Serial <= p.rec.Serial {
		return false, errors.New("the approval is not newer than the one that set the policy")
	}

	if err := p.write(crlPolicy{Closed: a.CRL == approval.CRLClosed, Serial: a.Serial}); err != nil {
		return false, err
	}

	return p.rec.Closed, nil
}

// failClosedOpen are the requests a fail-closed agent serves with a stale
// list: the list's delivery, the policy, the status (so the module sees why)
// and the operator's calls.
var failClosedOpen = map[string]bool{
	"POST /v1/crl": true, "POST /v1/policy": true, "GET /status": true,
	"POST /v1/suspend": true, "GET /v1/suspend": true, "POST /v1/readopt": true, "POST /v1/activate": true, "POST /v1/handoff": true,
}

// handedOver reports whether the agent owns its node (its ownership record exists).
func (a *Agent) handedOver() bool {
	if a.Records == nil {
		return false
	}

	_, err := a.Records.Read(ownershipRecord)

	return err == nil
}

// crlStale reports whether the agent's list is past its nextUpdate, or
// missing once it owns its node (the first was due at the handoff).
func (a *Agent) crlStale(now time.Time) bool {
	l := a.CRL.Current()
	if l == nil {
		return a.handedOver()
	}

	return l.Stale(now)
}

// guard checks every request (a kept-alive connection outlives its
// handshake): the peer certificate within its validity and not on the list;
// with the fail-closed policy and a stale list, only failClosedOpen.
func (a *Agent) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if err := a.CRL.Check(r.TLS.PeerCertificates[0]); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)

				return
			}
		}

		if a.CRLPolicy.Closed() && !failClosedOpen[r.Method+" "+r.URL.Path] && a.crlStale(a.now()) {
			http.Error(w, "the revocation list is past its nextUpdate and this agent fails closed: only a new list and the operator's calls are served", http.StatusServiceUnavailable)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// CRLDelivery is the body of POST /v1/crl.
type CRLDelivery struct {
	CRL string `json:"crl"` // base64 DER
}

// HandleCRL installs a newer list (plan 04, step 3): it authenticates itself
// by the agent CA's signature, so any certificate of the agent CA that is not
// itself revoked (guard) may deliver one, also while suspended.
func (a *Agent) HandleCRL(w http.ResponseWriter, r *http.Request) {
	var d CRLDelivery

	dec := json.NewDecoder(io.LimitReader(r.Body, 2*crl.MaxSize))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&d); err != nil {
		http.Error(w, "malformed delivery", http.StatusBadRequest)

		return
	}

	der, err := base64.StdEncoding.DecodeString(d.CRL)
	if err != nil {
		http.Error(w, "malformed delivery", http.StatusBadRequest)

		return
	}

	l, err := a.CRL.Install(der)

	switch {
	case errors.Is(err, crl.ErrNotNewer):
		w.WriteHeader(http.StatusOK)
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		a.logf("revocation list %s installed (%d serials, next update %s)", l.Number, l.Len(), l.NextUpdate.Format(time.RFC3339))
		w.WriteHeader(http.StatusOK)
	}
}

// HandlePolicy records a revocation list policy from an approval the
// operator signed, sent with the operator certificate (plan 04, step 3).
func (a *Agent) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "no client certificate", http.StatusForbidden)

		return
	}

	if id, err := pki.CertIdentity(r.TLS.PeerCertificates[0]); err != nil || id.Role != pki.RoleOperator {
		http.Error(w, "the policy is the operator's", http.StatusForbidden)

		return
	}

	var s approval.Signed

	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&s); err != nil {
		http.Error(w, "malformed approval", http.StatusBadRequest)

		return
	}

	closed, err := a.CRLPolicy.Set(s)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	a.logf("revocation list policy set by the operator: fail closed %v", closed)
	w.WriteHeader(http.StatusOK)
}
