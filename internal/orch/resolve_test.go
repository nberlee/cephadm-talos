package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/agent"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/wire"
)

// The operator's resolve of an uncertain job (plan 04, step 4) goes to the
// host's agent with the operator certificate; without an operation it lists.
func TestResolveCallsTheHostsAgent(t *testing.T) {
	o, h, _ := suspendSetup(t)
	ctx := context.Background()

	cfg, err := agent.TLSConfig([]byte(o.St.Agent.CACert), []byte(h.AgentCert), []byte(h.AgentKey))
	if err != nil {
		t.Fatal(err)
	}

	var got wire.Resolve

	job := wire.Operation{Version: wire.Version, Operation: "op-0000000000000001.prep", State: wire.OpUncertain, Job: &wire.JobRef{ID: "ab", Doc: "ceph-job-ab"}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || !strings.Contains(r.TLS.PeerCertificates[0].URIs[0].String(), "/operator/") {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode([]wire.Operation{job})

			return
		}

		_ = json.NewDecoder(r.Body).Decode(&got)
		done := job
		done.State, done.Result, done.Error = wire.OpFailed, &wire.JobResult{RC: -1}, "resolved by the operator"
		_ = json.NewEncoder(w).Encode(done)
	}))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	agentAddr = func(state.Host) string { return srv.Listener.Addr().String() }

	var out bytes.Buffer

	o.Out = &out

	if err := o.ListUnresolved(ctx, h.Name); err != nil || !strings.Contains(out.String(), "cephadm-talos resolve "+h.Name+" "+job.Operation) {
		t.Fatalf("list: %v %q", err, out.String())
	}

	if err := o.Resolve(ctx, h.Name, job.Operation); err != nil || !strings.Contains(out.String(), "failed (rc -1)") {
		t.Fatalf("resolve: %v %q", err, out.String())
	}

	if got != (wire.Resolve{Version: wire.Version, FSID: o.St.FSID, Host: h.Name, Operation: job.Operation}) {
		t.Fatalf("request %+v", got)
	}

	if err := o.Resolve(ctx, "nohost", job.Operation); err == nil {
		t.Fatal("an unknown host")
	}
}
