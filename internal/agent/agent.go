// Package agent is the per-node cephadm-talos agent: it reads the node's Talos
// container resources over the local machined socket and serves them to the
// talos mgr module over mutual TLS. It never writes to Talos and has no Ceph
// identity (docs/plans/02-agents-and-read-path.md).
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/role"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

// Port is the agent's HTTPS port (cephadm's agent port).
const Port = 4721

// Schema is the version of the status record.
const Schema = 1

// MaxRecord is the largest status record the agent serves.
const MaxRecord = 32 << 10

const (
	refreshEvery   = 30 * time.Second
	refreshTimeout = 20 * time.Second
	// minRefresh coalesces refreshes requested by the mgr (?refresh=1)
	minRefresh = 5 * time.Second
)

// Container is what the agent observed of one ContainerConfig container.
type Container struct {
	State       string `json:"state,omitempty"` // Talos state; empty if there is no ContainerStatus
	ImageDigest string `json:"image_digest,omitempty"`
	Restarts    uint64 `json:"restarts"`
	Instances   bool   `json:"instances"` // an instance (process) is left
}

// Record is the status the agent serves.
type Record struct {
	Schema       int                  `json:"schema"`
	Hostname     string               `json:"hostname"`
	TalosVersion string               `json:"talos_version"`
	ObservedAt   time.Time            `json:"observed_at"` // completion of the last successful refresh
	Containers   map[string]Container `json:"containers"`
}

// Agent keeps the last complete observation of its node.
type Agent struct {
	Talos *talos.Client
	Now   func() time.Time

	mu       sync.Mutex // guards inflight and lastDone
	inflight chan struct{}
	lastDone time.Time

	recMu sync.RWMutex
	rec   *Record

	// Life bounds every refresh (nil: never cancelled); Wait joins them
	Life context.Context
	jobs sync.WaitGroup

	logPrint func(format string, args ...any)
	// refresh replaces observe in tests
	refresh func(context.Context) error
}

// Wait returns when no refresh is running anymore; cancel Life first.
func (a *Agent) Wait() { a.jobs.Wait() }

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}

	return time.Now()
}

func (a *Agent) logf(format string, args ...any) {
	if a.logPrint != nil {
		a.logPrint(format, args...)

		return
	}

	log.Printf(format, args...)
}

// Current returns the last complete record, or nil before the first one.
func (a *Agent) Current() *Record {
	a.recMu.RLock()
	defer a.recMu.RUnlock()

	return a.rec
}

// Refresh runs a refresh, or joins the one in flight, and waits for it or for
// ctx. With coalesce set, a refresh that completed less than 5 seconds ago is
// good enough and nothing new is started.
func (a *Agent) Refresh(ctx context.Context, coalesce bool) error {
	a.mu.Lock()

	done := a.inflight
	if done == nil {
		if coalesce && a.now().Sub(a.lastDone) < minRefresh {
			a.mu.Unlock()

			return nil
		}

		done = make(chan struct{})
		a.inflight = done

		a.jobs.Go(func() {
			fn := a.refresh
			if fn == nil {
				fn = a.observe
			}

			life := a.Life
			if life == nil {
				life = context.Background()
			}

			// the refresh is not tied to one caller: others may be waiting for it
			rctx, cancel := context.WithTimeout(life, refreshTimeout)
			defer cancel()

			if err := fn(rctx); err != nil {
				a.logf("refresh: %v", err)
			}

			a.mu.Lock()
			a.inflight, a.lastDone = nil, a.now()
			a.mu.Unlock()

			close(done)
		})
	}

	a.mu.Unlock()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// observe lists the node's container resources and replaces the record only
// when every list succeeded within the deadline; a failed refresh keeps the
// previous record and its observed_at.
func (a *Agent) observe(ctx context.Context) error {

	hostname, err := a.Talos.Hostname(ctx, "")
	if err != nil {
		return err
	}

	version, err := a.Talos.Version(ctx, "")
	if err != nil {
		return err
	}

	statuses, err := a.Talos.ContainerStatuses(ctx, "")
	if err != nil {
		return err
	}

	images, err := a.Talos.ImageStatuses(ctx, "")
	if err != nil {
		return err
	}

	instances, err := a.Talos.InstanceContainers(ctx, "")
	if err != nil {
		return err
	}

	rec := &Record{Schema: Schema, Hostname: hostname, TalosVersion: version, Containers: map[string]Container{}}

	for name, s := range statuses {
		c := rec.Containers[name]
		c.State, c.ImageDigest, c.Restarts = s.State.String(), s.Image, s.RestartCount
		rec.Containers[name] = c
	}

	for name, img := range images {
		c := rec.Containers[name]
		if c.ImageDigest == "" {
			c.ImageDigest = img.Digest
		}

		rec.Containers[name] = c
	}

	for _, name := range instances {
		c := rec.Containers[name]
		c.Instances = true
		rec.Containers[name] = c
	}

	rec.ObservedAt = a.now()

	a.recMu.Lock()
	a.rec = rec
	a.recMu.Unlock()

	return nil
}

// Run refreshes every 30 seconds until ctx is done.
func (a *Agent) Run(ctx context.Context) {
	t := time.NewTicker(refreshEvery)
	defer t.Stop()

	for {
		_ = a.Refresh(ctx, false)

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Handler serves GET /status; ?refresh=1 refreshes first, unless a refresh
// was attempted in the last 5 seconds.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("refresh") == "1" {
			if err := a.Refresh(r.Context(), true); err != nil {
				return // the client went away
			}
		}

		rec := a.Current()
		if rec == nil {
			http.Error(w, "no observation yet", http.StatusServiceUnavailable)

			return
		}

		b, err := json.Marshal(rec)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		if len(b) > MaxRecord {
			http.Error(w, fmt.Sprintf("status record too large (%d bytes)", len(b)), http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})

	return mux
}

// TLSConfig returns the server side of the mutual TLS: the agent's certificate,
// and only client certificates issued by the agent CA for client auth.
func TLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("agent certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("agent CA: no certificate found")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	// the agent's own identity names its cluster; only that cluster's mgrs may call it
	own, err := pki.CertIdentity(leaf)
	if err != nil || own.Role != pki.RoleAgent {
		return nil, fmt.Errorf("agent certificate is not an agent's: %v %v", own, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}

			_, err := pki.Require(cs.PeerCertificates[0], pki.Identity{FSID: own.FSID, Role: pki.RoleMgr})

			return err
		},
	}, nil
}

// Env names of the agent's TLS material (base64 encoded PEM), set in its document.
const (
	EnvCA   = "CEPHADM_TALOS_AGENT_CA"
	EnvCert = "CEPHADM_TALOS_AGENT_CERT"
	EnvKey  = "CEPHADM_TALOS_AGENT_KEY"
	// EnvClientCert and EnvClientKey are the agent's client certificate, for the
	// mgr module's confirmation endpoint and bridge (plan 03)
	EnvClientCert = "CEPHADM_TALOS_AGENT_CLIENT_CERT"
	EnvClientKey  = "CEPHADM_TALOS_AGENT_CLIENT_KEY"
)

func envPEM(name string) ([]byte, error) {
	v := os.Getenv(name)
	if v == "" {
		return nil, fmt.Errorf("%s is not set", name)
	}

	return base64.StdEncoding.DecodeString(v)
}

// Main runs the agent in its container until ctx is done.
func Main(ctx context.Context) error {
	var pems [3][]byte

	for i, name := range []string{EnvCA, EnvCert, EnvKey} {
		b, err := envPEM(name)
		if err != nil {
			return err
		}

		pems[i] = b
	}

	cfg, err := TLSConfig(pems[0], pems[1], pems[2])
	if err != nil {
		return err
	}

	tc := &talos.Client{Dial: talos.DialSocket(constants.MachineSocketPath), Roles: []role.Role{role.Reader}}
	defer tc.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a := &Agent{Talos: tc, Life: ctx}

	var wg sync.WaitGroup

	wg.Go(func() { a.Run(ctx) })

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", Port),
		Handler:           a.Handler(),
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		// a request may wait for a refresh (20s) before its response is written
		WriteTimeout: refreshTimeout + 10*time.Second,
		IdleTimeout:  60 * time.Second,
	}

	served := make(chan error, 1)

	go func() {
		log.Printf("cephadm-talos agent listening on %s", srv.Addr)
		served <- srv.ListenAndServeTLS("", "")
	}()

	var serveErr error

	select {
	case serveErr = <-served: // the listener failed
	case <-ctx.Done():
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		if serr := srv.Shutdown(sctx); serr != nil {
			_ = srv.Close()
		}

		scancel()

		serveErr = <-served
	}

	cancel()
	wg.Wait()
	a.Wait() // before the deferred Close of the Talos client

	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}

	return serveErr
}
