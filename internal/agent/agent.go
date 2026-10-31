// Package agent is the per-node cephadm-talos agent: it reads the node's Talos
// container resources over the local machined socket and serves them to the
// talos mgr module over mutual TLS, and it is the only writer of its own node's
// Ceph documents (docs/plans/03-write-path.md, item 7). It reaches no other
// node's Talos API and has no Ceph identity.
package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/resources/containers"
	"github.com/siderolabs/talos/pkg/machinery/role"

	"github.com/nberlee/cephadm-talos/internal/daemons"
	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/records"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

// Port is the agent's HTTPS port (cephadm's agent port).
const Port = 4721

// Schema is the version of the status record: 2 adds the exit code of a
// container that exited (completed, failed, exited, backoff).
const Schema = 2

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
	ExitCode    int32  `json:"exit_code,omitempty"`
	// Version is the Ceph version the running daemon reports on its admin socket
	Version   string `json:"version,omitempty"`
	Instances bool   `json:"instances"` // an instance (process) is left
}

// Record is the status the agent serves.
type Record struct {
	Schema       int                  `json:"schema"`
	Hostname     string               `json:"hostname"`
	TalosVersion string               `json:"talos_version"`
	ObservedAt   time.Time            `json:"observed_at"` // completion of the last successful refresh
	Containers   map[string]Container `json:"containers"`
	// Records is "ok" or why the agent's records cannot be used
	Records string `json:"records,omitempty"`
	// Node is the agent's ownership of its node's Ceph documents (plan 03, item 7)
	Node *NodeStatus `json:"node,omitempty"`
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

	// Channel is the agent's side of the agent channel (plan 03); nil serves status only
	Channel *Channel
	// Records is the agent's durable records (plan 03); nil in tests that do not need them
	Records *records.Store
	// Node applies the node's Ceph documents (plan 03); nil in tests that do not need it
	Node *Node
	// Granter serves grants, operation lookups and the handoff (plan 03); nil serves none
	Granter *Granter
	// Exec runs the agent's admin socket queries; nil runs none
	Exec Execer

	// versions caches each daemon's reported version per instance
	versions map[string]versionSeen

	logPrint func(format string, args ...any)
	// refresh replaces observe in tests
	refresh func(context.Context) error
}

// versionSeen is what one instance of a container reported, or how often it
// was asked without an answer.
type versionSeen struct {
	// the instance: Talos resets generation and restarts when a container is
	// removed and created again, its PID and image tell the new one apart
	generation, restarts uint64
	pid                  uint32
	image                string

	version  string
	attempts int
}

// versionAttempts is how often one instance is asked: a daemon that just
// started may not have its socket yet.
const versionAttempts = 3

// daemonVersions asks each running daemon for its version, once per instance
// (Talos audits every exec), at most versionAttempts times without an answer.
// Only a document that passes the admission policy is asked: its environment
// is exactly its template's. This is a check, not a boundary: whoever could
// give a container another environment controls its processes anyway, and the
// query is a fixed read-only command whose answer is a version string. The
// bootstrap mon's document is not a grantable one and is not asked: it is
// replaced by the joining mon's template after bootstrap (plan 03, item 13).
func (a *Agent) daemonVersions(ctx context.Context, rec *Record, statuses map[string]containers.ContainerStatusSpec) {
	if a.Exec == nil || a.Node == nil || a.Node.Policy == nil {
		return
	}

	cfg, err := a.Talos.MachineConfig(ctx, "")
	if err != nil {
		return
	}

	docs, err := typedDocs([]byte(cfg))
	if err != nil {
		return
	}

	var disks []Disk

	if list, err := a.Talos.Disks(ctx, ""); err == nil {
		for _, d := range list {
			disks = append(disks, Disk{Serial: d.TypedSpec().Serial, Symlinks: d.TypedSpec().Symlinks})
		}
	}

	var names []string

	for k := range docs {
		if name, ok := strings.CutPrefix(k, "ContainerConfig/"); ok {
			names = append(names, name)
		}
	}

	seen := map[string]versionSeen{}

	for name, s := range statuses {
		td, ok := docs["ContainerConfig/"+name]
		if !ok || s.State != containers.ContainerStateRunning {
			continue
		}

		c, ok := td.doc.(*spec.ContainerConfig)
		if !ok {
			continue
		}

		entity := asokEntity(a.Node.FSID, c)
		if entity == "" {
			continue
		}

		v, ok := a.versions[name]
		if !ok || v.generation != s.Generation || v.restarts != s.RestartCount || v.pid != s.PID || v.image != s.Image {
			v = versionSeen{generation: s.Generation, restarts: s.RestartCount, pid: s.PID, image: s.Image}
		}

		// a refresh out of time asks no more: the attempts stay for the next one
		if v.version == "" && v.attempts < versionAttempts && ctx.Err() == nil &&
			a.Node.Policy.Check([]Doc{{Kind: "ContainerConfig", Name: name, YAML: td.yaml}}, disks, names) == nil {
			v.attempts++

			if version, err := daemonVersion(ctx, a.Exec, name, entity); err == nil {
				v.version = version
			}
		}

		seen[name] = v

		if v.version != "" {
			ct := rec.Containers[name]
			ct.Version = v.version
			rec.Containers[name] = ct
		}
	}

	a.versions = seen
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

	// a missing, unwritable or damaged records directory blocks every change (plan 03, item 6)
	if a.Records != nil {
		rec.Records = "ok"
		if err := a.Records.Check(); err != nil {
			rec.Records = err.Error()
		}
	}

	if a.Node != nil {
		st := a.Node.Status(ctx)
		rec.Node = &st
	}

	for name, s := range statuses {
		c := rec.Containers[name]
		c.State, c.ImageDigest, c.Restarts, c.ExitCode = s.State.String(), s.Image, s.RestartCount, s.ExitCode
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

	a.daemonVersions(ctx, rec, statuses)

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
	if a.Channel != nil {
		mux.HandleFunc("POST /v1/heartbeat", a.Channel.HandleHeartbeat)
	}

	if a.Granter != nil {
		mux.HandleFunc("POST /v1/grant", a.Granter.HandleGrant)
		mux.HandleFunc("GET /v1/operations/{id}", a.Granter.HandleOperation)
		mux.HandleFunc("POST /v1/handoff", a.Granter.HandleHandoff)
		mux.HandleFunc("GET /v1/node", a.Granter.HandleNode)
		mux.HandleFunc("POST /v1/abandon", a.Granter.HandleAbandon)
		mux.HandleFunc("POST /v1/close", a.Granter.HandleClose)
	}

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		// the status is the mgr module's
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			if id, err := pki.CertIdentity(r.TLS.PeerCertificates[0]); err != nil || id.Role != pki.RoleMgr {
				http.Error(w, "the status is served to the mgr only", http.StatusForbidden)

				return
			}
		}

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

	// the agent's own identity names its cluster; only that cluster's mgrs,
	// agents (the leader) and operator may call it, each handler checks the role
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

			id, err := pki.CertIdentity(cs.PeerCertificates[0])
			if err != nil {
				return err
			}

			switch {
			case id.FSID != own.FSID:
				return errors.New("a client of another cluster")
			case id.Role != pki.RoleMgr && id.Role != pki.RoleAgent && id.Role != pki.RoleOperator:
				return fmt.Errorf("role %s may not call an agent", id.Role)
			}

			return nil
		},
	}, nil
}

func envPEM(name string) ([]byte, error) {
	v := os.Getenv(name)
	if v == "" {
		return nil, fmt.Errorf("%s is not set", name)
	}

	return base64.StdEncoding.DecodeString(v)
}

// Main runs the agent in its container until ctx is done.
func Main(ctx context.Context) error {
	var pems [5][]byte

	for i, name := range []string{daemons.EnvCA, daemons.EnvCert, daemons.EnvKey, daemons.EnvClientCert, daemons.EnvClientKey} {
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

	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		return err
	}

	self, err := pki.CertIdentity(leaf)
	if err != nil {
		return err
	}

	ch, err := NewChannel(self)
	if err != nil {
		return err
	}

	// os:admin on its own node only: the local socket reaches no other node, and
	// machinedAccess grants every role there anyway (plan 03, "Roles and security")
	tc := &talos.Client{Dial: talos.DialSocket(constants.MachineSocketPath), Roles: []role.Role{role.Admin}}
	defer tc.Close() //nolint:errcheck

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// the client side, for the module's confirmations
	clientTLS, err := ClientTLSConfig(pems[0], pems[3], pems[4])
	if err != nil {
		return err
	}

	recs := &records.Store{Dir: filepath.Join(records.Mount, records.RecordsDir)}
	// from the agent's own document, which only the CLI writes; no
	// repositories admit no image
	repos := strings.Fields(os.Getenv(daemons.EnvImageRepos))
	node := &Node{Talos: tc, Records: recs, FSID: self.FSID, Host: self.Name, Policy: &Policy{
		FSID: self.FSID, Host: self.Name, CACert: string(pems[0]), Repos: repos,
	}}
	a := &Agent{
		Talos: tc, Life: ctx, Channel: ch, Records: recs, Node: node, Granter: NewGranter(node, ch, clientTLS, recs),
		Exec: func(ctx context.Context, container string, args []string, stdout, stderr io.Writer) (int, error) {
			return tc.Exec(ctx, "", container, args, nil, stdout, stderr)
		},
	}

	// an apply interrupted by the last stop is decided from the node first
	if err := a.Granter.Reconcile(ctx); err != nil {
		log.Printf("reconciling the last operations: %v", err)
	}

	var wg sync.WaitGroup

	wg.Go(func() { a.Run(ctx) })

	// the leader, while this host's mgr is the active one and heartbeats it
	leader := &LeaderLoop{Self: self, Channel: ch, ClientTLS: clientTLS, Repos: repos, CACert: string(pems[0])}
	wg.Go(func() { leader.Run(ctx) })

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
