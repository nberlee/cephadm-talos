package orch

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nberlee/cephadm-talos/internal/pki"
	"github.com/nberlee/cephadm-talos/internal/spec"
	"github.com/nberlee/cephadm-talos/internal/state"
	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos/talostest"
)

func TestVersionAtLeast(t *testing.T) {
	for v, ok := range map[string]bool{
		"v1.15.0-alpha.1": true,
		"v1.15.2":         true,
		"v1.16.0":         true,
		"v2.0.0":          true,
		"v1.14.2":         false,
		"":                false,
	} {
		if got := versionAtLeast(v, MinTalos); got != ok {
			t.Errorf("versionAtLeast(%q) = %v", v, got)
		}
	}
}

func TestShellJoin(t *testing.T) {
	if got := shellJoin([]string{"ceph -s; ceph df"}); got != "ceph -s; ceph df" {
		t.Fatal(got)
	}

	if got := shellJoin([]string{"ceph", "config", "set", "global", "x", "it's"}); got != `'ceph' 'config' 'set' 'global' 'x' 'it'\''s'` {
		t.Fatal(got)
	}
}

func TestParsePrepared(t *testing.T) {
	id, uuid, err := parsePrepared("cephadm-talos: preparing\nRunning command: ...\nosd_id 4\nosd_uuid 9b1c\n")
	if err != nil || id != 4 || uuid != "9b1c" {
		t.Fatalf("got %d %q %v", id, uuid, err)
	}

	for _, bad := range []string{"", "osd_id 4\n", "osd_uuid x\n", "osd_id -1\nosd_uuid x\n", "osd_id x\nosd_uuid x\n"} {
		if _, _, err := parsePrepared(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// valid reports whether Talos accepts a container name.
func valid(name string) error {
	_, err := spec.Render(spec.Container(name, "docker.io/library/alpine:3"))

	return err
}

func TestDocNameBounded(t *testing.T) {
	st := state.New("0123abcd-0000-4000-8000-000000000000")
	long := strings.Repeat("h", 63)

	a := st.DocName(state.Daemon{Type: state.TypeOSD, ID: long + "-vdb"})
	b := st.DocName(state.Daemon{Type: state.TypeOSD, ID: long + "-vdc"})

	if len(a) > 63 || a == b || valid(a) != nil {
		t.Fatalf("bad names %q %q", a, b)
	}

	if n := st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-"}); valid(n) != nil {
		t.Fatalf("trailing dash name %q", n)
	}

	up := st.DocName(state.Daemon{Type: state.TypeMon, ID: "Node-1"})
	if valid(up) != nil || up == st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-1"}) {
		t.Fatalf("uppercase name %q", up)
	}

	if got := st.DocName(state.Daemon{Type: state.TypeMon, ID: "node-1"}); got != "ceph-0123abcd-mon-node-1" {
		t.Fatalf("short name changed: %q", got)
	}
}

func TestCertCovers(t *testing.T) {
	ca, caKey, err := newCA("0123abcd-0000-4000-8000-000000000000")
	if err != nil {
		t.Fatal(err)
	}

	cert, _, err := newServerCert(ca, caKey, []string{"10.5.0.200", "10.5.0.2"}, []string{"node-1", "localhost"})
	if err != nil {
		t.Fatal(err)
	}

	if !certCovers(cert, []string{"10.5.0.2", "10.5.0.200"}, []string{"localhost", "node-1"}) {
		t.Fatal("same SANs in another order must be covered")
	}

	if certCovers(cert, []string{"10.5.0.2", "10.5.0.200", "10.5.0.3"}, []string{"localhost", "node-1"}) {
		t.Fatal("a new host must trigger a reissue")
	}
}

func TestLastVIPStart(t *testing.T) {
	logs := "CEPHADM-TALOS-VIP-START 1-1\nEntering BACKUP STATE\nCEPHADM-TALOS-VIP-START 2-7\nStartup complete\n"

	if m, ok := lastVIPStart(logs); m != "2-7" || ok {
		t.Fatalf("got %q %v, the latest start is not ready yet", m, ok)
	}

	if m, ok := lastVIPStart(logs + "(rgw) Entering MASTER STATE\n"); m != "2-7" || !ok {
		t.Fatalf("got %q %v", m, ok)
	}
}

func TestPickIncarnation(t *testing.T) {
	num := func(n string) json.Number { return json.Number(n) }

	for _, c := range []struct {
		published []string
		epochs    map[string]any
		active    string
		want      string
	}{
		{nil, nil, "42", "cli"},
		{[]string{"cli"}, nil, "42", "cli"},
		// the active mgr's own, once published
		{[]string{"cli", "42", "90"}, map[string]any{"42": num("8"), "90": num("3")}, "90", "90"},
		// else the highest epoch, not the highest gid
		{[]string{"cli", "42", "90"}, map[string]any{"42": num("8"), "90": num("3")}, "7", "42"},
		// a journal without a takeover epoch does not count
		{[]string{"cli", "42"}, map[string]any{}, "7", "cli"},
	} {
		if got := pickIncarnation(c.published, c.epochs, c.active); got != c.want {
			t.Errorf("%v %v active %s: %s, want %s", c.published, c.epochs, c.active, got, c.want)
		}
	}
}

func TestTheCLIWritesNothingUnderALeader(t *testing.T) {
	o := fakeOrch(t, talostest.New(t))
	o.incarnation = "42"

	if !o.Managed() || !errors.Is(o.save(), ErrManaged) {
		t.Fatal("the CLI saved state under a leader")
	}
}

func TestHandoffSealsTheState(t *testing.T) {
	o := fakeOrch(t, talostest.New(t, images()))
	ctx := context.Background()

	if err := o.setupAgent(ctx, "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	// a key that is not its certificate's stops it: the leader could not render it
	ca, caKey, err := pki.NewCA("rgw", 1)
	if err != nil {
		t.Fatal(err)
	}

	cert, _, _ := pki.Issue(ca, caKey, pki.Leaf{CommonName: "s3", Usage: x509.ExtKeyUsageServerAuth, Years: 1})
	_, other, _ := pki.Issue(ca, caKey, pki.Leaf{CommonName: "s3", Usage: x509.ExtKeyUsageServerAuth, Years: 1})
	o.St.RGW = &state.RGW{Cert: cert, Key: other, UserCert: true}

	if err := o.Handoff(ctx); err == nil || o.St.HandingOver {
		t.Fatal("handoff with an RGW key that is not its certificate's")
	}

	o.St.RGW = nil

	// documents still owed to a node stop it
	o.St.ConfPending = []string{"h1"}
	if err := o.Handoff(ctx); err == nil {
		t.Fatal("handoff with pending documents")
	}

	o.St.ConfPending = nil

	if err := o.Handoff(ctx); err != nil {
		t.Fatal(err)
	}

	// the next command reads a sealed state: it changes nothing
	st := reload(t, o)
	st.Hosts = []state.Host{{Name: "contact"}} // Open needs a node to go through

	next := &Orch{Talos: o.Talos, St: st, Out: io.Discard, StoreBackend: o.StoreBackend, AuthGet: noAuth}
	if err := next.Open(ctx); err != nil {
		t.Fatal(err)
	}

	if !next.St.Sealed || !next.Managed() || !errors.Is(next.save(), ErrManaged) {
		t.Fatalf("sealed %v managed %v", next.St.Sealed, next.Managed())
	}

	if err := next.Handoff(ctx); err == nil {
		t.Fatal("handed over twice")
	}
}

// A handoff that stops half-way blocks the CLI's changes until it is run again.
func TestAHalfHandoffBlocksTheCLI(t *testing.T) {
	o := fakeOrch(t, talostest.New(t, images()))
	ctx := context.Background()

	if err := o.setupAgent(ctx, "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	// an agent that does not answer: the handoff stops after recording itself
	h := state.Host{Name: "h1", Addr: "127.0.0.1:1"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	o.St.AddHost(h)

	if err := o.Handoff(ctx); err == nil {
		t.Fatal("handoff with an agent that does not answer")
	}

	if !o.St.HandingOver || o.St.Sealed || !o.Managed() || !errors.Is(o.save(), ErrManaged) {
		t.Fatalf("after a half handoff: handing over %v sealed %v", o.St.HandingOver, o.St.Sealed)
	}

	before := secretEntries(t, o)

	// the next run finishes it without having read the secrets: they stay
	st := reload(t, o)
	st.RemoveHost("h1") // the agent that did not answer
	st.Hosts = append(st.Hosts, state.Host{Name: "contact"})

	next := &Orch{Talos: o.Talos, St: st, Out: io.Discard, StoreBackend: o.StoreBackend, AuthGet: noAuth}
	if err := next.Open(ctx); err != nil {
		t.Fatal(err)
	}

	next.St.RemoveHost("h1")

	if err := next.Handoff(ctx); err != nil {
		t.Fatal(err)
	}

	if after := secretEntries(t, o); !maps.Equal(before, after) || len(after) == 0 {
		t.Fatalf("the resumed handoff changed the secrets: %v", slices.Collect(maps.Keys(after)))
	}
}

func secretEntries(t *testing.T, o *Orch) map[string]string {
	t.Helper()

	ctx := context.Background()

	keys, err := o.StoreBackend.List(ctx, store.SecretPrefix)
	if err != nil {
		t.Fatal(err)
	}

	m := map[string]string{}

	for _, k := range keys {
		v, err := o.StoreBackend.Get(ctx, k)
		if err != nil {
			t.Fatal(err)
		}

		m[k] = string(v)
	}

	return m
}

// The published state carries no private key: they are secrets, one entry
// each below their own prefix, which a reload reads back.
func TestSecretsStayOutOfThePublishedState(t *testing.T) {
	o := fakeOrch(t, talostest.New(t, images()))
	ctx := context.Background()

	if err := o.setupAgent(ctx, "node", "registry/agent:dev", false); err != nil {
		t.Fatal(err)
	}

	h := state.Host{Name: "h1", Addr: "node"}
	if err := o.ensureAgentCert(&h); err != nil {
		t.Fatal(err)
	}

	if err := o.ensureMgrCerts(&h, true); err != nil {
		t.Fatal(err)
	}

	o.St.AddHost(h)

	if err := o.save(); err != nil {
		t.Fatal(err)
	}

	keys, err := o.StoreBackend.List(ctx, store.Prefix)
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range keys {
		v, _ := o.StoreBackend.Get(ctx, k)
		raw, _ := base64.StdEncoding.DecodeString(string(v))

		if strings.Contains(string(v)+string(raw), "PRIVATE KEY") {
			t.Errorf("%s carries a private key", k)
		}
	}

	sec, err := o.StoreBackend.List(ctx, store.SecretPrefix)
	if err != nil || len(sec) != 5 { // the agent CA, two agent and two mgr keys
		t.Fatalf("secrets %v %v", sec, err)
	}

	back := reload(t, o)
	bh, _ := back.Host("h1")

	if back.Agent.CAKey != o.St.Agent.CAKey || bh.MgrServerKey != h.MgrServerKey || bh.AgentClientKey != h.AgentClientKey {
		t.Fatal("secrets lost on reload")
	}

	// a host gone takes its secrets along
	o.St.RemoveHost("h1")

	if err := o.save(); err != nil {
		t.Fatal(err)
	}

	if sec, _ = o.StoreBackend.List(ctx, store.SecretPrefix); len(sec) != 1 {
		t.Fatalf("secrets after removing the host: %v", sec)
	}
}

// A certificate file that also holds the key publishes only the certificate.
func TestUserCertKeepsTheKeyOutOfTheCertificate(t *testing.T) {
	caCert, caKey, err := pki.NewCA("user CA", 1)
	if err != nil {
		t.Fatal(err)
	}

	cert, key, err := pki.Issue(caCert, caKey, pki.Leaf{CommonName: "s3", Names: []string{"s3"}, Usage: x509.ExtKeyUsageServerAuth, Years: 1})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, []byte(key+cert+caCert), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(keyFile, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}

	c, k, err := userCert(certFile, keyFile)
	if err != nil || k != key {
		t.Fatal(err)
	}

	if strings.Contains(c, "PRIVATE KEY") || c != cert+caCert {
		t.Fatalf("published certificate:\n%s", c)
	}
}
