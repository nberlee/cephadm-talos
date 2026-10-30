// Package store keeps the cluster state in the mon config-key store, under the
// module's namespace mgr/cephadm/talos/ (plan 03, item 4). State is published
// as immutable records plus a manifest that names them, both under the writer's
// incarnation; there is no global "current" pointer. A record larger than one
// config-key entry is split into chunks before the manifest names it. Readers
// pick the incarnation through the leadership protocol and read its latest
// manifest; a delayed write of an earlier incarnation lands in that
// incarnation's namespace and is never read as the current state.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Prefix is the config-key namespace of cephadm-talos, inside the module's store.
const Prefix = "mgr/cephadm/talos/"

// MaxEntry is the largest value written to one config-key entry. Ceph v20.2.4
// limits an entry to mon_config_key_max_entry_size (64 KiB by default); chunks
// leave room for the encoding overhead.
const MaxEntry = 60 << 10

// Schema is the version of the manifest and record layout.
const Schema = 1

// Backend is a config-key store: the CLI reaches it through exec, the leader
// through the module's bridge.
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error) // ErrNotFound if missing
	List(ctx context.Context, prefix string) ([]string, error)
	// SetMany writes the entries in order; it returns once all are written
	SetMany(ctx context.Context, entries []KV) error
	// Remove deletes keys; missing ones are not an error
	Remove(ctx context.Context, keys []string) error
}

// KV is one config-key entry.
type KV struct {
	Key   string
	Value []byte
}

// Keep is how many publications of an incarnation are kept: the latest and
// the one before, which a reader may still be reading.
const Keep = 2

// ErrNotFound is returned by a Backend for a missing key.
var ErrNotFound = errors.New("config-key not found")

// part is the only form an incarnation or record name may take.
var part = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Manifest names the records of one publication.
type Manifest struct {
	Schema      int              `json:"schema"`
	Incarnation string           `json:"incarnation"`
	Seq         int64            `json:"seq"`
	Records     map[string]Entry `json:"records"`
}

// Entry is one record in a manifest: its chunk keys and its hash.
type Entry struct {
	Chunks []string `json:"chunks"`
	SHA256 string   `json:"sha256"`
	Size   int      `json:"size"`
}

// Store reads and writes one incarnation's publications.
type Store struct {
	B           Backend
	Incarnation string
}

func (s Store) base() (string, error) {
	if !part.MatchString(s.Incarnation) {
		return "", fmt.Errorf("store: invalid incarnation %q", s.Incarnation)
	}

	return Prefix + "inc/" + s.Incarnation + "/", nil
}

// Publish writes the records and then a manifest with the next sequence number.
// Record chunks are written first and never overwritten (their keys carry the
// sequence), so a reader of the previous manifest is never disturbed.
func (s Store) Publish(ctx context.Context, records map[string][]byte) (Manifest, error) {
	base, err := s.base()
	if err != nil {
		return Manifest{}, err
	}

	prev, err := s.Latest(ctx)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return Manifest{}, err
	}

	m := Manifest{Schema: Schema, Incarnation: s.Incarnation, Seq: prev.Seq + 1, Records: map[string]Entry{}}

	names := make([]string, 0, len(records))
	for n := range records {
		if !part.MatchString(n) {
			return Manifest{}, fmt.Errorf("store: invalid record name %q", n)
		}

		names = append(names, n)
	}

	sort.Strings(names)

	var chunks []KV

	for _, n := range names {
		data := records[n]
		sum := sha256.Sum256(data)
		e := Entry{SHA256: hex.EncodeToString(sum[:]), Size: len(data)}

		// config-key values travel as JSON strings: chunks are base64 text, so a
		// cut never splits a character
		enc := base64.StdEncoding.EncodeToString(data)

		for i := 0; i == 0 || i*MaxEntry < len(enc); i++ {
			key := fmt.Sprintf("%srec/%d/%s.%d", base, m.Seq, n, i)
			chunks = append(chunks, KV{Key: key, Value: []byte(enc[i*MaxEntry : min((i+1)*MaxEntry, len(enc))])})
			e.Chunks = append(e.Chunks, key)
		}

		m.Records[n] = e
	}

	if err := s.B.SetMany(ctx, chunks); err != nil {
		return Manifest{}, fmt.Errorf("store: write records: %w", err)
	}

	b, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, err
	}

	if len(b) > MaxEntry {
		return Manifest{}, fmt.Errorf("store: manifest of %d bytes exceeds %d", len(b), MaxEntry)
	}

	// the manifest last: it publishes the records it names
	if err := s.B.SetMany(ctx, []KV{{Key: fmt.Sprintf("%smanifest/%020d", base, m.Seq), Value: b}}); err != nil {
		return Manifest{}, err
	}

	return m, s.compact(ctx, m.Seq)
}

// compact removes this incarnation's publications older than the last Keep:
// their manifests first, so no reader finds a manifest without its records.
func (s Store) compact(ctx context.Context, latest int64) error {
	base, err := s.base()
	if err != nil {
		return err
	}

	var manifests, recs []string

	keys, err := s.B.List(ctx, base)
	if err != nil {
		return err
	}

	for _, k := range keys {
		rest := strings.TrimPrefix(k, base)

		var seq string

		switch {
		case strings.HasPrefix(rest, "manifest/"):
			seq = strings.TrimPrefix(rest, "manifest/")
		case strings.HasPrefix(rest, "rec/"):
			seq, _, _ = strings.Cut(strings.TrimPrefix(rest, "rec/"), "/")
		default:
			continue
		}

		n, err := strconv.ParseInt(seq, 10, 64)
		if err != nil || n > latest-Keep {
			continue
		}

		if strings.HasPrefix(rest, "manifest/") {
			manifests = append(manifests, k)
		} else {
			recs = append(recs, k)
		}
	}

	if len(manifests) > 0 {
		if err := s.B.Remove(ctx, manifests); err != nil {
			return err
		}
	}

	if len(recs) > 0 {
		return s.B.Remove(ctx, recs)
	}

	return nil
}

// Latest returns the incarnation's manifest with the highest sequence number,
// or ErrNotFound if it published none.
func (s Store) Latest(ctx context.Context) (Manifest, error) {
	base, err := s.base()
	if err != nil {
		return Manifest{}, err
	}

	keys, err := s.B.List(ctx, base+"manifest/")
	if err != nil {
		return Manifest{}, err
	}

	var (
		best    string
		bestSeq int64 = -1
	)

	for _, k := range keys {
		n, err := strconv.ParseInt(strings.TrimPrefix(k, base+"manifest/"), 10, 64)
		if err == nil && n > bestSeq {
			best, bestSeq = k, n
		}
	}

	if best == "" {
		return Manifest{}, ErrNotFound
	}

	b, err := s.B.Get(ctx, best)
	if err != nil {
		return Manifest{}, err
	}

	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("store: manifest %s: %w", best, err)
	}

	if m.Schema != Schema || m.Incarnation != s.Incarnation || m.Seq != bestSeq {
		return Manifest{}, fmt.Errorf("store: manifest %s is not schema %d of %s seq %d", best, Schema, s.Incarnation, bestSeq)
	}

	return m, nil
}

// Read returns a record of a manifest, checked against its hash.
func (s Store) Read(ctx context.Context, m Manifest, name string) ([]byte, error) {
	e, ok := m.Records[name]
	if !ok {
		return nil, ErrNotFound
	}

	base, err := s.base()
	if err != nil {
		return nil, err
	}

	var enc []byte

	for _, k := range e.Chunks {
		if !strings.HasPrefix(k, base+"rec/") {
			return nil, fmt.Errorf("store: chunk %s outside the incarnation", k)
		}

		b, err := s.B.Get(ctx, k)
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", k, err)
		}

		enc = append(enc, b...)
	}

	data, err := base64.StdEncoding.DecodeString(string(enc))
	if err != nil {
		return nil, fmt.Errorf("store: record %s: %w", name, err)
	}

	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != e.SHA256 || len(data) != e.Size {
		return nil, fmt.Errorf("store: record %s does not match its manifest", name)
	}

	return data, nil
}
