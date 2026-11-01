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
	"time"
)

// Prefix is the config-key namespace of cephadm-talos, inside the module's store.
const Prefix = "mgr/cephadm/talos/"

// SecretPrefix holds the state's private keys and passwords, one entry each,
// outside Prefix: the bridge reads and writes below Prefix only.
const SecretPrefix = "cephadm-talos/secrets/"

// MaxEntry is the largest value written to one config-key entry. Ceph v20.2.4
// limits an entry to mon_config_key_max_entry_size (64 KiB by default); chunks
// leave room for the encoding overhead.
const MaxEntry = 60 << 10

// Schema is the version of the manifest and record layout.
const Schema = 1

// Backend is a config-key store: the CLI reaches it through exec (a Snapshot),
// the leader through the module's bridge. A Snapshot's Get and List read one
// consistent snapshot, so a reader of a manifest finds its chunks even while a
// writer compacts. A backend without snapshots (the bridge) serves only
// readers that cannot race a compaction: an incarnation's own writer, and
// readers of a frozen incarnation. An incarnation has one writer at a time;
// its publications are serialized.
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error) // ErrNotFound if missing
	List(ctx context.Context, prefix string) ([]string, error)
	// SetMany writes the entries in order; it returns once all are written
	SetMany(ctx context.Context, entries []KV) error
	// Remove deletes keys; missing ones are not an error
	Remove(ctx context.Context, keys []string) error
	// EntryLimit is the largest value the store accepts (the mons'
	// mon_config_key_max_entry_size)
	EntryLimit() int
}

// minEntry is the smallest entry limit the store works with.
const minEntry = 4 << 10

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
	// Now is the clock for sequences; nil is time.Now
	Now func() time.Time
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}

	return time.Now()
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

	// The next sequence is above every manifest and every chunk already there,
	// and at least the current time in nanoseconds: an earlier attempt whose
	// write is still under way (its outcome unknown, not visible yet) has a lower
	// sequence than any later one, so landing late it neither overwrites a later
	// publication nor becomes the latest manifest. This assumes the writer's
	// clock does not step back.
	top, err := s.highest(ctx)
	if err != nil {
		return Manifest{}, err
	}

	top = max(top, s.now().UnixNano()-1)

	limit := s.B.EntryLimit()
	if limit < minEntry {
		return Manifest{}, fmt.Errorf("store: config-key entries are limited to %d bytes, at least %d are needed", limit, minEntry)
	}

	// below the limit, with room to spare
	chunkSize := min(MaxEntry, limit-limit/16)

	m := Manifest{Schema: Schema, Incarnation: s.Incarnation, Seq: top + 1, Records: map[string]Entry{}}

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

		for i := 0; i == 0 || i*chunkSize < len(enc); i++ {
			key := fmt.Sprintf("%srec/%d/%s.%d", base, m.Seq, n, i)
			chunks = append(chunks, KV{Key: key, Value: []byte(enc[i*chunkSize : min((i+1)*chunkSize, len(enc))])})
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

	if len(b) > chunkSize {
		return Manifest{}, fmt.Errorf("store: manifest of %d bytes exceeds %d", len(b), chunkSize)
	}

	// the manifest last: it publishes the records it names
	if err := s.B.SetMany(ctx, []KV{{Key: fmt.Sprintf("%smanifest/%020d", base, m.Seq), Value: b}}); err != nil {
		return Manifest{}, err
	}

	// a failed compaction leaves older publications behind: the manifest is
	// published regardless, which the returned manifest says
	if err := s.compact(ctx); err != nil {
		return m, fmt.Errorf("store: published %d, compaction failed: %w", m.Seq, err)
	}

	return m, nil
}

// highest returns the highest sequence of any manifest or record chunk of the
// incarnation, 0 if there is none.
func (s Store) highest(ctx context.Context) (int64, error) {
	base, err := s.base()
	if err != nil {
		return 0, err
	}

	keys, err := s.B.List(ctx, base)
	if err != nil {
		return 0, err
	}

	var top int64

	for _, k := range keys {
		if n, ok := seqOf(strings.TrimPrefix(k, base)); ok && n > top {
			top = n
		}
	}

	return top, nil
}

// seqOf returns the sequence of a key below an incarnation: manifest/<seq> or rec/<seq>/...
func seqOf(rest string) (int64, bool) {
	var seq string

	switch {
	case strings.HasPrefix(rest, "manifest/"):
		seq = strings.TrimPrefix(rest, "manifest/")
	case strings.HasPrefix(rest, "rec/"):
		seq, _, _ = strings.Cut(strings.TrimPrefix(rest, "rec/"), "/")
	default:
		return 0, false
	}

	n, err := strconv.ParseInt(seq, 10, 64)

	return n, err == nil && n >= 0
}

// compact removes this incarnation's publications older than the last Keep
// manifests: their manifests first, so no reader finds a manifest without its
// records, then every chunk below the oldest kept manifest.
func (s Store) compact(ctx context.Context) error {
	base, err := s.base()
	if err != nil {
		return err
	}

	keys, err := s.B.List(ctx, base)
	if err != nil {
		return err
	}

	var seqs []int64

	for _, k := range keys {
		rest := strings.TrimPrefix(k, base)
		if n, ok := seqOf(rest); ok && strings.HasPrefix(rest, "manifest/") {
			seqs = append(seqs, n)
		}
	}

	if len(seqs) <= Keep {
		return nil
	}

	sort.Slice(seqs, func(i, j int) bool { return seqs[i] > seqs[j] })
	oldest := seqs[Keep-1]

	var manifests, recs []string

	for _, k := range keys {
		rest := strings.TrimPrefix(k, base)

		n, ok := seqOf(rest)
		if !ok || n >= oldest {
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
