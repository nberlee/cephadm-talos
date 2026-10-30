package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Remote is a config-key store behind a channel that reads a whole prefix at
// once: exec in a Ceph container (the CLI) or the module's bridge (the leader).
type Remote interface {
	// Dump returns the entry limit (mon_config_key_max_entry_size) and every
	// entry below prefix
	Dump(ctx context.Context, prefix string) (limit int, entries map[string]string, err error)
	// Mutate runs the operations in order; after an error any prefix of them
	// may have happened
	Mutate(ctx context.Context, ops []Op) error
}

// Op is one config-key write: a set, or a removal when Remove is true.
type Op struct {
	Key    string
	Value  string
	Remove bool
}

// Snapshot is a Backend over a Remote. It reads one prefix with a single Dump
// and serves Get and List from that snapshot, which its own writes update; a
// write whose outcome is unknown makes the next read dump again.
type Snapshot struct {
	r      Remote
	prefix string
	// maxValue caps EntryLimit below what the channel carries; 0 is no cap
	maxValue int

	snap  map[string]string
	limit int
}

// NewSnapshot reads prefix through r.
func NewSnapshot(ctx context.Context, r Remote, prefix string, maxValue int) (*Snapshot, error) {
	s := &Snapshot{r: r, prefix: prefix, maxValue: maxValue}

	return s, s.load(ctx)
}

func (s *Snapshot) load(ctx context.Context) error {
	limit, entries, err := s.r.Dump(ctx, s.prefix)
	if err != nil {
		return err
	}

	for k := range entries {
		if !strings.HasPrefix(k, s.prefix) {
			return fmt.Errorf("config-key dump %s returned %s", s.prefix, k)
		}
	}

	if entries == nil {
		entries = map[string]string{}
	}

	s.snap, s.limit = entries, limit

	return nil
}

// fresh reloads the snapshot after a write whose outcome is unknown.
func (s *Snapshot) fresh(ctx context.Context) error {
	if s.snap != nil {
		return nil
	}

	return s.load(ctx)
}

func (s *Snapshot) inside(key string) error {
	if !strings.HasPrefix(key, s.prefix) {
		return fmt.Errorf("config-key %s is outside %s", key, s.prefix)
	}

	return nil
}

// EntryLimit is the mons' entry limit, capped by what the channel carries.
func (s *Snapshot) EntryLimit() int {
	if s.maxValue > 0 {
		return min(s.limit, s.maxValue)
	}

	return s.limit
}

func (s *Snapshot) Get(ctx context.Context, key string) ([]byte, error) {
	if err := s.inside(key); err != nil {
		return nil, err
	}

	if err := s.fresh(ctx); err != nil {
		return nil, err
	}

	v, ok := s.snap[key]
	if !ok {
		return nil, ErrNotFound
	}

	return []byte(v), nil
}

func (s *Snapshot) List(ctx context.Context, prefix string) ([]string, error) {
	if err := s.inside(prefix); err != nil {
		return nil, err
	}

	if err := s.fresh(ctx); err != nil {
		return nil, err
	}

	var out []string

	for k := range s.snap {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}

	sort.Strings(out)

	return out, nil
}

func (s *Snapshot) mutate(ctx context.Context, ops []Op) error {
	for _, op := range ops {
		if err := s.inside(op.Key); err != nil {
			return err
		}
	}

	if err := s.fresh(ctx); err != nil {
		return err
	}

	if err := s.r.Mutate(ctx, ops); err != nil {
		// some of the writes may have happened: the next read starts from a fresh snapshot
		s.snap = nil

		return err
	}

	for _, op := range ops {
		if op.Remove {
			delete(s.snap, op.Key)
		} else {
			s.snap[op.Key] = op.Value
		}
	}

	return nil
}

func (s *Snapshot) SetMany(ctx context.Context, kvs []KV) error {
	ops := make([]Op, 0, len(kvs))
	for _, kv := range kvs {
		ops = append(ops, Op{Key: kv.Key, Value: string(kv.Value)})
	}

	return s.mutate(ctx, ops)
}

func (s *Snapshot) Remove(ctx context.Context, keys []string) error {
	ops := make([]Op, 0, len(keys))
	for _, k := range keys {
		ops = append(ops, Op{Key: k, Remove: true})
	}

	return s.mutate(ctx, ops)
}
