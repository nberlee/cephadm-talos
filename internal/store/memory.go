package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Memory is a config-key store in memory, for tests; it enforces the entry size.
type Memory struct {
	mu    sync.Mutex
	m     map[string][]byte
	Limit int // 0: 64 KiB
}

// EntryLimit implements Backend.
func (b *Memory) EntryLimit() int {
	if b.Limit == 0 {
		return 64 << 10
	}

	return b.Limit
}

// Get implements Backend.
func (b *Memory) Get(_ context.Context, k string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	v, ok := b.m[k]
	if !ok {
		return nil, ErrNotFound
	}

	return append([]byte(nil), v...), nil
}

// Set writes one entry.
func (b *Memory) Set(_ context.Context, k string, v []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(v) > b.EntryLimit() {
		return errors.New("entry too large")
	}

	if b.m == nil {
		b.m = map[string][]byte{}
	}

	b.m[k] = append([]byte(nil), v...)

	return nil
}

// SetMany implements Backend.
func (b *Memory) SetMany(ctx context.Context, kvs []KV) error {
	for _, kv := range kvs {
		if err := b.Set(ctx, kv.Key, kv.Value); err != nil {
			return err
		}
	}

	return nil
}

// Remove implements Backend.
func (b *Memory) Remove(_ context.Context, keys []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, k := range keys {
		delete(b.m, k)
	}

	return nil
}

// List implements Backend.
func (b *Memory) List(_ context.Context, prefix string) ([]string, error) {
	// as the bridge: a directory only
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		return nil, fmt.Errorf("store: list %s: not a directory", prefix)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var out []string

	for k := range b.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}

	sort.Strings(out)

	return out, nil
}
