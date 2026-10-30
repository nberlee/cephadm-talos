package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// mem is a config-key store in memory that enforces the entry size.
type mem struct {
	mu    sync.Mutex
	m     map[string][]byte
	limit int
}

func (b *mem) EntryLimit() int {
	if b.limit == 0 {
		return 64 << 10
	}

	return b.limit
}

func (b *mem) Get(_ context.Context, k string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	v, ok := b.m[k]
	if !ok {
		return nil, ErrNotFound
	}

	return append([]byte(nil), v...), nil
}

func (b *mem) Set(_ context.Context, k string, v []byte) error {
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

func (b *mem) SetMany(ctx context.Context, kvs []KV) error {
	for _, kv := range kvs {
		if err := b.Set(ctx, kv.Key, kv.Value); err != nil {
			return err
		}
	}

	return nil
}

func (b *mem) Remove(_ context.Context, keys []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, k := range keys {
		delete(b.m, k)
	}

	return nil
}

func (b *mem) List(_ context.Context, prefix string) ([]string, error) {
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

func TestPublishAndRead(t *testing.T) {
	ctx := context.Background()
	b := &mem{}
	s := Store{B: b, Incarnation: "cli"}

	if _, err := s.Latest(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty store: %v", err)
	}

	big := bytes.Repeat([]byte("x"), 3*MaxEntry+17)

	m1, err := s.Publish(ctx, map[string][]byte{"hosts": []byte(`[1]`), "big": big})
	if err != nil {
		t.Fatal(err)
	}

	if len(m1.Records["big"].Chunks) != 5 { // base64: 4/3 of 3 entries and a bit
		t.Errorf("big record in %d chunks", len(m1.Records["big"].Chunks))
	}

	m2, err := s.Publish(ctx, map[string][]byte{"hosts": []byte(`[2]`)})
	if err != nil || m2.Seq <= m1.Seq {
		t.Fatalf("second publication %+v %v", m2, err)
	}

	latest, err := s.Latest(ctx)
	if err != nil || latest.Seq != m2.Seq {
		t.Fatalf("latest %+v %v", latest, err)
	}

	if v, err := s.Read(ctx, latest, "hosts"); err != nil || string(v) != `[2]` {
		t.Fatalf("hosts %q %v", v, err)
	}

	if _, err := s.Read(ctx, latest, "big"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a record of an older publication: %v", err)
	}

	// the older manifest is still readable: its chunks were never overwritten
	if v, err := s.Read(ctx, m1, "big"); err != nil || !bytes.Equal(v, big) {
		t.Fatalf("big %d bytes %v", len(v), err)
	}
}

func TestOnlyTheLastPublicationsAreKept(t *testing.T) {
	ctx := context.Background()
	b := &mem{}
	s := Store{B: b, Incarnation: "cli"}

	var ms []Manifest

	for i := range 5 {
		m, err := s.Publish(ctx, map[string][]byte{"hosts": bytes.Repeat([]byte{byte('a' + i)}, MaxEntry)})
		if err != nil {
			t.Fatal(err)
		}

		ms = append(ms, m)
	}

	for i, m := range ms {
		_, err := s.Read(ctx, m, "hosts")
		if kept := i >= len(ms)-Keep; kept != (err == nil) {
			t.Errorf("publication %d: kept %v, read error %v", m.Seq, kept, err)
		}
	}

	keys, _ := b.List(ctx, Prefix)
	if len(keys) != Keep*3 { // per publication: a manifest and two chunks
		t.Errorf("%d keys left: %v", len(keys), keys)
	}
}

func TestIncarnationsAreSeparate(t *testing.T) {
	ctx := context.Background()
	b := &mem{}
	old, cur := Store{B: b, Incarnation: "4178"}, Store{B: b, Incarnation: "4200"}

	if _, err := cur.Publish(ctx, map[string][]byte{"hosts": []byte("new")}); err != nil {
		t.Fatal(err)
	}

	// a delayed write of the predecessor lands in its own namespace
	if _, err := old.Publish(ctx, map[string][]byte{"hosts": []byte("stale")}); err != nil {
		t.Fatal(err)
	}

	m, _ := cur.Latest(ctx)
	if v, _ := cur.Read(ctx, m, "hosts"); string(v) != "new" {
		t.Fatalf("read %q", v)
	}
}

func TestCorruptionIsDetected(t *testing.T) {
	ctx := context.Background()
	b := &mem{}
	s := Store{B: b, Incarnation: "cli"}

	m, err := s.Publish(ctx, map[string][]byte{"hosts": []byte("abc")})
	if err != nil {
		t.Fatal(err)
	}

	_ = b.Set(ctx, m.Records["hosts"].Chunks[0], []byte("YWJk")) // "abd"

	if _, err := s.Read(ctx, m, "hosts"); err == nil {
		t.Fatal("corrupt record read")
	}

	// a chunk key pointing into another incarnation is refused
	m.Records["hosts"] = Entry{Chunks: []string{Prefix + "inc/other/rec/1/hosts.0"}, SHA256: m.Records["hosts"].SHA256, Size: 3}
	if _, err := s.Read(ctx, m, "hosts"); err == nil {
		t.Fatal("foreign chunk read")
	}
}

func TestNamesAreChecked(t *testing.T) {
	ctx := context.Background()

	if _, err := (Store{B: &mem{}, Incarnation: "../x"}).Publish(ctx, nil); err == nil {
		t.Error("bad incarnation accepted")
	}

	if _, err := (Store{B: &mem{}, Incarnation: "cli"}).Publish(ctx, map[string][]byte{"a/b": nil}); err == nil {
		t.Error("bad record name accepted")
	}
}

func TestChunksFollowTheConfiguredLimit(t *testing.T) {
	ctx := context.Background()
	b := &mem{limit: 8 << 10}
	s := Store{B: b, Incarnation: "cli"}

	m, err := s.Publish(ctx, map[string][]byte{"big": bytes.Repeat([]byte("y"), 50<<10)})
	if err != nil {
		t.Fatal(err)
	}

	if v, err := s.Read(ctx, m, "big"); err != nil || len(v) != 50<<10 {
		t.Fatalf("%d bytes %v", len(v), err)
	}

	if _, err := (Store{B: &mem{limit: 1024}, Incarnation: "cli"}).Publish(ctx, map[string][]byte{"a": nil}); err == nil {
		t.Error("published below the minimum entry size")
	}
}

func TestLeftoverChunksAreNeverOverwritten(t *testing.T) {
	ctx := context.Background()
	b := &mem{}
	s := Store{B: b, Incarnation: "cli"}

	m1, _ := s.Publish(ctx, map[string][]byte{"hosts": []byte("one")})

	// chunks of an attempt whose manifest never got written (or whose
	// acknowledgement was lost) at the next sequence
	stray := Prefix + "inc/cli/rec/" + strconv.FormatInt(m1.Seq+1, 10) + "/hosts.0"
	_ = b.Set(ctx, stray, []byte("c3RyYXk="))

	m2, err := s.Publish(ctx, map[string][]byte{"hosts": []byte("two")})
	if err != nil || m2.Seq <= m1.Seq+1 {
		t.Fatalf("publication %d over a leftover at %d: %v", m2.Seq, m1.Seq+1, err)
	}

	if v, _ := b.Get(ctx, stray); string(v) != "c3RyYXk=" {
		t.Error("leftover chunk overwritten")
	}

	if v, err := s.Read(ctx, m2, "hosts"); err != nil || string(v) != "two" {
		t.Fatalf("%q %v", v, err)
	}
}

// A write of an earlier attempt that lands only after a later publication
// (its outcome was unknown) never becomes the latest.
func TestALateWriteDoesNotWin(t *testing.T) {
	ctx := context.Background()
	b := &mem{}
	clock := time.Unix(1000, 0)
	s := Store{B: b, Incarnation: "cli", Now: func() time.Time { return clock }}

	early := clock.UnixNano() // the attempt that timed out before anything was visible

	clock = clock.Add(time.Second)

	m, err := s.Publish(ctx, map[string][]byte{"hosts": []byte("new")})
	if err != nil || m.Seq <= early {
		t.Fatalf("publication %d, earlier attempt %d: %v", m.Seq, early, err)
	}

	// the earlier attempt's manifest and chunk arrive now
	late := Manifest{Schema: Schema, Incarnation: "cli", Seq: early, Records: map[string]Entry{"hosts": {
		Chunks: []string{Prefix + "inc/cli/rec/" + strconv.FormatInt(early, 10) + "/hosts.0"}, SHA256: "x", Size: 3,
	}}}
	lb, _ := json.Marshal(late)
	_ = b.Set(ctx, late.Records["hosts"].Chunks[0], []byte("b2xk"))
	_ = b.Set(ctx, fmt.Sprintf("%sinc/cli/manifest/%020d", Prefix, early), lb)

	got, err := s.Latest(ctx)
	if err != nil || got.Seq != m.Seq {
		t.Fatalf("latest %d %v, want %d", got.Seq, err, m.Seq)
	}

	if v, err := s.Read(ctx, got, "hosts"); err != nil || string(v) != "new" {
		t.Fatalf("%q %v", v, err)
	}
}
