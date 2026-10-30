package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/store"
)

// configKeyTimeout bounds one config-key exec.
const configKeyTimeout = 2 * time.Minute

// configKeys is the CLI's store backend: the mon config-key store through exec
// in a Ceph container on one node (plan 03, step 3). It reads one prefix at a
// time with a single `config-key dump` and serves Get and List from that
// snapshot; writes go out in one exec each, through librados in the container.
type configKeys struct {
	o      *Orch
	node   string
	prefix string
	snap   map[string]string
}

func (o *Orch) configKeys(ctx context.Context, node, prefix string) (*configKeys, error) {
	c := &configKeys{o: o, node: node, prefix: prefix}

	return c, c.load(ctx)
}

func (c *configKeys) load(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, configKeyTimeout)
	defer cancel()

	var out, errb bytes.Buffer

	rc, _, err := c.o.execAdmin(ctx, c.node, []string{"ceph", "config-key", "dump", c.prefix}, nil, &out, &errb)
	if err != nil {
		return err
	}

	if rc != 0 {
		return fmt.Errorf("config-key dump %s: rc %d: %s", c.prefix, rc, strings.TrimSpace(errb.String()))
	}

	snap := map[string]string{}
	if err := json.Unmarshal(out.Bytes(), &snap); err != nil {
		return fmt.Errorf("config-key dump %s: %w", c.prefix, err)
	}

	c.snap = snap

	return nil
}

func (c *configKeys) inside(key string) error {
	if !strings.HasPrefix(key, c.prefix) {
		return fmt.Errorf("config-key %s is outside %s", key, c.prefix)
	}

	return nil
}

func (c *configKeys) Get(_ context.Context, key string) ([]byte, error) {
	if err := c.inside(key); err != nil {
		return nil, err
	}

	v, ok := c.snap[key]
	if !ok {
		return nil, store.ErrNotFound
	}

	return []byte(v), nil
}

func (c *configKeys) List(_ context.Context, prefix string) ([]string, error) {
	if err := c.inside(prefix); err != nil {
		return nil, err
	}

	var out []string

	for k := range c.snap {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}

	sort.Strings(out)

	return out, nil
}

// mutate runs set and rm operations in order in one librados process.
const mutateScript = `
import json, sys, rados
r = rados.Rados(conffile='/etc/ceph/ceph.conf')
r.conf_parse_env()
r.connect(timeout=30)
try:
    for line in sys.stdin:
        op = json.loads(line)
        if op['op'] == 'set':
            ret, _, outs = r.mon_command(json.dumps({'prefix': 'config-key set', 'key': op['key']}), op['value'].encode(), timeout=30)
        else:
            ret, _, outs = r.mon_command(json.dumps({'prefix': 'config-key rm', 'key': op['key']}), b'', timeout=30)
        if ret != 0:
            sys.stderr.write('%s %s: %s (%d)\n' % (op['op'], op['key'], outs, ret))
            sys.exit(1)
finally:
    r.shutdown()
`

func (c *configKeys) mutate(ctx context.Context, ops []map[string]string) error {
	ctx, cancel := context.WithTimeout(ctx, configKeyTimeout)
	defer cancel()

	var in bytes.Buffer

	enc := json.NewEncoder(&in)
	for _, op := range ops {
		if err := c.inside(op["key"]); err != nil {
			return err
		}

		if err := enc.Encode(op); err != nil {
			return err
		}
	}

	var errb bytes.Buffer

	rc, _, err := c.o.execAdmin(ctx, c.node, []string{"python3", "-c", mutateScript}, in.Bytes(), &errb, &errb)
	if err != nil {
		return err
	}

	if rc != 0 {
		return fmt.Errorf("config-key update: rc %d: %s", rc, strings.TrimSpace(errb.String()))
	}

	for _, op := range ops {
		if op["op"] == "set" {
			c.snap[op["key"]] = op["value"]
		} else {
			delete(c.snap, op["key"])
		}
	}

	return nil
}

func (c *configKeys) SetMany(ctx context.Context, kvs []store.KV) error {
	ops := make([]map[string]string, 0, len(kvs))
	for _, kv := range kvs {
		ops = append(ops, map[string]string{"op": "set", "key": kv.Key, "value": string(kv.Value)})
	}

	return c.mutate(ctx, ops)
}

func (c *configKeys) Remove(ctx context.Context, keys []string) error {
	ops := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		ops = append(ops, map[string]string{"op": "rm", "key": k})
	}

	return c.mutate(ctx, ops)
}
