package orch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nberlee/cephadm-talos/internal/store"
	"github.com/nberlee/cephadm-talos/internal/talos"
)

// configKeyTimeout bounds one config-key exec.
const configKeyTimeout = 2 * time.Minute

// execKeys is the CLI's channel to the mon config-key store (plan 03, step 3):
// exec in a Ceph container on one node, another node if that one has none
// running. A prefix is read with a single `config-key dump`; writes go out in
// one exec each, through librados in the container.
type execKeys struct {
	o    *Orch
	node string
}

// configKeys is the CLI's store backend: a snapshot of prefix through exec.
func (o *Orch) configKeys(ctx context.Context, node, prefix string) (*store.Snapshot, error) {
	return store.NewSnapshot(ctx, &execKeys{o: o, node: node}, prefix, 0)
}

// readScript prints the entry limit and the keys below a prefix as one JSON
// object, from one librados session.
const readScript = `
import json, sys, rados
r = rados.Rados(conffile='/etc/ceph/ceph.conf')
r.conf_parse_env()
r.connect()
try:
    ret, out, outs = r.mon_command(json.dumps({'prefix': 'config get', 'who': 'mon', 'key': 'mon_config_key_max_entry_size', 'format': 'json'}), b'')
    if ret != 0:
        sys.exit('config get mon_config_key_max_entry_size: %s (%d)' % (outs, ret))
    limit = json.loads(out)
    ret, out, outs = r.mon_command(json.dumps({'prefix': 'config-key dump', 'key': sys.argv[1]}), b'')
    if ret != 0:
        sys.exit('config-key dump: %s (%d)' % (outs, ret))
    json.dump({'limit': int(limit), 'keys': json.loads(out)}, sys.stdout)
finally:
    r.shutdown()
`

func (c *execKeys) Dump(ctx context.Context, prefix string) (int, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, configKeyTimeout)
	defer cancel()

	var out, errb bytes.Buffer

	rc, err := c.exec(ctx, []string{"python3", "-c", readScript, prefix}, nil, &out, &errb)
	if err != nil {
		return 0, nil, err
	}

	if rc != 0 {
		return 0, nil, fmt.Errorf("config-key dump %s: rc %d: %s", prefix, rc, strings.TrimSpace(errb.String()))
	}

	var res struct {
		Limit int               `json:"limit"`
		Keys  map[string]string `json:"keys"`
	}

	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return 0, nil, fmt.Errorf("config-key dump %s: %w", prefix, err)
	}

	return res.Limit, res.Keys, nil
}

func (c *execKeys) exec(ctx context.Context, argv []string, input []byte, stdout, stderr *bytes.Buffer) (int, error) {
	nodes := []string{c.node}

	for _, h := range c.o.St.Hosts {
		if h.Addr != c.node {
			nodes = append(nodes, h.Addr)
		}
	}

	var lastErr error

	for _, n := range nodes {
		stdout.Reset()
		stderr.Reset()

		rc, _, err := c.o.execAdmin(ctx, n, argv, input, stdout, stderr)
		if errors.Is(err, talos.ErrExecNotStarted) {
			lastErr = err

			continue // nothing ran on this host
		}

		if err == nil {
			c.node = n
		}

		return rc, err
	}

	return 0, fmt.Errorf("no host with a running Ceph container for the cluster state: %w", lastErr)
}

// mutate runs set and rm operations in order in one librados process.
const mutateScript = `
import json, sys, rados
r = rados.Rados(conffile='/etc/ceph/ceph.conf')
r.conf_parse_env()
r.connect()
try:
    for line in sys.stdin:
        op = json.loads(line)
        if op['op'] == 'set':
            ret, _, outs = r.mon_command(json.dumps({'prefix': 'config-key set', 'key': op['key']}), op['value'].encode())
        else:
            ret, _, outs = r.mon_command(json.dumps({'prefix': 'config-key rm', 'key': op['key']}), b'')
        if ret != 0:
            sys.stderr.write('%s %s: %s (%d)\n' % (op['op'], op['key'], outs, ret))
            sys.exit(1)
finally:
    r.shutdown()
`

func (c *execKeys) Mutate(ctx context.Context, ops []store.Op) error {
	ctx, cancel := context.WithTimeout(ctx, configKeyTimeout)
	defer cancel()

	var in bytes.Buffer

	enc := json.NewEncoder(&in)
	for _, op := range ops {
		line := map[string]string{"op": "set", "key": op.Key, "value": op.Value}
		if op.Remove {
			line = map[string]string{"op": "rm", "key": op.Key}
		}

		if err := enc.Encode(line); err != nil {
			return err
		}
	}

	var errb bytes.Buffer

	rc, err := c.exec(ctx, []string{"python3", "-c", mutateScript}, in.Bytes(), &errb, &errb)
	if err != nil {
		return err
	}

	if rc != 0 {
		return fmt.Errorf("config-key update: rc %d: %s", rc, strings.TrimSpace(errb.String()))
	}

	return nil
}
