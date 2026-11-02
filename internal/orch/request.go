package orch

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"
)

// requestScript runs in a Ceph container with the admin key in CEPH_ARGS: it
// parses a ceph orch command's words with the command descriptions the mon
// serves, the mgr's included (as the ceph CLI does), hashes the command with its input, and sends it once
// per request uuid through `ceph orch talos request` (plan 03, step 7). The
// request comes as JSON on stdin, after the key.
const requestScript = `
import hashlib, json, sys
import rados
from ceph_argparse import json_command, parse_json_funcsigs, validate_command
req = json.load(sys.stdin)
c = rados.Rados(conffile='/etc/ceph/ceph.conf')
c.conf_parse_env()
c.connect(timeout=60)
ret, out, err = json_command(c, target=('mon', ''), prefix='get_command_descriptions')
if ret != 0:
    sys.exit('the command descriptions: %s' % err)
cmd = validate_command(parse_json_funcsigs(out.decode(), 'cli'), ['orch'] + req['words'])
if not cmd:
    sys.exit(22)
cmd = dict(cmd)
cmd.pop('target', None)
body = {'cmd': cmd, 'inbuf': req.get('inbuf')}
inputs = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
ret, out, err = json_command(c, target=('mon-mgr', ''), prefix='orch talos request',
                             argdict={'request': req['request'], 'inputs': inputs}, inbuf=json.dumps(body).encode(), timeout=120)
for f, t in ((sys.stdout, out.decode()), (sys.stderr, err)):
    f.write(t if not t or t.endswith('\n') else t + '\n')
sys.exit(-ret if ret < 0 else ret)
`

// newRequest is a random request uuid.
func newRequest() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// Orch runs a ceph orch command once per request (cephadm-talos orch): a
// retry with the same request uuid returns the operation accepted the first
// time, through any mgr; input (a spec, e.g. with the operator's RGW key) goes
// over stdin after the admin key, never on a command line.
func (o *Orch) Orch(ctx context.Context, request string, words []string, input []byte) (int, error) {
	if request == "" {
		var err error
		if request, err = newRequest(); err != nil {
			return 1, err
		}
	}

	o.printf("request %s\n", request)

	req := map[string]any{"request": request, "words": words}
	if input != nil {
		req["inbuf"] = string(input)
	}

	b, err := json.Marshal(req)
	if err != nil {
		return 1, err
	}

	adm, err := o.confirmedAdminHost()
	if err != nil {
		return 1, err
	}

	res, err := o.jobInput(ctx, adm.Addr, "python3 -c "+shellQuote(requestScript), b, 3*time.Minute)
	fmt.Fprint(o.Out, res.Output)

	if err != nil && res.RC != 0 {
		return res.RC, nil
	}

	return res.RC, err
}
