"""The module's side of the agent channel (plan 03, items 1, 2, 3 and 5).

- Leadership: the module captures its own gid once a fresh `mgr dump` from the
  mons shows this mgr active, and heartbeats its local agent every 5 seconds.
- Confirmations: an agent sends a fresh challenge before it changes its node; the
  module answers only after a fresh `mgr dump` shows the captured gid still
  active, and signs the exact payload bytes with its server key.
- Bridge: the local agent (the leader) runs allowlisted mon commands with the
  mgr's credentials, each with a deadline; a call that misses it is "outcome
  unknown" and its late completion is kept.

Wire format version 1, shared with internal/wire (Go). Everything here is
mutual TLS on port 4722 with agent-CA certificates whose identity is checked.
"""
import base64
import hashlib
import json
import re
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

WIRE_VERSION = 1
BRIDGE_PORT = 4722
MAX_BODY = 64 << 10
# the agent counts the 10s confirmation validity from sending its challenge
CONFIRM_DEADLINE = 5.0
MGR_DUMP_DEADLINE = 5.0
MAX_BRIDGE_CALLS = 8
MAX_BRIDGE_DEADLINE = 60.0
LATE_KEEP = 3600.0
HEARTBEAT_INTERVAL = 5.0

ID_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
HEX_RE = re.compile(r'\A[0-9a-f]{16,128}\Z')


class Outcome:
    """A mon command's completion, shaped like mgr_module.CommandResult (ev, r, outb,
    outs); complete() may come after the deadline. Used by tests and fakes."""

    def __init__(self) -> None:
        self.ev = threading.Event()
        self.r = 0
        self.outb = ''
        self.outs = ''
        self.sent = time.monotonic()

    def complete(self, r: int, outb: str, outs: str) -> None:
        self.r, self.outb, self.outs = r, outb, outs
        self.ev.set()


# Bridge allowlist: call name -> function(args) -> mon command dict. Argument
# shapes are fixed; anything else is refused before it is sent. Later steps add
# config-key and auth calls here.
def _no_args(prefix: str) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    def build(args: Dict[str, Any]) -> Dict[str, Any]:
        if args:
            raise ValueError('%s takes no arguments' % prefix)
        return {'prefix': prefix, 'format': 'json'}
    return build


ALLOWLIST: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    'status': _no_args('status'),
    'health': _no_args('health'),
    'mgr dump': _no_args('mgr dump'),
}


class Leadership:
    """The captured incarnation: this mgr's gid once the mons show it active."""

    def __init__(self, mgr_id: str, mon_command: Callable[[Dict[str, Any], float], Outcome]) -> None:
        self.mgr_id = mgr_id
        self.mon_command = mon_command
        self.lock = threading.Lock()
        self.gid: Optional[int] = None
        self.epoch: Optional[int] = None

    def fresh_map(self) -> Optional[Dict[str, Any]]:
        out = self.mon_command({'prefix': 'mgr dump', 'format': 'json'}, MGR_DUMP_DEADLINE)
        if not out.ev.is_set() or out.r != 0:
            return None
        return json.loads(out.outb)

    def capture(self) -> bool:
        """Capture the gid if the mons show this mgr active; True once captured."""
        with self.lock:
            if self.gid is not None:
                return True
        m = self.fresh_map()
        if m is None or m.get('active_name') != self.mgr_id or not m.get('available', True):
            return False
        with self.lock:
            if self.gid is None:
                self.gid, self.epoch = int(m['active_gid']), int(m['epoch'])
        return True

    def captured(self) -> Optional[Tuple[int, int]]:
        with self.lock:
            return None if self.gid is None else (self.gid, self.epoch or 0)

    def still_active(self) -> bool:
        """A fresh check from the mons that the captured gid is the active one."""
        cap = self.captured()
        if cap is None:
            return False
        m = self.fresh_map()
        return m is not None and m.get('active_gid') == cap[0] and m.get('active_name') == self.mgr_id


def sign(key_pem: bytes, payload: bytes) -> bytes:
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError('mgr server key is not an EC key')
    return key.sign(payload, ec.ECDSA(hashes.SHA256()))


def check_confirm_request(req: Any, fsid: str, peer_name: str) -> Dict[str, Any]:
    """Validate a confirmation challenge; raises ValueError on anything unexpected."""
    if not isinstance(req, dict) or req.get('version') != WIRE_VERSION:
        raise ValueError('unknown wire version')
    want = {'fsid': str, 'session': str, 'host': str, 'revision': int, 'operation': str,
            'inputs_hash': str, 'challenge': str, 'version': int}
    if set(req) != set(want) or any(not isinstance(req[k], t) or isinstance(req[k], bool) for k, t in want.items()):
        raise ValueError('malformed confirmation request')
    if req['fsid'] != fsid or req['host'] != peer_name:
        raise ValueError('confirmation for another cluster or host')
    if not HEX_RE.match(req['session']) or not HEX_RE.match(req['challenge']) \
            or not re.match(r'\A[0-9a-f]{64}\Z', req['inputs_hash']) or not ID_RE.match(req['operation']) \
            or req['revision'] < 0:
        raise ValueError('malformed confirmation request')
    return req


class Channel:
    """The module's server on port 4722: confirmations and the bridge."""

    def __init__(self, fsid: str, mgr_id: str, leadership: Leadership,
                 mon_command: Callable[[Dict[str, Any], float], Outcome],
                 server_ctx: ssl.SSLContext, server_key: bytes,
                 require_identity: Callable[..., str], log: Any) -> None:
        self.fsid = fsid
        self.mgr_id = mgr_id
        self.leadership = leadership
        self.mon_command = mon_command
        self.server_key = server_key
        self.require_identity = require_identity
        self.log = log
        self.bridge_slots = threading.BoundedSemaphore(MAX_BRIDGE_CALLS)
        self.late_lock = threading.Lock()
        self.late: Dict[str, Tuple[Outcome, float]] = {}
        self.server: Optional[ThreadingHTTPServer] = None
        self.ctx = server_ctx

    # --- confirmation -------------------------------------------------------

    def confirm(self, req: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        cap = self.leadership.captured()
        if cap is None:
            return 503, {'error': 'no captured incarnation'}
        if not self.leadership.still_active():
            return 409, {'error': 'not the active mgr'}
        payload = json.dumps({
            'version': WIRE_VERSION, 'fsid': self.fsid, 'mgr': self.mgr_id, 'gid': cap[0],
            'session': req['session'], 'host': req['host'], 'revision': req['revision'],
            'operation': req['operation'], 'inputs_hash': req['inputs_hash'], 'challenge': req['challenge'],
        }, sort_keys=True, separators=(',', ':')).encode()
        sig = sign(self.server_key, payload)
        return 200, {'payload': base64.b64encode(payload).decode(), 'signature': base64.b64encode(sig).decode()}

    # --- bridge -------------------------------------------------------------

    def bridge(self, req: Any) -> Tuple[int, Dict[str, Any]]:
        if not isinstance(req, dict) or req.get('version') != WIRE_VERSION:
            return 400, {'error': 'unknown wire version'}
        call, args, deadline, dispatch = req.get('call'), req.get('args', {}), req.get('deadline'), req.get('dispatch_id')
        if call not in ALLOWLIST or not isinstance(args, dict) or not isinstance(dispatch, str) or not HEX_RE.match(dispatch) \
                or not isinstance(deadline, (int, float)) or isinstance(deadline, bool) or not 0 < deadline <= MAX_BRIDGE_DEADLINE \
                or set(req) - {'version', 'call', 'args', 'deadline', 'dispatch_id'}:
            return 400, {'error': 'call not allowed or malformed'}
        try:
            cmd = ALLOWLIST[call](args)
        except ValueError as e:
            return 400, {'error': str(e)}
        if self.leadership.captured() is None:
            return 503, {'error': 'no captured incarnation'}
        with self.late_lock:
            self._expire_late()
            if dispatch in self.late:
                return 409, {'error': 'dispatch id already used'}
        if not self.bridge_slots.acquire(blocking=False):
            return 429, {'error': 'too many outstanding bridge calls'}
        handed_off = False
        try:
            out = self.mon_command(cmd, float(deadline))
            if out.ev.is_set():
                return 200, {'outcome': 'done', 'r': out.r, 'out': out.outb, 'outs': out.outs}
            # keep the completion: the caller reconciles it later; its slot stays taken until it completes
            with self.late_lock:
                self.late[dispatch] = (out, time.monotonic())
            threading.Thread(target=self._release_when_done, args=(out,), daemon=True).start()
            handed_off = True
            return 200, {'outcome': 'unknown'}
        finally:
            if not handed_off:
                self.bridge_slots.release()

    def _release_when_done(self, out: Outcome) -> None:
        out.ev.wait(LATE_KEEP)
        self.bridge_slots.release()

    def late_result(self, dispatch: str) -> Tuple[int, Dict[str, Any]]:
        with self.late_lock:
            self._expire_late()
            entry = self.late.get(dispatch)
        if entry is None:
            return 404, {'error': 'unknown dispatch id'}
        out = entry[0]
        if not out.ev.is_set():
            return 200, {'outcome': 'unknown'}
        return 200, {'outcome': 'done', 'r': out.r, 'out': out.outb, 'outs': out.outs}

    def _expire_late(self) -> None:
        now = time.monotonic()
        for k in [k for k, (_, t) in self.late.items() if now - t > LATE_KEEP]:
            del self.late[k]

    # --- server -------------------------------------------------------------

    def handler(self) -> Any:
        channel = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, fmt: str, *args: Any) -> None:  # requests are not logged
                pass

            def reply(self, code: int, body: Dict[str, Any]) -> None:
                b = json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def peer(self) -> str:
                return channel.require_identity(self.connection.getpeercert(), channel.fsid, 'agent')

            def body(self) -> Any:
                n = int(self.headers.get('Content-Length') or 0)
                if n <= 0 or n > MAX_BODY:
                    raise ValueError('bad request size')
                return json.loads(self.rfile.read(n))

            def do_POST(self) -> None:
                try:
                    name = self.peer()
                except Exception as e:
                    self.reply(403, {'error': str(e)})
                    return
                try:
                    req = self.body()
                except Exception as e:
                    self.reply(400, {'error': str(e)})
                    return
                try:
                    if self.path == '/v1/confirm':
                        try:
                            req = check_confirm_request(req, channel.fsid, name)
                        except ValueError as e:
                            self.reply(400, {'error': str(e)})
                            return
                        self.reply(*channel.confirm(req))
                    elif self.path == '/v1/bridge':
                        if name != channel.mgr_id:  # only the local agent, the leader
                            self.reply(403, {'error': 'the bridge serves the local agent only'})
                            return
                        self.reply(*channel.bridge(req))
                    else:
                        self.reply(404, {'error': 'not found'})
                except Exception as e:
                    channel.log.exception('agent channel request failed')
                    self.reply(500, {'error': e.__class__.__name__})

            def do_GET(self) -> None:
                try:
                    name = self.peer()
                except Exception as e:
                    self.reply(403, {'error': str(e)})
                    return
                m = re.match(r'\A/v1/bridge/([0-9a-f]{16,128})\Z', self.path)
                if m is None or name != channel.mgr_id:
                    self.reply(404, {'error': 'not found'})
                    return
                self.reply(*channel.late_result(m.group(1)))

        return Handler

    def start(self, port: int = BRIDGE_PORT) -> None:
        srv = ThreadingHTTPServer(('', port), self.handler())
        srv.daemon_threads = True
        srv.socket = self.ctx.wrap_socket(srv.socket, server_side=True)
        self.server = srv
        threading.Thread(target=srv.serve_forever, name='talos-channel', daemon=True).start()

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()


def server_context(ca_file: str, cert_file: str, key_file: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca_file)
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


def new_dispatch_id() -> str:
    return secrets.token_hex(16)


def inputs_hash(inputs: bytes) -> str:
    return hashlib.sha256(inputs).hexdigest()


def read(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()


def heartbeat_body(fsid: str, mgr_id: str, gid: int, epoch: int, nonce: str) -> bytes:
    return json.dumps({'version': WIRE_VERSION, 'fsid': fsid, 'mgr': mgr_id, 'gid': gid, 'epoch': epoch, 'session': nonce},
                      sort_keys=True).encode()
