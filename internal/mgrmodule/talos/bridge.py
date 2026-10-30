"""The module's side of the agent channel (plan 03, items 1, 2, 3 and 5).

- Leadership: at serve() start the module takes its own gid from the mgr map this
  process was activated with, and captures it once a fresh `mgr dump` from the
  mons agrees. It heartbeats its local agent every 5 seconds.
- Confirmations: an agent sends a fresh challenge before it changes its node; the
  module answers only after a fresh `mgr dump` shows the captured gid still
  active, and signs the exact payload bytes with its server key.
- Bridge: the local agent (the leader) runs allowlisted mon commands with the
  mgr's credentials, each with a deadline; a call that misses it is "outcome
  unknown", and every call's outcome is kept by its dispatch id.

Mon commands are sent from persistent worker threads that live until each
command they sent has completed: Ceph completes a command on the thread state of
the thread that sent it. Wire format version 1, shared with internal/wire (Go).
Everything here is mutual TLS on port 4722 with agent-CA certificates whose
identity is checked.
"""
import base64
import hashlib
import http.client
import json
import queue
import re
import secrets
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

WIRE_VERSION = 1
BRIDGE_PORT = 4722
MAX_BODY = 64 << 10
MGR_DUMP_DEADLINE = 5.0
HEARTBEAT_INTERVAL = 5.0
# one connection carries one request; handshake, request and answer within this
REQUEST_DEADLINE = 15.0  # more than MAX_BRIDGE_DEADLINE, so an answer fits
MAX_CONNECTIONS = 16
# outstanding mon commands (sent, not yet completed), per purpose
BRIDGE_COMMANDS = 8
LEADERSHIP_COMMANDS = 2
# a bridge call answers within its connection's deadline; longer ones are
# fetched later by dispatch id
MAX_BRIDGE_DEADLINE = 10.0
# kept outcomes: pending ones are kept until they complete, completed ones for
# LATE_KEEP; at most MAX_RECORDS, each output at most MAX_OUTPUT bytes
LATE_KEEP = 3600.0
MAX_RECORDS = 64
MAX_OUTPUT = 256 << 10
SHUTDOWN_WAIT = 5.0

ID_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
HEX_RE = re.compile(r'\A[0-9a-f]{16,128}\Z')


class Job:
    """One mon command; complete() may come after any deadline."""

    def __init__(self, cmd: Dict[str, Any]) -> None:
        self.cmd = cmd
        self.ev = threading.Event()
        self.r = 0
        self.outb = ''
        self.outs = ''
        self.too_large = False

    def complete(self, r: int, outb: str, outs: str) -> None:
        self.r, self.outb, self.outs = r, outb, outs
        self.ev.set()


class Commands:
    """Persistent workers that send mon commands and wait for their completion.

    A worker never ends while a command it sent is outstanding, so Ceph's native
    completion always finds the sending thread's state. At most `workers`
    commands are outstanding; submit() refuses more instead of queueing."""

    def __init__(self, send: Callable[[Any, str], None], new_result: Callable[[], Any], workers: int, name: str) -> None:
        self.send = send
        self.new_result = new_result
        self.lock = threading.Lock()
        self.stopped = False
        self.slots = threading.BoundedSemaphore(workers)
        self.jobs: 'queue.Queue[Optional[Job]]' = queue.Queue()
        self.threads = [threading.Thread(target=self.work, name='%s-%d' % (name, i), daemon=True) for i in range(workers)]
        for t in self.threads:
            t.start()

    def work(self) -> None:
        while True:
            job = self.jobs.get()
            if job is None:
                return
            try:
                res = self.new_result()
                self.send(res, json.dumps(job.cmd))
                res.ev.wait()  # until Ceph completes it, however long that takes
                if len(res.outb or '') + len(res.outs or '') > MAX_OUTPUT:
                    job.too_large = True  # not kept: only the return code
                    job.complete(res.r, '', '')
                else:
                    job.complete(res.r, res.outb, res.outs)
            except Exception as e:  # a send that fails completes with an error
                job.complete(-5, '', 'send failed: %s' % e)
            finally:
                res = None  # an idle worker keeps no result
                self.slots.release()

    def submit(self, cmd: Dict[str, Any]) -> Optional[Job]:
        with self.lock:  # never behind the stop sentinels
            if self.stopped or not self.slots.acquire(blocking=False):
                return None
            job = Job(cmd)
            self.jobs.put(job)
        return job

    def stop(self) -> None:
        # idle workers end; busy ones end once their command completed
        with self.lock:
            self.stopped = True
            for _ in self.threads:
                self.jobs.put(None)


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
    """This process's incarnation: its gid from the map it was activated with,
    captured once the mons agree."""

    def __init__(self, mgr_id: str, activation_map: Optional[Dict[str, Any]], commands: Commands) -> None:
        self.mgr_id = mgr_id
        self.commands = commands
        self.lock = threading.Lock()
        # the candidate is taken once, from this process's own map at activation:
        # a later map could already show a successor with the same name
        m = activation_map or {}
        self.candidate: Optional[int] = int(m['active_gid']) if m.get('active_name') == mgr_id and m.get('active_gid') else None
        self.gid: Optional[int] = None
        self.epoch: Optional[int] = None

    def fresh_map(self) -> Optional[Dict[str, Any]]:
        job = self.commands.submit({'prefix': 'mgr dump', 'format': 'json'})
        if job is None or not job.ev.wait(MGR_DUMP_DEADLINE) or job.r != 0:
            return None
        return json.loads(job.outb)

    def capture(self) -> bool:
        """Capture the candidate once a fresh map shows it active; True once captured."""
        with self.lock:
            if self.gid is not None:
                return True
        if self.candidate is None:
            return False
        m = self.fresh_map()
        if m is None or m.get('active_gid') != self.candidate or m.get('active_name') != self.mgr_id:
            return False
        with self.lock:
            if self.gid is None:
                self.gid, self.epoch = self.candidate, int(m['epoch'])
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


class Record:
    """A bridge call's outcome, kept by dispatch id."""

    def __init__(self) -> None:
        self.job: Optional[Job] = None
        self.done_at: Optional[float] = None


class Server(ThreadingHTTPServer):
    """One request per connection; the TLS handshake happens in the connection's
    own thread, within the connection's absolute deadline, and connections are
    admitted only while there is room."""

    daemon_threads = True

    def __init__(self, addr: Tuple[str, int], handler: Any, ctx: ssl.SSLContext) -> None:
        super().__init__(addr, handler)
        self.ctx = ctx
        self.admit = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.open: Set[socket.socket] = set()

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.admit.acquire(blocking=False):
            request.close()
            return
        # registered here, in the accept thread, under the lock close_all takes:
        # a connection is either closed by close_all or refused here.
        # wrap_socket detaches the socket; a duplicate still shuts the connection down
        try:
            ctrl = request.dup()
        except OSError:
            request.close()
            self.admit.release()
            return
        with self.lock:
            if self.closed.is_set():
                for c in (request, ctrl):
                    c.close()
                self.admit.release()
                return
            self.open.add(ctrl)
        try:
            t = threading.Thread(target=self.process_request_thread, args=(request, client_address, ctrl), daemon=True)
            t.start()
        except Exception:
            with self.lock:
                self.open.discard(ctrl)
            for c in (request, ctrl):
                c.close()
            self.admit.release()

    def process_request_thread(self, request: Any, client_address: Any, ctrl: Any = None) -> None:  # type: ignore[override]
        conn: socket.socket = request

        def cut() -> None:
            try:
                ctrl.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(REQUEST_DEADLINE, cut)
        timer.daemon = True
        timer.start()
        try:
            conn.settimeout(REQUEST_DEADLINE)
            tls = self.ctx.wrap_socket(conn, server_side=True)
            self.finish_request(tls, client_address)
        except Exception:
            pass
        finally:
            timer.cancel()
            with self.lock:
                self.open.discard(ctrl)
            for c in (conn, ctrl):
                try:
                    c.close()
                except OSError:
                    pass
            self.admit.release()

    def close_all(self) -> None:
        with self.lock:
            self.closed.set()
            conns = list(self.open)
        for c in conns:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Channel:
    """The module's server on port 4722: confirmations and the bridge."""

    def __init__(self, fsid: str, mgr_id: str, leadership: Leadership, bridge_commands: Commands,
                 server_ctx: Optional[ssl.SSLContext], server_key: bytes,
                 require_identity: Callable[..., str], log: Any) -> None:
        self.fsid = fsid
        self.mgr_id = mgr_id
        self.leadership = leadership
        self.commands = bridge_commands
        self.server_key = server_key
        self.require_identity = require_identity
        self.log = log
        self.ctx = server_ctx
        self.lock = threading.Lock()
        self.records: Dict[str, Record] = {}
        self.server: Optional[Server] = None

    # --- confirmation -------------------------------------------------------

    def confirm(self, req: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        cap = self.leadership.captured()
        if cap is None:
            return 503, {'error': 'no captured incarnation'}
        if not self.leadership.still_active():
            return 409, {'error': 'not confirmed as the active mgr'}
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
        rec = Record()
        with self.lock:
            self._expire()
            if dispatch in self.records:
                return 409, {'error': 'dispatch id already used; fetch its outcome'}
            if len(self.records) >= MAX_RECORDS:
                return 429, {'error': 'too many kept outcomes'}
            self.records[dispatch] = rec  # registered before anything is sent
        job = self.commands.submit(cmd)
        if job is None:
            with self.lock:
                del self.records[dispatch]  # nothing was sent
            return 429, {'error': 'too many outstanding bridge calls'}
        with self.lock:
            rec.job = job
        if job.ev.wait(float(deadline)):
            return 200, self._outcome(dispatch, rec)
        return 200, {'outcome': 'unknown'}

    def _outcome(self, dispatch: str, rec: Record) -> Dict[str, Any]:
        job = rec.job
        if job is None or not job.ev.is_set():
            return {'outcome': 'unknown'}
        with self.lock:
            if rec.done_at is None:
                rec.done_at = time.monotonic()
        if job.too_large:
            return {'outcome': 'done', 'r': job.r, 'error': 'output larger than %d bytes' % MAX_OUTPUT}
        return {'outcome': 'done', 'r': job.r, 'out': job.outb, 'outs': job.outs}

    def outcome(self, dispatch: str) -> Tuple[int, Dict[str, Any]]:
        with self.lock:
            self._expire()
            rec = self.records.get(dispatch)
        if rec is None:
            return 404, {'error': 'unknown dispatch id'}
        return 200, self._outcome(dispatch, rec)

    def _expire(self) -> None:
        """Drop completed outcomes after LATE_KEEP; pending ones stay. Under self.lock."""
        now = time.monotonic()
        for k, rec in list(self.records.items()):
            if rec.job is not None and rec.job.ev.is_set() and rec.done_at is None:
                rec.done_at = now
            if rec.done_at is not None and now - rec.done_at > LATE_KEEP:
                del self.records[k]

    # --- server -------------------------------------------------------------

    def handler(self) -> Any:
        channel = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'  # one request per connection

            def log_message(self, fmt: str, *args: Any) -> None:  # requests are not logged
                pass

            def reply(self, code: int, body: Dict[str, Any]) -> None:
                b = json.dumps(body).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(b)))
                self.send_header('Connection', 'close')
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
                if channel.closing():
                    self.reply(503, {'error': 'shutting down'})
                    return
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
                if channel.closing():
                    self.reply(503, {'error': 'shutting down'})
                    return
                try:
                    name = self.peer()
                except Exception as e:
                    self.reply(403, {'error': str(e)})
                    return
                m = re.match(r'\A/v1/bridge/([0-9a-f]{16,128})\Z', self.path)
                if m is None or name != channel.mgr_id:
                    self.reply(404, {'error': 'not found'})
                    return
                self.reply(*channel.outcome(m.group(1)))

        return Handler

    def closing(self) -> bool:
        return self.server is None or self.server.closed.is_set()

    def start(self, port: int = BRIDGE_PORT) -> None:
        if self.ctx is None:
            raise ValueError('no TLS context')
        srv = Server(('', port), self.handler(), self.ctx)
        self.server = srv
        threading.Thread(target=srv.serve_forever, kwargs={'poll_interval': 0.5}, name='talos-channel', daemon=True).start()

    def stop(self) -> None:
        """Close admission and every open connection, stop accepting."""
        srv = self.server
        if srv is None:
            return
        srv.close_all()
        srv.shutdown()
        srv.server_close()


def server_context(ca_file: str, cert_file: str, key_file: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca_file)
    ctx.load_cert_chain(cert_file, key_file)
    return ctx


def post_json(addr: str, port: int, ctx: ssl.SSLContext, path: str, body: bytes, deadline: float,
              check_peer: Callable[[Optional[Dict[str, Any]]], Any], max_reply: int = 4096) -> Tuple[int, bytes]:
    """POST with an absolute deadline over connect, handshake, request and reply;
    check_peer sees the verified peer certificate before anything is sent."""
    end = time.monotonic() + deadline

    def left() -> float:
        r = end - time.monotonic()
        if r <= 0:
            raise TimeoutError('no reply within %.0fs' % deadline)
        return r

    raw = socket.create_connection((addr, port), timeout=left())
    # wrap_socket detaches raw; the duplicate lets the deadline cut the connection in any phase
    ctrl = raw.dup()
    expired = threading.Event()

    def cut() -> None:
        expired.set()
        try:
            ctrl.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    timer = threading.Timer(left(), cut)
    timer.daemon = True
    timer.start()
    conn = http.client.HTTPSConnection(addr, port, context=ctx, timeout=deadline)
    try:
        raw.settimeout(left())
        tls = ctx.wrap_socket(raw, server_hostname=addr)
        conn.sock = tls
        check_peer(tls.getpeercert())
        tls.settimeout(left())
        conn.request('POST', path, body=body, headers={'Content-Type': 'application/json'})
        resp = conn.getresponse()
        data = resp.read(max_reply + 1)
        if len(data) > max_reply:
            raise ValueError('reply larger than %d bytes' % max_reply)
        return resp.status, data
    except Exception:
        if expired.is_set():
            raise TimeoutError('no reply within %.0fs' % deadline)
        raise
    finally:
        timer.cancel()
        conn.close()
        for c in (raw, ctrl):
            try:
                c.close()
            except OSError:
                pass


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
