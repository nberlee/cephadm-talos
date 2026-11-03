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
import os
import queue
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import ledger

WIRE_VERSION = 1
# confirmations, for every agent; the bridge, for the local agent only, on loopback
CONFIRM_PORT = 4722
BRIDGE_PORT = 4723
BRIDGE_ADDR = '127.0.0.1'
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
# kept outcomes, by dispatch id: pending ones until they complete; completed
# ones for LATE_KEEP if their call's answer was "unknown", for ANSWERED_KEEP if
# the call answered "done" (in case that answer was lost), not at all for an
# answered read-only call, which can be repeated. At most MAX_RECORDS, each
# output at most MAX_OUTPUT bytes.
LATE_KEEP = 3600.0
ANSWERED_KEEP = 60.0
MAX_RECORDS = 64
MAX_OUTPUT = 256 << 10
SHUTDOWN_WAIT = 5.0

ID_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
HEX_RE = re.compile(r'\A[0-9a-f]{16,128}\Z')


class Job:
    """One mon command; complete() may come after any deadline."""

    def __init__(self, cmd: Dict[str, Any], reduce: Optional[Callable[[str], str]] = None) -> None:
        self.cmd = cmd
        # reduce shrinks the output before it is kept (a dump to its keys)
        self.reduce = reduce
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
                if job.reduce is not None and res.r == 0:
                    try:
                        res.outb = job.reduce(res.outb or '')
                    except Exception as e:
                        job.complete(-22, '', 'unexpected output: %s' % e)  # EINVAL
                        continue
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

    def submit(self, cmd: Dict[str, Any], reduce: Optional[Callable[[str], str]] = None) -> Optional[Job]:
        with self.lock:  # never behind the stop sentinels
            if self.stopped or not self.slots.acquire(blocking=False):
                return None
            job = Job(cmd, reduce)
            self.jobs.put(job)
        return job

    def stop(self) -> None:
        # idle workers end; busy ones end once their command completed
        with self.lock:
            self.stopped = True
            for _ in self.threads:
                self.jobs.put(None)


# Bridge allowlist: call name -> function(args) -> mon command dict. Argument
# shapes are fixed; anything else is refused before it is sent.
def _args(args: Dict[str, Any], names: Set[str]) -> None:
    if set(args) != names:
        raise ValueError('arguments must be exactly %s' % sorted(names))


def _no_args(prefix: str) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    def build(args: Dict[str, Any]) -> Dict[str, Any]:
        if args:
            raise ValueError('%s takes no arguments' % prefix)
        return {'prefix': prefix, 'format': 'json'}
    return build


# the leader's store: config-key entries of cephadm-talos only (internal/store)
STORE_PREFIX_FULL = 'mgr/cephadm/talos/'
STORE_KEY_RE = re.compile(r'\Amgr/cephadm/talos/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\Z')
STORE_DUMP_RE = re.compile(r'\Amgr/cephadm/talos/(?:[A-Za-z0-9._-]+/)*\Z')
MAX_KEY = 256
# one value per call, below the request body limit with room for the envelope
MAX_VALUE = 48 << 10


def _store_key(v: Any, pattern: 're.Pattern[str]') -> str:
    if not isinstance(v, str) or len(v) > MAX_KEY or not pattern.match(v) \
            or any(p in ('.', '..') for p in v.split('/')):
        raise ValueError('key outside %s' % STORE_PREFIX_FULL)
    return v


# a page of 'config-key keys' stays well below MAX_OUTPUT
KEYS_PAGE = 128 << 10


def _config_key_keys(args: Dict[str, Any]) -> Dict[str, Any]:
    _args(args, {'prefix', 'after'})
    prefix = _store_key(args['prefix'], STORE_DUMP_RE)
    after = args['after']
    if after != '' and (_store_key(after, STORE_KEY_RE) and not after.startswith(prefix)):
        raise ValueError('after must be empty or a key below the prefix')
    # config-key ls returns keys only; prefix and page are applied in the mgr (REDUCE)
    return {'prefix': 'config-key ls', 'format': 'json'}


def _keys_page(prefix: str, after: str) -> Callable[[str], str]:
    """config-key ls reduced to one page of the sorted keys below prefix, after
    the key `after`: {"keys": [...], "more": bool}."""
    def reduce(out: str) -> str:
        keys = json.loads(out)
        if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
            raise ValueError('config-key ls is not a list of keys')
        page: List[str] = []
        size = 0
        rest = sorted(k for k in keys if k.startswith(prefix) and k > after)
        for k in rest:
            size += len(k) + 4  # quotes, comma, space
            if size > KEYS_PAGE:
                break
            page.append(k)
        return json.dumps({'keys': page, 'more': len(page) < len(rest)})
    return reduce


def _config_key_get(args: Dict[str, Any]) -> Dict[str, Any]:
    _args(args, {'key'})
    return {'prefix': 'config-key get', 'key': _store_key(args['key'], STORE_KEY_RE)}


def _config_key_set(args: Dict[str, Any]) -> Dict[str, Any]:
    _args(args, {'key', 'value'})
    v = args['value']
    if not isinstance(v, str) or len(v.encode()) > MAX_VALUE:
        raise ValueError('value must be a string of at most %d bytes' % MAX_VALUE)
    return {'prefix': 'config-key set', 'key': _store_key(args['key'], STORE_KEY_RE), 'val': v}


def _config_key_rm(args: Dict[str, Any]) -> Dict[str, Any]:
    _args(args, {'key'})
    return {'prefix': 'config-key rm', 'key': _store_key(args['key'], STORE_KEY_RE)}


def _entry_limit(args: Dict[str, Any]) -> Dict[str, Any]:
    if args:
        raise ValueError('config get takes no arguments')
    return {'prefix': 'config get', 'who': 'mon', 'key': 'mon_config_key_max_entry_size', 'format': 'json'}


# keys the leader renders into daemon documents (item 4): never client.admin
DAEMON_ID_RE = r'[a-z0-9][a-z0-9-]{0,62}'
AUTH_GET_RE = re.compile(r'\A(?:mon\.|client\.bootstrap-osd|osd\.(?:0|[1-9][0-9]{0,8})|mgr\.%s|client\.rgw\.%s)\Z' % (DAEMON_ID_RE, DAEMON_ID_RE))
# identities the leader creates, with the caps the CLI gives them (internal/orch)
CREATE_CAPS = {
    'mgr': ['mon', 'profile mgr', 'osd', 'allow *', 'mds', 'allow *'],
    'client.rgw': ['mon', 'allow rw', 'osd', 'allow rwx', 'mgr', 'allow rw'],
}
CREATE_RE = re.compile(r'\A(mgr|client\.rgw)\.%s\Z' % DAEMON_ID_RE)


def _auth_get(args: Dict[str, Any]) -> Dict[str, Any]:
    # client.bootstrap-osd names the OSD creation it serves
    _args(args, {'entity', 'operation'} if args.get('entity') == 'client.bootstrap-osd' else {'entity'})
    if 'operation' in args and not (isinstance(args['operation'], str) and re.match(r'\Aop-[0-9a-f]{16}\Z', args['operation'])):
        raise ValueError('not an operation id')
    e = args['entity']
    if not isinstance(e, str) or not AUTH_GET_RE.match(e):
        raise ValueError('entity not allowed')
    return {'prefix': 'auth get', 'entity': e, 'format': 'json'}


def _auth_get_or_create(args: Dict[str, Any]) -> Dict[str, Any]:
    _args(args, {'entity', 'operation'})
    e = args['entity']
    m = CREATE_RE.match(e) if isinstance(e, str) else None
    if m is None or not isinstance(args['operation'], str) or not re.match(r'\Aop-[0-9a-f]{16}\Z', args['operation']):
        raise ValueError('entity not allowed')
    return {'prefix': 'auth get-or-create', 'entity': e, 'caps': list(CREATE_CAPS[m.group(1)]), 'format': 'json'}


# Secrets the leader renders into documents (internal/state Secrets), below
# their own prefix: never the CA keys or the agents' keys. A host's mgr keys
# only for a host the inventory places a mgr on (Channel.bridge).
SECRET_PREFIX = 'cephadm-talos/secrets/'
SECRET_RE = re.compile(r'\A(?:host/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/mgr-(?:server|client)\.key|rgw/server\.key|rgw/vrrp'
                       r'|issued/(op-[0-9a-f]{16})/[0-9a-f]{16}/mgr-(?:server|client)\.key'
                       r'|(?:issued/op-[0-9a-f]{16}/[0-9a-f]{16}|user/op-[0-9a-f]{16})/rgw-server\.key'
                       r'|ingress/op-[0-9a-f]{16}/vrrp)\Z')


def _secret_get(args: Dict[str, Any]) -> Dict[str, Any]:
    _args(args, {'name'})
    n = args['name']
    if not isinstance(n, str) or not SECRET_RE.match(n):
        raise ValueError('secret not allowed')
    return {'prefix': 'config-key get', 'key': SECRET_PREFIX + n}


# the leader's view of the module's ledger (ledger.py): read in pages after a key
LEDGER_PAGE = 128 << 10


def _ledger(args: Dict[str, Any]) -> Dict[str, Any]:
    _args(args, {'after'})
    if not isinstance(args['after'], str) or len(args['after']) > MAX_KEY:
        raise ValueError('after must be a ledger key or empty')
    return {}  # answered by the module, not the mons


# the operator's approvals (internal/approval), signed on the workstation; the
# agents verify them, the module only finds the newest
APPROVAL_PREFIX = 'cephadm-talos/approvals/'
APPROVAL_KEY_RE = re.compile(r'\Acephadm-talos/approvals/\d{20}\Z')


def _approval(args: Dict[str, Any]) -> Dict[str, Any]:
    if args:
        raise ValueError('approval takes no arguments')
    return {}  # answered by the module (Channel.approval)


def _operation_with(*more: str) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    def build(args: Dict[str, Any]) -> Dict[str, Any]:
        _args(args, {'operation', *more})
        if not isinstance(args['operation'], str) or not re.match(r'\Aop-[0-9a-f]{16}\Z', args['operation']):
            raise ValueError('not an operation id')
        if 'serial' in more and not (isinstance(args['serial'], str) and re.match(r'\A[A-Za-z0-9._-]{1,64}\Z', args['serial'])
                                     and isinstance(args['link'], str) and re.match(r'\A/dev/disk/by-id/[A-Za-z0-9._:-]{1,200}\Z', args['link'])
                                     and isinstance(args['job'], str) and re.match(r'\A[0-9a-f]{16}\Z', args['job'])):
            raise ValueError('not a disk binding')
        if 'osd' in more and not (type(args['osd']) is int and 0 <= args['osd'] < 1 << 30):
            raise ValueError('not an OSD id')
        if 'gid' in more and not (type(args['gid']) is int and 0 < args['gid'] < 1 << 63):
            raise ValueError('not a mgr gid')
        if 'daemon' in more and not (isinstance(args['daemon'], str) and ledger.DAEMON_RE.match(args['daemon'])):
            raise ValueError('not a daemon name')
        if 'keep' in more and not (isinstance(args['keep'], str) and ledger.RGW_CERT_RE.match(args['keep'])):
            raise ValueError('not an RGW certificate id')
        return {}  # answered by the module (Channel.local)
    return build


_operation = _operation_with()


def _osd_dump(args: Dict[str, Any]) -> Dict[str, Any]:
    if args:
        raise ValueError('osd dump takes no arguments')
    return {'prefix': 'osd dump', 'format': 'json'}


def _osds(out: str) -> str:
    """osd dump reduced to each OSD's id, uuid and whether it is up and in."""
    d = json.loads(out)
    return json.dumps([{'osd': o['osd'], 'uuid': o.get('uuid', ''), 'up': bool(o.get('up')), 'in': bool(o.get('in'))} for o in d.get('osds', [])])


# calls whose output is reduced in the mgr before it is kept and returned
REDUCE: Dict[str, Callable[[Dict[str, Any]], Callable[[str], str]]] = {
    'config-key keys': lambda args: _keys_page(args['prefix'], args['after']),
    'osd dump': lambda args: _osds,
}

# calls that change nothing: an answered one is not kept
READ_ONLY = {'status', 'health', 'mgr dump', 'config-key keys', 'config-key get', 'entry limit', 'auth get', 'secret get', 'ledger', 'approval', 'osd dump'}
# calls that release a credential: checked against the fold, while active
CREDENTIALS = {'auth get', 'auth get-or-create', 'secret get'}
# mon commands the handlers send that change nothing (any other one is a mutation)
READ_PREFIXES = {'auth get', 'config get', 'config-key get', 'config-key ls', 'mgr dump', 'mon ok-to-stop', 'osd dump',
                 'osd metadata', 'osd ok-to-stop', 'osd safe-to-destroy', 'quorum_status', 'status', 'health'}
# calls the module answers itself, for operations of its ledger (ledger.py)
LOCAL = {'mgr cert', 'retire', 'retire host', 'bind disk', 'confirm osd', 'close create', 'osd out', 'drain', 'mon rm',
         'ok to stop', 'noout set', 'noout unset', 'maintained', 'mgr fail', 'ok to stop daemon', 'upgrade done', 'upgrade refused',
         'rgw cert', 'rgw cert done', 'retire keepalived', 'mgr cert done'}

ALLOWLIST: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    'status': _no_args('status'),
    'health': _no_args('health'),
    'mgr dump': _no_args('mgr dump'),
    'config-key keys': _config_key_keys,
    'config-key get': _config_key_get,
    'config-key set': _config_key_set,
    'config-key rm': _config_key_rm,
    'entry limit': _entry_limit,
    'auth get': _auth_get,
    'auth get-or-create': _auth_get_or_create,
    'secret get': _secret_get,
    'ledger': _ledger,
    'approval': _approval,
    'mgr cert': _operation,
    'mgr cert done': _operation,
    'bind disk': _operation_with('serial', 'link', 'job'),
    'confirm osd': _operation_with('osd'),
    'close create': _operation,
    'osd out': _operation,
    'drain': _operation,
    'osd dump': _osd_dump,
    'retire': _operation,
    'retire host': _operation,
    'mon rm': _operation,
    'ok to stop': _operation,
    'noout set': _operation,
    'noout unset': _operation,
    'maintained': _operation,
    'mgr fail': _operation_with('gid'),
    'ok to stop daemon': _operation_with('daemon'),
    'upgrade done': _operation,
    'upgrade refused': _operation,
    'rgw cert': _operation,
    'rgw cert done': _operation_with('keep'),
    'retire keepalived': _operation_with('daemon'),
}


def issue_mgr_certs(ca_cert_pem: bytes, ca_key_pem: bytes, fsid: str, host: str, addr: str) -> Dict[str, str]:
    """A mgr's server certificate (for its host's address and name) and client
    certificate, as internal/pki issues them: P-256, 3 years, the identity
    cephadm-talos://<fsid>/mgr/<host> as URI SAN, one extended key usage each."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    ca = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    now = datetime.datetime.now(datetime.timezone.utc)
    out: Dict[str, str] = {}
    for role, usage in (('server', ExtendedKeyUsageOID.SERVER_AUTH), ('client', ExtendedKeyUsageOID.CLIENT_AUTH)):
        key = ec.generate_private_key(ec.SECP256R1())
        sans: List[x509.GeneralName] = [x509.UniformResourceIdentifier('cephadm-talos://%s/mgr/%s' % (fsid, host))]
        if role == 'server':
            sans += [x509.DNSName(host), x509.IPAddress(ipaddress.ip_address(addr))]
        b = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mgr ' + host)]))
             .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=3 * 365))
             .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                          key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
             .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
             .add_extension(x509.SubjectAlternativeName(sans), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False))  # type: ignore[arg-type]
        cert = b.sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
        out[role + '_cert'] = cert.public_bytes(serialization.Encoding.PEM).decode()
        out[role + '_key'] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                               serialization.NoEncryption()).decode()
    return out


def new_rgw_ca(fsid: str) -> Tuple[str, str]:
    """An RGW CA (P-256, 10 years), as the CLI creates one: certificate, key."""
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'cephadm-talos RGW CA ' + fsid)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=10 * 365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode())


def issue_rgw_cert(ca_cert_pem: bytes, ca_key_pem: bytes, ips: List[str], names: List[str]) -> Tuple[str, str]:
    """An RGW serving certificate (P-256, 1 year, server auth: browsers accept at most 398 days) for addresses
    and names: certificate, key."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    ca = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    sans: List[x509.GeneralName] = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'rgw')]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)  # type: ignore[arg-type]
            .sign(ca_key, hashes.SHA256()))  # type: ignore[arg-type]
    return (cert.public_bytes(serialization.Encoding.PEM).decode() + ca.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()).decode())


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

    def fresh_map(self, commands: Optional[Commands] = None) -> Optional[Dict[str, Any]]:
        job = (commands or self.commands).submit({'prefix': 'mgr dump', 'format': 'json'})
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

    def still_active(self, commands: Optional[Commands] = None) -> bool:
        """A fresh check from the mons that the captured gid is the active one,
        on commands (default: the leadership's own) so bridge writes do not
        compete with confirmations and the heartbeat."""
        cap = self.captured()
        if cap is None:
            return False
        m = self.fresh_map(commands)
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

    def __init__(self, local: bool = False) -> None:
        self.job: Optional[Job] = None
        self.done_at: Optional[float] = None
        self.answered = False  # the call itself returned "done"
        # a local handler's (and auth get-or-create's): the mutations it sent,
        # and its answer once it returned, as kept (never a credential)
        self.local = local
        self.returned = False
        self.sent: List[Job] = []
        self.result: Optional[Dict[str, Any]] = None
        # a ledger entry the handler appended whose write the mons did not
        # answer: (ledger, key), settled once the ledger no longer has it pending
        self.ledger: Optional[Tuple[Any, str]] = None

    def finished(self) -> bool:
        if self.local:
            led = self.ledger
            pending = None if led is None else getattr(led[0], 'pending', None)
            settled = pending is None or pending[0] != led[1]
            return self.returned and settled and all(j.ev.is_set() for j in self.sent)
        return self.job is not None and self.job.ev.is_set()


class Credentials:
    """The module's server identity: the TLS context, the confirmation signing
    key and the agent CA certificate it issues from, built from one read of
    their files, so the key always matches the certificate of the context."""

    def __init__(self, ctx: Optional[ssl.SSLContext], server_key: bytes, ca_cert: bytes, digest: str = '') -> None:
        self.ctx = ctx
        self.server_key = server_key
        self.ca_cert = ca_cert
        self.digest = digest


def files_digest(*paths: str) -> str:
    h = hashlib.sha256()
    for path in paths:
        b = read(path)
        h.update(len(b).to_bytes(8, 'big') + b)
    return h.hexdigest()


def load_credentials(ca_file: str, cert_file: str, key_file: str) -> Credentials:
    """The credentials of one read of the three files; raises unless the
    certificate and the key load and match."""
    ca, cert, key = read(ca_file), read(cert_file), read(key_file)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=ca.decode())
    # load_cert_chain reads files: the bytes just read go through a private
    # temporary file, so context and signing key come from the same read
    with tempfile.TemporaryDirectory() as d:
        cp, kp = os.path.join(d, 'c'), os.path.join(d, 'k')
        for path, data in ((cp, cert), (kp, key)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
        ctx.load_cert_chain(cp, kp)  # raises on a key that does not match
    h = hashlib.sha256()
    for b in (ca, cert, key):
        h.update(len(b).to_bytes(8, 'big') + b)
    return Credentials(ctx, key, ca, h.hexdigest())


class Server(ThreadingHTTPServer):
    """One request per connection; the TLS handshake happens in the connection's
    own thread, within the connection's absolute deadline, and connections are
    admitted only while there is room."""

    daemon_threads = True

    def __init__(self, addr: Tuple[str, int], handler: Any, ctx: Any) -> None:
        super().__init__(addr, handler)
        # a TLS context, or a function returning the current Credentials,
        # which each connection captures when it is accepted
        self.credentials: Callable[[], Credentials] = ctx if callable(ctx) else (lambda c=Credentials(ctx, b'', b''): c)
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
            creds = self.credentials()
            tls = creds.ctx.wrap_socket(conn, server_side=True)  # type: ignore[union-attr]
            tls.credentials = creds  # type: ignore[attr-defined]  # what this connection's confirmations are signed with
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


UUID_RE = re.compile(r'\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')


def device_matches(device_ids: str, serial: str) -> bool:
    """Whether an OSD's device_ids (comma-separated <dev>=<identifier>) name a
    disk with this serial: the identifier is the serial, or has it as its
    '_'-separated parts (Ceph's vendor_model_serial, or udev's ID_SERIAL)."""
    s = serial.replace(' ', '_')
    for item in device_ids.split(','):
        _, _, ident = item.partition('=')
        ident = ident.replace(' ', '_')
        if ident == s or ident.endswith('_' + s) or ident.startswith(s + '_') or ('_' + s + '_') in ident:
            return True
    return False


def _daemon_of(entity: str) -> str:
    """The daemon name ("<type>.<id>") of a CephX entity."""
    return 'rgw.' + entity[len('client.rgw.'):] if entity.startswith('client.rgw.') else entity


class Channel:
    """The module's server on port 4722: confirmations and the bridge."""

    def __init__(self, fsid: str, mgr_id: str, leadership: Leadership, bridge_commands: Commands,
                 server_ctx: Optional[ssl.SSLContext], server_key: bytes,
                 require_identity: Callable[..., str], log: Any, authority: Callable[[], Any],
                 ca_cert: bytes = b'', digest: str = '') -> None:
        self.fsid = fsid
        # the server identity, replaced as a whole by reload
        # mutations sent for a daemon's generation, which a removal waits for
        self.inflight: Dict[str, List[Job]] = {}
        self.local_lock = threading.Lock()
        # authority returns (ledger.Ledger, ledger.Fold); it raises while there is none
        self.authority = authority
        self.mgr_id = mgr_id
        self.leadership = leadership
        self.commands = bridge_commands
        self.require_identity = require_identity
        self.log = log
        self.creds = Credentials(server_ctx, server_key, ca_cert, digest)
        self.lock = threading.Lock()
        self.records: Dict[str, Record] = {}
        # the record of the local handler running on this thread, which _mon
        # adds the mutations it sends to
        self._tl = threading.local()
        self.server: Optional[Server] = None
        self.bridge_server: Optional[Server] = None

    def credentials(self) -> Credentials:
        return self.creds

    @property
    def ca_cert(self) -> bytes:
        return self.creds.ca_cert

    def reload(self, ca_file: str, cert_file: str, key_file: str) -> bool:
        """Load the server identity again when its files changed (plan 04,
        step 1); a load that fails keeps the current one. True on a swap."""
        try:
            if files_digest(ca_file, cert_file, key_file) == self.creds.digest:
                return False
            creds = load_credentials(ca_file, cert_file, key_file)
        except Exception as e:
            self.log.warning('the server certificate was not reloaded: %s', e)
            return False
        if creds.digest == self.creds.digest:
            return False
        self.creds = creds  # one assignment: a connection sees the old or the new object whole
        self.log.info('server certificate reloaded')
        return True

    # --- confirmation -------------------------------------------------------

    def confirm(self, req: Dict[str, Any], creds: Optional[Credentials] = None) -> Tuple[int, Dict[str, Any]]:
        cap = self.leadership.captured()
        if cap is None:
            return 503, {'error': 'no captured incarnation'}
        if not self.leadership.still_active():
            return 409, {'error': 'not confirmed as the active mgr'}
        payload = json.dumps({
            'version': WIRE_VERSION, 'fsid': self.fsid, 'mgr': self.mgr_id, 'gid': cap[0], 'epoch': cap[1],
            'session': req['session'], 'host': req['host'], 'revision': req['revision'],
            'operation': req['operation'], 'inputs_hash': req['inputs_hash'], 'challenge': req['challenge'],
        }, sort_keys=True, separators=(',', ':')).encode()
        sig = sign((creds or self.creds).server_key, payload)
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
        cap = self.leadership.captured()
        if cap is None:
            return 503, {'error': 'no captured incarnation'}
        if call == 'approval':
            return self.approval()
        if call == 'ledger' or call in CREDENTIALS:
            try:
                led, fold = self.authority()
            except Exception as e:
                return 503, {'error': 'no ledger yet: %s' % e}
            if call == 'ledger':
                return 200, self._ledger_page(led, args['after'])
            if call == 'secret get':
                m = SECRET_RE.match(args['name'])
                allowed = fold.secret_allowed(args['name'], m.group(1)) if m.group(2) is None else fold.mgr_keys_allowed(m.group(2))
            elif call == 'auth get-or-create':
                allowed = True  # checked with its operation under the lock retirement takes (create)
            elif args['entity'] == 'client.bootstrap-osd':
                allowed = fold.creating(args['operation']) is not None and args['operation'] in {e['id'] for _, e in led.executable()}
            else:
                allowed = fold.entity_allowed(args['entity'])
            if not allowed:
                return 400, {'error': '%s not allowed: not in the accepted cluster' % call}
            # a credential goes out only while the mons show this incarnation active
            if not self.leadership.still_active(self.commands):
                return 409, {'error': 'not confirmed as the active mgr'}
        # writes go to this incarnation's own namespace only; reads are cluster-wide
        if call in ('config-key set', 'config-key rm') and not cmd['key'].startswith('%sinc/%d/' % (STORE_PREFIX_FULL, cap[0])):
            return 400, {'error': 'writes only below this incarnation'}
        # a change is made only while the mons still show this incarnation active
        # (checked before, not atomically with, the change)
        if call not in READ_ONLY and call not in CREDENTIALS and not self.leadership.still_active(self.commands):
            return 409, {'error': 'not confirmed as the active mgr'}
        if call in LOCAL or call == 'auth get-or-create':
            return self._local_call(dispatch, call, args, cmd, float(deadline))
        rec = Record()
        refused = self._register(dispatch, rec)
        if refused is not None:
            return refused
        job = self.commands.submit(cmd, REDUCE[call](args) if call in REDUCE else None)
        if job is None:
            with self.lock:
                del self.records[dispatch]  # nothing was sent
            return 429, {'error': 'too many outstanding bridge calls'}
        if call == 'auth get-or-create':
            self._track(_daemon_of(args['entity']), job)
        with self.lock:
            rec.job = job
        if job.ev.wait(float(deadline)):
            out = self._outcome(dispatch, rec)
            with self.lock:
                if call in READ_ONLY or call in CREDENTIALS:
                    self.records.pop(dispatch, None)
                else:
                    rec.answered = True
            return 200, out
        if call in CREDENTIALS:
            # a credential is never kept for a later fetch, which would skip the
            # leadership check: the caller asks again with a new dispatch id
            with self.lock:
                self.records.pop(dispatch, None)
        return 200, {'outcome': 'unknown'}

    def _register(self, dispatch: str, rec: Record) -> Optional[Tuple[int, Dict[str, Any]]]:
        """Keep a call's record under its dispatch id before anything is sent;
        a refusal if the id is used or there is no room."""
        with self.lock:
            self._expire()
            if dispatch in self.records:
                return 409, {'error': 'dispatch id already used; fetch its outcome'}
            if len(self.records) >= MAX_RECORDS:
                # an answered call's outcome is a courtesy: the oldest one makes room
                answered = [(r.done_at, k) for k, r in self.records.items() if r.answered and r.done_at is not None]
                if not answered:
                    return 429, {'error': 'too many kept outcomes'}
                del self.records[min(answered)[1]]
            self.records[dispatch] = rec  # registered before anything is sent
        return None

    def _local_call(self, dispatch: str, call: str, args: Dict[str, Any], cmd: Dict[str, Any],
                    deadline: float) -> Tuple[int, Dict[str, Any]]:
        """A local handler or auth get-or-create under its dispatch id (plan 03,
        step 7 slice D): its outcome can be fetched like any call's while it
        runs and after. A refusal (non-200) means nothing was sent; a handler
        that sent a mutation and then failed answers done with its error; one
        whose mutations are not answered yet is unknown until they are."""
        rec = Record(local=True)
        refused = self._register(dispatch, rec)
        if refused is not None:
            return refused
        before = self._ledger_mark()
        self._tl.rec = rec
        try:
            code, body = self.local(call, args['operation'], args) if call in LOCAL else self.create(args, cmd, deadline)
        except Exception as e:
            code, body = 503, {'error': '%s: %s' % (call, e.__class__.__name__)}
        finally:
            self._tl.rec = None
        # a ledger entry (a retirement, a module entry) is a mutation too
        after = self._ledger_mark()
        appended = before is not None and after is not None and after[0] is before[0] and after[1:] != before[1:]
        if appended and after is not None and after[2] is not None:
            rec.ledger = (after[0], after[2][0])
        with self.lock:
            sent = list(rec.sent)
            if not sent and not appended and code != 200:
                self.records.pop(dispatch, None)  # nothing was sent
                return code, body
            if code != 200:
                kept: Optional[Dict[str, Any]] = {'outcome': 'done', 'r': -5, 'error': str(body.get('error', 'failed'))}
            elif body.get('outcome') == 'unknown':
                kept = None  # its mutation's answer decides (_outcome)
            else:
                kept = dict(body)
                if call in CREDENTIALS and 'out' in kept:
                    kept = {'outcome': 'done', 'r': kept.get('r', 0), 'error': 'a credential is not kept; ask again'}
            rec.result, rec.returned = kept, True
            if not rec.finished():
                return 200, {'outcome': 'unknown'}
            rec.answered = kept is not None
        if code != 200:
            return 200, kept or {'outcome': 'unknown'}
        return 200, body

    def _ledger_mark(self) -> Optional[Tuple[Any, int, Optional[Tuple[str, str]]]]:
        """The ledger with its sequence number and pending append, to tell
        whether a handler appended (None without a ledger)."""
        try:
            led, _ = self.authority()
        except Exception:
            return None
        return led, getattr(led, 'seq', 0), getattr(led, 'pending', None)

    # --- calls for the ledger's operations (ledger.py) ------------------------

    def _track(self, daemon: str, job: Job) -> None:
        with self.lock:
            self.inflight.setdefault(daemon, []).append(job)

    def _pending(self, daemon: str) -> bool:
        with self.lock:
            jobs = [j for j in self.inflight.get(daemon, []) if not j.ev.is_set()]
            self.inflight[daemon] = jobs
            return bool(jobs)

    def _mon(self, cmd: Dict[str, Any], daemon: Optional[str] = None,
             reduce: Optional[Callable[[str], str]] = None) -> Optional[Job]:
        """One mon command and its answer within the bridge deadline; None
        without one (a tracked mutation stays tracked until it completes)."""
        job = self.commands.submit(cmd, reduce)
        if job is None:
            return None
        self._sent(cmd, job)
        if daemon is not None:
            self._track(daemon, job)
        return job if job.ev.wait(MAX_BRIDGE_DEADLINE) else None

    def _sent(self, cmd: Dict[str, Any], job: Job) -> None:
        """Count a mutation a local handler sent in its dispatch record."""
        rec = getattr(self._tl, 'rec', None)
        if rec is not None and cmd.get('prefix') not in READ_PREFIXES:
            with self.lock:
                rec.sent.append(job)

    def create(self, args: Dict[str, Any], cmd: Dict[str, Any], deadline: float) -> Tuple[int, Dict[str, Any]]:
        """auth get-or-create of the daemon an accepted add deploys, while that
        add's generation is open: checked, sent and tracked under the lock that
        retirement takes, so a retirement sees it. Its outcome is never kept."""
        with self.local_lock:
            try:
                led, _ = self.authority()
                led.settle()  # an unanswered entry (a retirement among them) counts first
                led, fold = self.authority()
            except Exception as e:
                return 503, {'error': 'no settled ledger: %s' % e}
            daemon = _daemon_of(args['entity'])
            op = {e['id']: e for _, e in led.executable()}.get(args['operation'])
            if op is None or op['kind'] != 'add_daemon' or op['daemon'] != daemon or fold.open_generation(daemon) != op['id']:
                return 400, {'error': 'auth get-or-create not allowed: no add of %s in its open generation' % daemon}
            if self._pending(daemon):  # an earlier generation's auth rm, among others
                return 409, {'error': 'mutations for %s are not answered yet; ask again' % daemon}
            job = self.commands.submit(cmd)
            if job is None:
                return 429, {'error': 'too many outstanding bridge calls'}
            self._sent(cmd, job)
            self._track(daemon, job)
        if not job.ev.wait(deadline):
            return 200, {'outcome': 'unknown'}
        if job.too_large:
            return 200, {'outcome': 'done', 'r': job.r, 'error': 'output larger than %d bytes' % MAX_OUTPUT}
        return 200, {'outcome': 'done', 'r': job.r, 'out': job.outb, 'outs': job.outs}

    def local(self, call: str, op_id: str, args: Optional[Dict[str, Any]] = None) -> Tuple[int, Dict[str, Any]]:
        with self.local_lock:  # one at a time: they read the fold, then append
            try:
                led, _ = self.authority()
                led.settle()  # an unanswered entry (a close or retire) counts before anything is decided
                led, fold = self.authority()
            except Exception as e:
                return 503, {'error': 'no settled ledger: %s' % e}
            ops = {e['id']: e for _, e in led.executable()}
            op = ops.get(op_id)
            try:
                if call == 'mgr cert':
                    return self._mgr_cert(fold, op, led)
                if call in ('osd out', 'drain') or (call == 'retire' and op is not None and op['kind'] == 'remove_osd'):
                    return self._removal(call, led, fold, ops, op)
                if call == 'retire':
                    return self._retire(led, fold, ops, op)
                if call == 'mon rm':
                    return self._mon_rm(led, fold, ops, op)
                if call in ('ok to stop', 'noout set', 'noout unset', 'maintained'):
                    return self._maintenance(call, led, fold, op)
                if call == 'mgr fail':
                    return self._mgr_fail(fold, op, (args or {}).get('gid'))
                if call in ('ok to stop daemon', 'upgrade done', 'upgrade refused'):
                    return self._upgrade(call, led, fold, op, (args or {}).get('daemon'))
                if call == 'rgw cert':
                    return self._rgw_cert(led, fold, op)
                if call == 'retire keepalived':
                    return self._retire_keepalived(led, fold, ops, op, (args or {}).get('daemon'))
                if call == 'mgr cert done':
                    return self._mgr_cert_done(led, fold, op)
                if call == 'rgw cert done':
                    return self._rgw_cert_done(led, fold, ops, op, (args or {}).get('keep'))
                if call in ('bind disk', 'confirm osd', 'close create'):
                    return self._creation(call, led, fold, op, args or {})
                return self._retire_host(led, fold, ops, op)
            except Exception as e:  # a ledger entry without an answer, among others: asked again
                return 503, {'error': '%s: %s' % (call, e.__class__.__name__)}

    def _mgr_cert(self, fold: Any, op: Optional[Dict[str, Any]], led: Any = None) -> Tuple[int, Dict[str, Any]]:
        if op is not None and op['kind'] == 'renew_mgr':
            return self._mgr_renewal_cert(led, fold, op)
        if op is None or op['kind'] != 'add_daemon' or not op['daemon'].startswith('mgr.') \
                or fold.open_generation(op['daemon']) != op['id'] or op['host'] not in fold.hosts:
            return 400, {'error': 'no add of a mgr in its open generation'}
        name, host = op['daemon'], op['host']
        job = self._mon({'prefix': 'config-key get', 'key': SECRET_PREFIX + 'agent-ca.key'})
        if job is None or job.r != 0 or not self.ca_cert:
            return 503, {'error': 'the agent CA is not available'}
        certs = issue_mgr_certs(self.ca_cert, job.outb.encode(), self.fsid, host, fold.hosts[host])
        attempt = secrets.token_hex(8)
        for role in ('server', 'client'):
            key = '%sissued/%s/%s/mgr-%s.key' % (SECRET_PREFIX, op['id'], attempt, role)
            w = self._mon({'prefix': 'config-key set', 'key': key, 'val': certs[role + '_key']}, name)
            if w is None or w.r != 0:
                return 503, {'error': 'the key of attempt %s was not written; ask again' % attempt}
        out = {'attempt': attempt, 'server_cert': certs['server_cert'], 'client_cert': certs['client_cert']}
        return 200, {'outcome': 'done', 'r': 0, 'out': json.dumps(out), 'outs': ''}

    def _mgr_renewal_cert(self, led: Any, fold: Any, op: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """A renewal's mgr certificates (plan 04, step 1): issued once per renewal,
        recorded with a module entry, the certificates kept beside the keys, so a
        retry or a successor gets the same ones."""
        name, host = op['daemon'], op['host']
        if led is None or op['id'] not in fold.mgr_renewals.get(name, {}) or host not in fold.hosts:
            return 400, {'error': 'no renewal of a mgr in its open generation'}
        attempt = fold.mgr_renewals[name][op['id']]
        if attempt is None:
            job = self._mon({'prefix': 'config-key get', 'key': SECRET_PREFIX + 'agent-ca.key'})
            if job is None or job.r != 0 or not self.ca_cert:
                return 503, {'error': 'the agent CA is not available'}
            certs = issue_mgr_certs(self.ca_cert, job.outb.encode(), self.fsid, host, fold.hosts[host])
            attempt = secrets.token_hex(8)
            for item in ('server_key', 'client_key', 'server_cert', 'client_cert'):
                role, kind = item.split('_')
                key = '%sissued/%s/%s/mgr-%s.%s' % (SECRET_PREFIX, op['id'], attempt, role, 'key' if kind == 'key' else 'crt')
                w = self._mon({'prefix': 'config-key set', 'key': key, 'val': certs[item]}, name)
                if w is None or w.r != 0:
                    return 503, {'error': 'the certificates of attempt %s were not written; ask again' % attempt}
            led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'mgr_cert', 'of': op['id'], 'daemon': name, 'host': host, 'attempt': attempt})
        out = {'attempt': attempt}
        for role in ('server', 'client'):
            job = self._mon({'prefix': 'config-key get', 'key': '%sissued/%s/%s/mgr-%s.crt' % (SECRET_PREFIX, op['id'], attempt, role)})
            if job is None or job.r != 0:
                return 503, {'error': 'the certificates of attempt %s cannot be read; ask again' % attempt}
            out[role + '_cert'] = job.outb
        return 200, {'outcome': 'done', 'r': 0, 'out': json.dumps(out), 'outs': ''}

    def _mgr_cert_done(self, led: Any, fold: Any, op: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        """A renewal's end: the mgr keeps the renewal's keys; every other key of
        that mgr (its add's, the CLI's, earlier renewals') is retired by a module
        entry first, then deleted. Asked again, it deletes what is left."""
        if op is None or op['kind'] != 'renew_mgr' or op['id'] not in fold.mgr_renewals.get(op['daemon'], {}):
            return 400, {'error': 'no renewal of a mgr in its open generation'}
        name, host = op['daemon'], op['host']
        if fold.mgr_renewals[name][op['id']] is None:
            return 400, {'error': 'the renewal issued no certificates'}
        gen = fold.open_generation(name)
        if not any(e['kind'] == 'mgr_cert_done' and e['of'] == op['id'] for _, e in led.executable()):
            led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'mgr_cert_done', 'of': op['id'], 'daemon': name, 'host': host, 'keep': op['id']})
        old = ['%sissued/%s/' % (SECRET_PREFIX, o) for o in list(fold.mgr_renewals[name]) + [gen] if o != op['id'] and o != 'cli']
        if gen == 'cli':
            old += ['%shost/%s/mgr-server.key' % (SECRET_PREFIX, host), '%shost/%s/mgr-client.key' % (SECRET_PREFIX, host)]
        keys = self._mon({'prefix': 'config-key ls'}, None, lambda out: json.dumps([k for k in json.loads(out) if any(k.startswith(p) for p in old)]))
        if keys is None or keys.r != 0 or keys.too_large:
            return 503, {'error': 'cannot list the secrets; ask again'}
        for k in json.loads(keys.outb):
            if any(k.startswith(p) for p in old):
                rm = self._mon({'prefix': 'config-key rm', 'key': k}, name)
                if rm is None or rm.r not in (0, -2):
                    return 503, {'error': 'cannot remove a key of %s; ask again' % name}
        return 200, {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}

    def _retire(self, led: Any, fold: Any, ops: Dict[str, Dict[str, Any]], op: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        if op is None or op['kind'] != 'remove_daemon':
            return 400, {'error': 'no removal of a daemon'}
        name = op['daemon']
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        if any(e['kind'] == 'retire' and e['of'] == op['id'] for e in ops.values()):
            return 200, done  # retired already
        if name not in fold.generations:
            return 400, {'error': '%s is not in the cluster' % name}
        later = [e for k, e in led.executable() if e['kind'] == 'add_daemon' and e['daemon'] == name and (e['epoch'], e['seq']) > (op['epoch'], op['seq'])]
        if later:
            return 400, {'error': '%s was added again after this removal' % name}
        gen, is_open = fold.generations[name]
        if is_open:  # nothing more is created or issued for this generation
            led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'close', 'of': op['id'], 'daemon': name, 'host': op['host']})
        if self._pending(name):
            return 409, {'error': 'mutations for %s are not answered yet; ask again' % name}
        if name.startswith('mon.'):  # the mon. key is shared: nothing of its own to remove
            led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'retire', 'of': op['id'], 'daemon': name, 'host': op['host']})
            return 200, done
        # a mgr's entity is its daemon name; an RGW's is client.rgw.<id>
        entity = 'client.' + name if name.startswith('rgw.') else name
        # tracked: an unanswered removal holds the retirement until it is answered,
        # so it cannot land on a later generation's key
        job = self._mon({'prefix': 'auth rm', 'entity': entity}, name)
        if job is None or job.r not in (0, -2):  # ENOENT: gone already
            return 503, {'error': 'auth rm %s: no answer or refused; ask again' % entity}
        # a mgr's keys go with it; an RGW's serving certificate is shared, its keys
        # go once no RGW renders it (rgw cert done)
        mine = [] if name.startswith('rgw.') else ['%sissued/%s/' % (SECRET_PREFIX, gen)] if gen != 'cli' else \
            ['%shost/%s/mgr-server.key' % (SECRET_PREFIX, op['host']), '%shost/%s/mgr-client.key' % (SECRET_PREFIX, op['host'])]
        # and the keys of its renewals (plan 04, step 1)
        if name.startswith('mgr.'):
            mine += ['%sissued/%s/' % (SECRET_PREFIX, o) for o in fold.mgr_renewals.get(name, {})]
        # the generation's keys only, reduced before the output limit applies
        keys = self._mon({'prefix': 'config-key ls'}, None, lambda out: json.dumps([k for k in json.loads(out) if any(k.startswith(p) for p in mine)]))
        if keys is None or keys.r != 0 or keys.too_large:
            return 503, {'error': 'cannot list the secrets; ask again'}
        for k in json.loads(keys.outb):
            if any(k.startswith(p) for p in mine):
                rm = self._mon({'prefix': 'config-key rm', 'key': k}, name)
                if rm is None or rm.r not in (0, -2):
                    return 503, {'error': 'cannot remove a key of %s; ask again' % name}
        led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'retire', 'of': op['id'], 'daemon': name, 'host': op['host']})
        return 200, done

    def _mon_rm(self, led: Any, fold: Any, ops: Dict[str, Dict[str, Any]], op: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        """A mon's removal from the monmap before its documents go, as cephadm's
        MonService.pre_remove: only while the quorum without it is a majority of
        the monmap without it (_check_safe_to_destroy)."""
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        if op is None or op['kind'] != 'remove_daemon' or not op['daemon'].startswith('mon.'):
            return 400, {'error': 'no removal of a mon'}
        name = op['daemon']
        mon_id = name.split('.', 1)[1]
        if any(e['kind'] == 'retire' and e['of'] == op['id'] for e in ops.values()):
            return 200, done
        if name not in fold.daemons:
            return 400, {'error': '%s is not in the cluster' % name}
        later = [e for k, e in led.executable() if e['kind'] == 'add_daemon' and e['daemon'] == name and (e['epoch'], e['seq']) > (op['epoch'], op['seq'])]
        if later:
            return 400, {'error': '%s was added again after this removal' % name}
        # a monmap read must not be older than a mon rm this module already sent
        if self._pending(name):
            return 409, {'error': 'mutations for %s are not answered yet; ask again' % name}
        q = self._mon({'prefix': 'quorum_status', 'format': 'json'})
        if q is None or q.r != 0 or q.too_large:
            return 503, {'error': 'cannot read the quorum; ask again'}
        try:
            status = json.loads(q.outb)
            mons = [m['name'] for m in status['monmap']['mons']]
            quorum = list(status['quorum_names'])
        except (ValueError, KeyError, TypeError):
            return 503, {'error': 'cannot read the quorum; ask again'}
        if mon_id not in mons:
            return 200, done  # removed already
        rest = [m for m in mons if m != mon_id]
        rest_quorum = [m for m in quorum if m != mon_id]
        if not rest or len(rest_quorum) <= len(rest) / 2:
            return 409, {'error': 'removing %s would break the mon quorum (quorum %s of %s)' % (name, rest_quorum, rest)}
        job = self._mon({'prefix': 'mon rm', 'name': mon_id}, name)
        if job is None or job.r not in (0, -2):  # ENOENT: gone already
            return 503, {'error': 'mon rm %s: no answer or refused; ask again' % mon_id}
        return 200, done

    def _maintenance(self, call: str, led: Any, fold: Any, op: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        """The module's steps of a host's maintenance: Ceph's checks that its
        daemons can stop (as cephadm's _host_ok_to_stop), noout for its CRUSH
        bucket, and the end of the maintenance in the fold."""
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        kinds = ledger.STARTS if call in ('noout unset', 'maintained') else ledger.STOPS
        if op is None or op['kind'] not in kinds:
            return 400, {'error': 'no %s operation' % ' or '.join(kinds)}
        host = op['host']
        if host not in fold.maintenance:
            return (200, done) if call == 'maintained' else (400, {'error': '%s is not in maintenance' % host})
        # an unanswered noout change first: a late one must not undo a later one
        if call != 'ok to stop' and self._pending('host/' + host):
            return 409, {'error': 'noout changes for %s are not answered yet; ask again' % host}
        if call == 'maintained':
            led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'maintained', 'of': op['id'], 'host': host})
            return 200, done
        on = [n for n, h in fold.daemons.items() if h == host]
        osds = sorted(n.split('.', 1)[1] for n in on if n.startswith('osd.'))
        if call == 'ok to stop':
            checks = ([{'prefix': 'osd ok-to-stop', 'ids': osds, 'max': 16, 'format': 'json'}] if osds else []) + \
                [{'prefix': 'mon ok-to-stop', 'ids': [n.split('.', 1)[1]]} for n in on if n.startswith('mon.')]
            for cmd in checks:
                job = self._mon(cmd)
                if job is None:
                    return 503, {'error': '%s: no answer; ask again' % cmd['prefix']}
                if job.r != 0:
                    return 409, {'error': '%s: %s' % (cmd['prefix'], job.outs.strip()[:500])}
            return 200, done
        # noout set or unset, on the host's CRUSH bucket (only a name Ceph cannot take for ids)
        if re.match(r'\A(osd\.)?[0-9]+\Z', host) or host in ('all', 'any'):
            return 400, {'error': 'host name %s is ambiguous for osd set-group' % host}
        prefix = 'osd set-group' if call == 'noout set' else 'osd unset-group'
        job = self._mon({'prefix': prefix, 'flags': 'noout', 'who': [host]}, 'host/' + host)
        if job is None or job.r != 0:
            return 503, {'error': '%s noout %s: no answer or refused; ask again' % (prefix, host)}
        return 200, done

    def _mgr_fail(self, fold: Any, op: Optional[Dict[str, Any]], gid: Any) -> Tuple[int, Dict[str, Any]]:
        """`mgr fail` of the active mgr by its gid, for an operation that must stop
        it: only while it runs on the operation's host and a standby is available.
        The active mgr respawns, so the answer may never come; done also when
        that gid is no longer the active one."""
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        upgrading = op is not None and op['kind'] == 'upgrade_start' and (fold.upgrade or {}).get('op') == op['id']
        if not upgrading and (op is None or op['kind'] not in ledger.STOPS or op['host'] not in fold.maintenance):
            return 400, {'error': 'no operation that must stop the active mgr'}
        job = self._mon({'prefix': 'mgr dump', 'format': 'json'})
        if job is None or job.r != 0 or job.too_large:
            return 503, {'error': 'cannot read the mgr map; ask again'}
        try:
            mm = json.loads(job.outb)
            active_gid, active = mm.get('active_gid'), mm.get('active_name')
            standbys = [s for s in mm.get('standbys', []) if s.get('available', True)]
        except (ValueError, AttributeError):
            return 503, {'error': 'cannot read the mgr map; ask again'}
        if active_gid != gid:
            return 200, done
        if not upgrading and (active != op['host'] or 'mgr.' + op['host'] not in fold.daemons):
            return 400, {'error': 'the active mgr is not on %s' % op['host']}
        if not standbys:
            return 409, {'error': 'no standby mgr is available'}
        self._mon({'prefix': 'mgr fail', 'who': str(gid)}, 'mgr.%s' % active)
        return 200, done

    def _upgrade(self, call: str, led: Any, fold: Any, op: Optional[Dict[str, Any]], daemon: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        """The module's steps of the upgrade in progress: Ceph's check that one
        daemon of a step can stop, and the end of the upgrade in the fold."""
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        if op is None or op['kind'] != 'upgrade_start':
            return 400, {'error': 'no upgrade'}
        if (fold.upgrade or {}).get('op') != op['id']:
            return (200, done) if call != 'ok to stop daemon' else (400, {'error': 'the upgrade is not in progress'})
        if call != 'ok to stop daemon':
            led.append({'id': 'm-' + secrets.token_hex(8), 'kind': call.replace(' ', '_'), 'of': op['id']})
            return 200, done
        if daemon not in fold.daemons:
            return 400, {'error': '%s is not a daemon of the cluster' % daemon}
        t, i = daemon.split('.', 1)
        if t not in ('osd', 'mon'):
            return 200, done
        cmd = {'prefix': 'osd ok-to-stop', 'ids': [i], 'max': 16, 'format': 'json'} if t == 'osd' else {'prefix': 'mon ok-to-stop', 'ids': [i]}
        job = self._mon(cmd)
        if job is None:
            return 503, {'error': '%s: no answer; ask again' % cmd['prefix']}
        if job.r != 0:
            return 409, {'error': '%s: %s' % (cmd['prefix'], job.outs.strip()[:500])}
        return 200, done

    def _secret(self, name: str) -> Optional[str]:
        job = self._mon({'prefix': 'config-key get', 'key': SECRET_PREFIX + name})
        return job.outb if job is not None and job.r == 0 and not job.too_large else None

    def _secret_or_absent(self, name: str) -> Tuple[bool, Optional[str]]:
        """(answered, value): value None when the mons answered that it is absent."""
        job = self._mon({'prefix': 'config-key get', 'key': SECRET_PREFIX + name})
        if job is None or job.too_large or job.r not in (0, -2):
            return False, None
        return True, (job.outb if job.r == 0 else None)

    def _rgw_ca(self, fold: Any) -> Optional[Tuple[str, str]]:
        """The RGW CA (certificate, key): the module's own (one entry, written
        once), else the CLI's (its key a secret, its certificate in the sealed
        state), else a new one; None without an answer."""
        # a CA write without an answer may still land: wait for it, so a retry
        # does not create another CA it would then overwrite
        if self._pending('rgw/ca'):
            return None
        ok, pair = self._secret_or_absent('rgw/ca.pem')
        if not ok:
            return None
        if pair:
            m = re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', pair, re.S)
            return (pair[:m.start()], m.group(0) + '\n') if m else None
        ok, cli_key = self._secret_or_absent('rgw/ca.key')
        if not ok:
            return None
        if cli_key and fold.cli_rgw.get('ca_cert'):
            return fold.cli_rgw['ca_cert'], cli_key
        cert, key = new_rgw_ca(self.fsid)
        w = self._mon({'prefix': 'config-key set', 'key': SECRET_PREFIX + 'rgw/ca.pem', 'val': cert + key}, 'rgw/ca')
        return (cert, key) if w is not None and w.r == 0 else None

    def _rgw_cert(self, led: Any, fold: Any, op: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        """A generated RGW serving certificate for an executable RGW add, ingress
        apply or renewal (plan 04, step 1), from the module's RGW CA, for the names the fold gives:
        every RGW host's name and address and the VIP. Once per operation: asked
        again, it returns the one it issued."""
        if op is None or not (op['kind'] == 'add_daemon' and op['daemon'].startswith('rgw.') and not op.get('cert')
                              or op['kind'] in ('apply_ingress', 'renew_rgw_cert')):
            return 400, {'error': 'no RGW add, ingress or renewal that needs a generated certificate'}
        done = [cid for cid in fold.rgw_certs if cid.startswith('issued/%s/' % op['id'])]
        if done:
            attempt = done[0].split('/')[2]
            cert = self._secret('%s/rgw-server.crt' % done[0])
            if cert is None:
                return 503, {'error': 'cannot read the certificate; ask again'}
            return 200, {'outcome': 'done', 'r': 0, 'out': json.dumps({'attempt': attempt, 'cert': cert}), 'outs': ''}
        ca = self._rgw_ca(fold)
        if ca is None:
            return 503, {'error': 'the RGW CA is not available; ask again'}
        ca_cert, ca_key = ca
        hosts = {h for n, h in fold.daemons.items() if n.startswith('rgw.')} | ({op['host']} if op['kind'] == 'add_daemon' else set())
        names = sorted(hosts)
        ips = sorted({fold.hosts[h] for h in hosts if h in fold.hosts} | ({fold.vip} if fold.vip else set()))
        cert, key = issue_rgw_cert(ca_cert.encode(), ca_key.encode(), ips, names)
        attempt = secrets.token_hex(8)
        base = 'issued/%s/%s' % (op['id'], attempt)
        for name, val in (('%s/rgw-server.key' % base, key), ('%s/rgw-server.crt' % base, cert)):
            w = self._mon({'prefix': 'config-key set', 'key': SECRET_PREFIX + name, 'val': val})
            if w is None or w.r != 0:
                return 503, {'error': 'the certificate of attempt %s was not written; ask again' % attempt}
        led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'rgw_cert', 'of': op['id'], 'attempt': attempt})
        return 200, {'outcome': 'done', 'r': 0, 'out': json.dumps({'attempt': attempt, 'cert': cert}), 'outs': ''}

    def _retire_keepalived(self, led: Any, fold: Any, ops: Dict[str, Dict[str, Any]], op: Optional[Dict[str, Any]], daemon: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        """A keepalived an executable ingress apply left out, retired once the
        leader removed its document (it holds no key of its own)."""
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        if op is None or op['kind'] != 'apply_ingress' or not daemon or not daemon.startswith('keepalived.'):
            return 400, {'error': 'no ingress apply, or not a keepalived'}
        if daemon not in fold.daemons:
            return 200, done
        # left out by this operation (a newer one may place it again: the fold
        # then keeps it)
        if fold.daemons[daemon] in op['hosts']:
            return 400, {'error': '%s is in this ingress\'s placement' % daemon}
        led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'retire', 'of': op['id'], 'daemon': daemon, 'host': fold.daemons[daemon]})
        return 200, done

    def _rgw_cert_done(self, led: Any, fold: Any, ops: Dict[str, Dict[str, Any]], op: Optional[Dict[str, Any]], keep: Optional[str]) -> Tuple[int, Dict[str, Any]]:
        """After a roll: the certificates that entered the fold before its
        operation are retired, except the one every RGW renders now, and their
        keys removed."""
        if op is None or keep not in fold.rgw_certs:
            return 400, {'error': 'no executable operation, or not a certificate of the cluster'}
        if not any(e['kind'] == 'rgw_cert_done' and e['of'] == op['id'] and e['keep'] == keep for e in ops.values()):
            led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'rgw_cert_done', 'of': op['id'], 'keep': keep})
        _, after = self.authority()
        # every retired certificate's keys, also those an earlier call left behind
        for cid, c in after.rgw_certs.items():
            if c['retired']:
                for name in (['rgw/server.key'] if cid == 'cli' else ['%s/rgw-server.key' % cid, '%s/rgw-server.crt' % cid]):
                    rm = self._mon({'prefix': 'config-key rm', 'key': SECRET_PREFIX + name})
                    if rm is None or rm.r not in (0, -2):
                        return 503, {'error': 'cannot remove the key of %s; ask again' % cid}
        return 200, {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}

    def _creation(self, call: str, led: Any, fold: Any, op: Optional[Dict[str, Any]], args: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """The module's steps of an OSD creation: bind it to its disk once,
        confirm it from the OSD map and the OSD's metadata, or close it."""
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        if op is None or op['kind'] != 'create_osd' or op['id'] not in fold.creations:
            return 400, {'error': 'no creation of an OSD'}
        c = fold.creations[op['id']]
        mid = 'm-' + secrets.token_hex(8)
        if call == 'bind disk':
            b = c['bind']
            if b is not None:
                same = (b['serial'], b['link'], b['job']) == (args['serial'], args['link'], args['job'])
                return (200, done) if same else (400, {'error': 'the creation is bound to another disk or job'})
            if c['closed']:
                return 400, {'error': 'the creation is closed'}
            led.append({'id': mid, 'kind': 'bind', 'of': op['id'], 'host': op['host'], 'serial': args['serial'], 'link': args['link'], 'job': args['job']})
            return 200, done
        if call == 'close create':
            if c['confirmed']:
                return 400, {'error': 'the creation is confirmed'}
            if not c['closed']:
                led.append({'id': mid, 'kind': 'close_create', 'of': op['id'], 'host': op['host']})
            return 200, done
        # confirm osd
        if c['confirmed']:
            return 200, done
        if fold.creating(op['id']) is None:
            return 400, {'error': 'the creation is not bound, or closed'}
        osd = args['osd']
        name = 'osd.%d' % osd
        if name in fold.daemons:
            return 400, {'error': '%s is an OSD of the cluster already' % name}
        dump = self._mon({'prefix': 'osd dump', 'format': 'json'}, None, _osds)
        if dump is None or dump.r != 0 or dump.too_large:
            return 503, {'error': 'cannot read the OSD map; ask again'}
        entry = [o for o in json.loads(dump.outb) if o['osd'] == osd]
        if not entry or not entry[0]['up'] or not UUID_RE.match(entry[0]['uuid']):
            return 409, {'error': '%s is not up in the OSD map yet' % name}
        meta = self._mon({'prefix': 'osd metadata', 'id': osd, 'format': 'json'})
        if meta is None or meta.r != 0 or meta.too_large:
            return 409, {'error': 'no metadata of %s yet' % name}
        md = json.loads(meta.outb)
        if md.get('hostname') != op['host'] or not device_matches(md.get('device_ids', ''), c['bind']['serial']):
            return 409, {'error': 'the metadata of %s does not name the bound host and disk' % name}
        led.append({'id': mid, 'kind': 'confirm', 'of': op['id'], 'host': op['host'], 'daemon': name, 'uuid': entry[0]['uuid']})
        return 200, done

    def _osd(self, osd: int) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[int, Dict[str, Any]]]]:
        """An OSD of the OSD map (None if it has none), or an answer to give."""
        dump = self._mon({'prefix': 'osd dump', 'format': 'json'}, None, _osds)
        if dump is None or dump.r != 0 or dump.too_large:
            return None, (503, {'error': 'cannot read the OSD map; ask again'})
        entry = [o for o in json.loads(dump.outb) if o['osd'] == osd]
        return (entry[0] if entry else None), None

    def _safe(self, osd: int) -> Optional[bool]:
        """Whether `osd safe-to-destroy` lists the OSD (its rc is 0 either way); None without an answer."""
        job = self._mon({'prefix': 'osd safe-to-destroy', 'ids': [str(osd)], 'format': 'json'})
        if job is None or job.too_large:
            return None
        try:
            return osd in json.loads(job.outb).get('safe_to_destroy', [])
        except (ValueError, AttributeError):
            return False

    def _removal(self, call: str, led: Any, fold: Any, ops: Dict[str, Dict[str, Any]], op: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        """The module's steps of an OSD removal, each checked against the OSD map
        by id and uuid first: out, drain (safe to destroy unless forced, while it
        runs), and the retirement (down, still out unless forced, purge)."""
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        if op is None or op['kind'] != 'remove_osd':
            return 400, {'error': 'no removal of an OSD'}
        name, osd = op['daemon'], int(op['daemon'].split('.', 1)[1])
        if any(e['kind'] == 'retire' and e['of'] == op['id'] for e in ops.values()):
            return 200, done
        if fold.uuids.get(name) != op['uuid']:
            return 400, {'error': '%s is not that OSD of the cluster' % name}
        # an earlier purge or out still unanswered first: the OSD map read below
        # must not be older than what this module already sent
        if self._pending(name):
            return 409, {'error': 'mutations for %s are not answered yet; ask again' % name}
        entry, answer = self._osd(osd)
        if answer is not None:
            return answer
        if entry is not None and entry['uuid'] != op['uuid']:
            return 400, {'error': '%s in the OSD map is another OSD' % name}
        drained = any(e['kind'] == 'drained' and e['of'] == op['id'] for e in ops.values())
        mid = 'm-' + secrets.token_hex(8)
        # after its drain the OSD stays out: one marked in again may hold data
        # the drain never checked, and a new `osd out` would hide that
        if drained and not op['force'] and entry is not None and entry.get('in'):
            return 409, {'error': '%s was marked in again after its drain' % name}
        if call == 'osd out':
            if entry is None:
                return 200, done
            job = self._mon({'prefix': 'osd out', 'ids': [str(osd)]}, name)
            return (200, done) if job is not None and job.r == 0 else (503, {'error': 'osd out %s: no answer or refused' % name})
        if call == 'drain':
            if drained:
                return 200, done
            if entry is None:
                return 400, {'error': '%s is not in the OSD map' % name}
            # checked while it runs on the first removal; an OSD a failed removal
            # already stopped is checked as it is
            if not op['force'] and (entry.get('in') or not self._safe(osd)):
                return 409, {'error': '%s is not out and safe to destroy yet' % name}
            led.append({'id': mid, 'kind': 'drained', 'of': op['id'], 'daemon': name, 'host': op['host']})
            return 200, done
        # the retirement
        if not drained:
            return 400, {'error': '%s was not drained' % name}
        if entry is not None:
            if entry['up']:
                return 409, {'error': '%s is not down yet' % name}
            # the drained entry is the safety check, as in cephadm (the OSD out
            # since, checked above): once stopped, safe-to-destroy answers only
            # while every PG is active+clean
            job = self._mon({'prefix': 'osd purge-actual', 'id': osd, 'yes_i_really_mean_it': True}, name)
            if job is None or job.r != 0:
                return 503, {'error': 'osd purge-actual %s: no answer or refused; ask again' % name}
        led.append({'id': mid, 'kind': 'retire', 'of': op['id'], 'daemon': name, 'host': op['host']})
        return 200, done

    def _retire_host(self, led: Any, fold: Any, ops: Dict[str, Dict[str, Any]], op: Optional[Dict[str, Any]]) -> Tuple[int, Dict[str, Any]]:
        if op is None or op['kind'] != 'remove_host':
            return 400, {'error': 'no removal of a host'}
        done = {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        if any(e['kind'] == 'retire_host' and e['of'] == op['id'] for e in ops.values()) or op['host'] not in fold.hosts:
            return 200, done
        if any(h == op['host'] for h in fold.daemons.values()):
            return 400, {'error': '%s still has daemons' % op['host']}
        led.append({'id': 'm-' + secrets.token_hex(8), 'kind': 'retire_host', 'of': op['id'], 'host': op['host']})
        return 200, done

    def approval(self) -> Tuple[int, Dict[str, Any]]:
        """The newest approval in config-key, as written ("" if there is none)."""
        keys = self._mon({'prefix': 'config-key ls'}, None,
                         lambda out: json.dumps(sorted(k for k in json.loads(out) if APPROVAL_KEY_RE.match(k))[-1:]))
        if keys is None or keys.r != 0 or keys.too_large:
            return 503, {'error': 'cannot list the approvals; ask again'}
        newest = json.loads(keys.outb)
        if not newest:
            return 200, {'outcome': 'done', 'r': 0, 'out': '', 'outs': ''}
        job = self._mon({'prefix': 'config-key get', 'key': newest[0]})
        if job is None or job.r != 0 or job.too_large:
            return 503, {'error': 'cannot read the approval; ask again'}
        return 200, {'outcome': 'done', 'r': 0, 'out': job.outb, 'outs': ''}

    def _ledger_page(self, led: Any, after: str) -> Dict[str, Any]:
        """The executable entries after a key, in order, a page at a time."""
        rest = [(k, e) for k, e in led.executable() if k > after]
        page, size = [], 0
        for k, e in rest:
            size += len(k) + len(json.dumps(e)) + 8
            if size > LEDGER_PAGE:
                break
            page.append([k, e])
        return {'outcome': 'done', 'r': 0, 'out': json.dumps({'entries': page, 'more': len(page) < len(rest)}), 'outs': ''}

    def _outcome(self, dispatch: str, rec: Record) -> Dict[str, Any]:
        if rec.local:
            if not rec.finished():
                return {'outcome': 'unknown'}
            with self.lock:
                if rec.done_at is None:
                    rec.done_at = time.monotonic()
            if rec.result is not None:
                return rec.result
            # auth get-or-create answered after its call returned unknown
            job = rec.sent[-1]
            return {'outcome': 'done', 'r': job.r, 'error': 'a credential is not kept; ask again'}
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
        """Drop completed outcomes after their keep time; pending ones stay. Under self.lock."""
        now = time.monotonic()
        for k, rec in list(self.records.items()):
            if rec.finished() and rec.done_at is None:
                rec.done_at = now
            if rec.done_at is not None and now - rec.done_at > (ANSWERED_KEEP if rec.answered else LATE_KEEP):
                del self.records[k]

    # --- server -------------------------------------------------------------

    def handler(self, local: bool = False) -> Any:
        """The handler of the public listener (confirmations), or with local
        that of the loopback listener (the bridge)."""
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
                    if self.path == '/v1/confirm' and not local:
                        try:
                            req = check_confirm_request(req, channel.fsid, name)
                        except ValueError as e:
                            self.reply(400, {'error': str(e)})
                            return
                        self.reply(*channel.confirm(req, getattr(self.connection, 'credentials', None)))
                    elif self.path == '/v1/bridge' and local:
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
                if m is None or not local or name != channel.mgr_id:
                    self.reply(404, {'error': 'not found'})
                    return
                self.reply(*channel.outcome(m.group(1)))

        return Handler

    def closing(self) -> bool:
        return any(srv is None or srv.closed.is_set() for srv in (self.server, self.bridge_server))

    def start(self, port: int = CONFIRM_PORT, bridge_port: int = BRIDGE_PORT) -> None:
        """Serve confirmations on all interfaces and the bridge on loopback,
        both with the same TLS context and client certificate checks."""
        if self.creds.ctx is None:
            raise ValueError('no TLS context')
        srv = Server(('', port), self.handler(), self.credentials)
        try:
            local = Server((BRIDGE_ADDR, bridge_port), self.handler(local=True), self.credentials)
        except Exception:
            srv.server_close()
            raise
        self.server, self.bridge_server = srv, local
        for s, name in ((srv, 'talos-channel'), (local, 'talos-bridge')):
            threading.Thread(target=s.serve_forever, kwargs={'poll_interval': 0.5}, name=name, daemon=True).start()

    def stop(self) -> None:
        """Close admission and every open connection, stop accepting."""
        for srv in (self.server, self.bridge_server):
            if srv is None:
                continue
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
