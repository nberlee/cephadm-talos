"""
talos: a read-only orchestrator backend for Ceph on Talos Linux, installed
as the mgr module "cephadm" (Ceph accepts only cephadm, rook and
test_orchestrator as orchestrator backend).

The cephadm-talos CLI writes the inventory to /etc/ceph/talos/inventory.json on
every host. The agent on each host serves what Talos runs there over mutual
TLS; this module polls the agents and answers `ceph orch status`, `orch host
ls` and `orch ps`. Everything else stays unimplemented: writes go through the
cephadm-talos CLI (docs/plans/02-agents-and-read-path.md).
"""

import base64
import datetime
import errno
import hashlib
import http.client
import json
import os
import re
import secrets
import ssl
import string
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import orchestrator
from ceph.deployment.hostspec import HostSpec
from ceph.deployment.service_spec import PlacementSpec, ServiceSpec
from mgr_module import CLICommandBase, CommandResult, HandleCommandResult, MgrModule, Option
from orchestrator import DaemonDescription, DaemonDescriptionStatus, OrchestratorError, handle_orch_error, UpgradeStatusSpec

from . import bridge, ledger

TalosCLICommand = CLICommandBase.make_registry_subtype("TalosCLICommand")

TALOS_DIR = '/etc/ceph/talos'
# journal states after which the leader does nothing more for an operation
TERMINAL = ('completed', 'nochange', 'failed', 'refused', 'abandoned')
# certificate renewal (plan 04, step 1): checked once a day, renewed this long
# before expiry, warned about when renewal keeps failing; the operator's
# certificate (its public copy, written by the CLI) warned about earlier
CERT_CHECK_INTERVAL = 24 * 3600.0
CERT_RENEW_BEFORE = datetime.timedelta(days=30)
CERT_ALERT_BEFORE = datetime.timedelta(days=7)
OPERATOR_WARN_BEFORE = datetime.timedelta(days=60)
OPERATOR_CERT_KEY = 'cephadm-talos/operator.crt'
INVENTORY_SCHEMA = 1
RECORD_SCHEMA = 2
AGENT_PORT = 4721
MAX_RECORD = 32 << 10
POLL_INTERVAL = 30.0
# the agent answers from memory; with ?refresh=1 it may first refresh for up to 20s
REQUEST_TIMEOUT = 10.0
REFRESH_TIMEOUT = 30.0
STALE_AFTER = datetime.timedelta(minutes=2)
MAX_WORKERS = 8


class InventoryError(Exception):
    pass


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def parse_time(s: str) -> datetime.datetime:
    # Go's RFC 3339 with nanoseconds; Python takes microseconds
    s = s.replace('Z', '+00:00')
    if '.' in s:
        head, rest = s.split('.', 1)
        frac, tz = rest[:-6], rest[-6:]
        s = '%s.%s%s' % (head, frac[:6], tz)
    t = datetime.datetime.fromisoformat(s)
    if t.tzinfo is None:
        t = t.replace(tzinfo=datetime.timezone.utc)
    return t


def _str(v: Any) -> bool:
    return isinstance(v, str) and v != ''


# The cluster state lives in the module's store (plan 03, item 4, internal/store):
# talos/inc/<incarnation>/manifest/<seq> names base64 chunks of each record.
STORE_PREFIX = 'talos/inc/'
STORE_SCHEMA = 1
# the CLI publishes until the leader takes over (plan 03, step 6)
INCARNATION = 'cli'
MODULE_PREFIX = 'mgr/cephadm/'
# acceptances one at a time: an `orch talos request` holds it while its command
# runs, and its nested call back into this module (a fresh Python thread state
# on the same OS thread, so a thread-local would be lost) re-enters it
_ACCEPT_LOCK = threading.RLock()


def _accepting(f: Any) -> Any:
    import functools

    @functools.wraps(f)
    def w(self: Any, *args: Any, **kwargs: Any) -> Any:
        with _ACCEPT_LOCK:
            self._not_suspended()
            return f(self, *args, **kwargs)
    return w

UUID_RE = re.compile(r'\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')

# the CLI's enrollment records (cephadm-talos host add after the handoff)
ENROLL_PREFIX = 'cephadm-talos/enroll/'
# the CLI's control record while the cluster is suspended for a recovery
# (plan 03, step 7 slice D): nothing is accepted while it exists
SUSPENSION_KEY = 'cephadm-talos/suspension'


def choose_incarnation(entries: Dict[str, str], own: Optional[int]) -> str:
    """The incarnation whose cluster state is current, as the CLI and the leader
    choose it: this mgr's own once it published, else the published one with
    the highest epoch in its takeover record, else the CLI's."""
    published = set()
    for k in entries:
        if k.startswith(STORE_PREFIX):
            inc, _, rest = k[len(STORE_PREFIX):].partition('/')
            if rest.startswith('manifest/'):
                published.add(inc)
    if own is not None and str(own) in published:
        return str(own)
    best, best_epoch = INCARNATION, -1
    for inc in published:
        if not inc.isdigit():
            continue
        try:
            epoch = json.loads(entries.get(STORE_PREFIX + inc + '/journal/takeover', '')).get('epoch')
        except (ValueError, AttributeError):
            continue
        if isinstance(epoch, int) and not isinstance(epoch, bool) and epoch > best_epoch:
            best, best_epoch = inc, epoch
    return best


def inventory_from_store(entries: Dict[str, str], incarnation: str = INCARNATION) -> Dict[str, Any]:
    """Read the inventory record of an incarnation's latest manifest from a snapshot
    of the module's store (get_store_prefix); every problem is an InventoryError."""
    inv, key = record_from_store(entries, incarnation, 'inventory')
    return check_inventory(inv, key)


def rgw_cert_pair(pem: str) -> Tuple[str, str]:
    """The operator's RGW certificate chain and its key from one PEM: the key
    must be the first certificate's, the certificate valid now."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    blocks = re.findall(r'-----BEGIN ([A-Z ]+)-----.*?-----END \1-----', pem, re.S)
    texts = [m.group(0) for m in re.finditer(r'-----BEGIN ([A-Z ]+)-----.*?-----END \1-----', pem, re.S)]
    chain = [t for t, b in zip(texts, blocks) if b == 'CERTIFICATE']
    keys = [t for t, b in zip(texts, blocks) if b.endswith('PRIVATE KEY')]
    if not chain or len(keys) != 1:
        raise OrchestratorError('rgw_frontend_ssl_certificate: a certificate chain and one private key')
    try:
        cert = x509.load_pem_x509_certificate(chain[0].encode())
        key = serialization.load_pem_private_key(keys[0].encode(), None)
    except Exception:
        raise OrchestratorError('rgw_frontend_ssl_certificate: does not parse')
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if cert.public_key().public_bytes(serialization.Encoding.PEM, pub) != key.public_key().public_bytes(serialization.Encoding.PEM, pub):
        raise OrchestratorError('rgw_frontend_ssl_certificate: the key is not the certificate\'s')
    # the Ceph image's cryptography may predate the *_utc attributes (naive UTC then)
    before = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    after = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    if not before <= now <= after:
        raise OrchestratorError('rgw_frontend_ssl_certificate: the certificate is not valid now')
    joined = '\n'.join(chain) + '\n'
    if len(joined) > 16384:
        raise OrchestratorError('rgw_frontend_ssl_certificate: the chain is larger than 16 KiB')
    return joined, keys[0] + '\n'


def cli_baseline(entries: Dict[str, str]) -> Dict[str, Any]:
    """The inventory of the CLI's sealed state, the root of what the module
    authorizes (ledger.Fold): no incarnation can write it through the bridge."""
    cluster, key = record_from_store(entries, INCARNATION, 'cluster')
    if not isinstance(cluster, dict) or cluster.get('sealed') is not True:
        raise InventoryError('the CLI has not handed the cluster over (%s is not sealed)' % key)
    # with the CLI's RGW settings (public: port, VIP, CA certificate)
    return dict(inventory_from_store(entries, INCARNATION), cli_rgw=cluster.get('rgw') or {})


def record_from_store(entries: Dict[str, str], incarnation: str, name: str) -> Tuple[Any, str]:
    """Read one record of an incarnation's latest manifest, and the manifest's key."""
    base = STORE_PREFIX + incarnation + '/'
    seqs = {}
    for k in entries:
        if k.startswith(base + 'manifest/'):
            try:
                seqs[int(k[len(base) + len('manifest/'):])] = k
            except ValueError:
                continue
    if not seqs:
        raise InventoryError('no cluster state published in the store (%s)' % base)
    key = seqs[max(seqs)]
    try:
        m = json.loads(entries[key])
        if not isinstance(m, dict):
            raise ValueError('manifest is not an object')
        if m.get('schema') != STORE_SCHEMA or m.get('incarnation') != incarnation \
                or type(m.get('seq')) is not int or m['seq'] != max(seqs):
            raise ValueError('unexpected manifest %r' % {k: m.get(k) for k in ('schema', 'incarnation', 'seq')})
        recs = m.get('records')
        e = recs.get(name) if isinstance(recs, dict) else None
        if not isinstance(e, dict) or not isinstance(e.get('chunks'), list) or not e['chunks'] \
                or not _str(e.get('sha256')) or type(e.get('size')) is not int:
            raise ValueError('invalid %s entry %r' % (name, e))
        enc = ''
        for c in e['chunks']:
            if not _str(c) or not c.startswith(MODULE_PREFIX + base + 'rec/'):
                raise ValueError('chunk %r outside the incarnation' % c)
            part = entries[c[len(MODULE_PREFIX):]]
            if not isinstance(part, str):
                raise ValueError('chunk %s is not text' % c)
            enc += part
        data = base64.b64decode(enc, validate=True)
        if hashlib.sha256(data).hexdigest() != e['sha256'] or len(data) != e['size']:
            raise ValueError('%s does not match its manifest' % name)
        rec = json.loads(data)
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise InventoryError('cannot read the %s from %s: %s' % (name, key, e))
    return rec, key


def check_inventory(inv: Any, path: str) -> Dict[str, Any]:
    """Check an inventory; every problem is an InventoryError."""
    if not isinstance(inv, dict) or inv.get('schema') != INVENTORY_SCHEMA:
        raise InventoryError('%s has schema %r, this module needs %d' % (
            path, inv.get('schema') if isinstance(inv, dict) else None, INVENTORY_SCHEMA))
    for key in ('hosts', 'daemons'):
        if not isinstance(inv.get(key), list):
            raise InventoryError('%s: %s is missing' % (path, key))
    names = set()
    for h in inv['hosts']:
        if not isinstance(h, dict) or not _str(h.get('name')) or not _str(h.get('addr')) or h['name'] in names \
                or not isinstance(h.get('labels', []), list) or not isinstance(h.get('maintenance', False), bool):
            raise InventoryError('%s: invalid or duplicate host %r' % (path, h))
        names.add(h['name'])
    ids = set()
    for d in inv['daemons']:
        if not isinstance(d, dict) or not all(_str(d.get(k)) for k in ('doc_name', 'host', 'daemon_type', 'daemon_id', 'service_name')):
            raise InventoryError('%s: invalid daemon %r' % (path, d))
        if d['host'] not in names:
            raise InventoryError('%s: daemon %s on unknown host %s' % (path, d['doc_name'], d['host']))
        key = (d['daemon_type'], d['daemon_id'])
        if key in ids:
            raise InventoryError('%s: duplicate daemon %s.%s' % (path, *key))
        ids.add(key)
    for key in ('updated_at', 'cert_expiry'):
        if inv.get(key) is not None:
            try:
                if not isinstance(inv[key], str):
                    raise ValueError('not a string')
                parse_time(inv[key])
            except ValueError:
                raise InventoryError('%s: invalid %s %r' % (path, key, inv[key]))
    return inv


IDENTITY_SCHEME = 'cephadm-talos://'
# the same form internal/pki accepts: no escapes, nothing to canonicalize
IDENTITY_PART = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')


def cert_identity(peercert: Optional[Dict[str, Any]]) -> Tuple[str, str, str]:
    """The (fsid, role, name) of a verified peer certificate's identity URI SAN (plan 03, item 3).

    Like Go's URL parsing in internal/pki, the scheme is matched in any case; every
    such SAN counts, and there must be exactly one, in the exact form
    cephadm-talos://<fsid>/<role>/<name>."""
    found = []
    for kind, value in (peercert or {}).get('subjectAltName', ()):
        # the scheme alone makes it an identity SAN, as for Go; the form is checked after
        if kind != 'URI' or value[:len(IDENTITY_SCHEME) - 2].lower() != IDENTITY_SCHEME[:-2]:
            continue
        if value[:len(IDENTITY_SCHEME)].lower() != IDENTITY_SCHEME:
            raise ValueError('malformed identity %r' % value)
        rest = value[len(IDENTITY_SCHEME):]
        if rest.endswith('#'):  # Go's URL parser drops an empty fragment
            rest = rest[:-1]
        parts = rest.split('/')
        if len(parts) != 3 or not all(IDENTITY_PART.match(p) for p in parts):
            raise ValueError('malformed identity %r' % value)
        found.append((parts[0], parts[1], parts[2]))
    if len(found) != 1:
        raise ValueError('certificate carries %d cephadm-talos identities, want 1' % len(found))
    return found[0]


def require_identity(peercert: Optional[Dict[str, Any]], fsid: str, role: str, name: Optional[str] = None) -> str:
    """Check a peer's identity; returns its name. Endpoints check this, never the common name."""
    got = cert_identity(peercert)
    if got[0] != fsid or got[1] != role or (name is not None and got[2] != name):
        raise ValueError('peer is %s/%s/%s, want %s/%s/%s' % (got + (fsid, role, name or '*')))
    return got[2]


def fetch_record(addr: str, tls: ssl.SSLContext, refresh: bool = False,
                 expect: Optional[Tuple[str, str]] = None) -> Dict[str, Any]:
    """Fetch and validate one agent's status record within an overall deadline; raises on any problem.

    expect is the (fsid, host) the agent's certificate must be issued to."""
    total = REFRESH_TIMEOUT if refresh else REQUEST_TIMEOUT
    conn = http.client.HTTPSConnection(addr, AGENT_PORT, context=tls, timeout=total)
    expired = threading.Event()
    # http.client forgets conn.sock on `Connection: close` while the response
    # still reads from it, so the deadline keeps its own reference
    sock: List[Optional[socket.socket]] = [None]

    def cut() -> None:
        # a trickling peer resets every socket timeout; the deadline closes the
        # connection, so headers and body together cannot outlive it
        expired.set()
        for s in (sock[0], conn.sock):
            if s is not None:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    timer = threading.Timer(total, cut)
    timer.daemon = True
    timer.start()
    try:
        conn.connect()
        sock[0] = conn.sock
        if expired.is_set():  # the deadline passed while connecting
            cut()
        if expect is not None:
            require_identity(conn.sock.getpeercert(), expect[0], 'agent', expect[1])
        conn.request('GET', '/status?refresh=1' if refresh else '/status')
        resp = conn.getresponse()
        body = resp.read(MAX_RECORD + 1)
        if len(body) > MAX_RECORD:
            raise ValueError('status record larger than %d bytes' % MAX_RECORD)
        if resp.status != 200:
            raise ValueError('agent answered %d: %s' % (resp.status, body[:200].decode(errors='replace').strip()))
        return validate_record(json.loads(body))
    except Exception:
        if expired.is_set():
            raise TimeoutError('agent did not answer within %.0fs' % total)
        raise
    finally:
        timer.cancel()
        conn.close()


def validate_record(rec: Any) -> Dict[str, Any]:
    """Check a whole record; any bad part rejects it, so it never reaches the mapping."""
    if not isinstance(rec, dict) or rec.get('schema') != RECORD_SCHEMA:
        raise ValueError('status record of unknown schema %r' % (rec.get('schema') if isinstance(rec, dict) else None))
    if not isinstance(rec.get('containers'), dict) or not isinstance(rec.get('observed_at'), str):
        raise ValueError('incomplete status record')
    for name, c in rec['containers'].items():
        if not isinstance(c, dict) or not isinstance(c.get('state', ''), str) or not isinstance(c.get('image_digest', ''), str) \
                or not isinstance(c.get('restarts', 0), int) or not isinstance(c.get('instances', False), bool) \
                or not isinstance(c.get('exit_code', 0), int) or isinstance(c.get('exit_code', 0), bool) \
                or not isinstance(c.get('version', ''), str):
            raise ValueError('invalid container %r in status record' % name)
    rec['observed_at'] = parse_time(rec['observed_at'])
    return rec


# Talos container state -> orchestrator status
STATES = {
    'running': DaemonDescriptionStatus.running,
    'pending': DaemonDescriptionStatus.starting,
    'pulling': DaemonDescriptionStatus.starting,
    'starting': DaemonDescriptionStatus.starting,
    'exited': DaemonDescriptionStatus.error,
    'backoff': DaemonDescriptionStatus.error,
    'stopping': DaemonDescriptionStatus.stopped,
    # restart policies other than always (plan 03, item 12)
    'completed': DaemonDescriptionStatus.stopped,
    'failed': DaemonDescriptionStatus.error,
}


def daemon_status(daemon: Dict[str, Any], host: Dict[str, Any], obs: Tuple[Optional[Dict[str, Any]], str],
                  now: datetime.datetime) -> Tuple[DaemonDescriptionStatus, str, Optional[Dict[str, Any]]]:
    """Map what the agent saw to a status, a description and the container record."""
    if host.get('maintenance'):
        return DaemonDescriptionStatus.stopped, 'host in maintenance', None
    if daemon.get('local_only'):
        return DaemonDescriptionStatus.stopped, 'removal pending (cluster-side cleanup not done)', None
    rec, err = obs
    if rec is None:
        return DaemonDescriptionStatus.unknown, 'no status from the agent: %s' % (err or 'not polled yet'), None
    if now - rec['observed_at'] > STALE_AFTER:
        return DaemonDescriptionStatus.unknown, 'agent status stale since %s' % rec['observed_at'].isoformat(), None
    c = rec['containers'].get(daemon['doc_name'])
    if c is None or (not c.get('state') and not c.get('instances')):
        return DaemonDescriptionStatus.error, 'missing: Talos does not run %s' % daemon['doc_name'], None
    if not c.get('state'):
        return DaemonDescriptionStatus.stopped, 'stopping', c
    status = STATES.get(c['state'], DaemonDescriptionStatus.unknown)
    desc = c['state']
    if desc in ('completed', 'failed', 'exited', 'backoff') and c.get('exit_code'):
        desc = '%s (exit %d)' % (desc, c['exit_code'])
    return status, desc, c


def build_daemons(inv: Dict[str, Any], observations: Dict[str, Tuple[Optional[Dict[str, Any]], str]],
                  now: datetime.datetime) -> List[DaemonDescription]:
    hosts = {h['name']: h for h in inv['hosts']}
    out = []
    for d in inv['daemons']:
        host = hosts.get(d['host'], {'name': d['host']})
        obs = observations.get(d['host'], (None, ''))
        status, desc, c = daemon_status(d, host, obs, now)
        if d['daemon_id'].startswith('pending-'):
            desc = 'numeric OSD ID not yet known; ' + desc
        rec = obs[0]
        dd = DaemonDescription(
            daemon_type=d['daemon_type'],
            daemon_id=d['daemon_id'],
            hostname=d['host'],
            container_id=d['doc_name'],
            container_image_name=d.get('desired_image') or None,
            container_image_digests=[c['image_digest']] if c and c.get('image_digest') else None,
            # what the daemon reports on its admin socket, else what the cluster runs
            version=((c or {}).get('version') or inv.get('ceph_version')) if d['daemon_type'] != 'keepalived' else None,
            status=status,
            status_desc=desc,
            last_refresh=rec['observed_at'] if rec else None,
            service_name=d['service_name'],
            ip=host.get('addr'),
        )
        out.append(dd)
    return out


def filter_daemons(daemons: List[DaemonDescription], service_name: Optional[str] = None, daemon_type: Optional[str] = None,
                   daemon_id: Optional[str] = None, host: Optional[str] = None) -> List[DaemonDescription]:
    return [
        d for d in daemons
        if (service_name is None or d.service_name() == service_name)
        and (daemon_type is None or d.daemon_type == daemon_type)
        and (daemon_id is None or d.daemon_id == daemon_id)
        and (host is None or d.hostname == host)
    ]


def build_hosts(inv: Dict[str, Any]) -> List[HostSpec]:
    return [HostSpec(h['name'], addr=h['addr'], labels=h.get('labels') or [],
                     status='maintenance' if h.get('maintenance') else '') for h in inv['hosts']]


class Poller:
    """Polls every inventory host's agent with bounded parallelism."""

    def __init__(self, fetch: Callable[[str, bool], Dict[str, Any]]) -> None:
        self.fetch = fetch
        self.stop = threading.Event()
        self.lock = threading.Lock()
        # one poll cycle at a time: a refresh and the background poll never interleave
        self.cycle = threading.Lock()
        self.observations: Dict[str, Tuple[Optional[Dict[str, Any]], str]] = {}
        self.executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix='talos-poll')

    def poll(self, hosts: List[Dict[str, Any]], refresh: bool = False) -> None:
        with self.cycle:
            self._poll(hosts, refresh)

    def _poll(self, hosts: List[Dict[str, Any]], refresh: bool) -> None:
        if self.stop.is_set():
            return
        futures = {}
        for h in hosts:
            try:
                futures[h['name']] = self.executor.submit(self.fetch, h['addr'], refresh)
            except RuntimeError:  # shut down meanwhile
                return
        for name, f in futures.items():
            try:
                obs: Tuple[Optional[Dict[str, Any]], str] = (f.result(), '')
            except Exception as e:  # each host stands on its own
                obs = (None, str(e) or e.__class__.__name__)
            with self.lock:
                self.observations[name] = obs
        with self.lock:
            for name in list(self.observations):
                if name not in futures:
                    del self.observations[name]

    def snapshot(self) -> Dict[str, Tuple[Optional[Dict[str, Any]], str]]:
        with self.lock:
            return dict(self.observations)

    def shutdown(self) -> None:
        self.stop.set()
        # requests in flight end within their timeout
        self.executor.shutdown(wait=True, cancel_futures=True)


def tls_context(directory: str = TALOS_DIR) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=os.path.join(directory, 'agent-ca.crt'))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(os.path.join(directory, 'mgr-client.crt'), os.path.join(directory, 'mgr-client.key'))
    return ctx



# RGW_SPEC_FIELDS are the RGW spec fields this backend takes; Ceph 21 moves an
# operator's PEM bundle from rgw_frontend_ssl_certificate into ssl_cert and
# ssl_key (certificate_source inline) when ssl is set, and adds its defaults
RGW_SPEC_FIELDS = {'rgw_frontend_port', 'ssl', 'rgw_frontend_ssl_certificate', 'ssl_cert', 'ssl_key', 'certificate_source',
                   'rgw_exit_timeout_secs'}


def rgw_spec_pem(spec: Any) -> Optional[str]:
    """The operator's PEM bundle of an RGW spec ('' for none), or None if the
    spec has anything this backend does not take."""
    j = spec.to_json()
    if set(j) - {'service_type', 'service_id', 'service_name', 'placement', 'spec'}:
        return None
    s = dict(j.get('spec') or {})
    # to_json drops falsy values: a 0 is read from the spec itself
    if set(s) - RGW_SPEC_FIELDS or getattr(spec, 'rgw_exit_timeout_secs', 120) not in (None, 120) or getattr(spec, 'rgw_frontend_port', None) == 0:
        return None
    legacy = s.get('rgw_frontend_ssl_certificate')
    legacy = '\n'.join(legacy) if isinstance(legacy, list) else (legacy or '')
    split = (s.get('ssl_cert') or '').strip(), (s.get('ssl_key') or '').strip()
    if legacy and any(split) or bool(split[0]) != bool(split[1]):
        return None
    pem = legacy or ('%s\n%s\n' % split if split[0] else '')
    if s.get('certificate_source') not in (None, 'cephadm-signed', 'inline') or s.get('certificate_source') == 'inline' and not pem:
        return None
    return pem


def cert_not_after(pem: Optional[str]) -> Optional[datetime.datetime]:
    """The notAfter of the first certificate in a PEM text, None if there is none."""
    from cryptography import x509
    try:
        return x509.load_pem_x509_certificate((pem or '').encode()).not_valid_after_utc
    except ValueError:
        return None


def served_leaf(addr: str, port: int, timeout: float = 5.0) -> Optional[bytes]:
    """The leaf certificate (DER) a TLS server serves (an RGW), unverified: only
    which one it is and its expiry are read. None if it does not answer."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((addr, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as tls:
                return tls.getpeercert(binary_form=True) or None
    except OSError:
        return None


def leaf_der(pem: Optional[str]) -> Optional[bytes]:
    """The first certificate of a PEM chain, as DER; None if there is none."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try:
        return x509.load_pem_x509_certificate((pem or '').encode()).public_bytes(serialization.Encoding.DER)
    except ValueError:
        return None


def der_not_after(der: bytes) -> Optional[datetime.datetime]:
    from cryptography import x509
    try:
        return x509.load_der_x509_certificate(der).not_valid_after_utc
    except ValueError:
        return None


class Module(orchestrator.Orchestrator, MgrModule):
    CLICommand = TalosCLICommand
    MODULE_OPTIONS = [
        # as in cephadm: the keepalived image of the ingress (a digest the operator approved)
        Option('container_image_keepalived', type='str', default='', desc='keepalived container image of the ingress, by digest'),
        # the renewal threshold of the daily certificate check (plan 04, step 1); a
        # larger value renews earlier, for tests
        Option('talos_cert_renew_days', type='int', default=30, min=1, desc='renew certificates that expire within this many days'),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._poller = Poller(self._fetch)

    def _fetch(self, addr: str, refresh: bool) -> Dict[str, Any]:
        inv = self._inventory()
        names = [h['name'] for h in inv['hosts'] if h['addr'] == addr]
        if len(names) != 1:
            raise ValueError('address %s is not one inventory host' % addr)
        return fetch_record(addr, tls_context(), refresh=refresh, expect=(inv['fsid'], names[0]))

    def _inventory(self) -> Dict[str, Any]:
        entries = self.get_store_prefix(STORE_PREFIX)
        return inventory_from_store(entries, choose_incarnation(entries, getattr(self, '_gid', None)))

    def _not_suspended(self) -> None:
        """Refuse an acceptance while the CLI's suspension record exists, or
        cannot be read (checked under _ACCEPT_LOCK, before every acceptance)."""
        r, out, err = self.mon_command({'prefix': 'config-key get', 'key': SUSPENSION_KEY})
        if r == -errno.ENOENT:
            return
        if r != 0:
            raise OrchestratorError('cannot read the suspension record (%s): nothing is accepted' % err.strip())
        try:
            session = json.loads(out)['session']
        except (ValueError, KeyError, TypeError):
            session = '(unreadable)'
        raise OrchestratorError('the cluster is suspended for recovery session %s: nothing is accepted until `cephadm-talos resume`' % session)

    def _authority(self) -> Tuple[ledger.Ledger, ledger.Fold]:
        """This incarnation's ledger and the fold it authorizes; raises without them."""
        led = getattr(self, '_ledger', None)
        if led is None or not led.ready:
            raise OrchestratorError('this mgr has not opened the ledger: it is not the leader yet')
        return led, ledger.Fold(cli_baseline(self.get_store_prefix(STORE_PREFIX)), led.executable())

    def _journal(self, op_id: str) -> Optional[Dict[str, Any]]:
        """The leader's journal record of an operation, from any incarnation (shown
        to the operator; it authorizes nothing)."""
        best: Optional[Dict[str, Any]] = None
        for k, v in self.get_store_prefix(STORE_PREFIX).items():
            if k.endswith('/journal/op/' + op_id):
                try:
                    rec = json.loads(v)
                except ValueError:
                    continue
                if isinstance(rec, dict) and (best is None or rec.get('state') in TERMINAL):
                    best = rec
        return best

    def _unfinished(self, daemon: Optional[str], host: str) -> Optional[str]:
        """An accepted operation that conflicts and that the leader's journal does
        not show finished: for a daemon, one on that daemon or the removal of its
        host; for a host (daemon None), any on that host."""
        led, _ = self._authority()
        for _, e in led.executable():
            if e['id'].startswith('m-'):
                continue
            if daemon is not None and e.get('daemon') is None and e['kind'] not in ledger.HOST_KINDS:
                continue
            if daemon is not None and e.get('daemon') != daemon and not (e['kind'] in ledger.HOST_KINDS and e['host'] == host):
                continue
            if daemon is None and e.get('host') != host:
                continue
            rec = self._journal(e['id'])
            if rec is None or rec.get('state') not in TERMINAL:
                return e['id']
        return None

    def _settle(self) -> None:
        """An earlier append whose outcome is unknown counts before any check."""
        led, _ = self._authority()
        try:
            led.settle()
        except ledger.LedgerError as e:
            raise OrchestratorError('an earlier operation is not settled yet (%s); try again' % e)

    def _not_in_maintenance(self, host: str) -> None:
        _, fold = self._authority()
        if host in fold.maintenance:
            raise OrchestratorError('%s is in maintenance (ceph orch host maintenance exit %s)' % (host, host))

    def _rgw_port(self) -> Optional[int]:
        """The RGWs' port: the newest RGW add's, else the CLI's, None before any."""
        led, _ = self._authority()
        for _, e in reversed(led.executable()):
            if e['kind'] == 'add_daemon' and e['daemon'].startswith('rgw.'):
                return int(e['port'])
        try:
            cluster, _ = record_from_store(self.get_store_prefix(STORE_PREFIX), INCARNATION, 'cluster')
            return int(((cluster or {}).get('rgw') or {}).get('port')) or None
        except Exception:
            return None

    def _add_rgw(self, spec: Any) -> List[str]:
        """One RGW of service default on one host: with a generated certificate,
        or the operator's (`daemon add -i`, rgw_frontend_ssl_certificate)."""
        p = spec.placement
        if spec.service_id != 'default':
            raise OrchestratorError('the RGW service is default: daemon add rgw default <host>')
        if p is None or len(p.hosts) != 1 or p.count not in (None, 1) or p.count_per_host or p.label or p.host_pattern \
                or p.hosts[0].network or p.hosts[0].name:
            raise OrchestratorError('place exactly one RGW on one named host')
        host = p.hosts[0].hostname
        pem = rgw_spec_pem(spec)
        if pem is None:
            raise OrchestratorError('only the port and the operator\'s certificate are supported for an RGW by this backend')
        self._settle()
        _, fold = self._authority()
        if host not in fold.hosts:
            raise OrchestratorError('%s is not a host of the cluster' % host)
        name = 'rgw.' + host
        if name in fold.daemons:
            raise OrchestratorError('%s exists already' % name)
        current = self._rgw_port()
        port = spec.rgw_frontend_port or current or 443
        if current is not None and port != current:
            raise OrchestratorError('the RGWs serve on port %d' % current)
        op_id = 'op-' + os.urandom(8).hex()
        extra: Dict[str, Any] = {'port': port}
        if pem:
            chain, key = rgw_cert_pair(pem)
            # the key first, as a secret of this operation; the chain is public
            r, _, outs = self.mon_command({'prefix': 'config-key set', 'key': '%suser/%s/rgw-server.key' % (bridge.SECRET_PREFIX, op_id), 'val': key})
            if r != 0:
                raise OrchestratorError('the key was not written: %s' % outs)
            extra['cert'] = chain
        op_id = self._accept('add_daemon', name, host, op_id=op_id, **extra)
        return ['Scheduled to deploy %s on host %s (operation %s)' % (name, host, op_id)]

    def _request_fields(self) -> Dict[str, Any]:
        """The request uuid and inputs hash for the entry being accepted, if a
        request is in progress on this thread (orch talos request)."""
        r = self.__dict__.get('_request_active')
        return {'request': r[0], 'inputs': r[1]} if r else {}

    @_accepting
    def _accept(self, kind: str, daemon: Optional[str], host: str, op_id: Optional[str] = None, **extra: Any) -> str:
        """Accept an operation: checks, then one ledger entry (ledger.py)."""
        led, fold = self._authority()
        lead = getattr(self, '_leadership', None)
        if lead is None or not lead.still_active():
            raise OrchestratorError('this mgr is not confirmed as the active one; try again')
        # an earlier append whose outcome is unknown counts before any check
        try:
            led.settle()
        except ledger.LedgerError as e:
            raise OrchestratorError('an earlier operation is not settled yet (%s); try again' % e)
        # one operation at a time per daemon (per host for a host's removal): a
        # lying journal can only refuse commands
        busy = self._unfinished(daemon, host)
        if busy:
            raise OrchestratorError('%s has operation %s in progress (orch talos operation %s)' % (daemon or host, busy, busy))
        # a mgr's renewal changes its certificates in the state only while its
        # host is in maintenance; the exit renders them (plan 04, step 1)
        if kind not in ('exit_maintenance', 'renew_mgr', 'renew_agent'):
            self._not_in_maintenance(host)
        op_id = op_id or 'op-' + os.urandom(8).hex()
        entry = {'id': op_id, 'kind': kind, 'host': host, **extra, **self._request_fields()}
        if daemon:
            entry['daemon'] = daemon
        try:
            led.append(entry)
        except ledger.OutcomeUnknown:
            raise OrchestratorError('the mons did not answer: operation %s may have been accepted (orch talos operation %s)' % (op_id, op_id))
        except ledger.LedgerError as e:
            raise OrchestratorError('not accepted: %s' % e)
        return op_id

    def _ledger_mon(self, cmds: bridge.Commands) -> Callable[[Dict[str, Any], float], Optional[Tuple[int, str, str]]]:
        def mon(cmd: Dict[str, Any], deadline: float) -> Optional[Tuple[int, str, str]]:
            job = cmds.submit(cmd)
            if job is None or not job.ev.wait(deadline):
                return None
            if job.too_large:
                return -27, '', 'output too large'  # EFBIG
            return job.r, job.outb, job.outs
        return mon

    def _send_mon(self, result: Any, cmd: str) -> None:
        self.send_command(result, 'mon', '', cmd, '')

    def _lead(self, activation_map: Optional[Dict[str, Any]]) -> None:
        """Capture the incarnation, serve the agent channel, heartbeat the local agent (items 1, 2, 5)."""
        leader_cmds = bridge.Commands(self._send_mon, lambda: CommandResult(''), bridge.LEADERSHIP_COMMANDS, 'talos-lead-cmd')
        bridge_cmds = bridge.Commands(self._send_mon, lambda: CommandResult(''), bridge.BRIDGE_COMMANDS, 'talos-bridge-cmd')
        leadership = bridge.Leadership(self.get_mgr_id(), activation_map, leader_cmds)
        if leadership.candidate is None:
            self.log.warning('this mgr was not active in the map it started with; it confirms nothing')
        channel: Optional[bridge.Channel] = None
        nonce = ''
        try:
            while not self._poller.stop.is_set():
                try:
                    inv = self._inventory()
                    if channel is None:
                        creds = bridge.load_credentials(os.path.join(TALOS_DIR, 'agent-ca.crt'), os.path.join(TALOS_DIR, 'mgr-server.crt'),
                                                        os.path.join(TALOS_DIR, 'mgr-server.key'))
                        c = bridge.Channel(
                            inv['fsid'], self.get_mgr_id(), leadership, bridge_cmds, creds.ctx, creds.server_key,
                            require_identity, self.log, self._authority, creds.ca_cert, creds.digest)
                        c.start()
                        channel = c  # only a started channel; a failed start is retried
                    else:
                        # a renewed server certificate, once the leader granted its files
                        channel.reload(os.path.join(TALOS_DIR, 'agent-ca.crt'), os.path.join(TALOS_DIR, 'mgr-server.crt'),
                                       os.path.join(TALOS_DIR, 'mgr-server.key'))
                    if leadership.capture():
                        gid, epoch = leadership.captured() or (0, 0)
                        self._gid = gid  # this incarnation's state, once its leader published it
                        self._leadership = leadership
                        if getattr(self, '_ledger', None) is None:
                            self._ledger = ledger.Ledger(self._ledger_mon(bridge_cmds), gid, epoch)
                        try:
                            if not self._ledger.ready:
                                self._ledger.open()  # its takeover entry, before anything is accepted
                            else:
                                self._ledger.settle()  # an append the mons did not answer
                        except ledger.LedgerError as e:
                            self.log.warning('the ledger: %s', e)
                        nonce = self._heartbeat(inv, gid, epoch, nonce)
                        self._schedule_cert_check()
                except InventoryError as e:
                    self.log.warning('%s', e)
                except Exception:  # leadership must survive anything
                    self.log.exception('agent channel failed')
                self._poller.stop.wait(bridge.HEARTBEAT_INTERVAL)
        finally:
            if channel is not None:
                channel.stop()
            leader_cmds.stop()
            bridge_cmds.stop()

    def _heartbeat(self, inv: Dict[str, Any], gid: int, epoch: int, nonce: str) -> str:
        """Tell the local agent it is the leader's; returns the agent's session nonce."""
        mine = [h['addr'] for h in inv['hosts'] if h['name'] == self.get_mgr_id()]
        if len(mine) != 1:
            raise ValueError('this mgr\'s host %s is not one inventory host' % self.get_mgr_id())
        status, body = bridge.post_json(
            mine[0], AGENT_PORT, tls_context(), '/v1/heartbeat', bridge.heartbeat_body(inv['fsid'], self.get_mgr_id(), gid, epoch, nonce),
            bridge.HEARTBEAT_INTERVAL, lambda cert: require_identity(cert, inv['fsid'], 'agent', self.get_mgr_id()))
        if status != 200:
            raise ValueError('agent answered %d to the heartbeat' % status)
        reply = json.loads(body)
        if not isinstance(reply, dict) or reply.get('version') != bridge.WIRE_VERSION or not isinstance(reply.get('session'), str):
            raise ValueError('malformed heartbeat reply')
        return reply['session']

    def serve(self) -> None:
        # the map this process was activated with names its own gid; later maps may not
        lead = threading.Thread(target=self._lead, args=(self.get('mgr_map'),), name='talos-lead', daemon=True)
        self._lead_thread = lead
        lead.start()
        while not self._poller.stop.is_set():
            try:
                self._poller.poll(self._inventory()['hosts'])
            except InventoryError as e:
                self.log.warning('%s', e)
            except Exception:  # polling must survive anything
                self.log.exception('poll failed')
            self._poller.stop.wait(POLL_INTERVAL)

    def shutdown(self) -> None:
        self._poller.shutdown()
        lead = getattr(self, '_lead_thread', None)
        if lead is not None:
            lead.join(bridge.SHUTDOWN_WAIT + bridge.HEARTBEAT_INTERVAL)

    def available(self) -> Tuple[bool, str, Dict[str, Any]]:
        try:
            inv = self._inventory()
        except InventoryError as e:
            return False, str(e), {}
        details: Dict[str, Any] = {'inventory_revision': inv.get('revision')}
        if inv.get('updated_at'):
            age = utcnow() - parse_time(inv['updated_at'])
            details['inventory_age_seconds'] = int(age.total_seconds())
        if inv.get('cert_expiry'):
            details['agent_cert_expiry'] = inv['cert_expiry']
        return True, '', details

    @handle_orch_error
    def daemon_action(self, action: str, daemon_name: str, image: Optional[str] = None, force: bool = False) -> str:
        if action not in ('restart', 'redeploy'):
            raise OrchestratorError('daemon %s is not supported by this backend: only restart and redeploy' % action)
        if image is not None or force:
            raise OrchestratorError('an image or --force is not supported by this backend')
        _, fold = self._authority()
        host = fold.daemons.get(daemon_name)
        if host is None:
            raise OrchestratorError('%s is not a daemon of the cluster' % daemon_name)
        op_id = self._accept(action, daemon_name, host)
        return 'Scheduled to %s %s on host %s (operation %s)' % (action, daemon_name, host, op_id)

    @handle_orch_error
    def add_daemon(self, spec: ServiceSpec) -> List[str]:
        if spec.service_type == 'rgw':
            return self._add_rgw(spec)
        if spec.service_type not in ('mon', 'mgr'):
            raise OrchestratorError('daemon add %s is not supported by this backend: only mon, mgr and rgw' % spec.service_type)
        p = spec.placement
        if p is None or len(p.hosts) != 1 or p.count not in (None, 1) or p.count_per_host or p.label or p.host_pattern:
            raise OrchestratorError('place exactly one daemon on one named host')
        h = p.hosts[0]
        if h.network or h.name:
            raise OrchestratorError('a network or daemon name is not supported by this backend: mon and mgr ids are host names')
        # exactly the spec `orch daemon add mon|mgr <host>` builds: any other
        # field, also one a newer Ceph adds, is refused rather than ignored
        if spec.to_json() != ServiceSpec(spec.service_type, placement=PlacementSpec(hosts=[h.hostname])).to_json():
            raise OrchestratorError('spec options are not supported by this backend')
        _, fold = self._authority()
        if h.hostname not in fold.hosts:
            raise OrchestratorError('%s is not a host of the cluster' % h.hostname)
        name = '%s.%s' % (spec.service_type, h.hostname)
        if name in fold.daemons:
            raise OrchestratorError('%s exists already' % name)
        op_id = self._accept('add_daemon', name, h.hostname)
        return ['Scheduled to deploy %s on host %s (operation %s)' % (name, h.hostname, op_id)]

    @handle_orch_error
    def remove_daemons(self, names: List[str]) -> List[str]:
        self._settle()
        _, fold = self._authority()
        active = 'mgr.' + self.get_mgr_id()
        for n in names:
            if not n.startswith(('mgr.', 'mon.', 'rgw.')):
                raise OrchestratorError('daemon rm %s is not supported by this backend: only mon, mgr and rgw' % n)
            if n not in fold.daemons:
                raise OrchestratorError('%s is not a daemon of the cluster' % n)
            # the VIP leaves a host before its RGW: an ingress without that host first
            if n.startswith('rgw.') and any(d.startswith('keepalived.') and h == fold.daemons[n] for d, h in fold.daemons.items()):
                raise OrchestratorError('%s has a keepalived of the ingress: apply the ingress without %s first' % (fold.daemons[n], fold.daemons[n]))
            if n == active:
                raise OrchestratorError('%s is the active mgr: fail it over first (ceph mgr fail)' % n)
        for t in ('mon', 'mgr'):
            if any(n.startswith(t + '.') for n in names) and not {n for n in fold.daemons if n.startswith(t + '.')} - set(names):
                raise OrchestratorError('the cluster would have no %s left' % t)
        if len(set(names)) != len(names):
            raise OrchestratorError('a daemon named twice')
        for n in names:  # every name checked before any is accepted
            busy = self._unfinished(n, fold.daemons[n])
            if busy:
                raise OrchestratorError('%s has operation %s in progress (orch talos operation %s)' % (n, busy, busy))
            self._not_in_maintenance(fold.daemons[n])
        return ['Scheduled to remove %s from host %s (operation %s)' % (n, fold.daemons[n], self._accept('remove_daemon', n, fold.daemons[n]))
                for n in names]

    @handle_orch_error
    def create_osds(self, drive_group: Any, skip_validation: bool = False) -> str:
        """One OSD on one disk of one host (`ceph orch daemon add osd HOST:DEVICE`)."""
        if skip_validation:
            raise OrchestratorError('--skip-validation is not supported by this backend')
        p = drive_group.placement
        pattern = getattr(p, 'host_pattern', None)
        host = getattr(pattern, 'pattern', pattern)
        if p is None or not isinstance(host, str) or p.hosts or p.label or p.count is not None or p.count_per_host is not None:
            raise OrchestratorError('name exactly one host')
        sel = drive_group.data_devices
        paths = getattr(sel, 'paths', None) or []
        if sel is None or len(paths) != 1 or any(getattr(sel, a, None) for a in ('model', 'vendor', 'size', 'rotational', 'limit', 'all', 'actuators')):
            raise OrchestratorError('name exactly one data device by its path')
        dev = getattr(paths[0], 'path', None)
        if not isinstance(dev, str) or not re.match(r'\A/dev/[A-Za-z0-9][A-Za-z0-9._:/-]{0,200}\Z', dev) \
                or getattr(paths[0], 'crush_device_class', None):
            raise OrchestratorError('the data device must be a /dev/ path without other attributes')
        # everything else of the drive group at its default: the spec must be the
        # one `daemon add osd HOST:DEVICE` builds for exactly this host and disk
        from ceph.deployment.drive_group import DeviceSelection, DriveGroupSpec
        from ceph.deployment.service_spec import PlacementSpec
        if drive_group.method not in (None, 'raw'):
            raise OrchestratorError('the %s method is not supported by this backend' % drive_group.method)
        want = DriveGroupSpec(placement=PlacementSpec(host_pattern=host), data_devices=DeviceSelection(paths=[dev]), method=drive_group.method)
        if getattr(drive_group, 'preview_only', False) or drive_group.to_json() != want.to_json():
            raise OrchestratorError('only one OSD on one disk, without other drive group options, is supported by this backend')
        _, fold = self._authority()
        if host not in fold.hosts:
            raise OrchestratorError('%s is not a host of the cluster' % host)
        op_id = self._accept_create(host, dev)
        return 'Scheduled to create an OSD on %s:%s (operation %s)' % (host, dev, op_id)

    @_accepting
    def _accept_create(self, host: str, device: str) -> str:
        """Accept an OSD creation: not beside an unfinished one on the same disk
        name or a host removal."""
        led, _ = self._authority()
        lead = getattr(self, '_leadership', None)
        if lead is None or not lead.still_active():
            raise OrchestratorError('this mgr is not confirmed as the active one; try again')
        try:
            led.settle()
        except ledger.LedgerError as e:
            raise OrchestratorError('an earlier operation is not settled yet (%s); try again' % e)
        for _, e in led.executable():
            if e['id'].startswith('m-') or e.get('host') != host or not (e['kind'] in ledger.HOST_KINDS or e.get('device') == device):
                continue
            rec = self._journal(e['id'])
            if rec is None or rec.get('state') not in TERMINAL:
                raise OrchestratorError('%s has operation %s in progress (orch talos operation %s)' % (host, e['id'], e['id']))
        self._not_in_maintenance(host)
        op_id = 'op-' + os.urandom(8).hex()
        try:
            led.append({'id': op_id, 'kind': 'create_osd', 'host': host, 'device': device, **self._request_fields()})
        except ledger.OutcomeUnknown:
            raise OrchestratorError('the mons did not answer: operation %s may have been accepted (orch talos operation %s)' % (op_id, op_id))
        except ledger.LedgerError as e:
            raise OrchestratorError('not accepted: %s' % e)
        return op_id

    @handle_orch_error
    def remove_osds(self, osd_ids: List[str], replace: bool = False, replace_block: bool = False, replace_db: bool = False,
                    replace_wal: bool = False, force: bool = False, zap: bool = False, no_destroy: bool = False) -> str:
        if replace or replace_block or replace_db or replace_wal or no_destroy:
            raise OrchestratorError('--replace and --no-destroy are not supported by this backend')
        self._settle()
        led, fold = self._authority()
        names = []
        for i in osd_ids:
            name = 'osd.%s' % i
            if not re.match(r'\A(0|[1-9][0-9]{0,8})\Z', str(i)) or name not in fold.daemons or name not in fold.uuids:
                raise OrchestratorError('%s is not an OSD of the cluster' % name)
            names.append(name)
        if len(set(names)) != len(names):
            raise OrchestratorError('an OSD named twice')
        for n in names:  # every one checked before any is accepted
            busy = self._unfinished(n, fold.daemons[n])
            if busy:
                raise OrchestratorError('%s has operation %s in progress (orch talos operation %s)' % (n, busy, busy))
            self._not_in_maintenance(fold.daemons[n])
        out = []
        for n in names:
            op_id = self._accept_osd_removal(n, fold.daemons[n], fold.uuids[n], zap, force)
            out.append('Scheduled to remove %s from host %s (operation %s)' % (n, fold.daemons[n], op_id))
        return '\n'.join(out)

    @_accepting
    def _accept_osd_removal(self, name: str, host: str, uuid: str, zap: bool, force: bool) -> str:
        led, _ = self._authority()
        lead = getattr(self, '_leadership', None)
        if lead is None or not lead.still_active():
            raise OrchestratorError('this mgr is not confirmed as the active one; try again')
        try:
            led.settle()
        except ledger.LedgerError as e:
            raise OrchestratorError('an earlier operation is not settled yet (%s); try again' % e)
        op_id = 'op-' + os.urandom(8).hex()
        try:
            led.append({'id': op_id, 'kind': 'remove_osd', 'daemon': name, 'host': host, 'uuid': uuid, 'zap': bool(zap), 'force': bool(force),
                        **self._request_fields()})
        except ledger.OutcomeUnknown:
            raise OrchestratorError('the mons did not answer: operation %s may have been accepted (orch talos operation %s)' % (op_id, op_id))
        except ledger.LedgerError as e:
            raise OrchestratorError('not accepted: %s' % e)
        return op_id

    @handle_orch_error
    def remove_osds_status(self) -> List[Dict[str, Any]]:
        """The OSD removals not finished: from the ledger, with the leader's phase."""
        led, fold = self._authority()
        entries = led.executable()
        out = []
        for _, e in entries:
            if e['kind'] != 'remove_osd':
                continue
            rec = self._journal(e['id'])
            if rec is not None and rec.get('state') in TERMINAL:
                continue
            drained = any(x['kind'] == 'drained' and x.get('of') == e['id'] for _, x in entries)
            out.append({'osd_id': int(e['daemon'].split('.', 1)[1]), 'hostname': e['host'],
                        'drain_status': (rec or {}).get('phase') or ('drained' if drained else 'draining'),
                        'pg_count': None, 'replace': False, 'force': e['force'], 'zap': e['zap'], 'drain_started_at': None})
        return out

    @handle_orch_error
    def remove_host(self, host: str, force: bool = False, offline: bool = False, rm_crush_entry: bool = False) -> str:
        if offline or rm_crush_entry:
            raise OrchestratorError('--offline and --rm-crush-entry are not supported by this backend')
        _, fold = self._authority()
        if host not in fold.hosts:
            raise OrchestratorError('%s is not a host of the cluster' % host)
        on = sorted(n for n, h in fold.daemons.items() if h == host)
        if on:
            raise OrchestratorError('%s still has daemons: %s' % (host, ', '.join(on)))
        if host == self.get_mgr_id():
            raise OrchestratorError('%s runs the active mgr' % host)
        op_id = self._accept('remove_host', None, host)
        return 'Scheduled to remove host %s (operation %s)' % (host, op_id)

    def _may_stop(self, hostname: str) -> None:
        """What a maintenance or powercycle of a host needs before acceptance."""
        self._settle()
        _, fold = self._authority()
        if hostname not in fold.hosts:
            raise OrchestratorError('%s is not a host of the cluster' % hostname)
        if hostname in fold.maintenance:
            raise OrchestratorError('%s is already in maintenance' % hostname)
        if fold.upgrade is not None:
            raise OrchestratorError('an upgrade is in progress (operation %s)' % fold.upgrade['op'])
        led, _ = self._authority()
        for _, e in led.executable():
            if e['kind'] == 'apply_ingress' and hostname in e['hosts'] + ((fold.ingress or {}).get('hosts') or []):
                rec = self._journal(e['id'])
                if rec is None or rec.get('state') not in TERMINAL:
                    raise OrchestratorError('ingress operation %s on %s is in progress' % (e['id'], hostname))
        if len(fold.hosts) < 2:
            raise OrchestratorError('maintenance is not supported on single node clusters')
        # osd set-group resolves numbers (OSD ids), all and any before CRUSH bucket names
        if any(n.startswith('osd.') and h == hostname for n, h in fold.daemons.items()) \
                and (re.match(r'\A(osd\.)?[0-9]+\Z', hostname) or hostname in ('all', 'any')):
            raise OrchestratorError('host name %s is ambiguous for osd set-group noout' % hostname)
        if hostname == self.get_mgr_id():
            standbys = [m for m in (self.get('mgr_map') or {}).get('standbys', []) if m.get('available', True)]
            if not standbys:
                raise OrchestratorError('%s runs the active mgr and no standby mgr is available' % hostname)

    @handle_orch_error
    def add_host(self, host_spec: HostSpec) -> str:
        """A node the CLI enrolled (cephadm-talos host add): its enrollment record
        gives its address and agent certificates."""
        host, addr = host_spec.hostname, host_spec.addr or host_spec.hostname
        if getattr(host_spec, 'status', None) or getattr(host_spec, 'location', None) or getattr(host_spec, 'oob', None):
            raise OrchestratorError('maintenance status, location and oob are not supported by this backend')
        labels = list(host_spec.labels or [])
        if len(labels) > 32 or any(not ledger.LABEL_RE.match(x) for x in labels):
            raise OrchestratorError('labels: at most 32, letters, digits, dots, dashes and underscores')
        self._settle()
        _, fold = self._authority()
        if host in fold.hosts:
            raise OrchestratorError('%s is a host of the cluster already' % host)
        r, out, _ = self.mon_command({'prefix': 'config-key get', 'key': ENROLL_PREFIX + host})
        if r != 0:
            raise OrchestratorError('%s is not enrolled: add it with cephadm-talos host add <addr>' % host)
        try:
            rec = json.loads(out)
        except ValueError:
            raise OrchestratorError('the enrollment record of %s does not decode' % host)
        if rec.get('name') != host or rec.get('addr') != addr:
            raise OrchestratorError('%s was enrolled with the address %s' % (host, rec.get('addr')))
        op_id = self._accept('add_host', None, host, addr=addr, agent_cert=rec.get('agent_cert'),
                             agent_client_cert=rec.get('agent_client_cert'), labels=labels)
        return 'Scheduled to add host %s with addr %s (operation %s)' % (host, addr, op_id)

    @handle_orch_error
    def enter_host_maintenance(self, hostname: str, force: bool = False, yes_i_really_mean_it: bool = False) -> str:
        """Stop a host's daemons (their documents removed) and set noout for it."""
        if yes_i_really_mean_it:
            raise OrchestratorError('--yes-i-really-mean-it is not supported by this backend')
        self._may_stop(hostname)
        op_id = self._accept('enter_maintenance', None, hostname, force=bool(force))
        return 'Scheduled to put host %s into maintenance (operation %s)' % (hostname, op_id)

    @handle_orch_error
    def hardware_powercycle(self, hostname: str, yes_i_really_mean_it: bool = False) -> str:
        """Reboot a host through its agent, its daemons stopped as for maintenance first."""
        if not yes_i_really_mean_it:
            raise OrchestratorError('you must pass --yes-i-really-mean-it')
        self._may_stop(hostname)
        op_id = self._accept('powercycle_host', None, hostname)
        return 'Scheduled to powercycle host %s (operation %s)' % (hostname, op_id)

    @handle_orch_error
    def exit_host_maintenance(self, hostname: str, force: bool = False, offline: bool = False) -> str:
        """Start a host's daemons again and clear its noout."""
        if force or offline:
            raise OrchestratorError('--force and --offline are not supported by this backend')
        self._settle()
        _, fold = self._authority()
        if hostname not in fold.maintenance:
            raise OrchestratorError('%s is not in maintenance' % hostname)
        op_id = self._accept('exit_maintenance', None, hostname)
        return 'Scheduled to take host %s out of maintenance (operation %s)' % (hostname, op_id)

    def _approved_images(self) -> List[str]:
        """The images of the operator's newest approval in config-key: its payload
        as written (the agents verify its signature; this is presence only)."""
        r, out, _ = self.mon_command({'prefix': 'config-key ls', 'format': 'json'})
        keys = sorted(k for k in json.loads(out) if bridge.APPROVAL_KEY_RE.match(k)) if r == 0 else None
        if keys is None:
            raise OrchestratorError('cannot list the approvals; try again')
        if not keys:
            return []
        r, out, _ = self.mon_command({'prefix': 'config-key get', 'key': keys[-1]})
        if r != 0:
            raise OrchestratorError('cannot read the approval; try again')
        try:
            images = json.loads(base64.b64decode(json.loads(out)['payload']))['images']
        except (ValueError, KeyError, TypeError):
            raise OrchestratorError('the newest approval does not decode')
        return [i for i in images if isinstance(i, str)]

    def _check_certs(self, now: Optional[datetime.datetime] = None) -> None:
        """The daily check (plan 04, step 1): renew the mgr certificates and the
        generated RGW certificates in use that expire within 30 days, and report
        what needs the operator in health checks."""
        now = now or datetime.datetime.now(datetime.timezone.utc)
        entries = self.get_store_prefix(STORE_PREFIX)
        inc = choose_incarnation(entries, getattr(self, '_gid', None))
        cluster, _ = record_from_store(entries, inc, 'cluster')
        hosts, _ = record_from_store(entries, inc, 'hosts')
        daemons, _ = record_from_store(entries, inc, 'daemons')
        by_name = {h['name']: h for h in hosts or []}
        days = self.get_module_option('talos_cert_renew_days')
        renew_before = datetime.timedelta(days=int(days)) if days else CERT_RENEW_BEFORE
        checks: Dict[str, Dict[str, Any]] = {}
        alerts: List[str] = []

        def warn(name: str, summary: str, detail: List[str]) -> None:
            checks[name] = {'severity': 'warning', 'summary': summary, 'count': len(detail), 'detail': detail}

        # the mgrs' certificates
        for d in daemons or []:
            if d.get('type') != 'mgr' or d.get('host') not in by_name:
                continue
            h = by_name[d['host']]
            ends = [cert_not_after(h.get(k)) for k in ('mgr_server_cert', 'mgr_client_cert') if h.get(k)]
            if not ends:
                continue
            # the warning's threshold is fixed; only renewal follows the setting
            if min(ends) - now <= CERT_ALERT_BEFORE:
                alerts.append('mgr.%s certificates expire %s' % (h['name'], min(ends).isoformat()))
            if min(ends) - now <= renew_before:
                self._accept_renewal(lambda name=h['name']: self._accept('renew_mgr', 'mgr.' + name, name))
        # every host's agent certificates (plan 04, step 2)
        for h in hosts or []:
            ends = [cert_not_after(h.get(k)) for k in ('agent_cert', 'agent_client_cert') if h.get(k)]
            if not ends:
                continue
            if min(ends) - now <= CERT_ALERT_BEFORE:
                alerts.append('the agent of %s: certificates expire %s' % (h['name'], min(ends).isoformat()))
            if min(ends) - now <= renew_before:
                self._accept_renewal(lambda name=h['name']: self._accept('renew_agent', None, name))
        # the RGW certificates: the ones the daemons name and the ones they serve
        rgw = (cluster or {}).get('rgw') or {}
        certs = {c['id']: c for c in rgw.get('certs') or []}
        due_generated, user = False, []
        port = self._rgw_port()
        user_certs = [c['cert'] for c in certs.values() if c.get('user')] + ([rgw['cert']] if rgw.get('user_cert') and rgw.get('cert') else [])
        for d in daemons or []:
            if d.get('type') != 'rgw' or d.get('host') not in by_name:
                continue
            ref = d.get('cert') or 'cli'
            c = certs.get(ref) if ref != 'cli' else {'id': 'cli', 'cert': rgw.get('cert'), 'user': rgw.get('user_cert')}
            served = served_leaf(by_name[d['host']]['addr'], port) if port else None
            # an RGW serving an operator's certificate (named or not) is the operator's to renew
            served_user = served is not None and any(leaf_der(u) == served for u in user_certs)
            served_end = der_not_after(served) if served is not None else None
            for end, is_user in ((cert_not_after(c.get('cert')) if c and c.get('cert') else None, bool(c and c.get('user'))), (served_end, served_user)):
                if end is None:
                    continue
                if is_user:
                    line = 'rgw.%s serves the operator\'s certificate, which expires %s' % (d['host'], end.isoformat())
                    if end - now <= CERT_RENEW_BEFORE and line not in user:
                        user.append(line)
                    continue
                if end - now <= CERT_ALERT_BEFORE:
                    alerts.append('rgw.%s certificate expires %s' % (d['host'], end.isoformat()))
                if end - now <= renew_before:
                    due_generated = True
        if due_generated:
            self._accept_renewal(lambda: self._accept_rgw_renewal())
        if user:
            warn('TALOS_RGW_CERT_EXPIRING', "an operator's RGW certificate expires within 30 days", user)
        if alerts:
            warn('TALOS_CERT_RENEWAL', 'certificates expire within 7 days: their renewal keeps failing', alerts)
        # the operator's certificate, from the public copy the CLI keeps
        r, out, _ = self.mon_command({'prefix': 'config-key get', 'key': OPERATOR_CERT_KEY})
        end = cert_not_after(out) if r == 0 and out else None
        if end is not None and end - now <= OPERATOR_WARN_BEFORE:
            warn('TALOS_OPERATOR_CERT_EXPIRING', "the operator's certificate expires within 60 days",
                 ['it expires %s: any cephadm-talos command renews it' % end.isoformat()])
        self.set_health_checks(checks)

    def _schedule_cert_check(self) -> None:
        """Run the daily certificate check, at the leader's first tick and then
        once a day, in a thread of its own (it reads every RGW's certificate)."""
        led = getattr(self, '_ledger', None)
        if led is None or not led.ready or time.monotonic() < getattr(self, '_certs_next', 0.0):
            return
        self._certs_next = time.monotonic() + CERT_CHECK_INTERVAL

        def run() -> None:
            try:
                self._check_certs()
            except Exception as e:  # the next day tries again
                self.log.warning('the certificate check: %s', e)
        threading.Thread(target=run, name='talos-certs', daemon=True).start()

    def _accept_renewal(self, accept: Callable[[], str]) -> None:
        """Accept a renewal; one that is refused (busy, suspended) waits for the next check."""
        try:
            op = accept()
            self.log.info('certificate renewal accepted: operation %s', op)
        except OrchestratorError as e:
            self.log.info('certificate renewal not accepted now: %s', e)

    def _accept_rgw_renewal(self) -> str:
        """A renewal of the generated RGW certificate, unless one, an ingress
        apply or an RGW add is unfinished."""
        led, _ = self._authority()
        for _, e in led.executable():
            if e['kind'] in ('renew_rgw_cert', 'apply_ingress') or e['kind'] == 'add_daemon' and e['daemon'].startswith('rgw.'):
                rec = self._journal(e['id'])
                if rec is None or rec.get('state') not in TERMINAL:
                    raise OrchestratorError('operation %s on the RGW certificates is in progress' % e['id'])
        return self._accept_cluster('renew_rgw_cert')

    @_accepting
    def _accept_cluster(self, kind: str, op_id: Optional[str] = None, **fields: Any) -> str:
        """Accept an operation about the whole cluster (an upgrade's): no host."""
        led, _ = self._authority()
        lead = getattr(self, '_leadership', None)
        if lead is None or not lead.still_active():
            raise OrchestratorError('this mgr is not confirmed as the active one; try again')
        try:
            led.settle()
        except ledger.LedgerError as e:
            raise OrchestratorError('an earlier operation is not settled yet (%s); try again' % e)
        op_id = op_id or 'op-' + os.urandom(8).hex()
        try:
            led.append({'id': op_id, 'kind': kind, **fields, **self._request_fields()})
        except ledger.OutcomeUnknown:
            raise OrchestratorError('the mons did not answer: operation %s may have been accepted (orch talos operation %s)' % (op_id, op_id))
        except ledger.LedgerError as e:
            raise OrchestratorError('not accepted: %s' % e)
        return op_id

    @handle_orch_error
    def upgrade_start(self, image: Optional[str], version: Optional[str], daemon_types: Optional[List[str]],
                      hosts: Optional[str], services: Optional[List[str]], limit: Optional[int],
                      bucket_type: Optional[str] = None, bucket_name: Optional[str] = None) -> str:
        """Upgrade the cluster to an image the operator approved, daemon by daemon."""
        if version or daemon_types or hosts or services or limit is not None or bucket_type or bucket_name:
            raise OrchestratorError('only --image is supported by this backend')
        if not isinstance(image, str) or not ledger.IMAGE_RE.match(image):
            raise OrchestratorError('name the image by its digest: <repository>@sha256:<hex>')
        self._settle()
        _, fold = self._authority()
        if fold.upgrade is not None:
            raise OrchestratorError('an upgrade is in progress (operation %s)' % fold.upgrade['op'])
        if fold.maintenance:
            raise OrchestratorError('hosts in maintenance: %s' % ', '.join(sorted(fold.maintenance)))
        current = self._inventory().get('image', '')
        if image.split('@')[0] != current.split('@')[0]:
            raise OrchestratorError('the image is not from the cluster\'s repository %s' % current.split('@')[0])
        if image == current:
            raise OrchestratorError('the cluster runs %s already' % image)
        if image not in self._approved_images():
            raise OrchestratorError('the operator has not approved %s (cephadm-talos approve --image)' % image)
        op_id = self._accept_cluster('upgrade_start', image=image)
        return 'Scheduled to upgrade to %s (operation %s)' % (image, op_id)

    def _upgrade_paused(self, fold: Any) -> bool:
        """Paused by the operator (the fold) or by the leader after a failed step
        (its inventory, for the same upgrade)."""
        try:
            u = self._inventory().get('upgrade') or {}
        except Exception:
            u = {}
        return bool(fold.upgrade['paused'] or u.get('op') == fold.upgrade['op'] and u.get('paused'))

    def _upgrade_control(self, kind: str) -> str:
        self._settle()
        _, fold = self._authority()
        if fold.upgrade is None:
            raise OrchestratorError('no upgrade is in progress')
        if kind == 'upgrade_pause' and fold.upgrade['paused']:
            raise OrchestratorError('the upgrade is paused already')
        if kind == 'upgrade_resume' and not self._upgrade_paused(fold):
            raise OrchestratorError('the upgrade is not paused')
        return self._accept_cluster(kind, upgrade=fold.upgrade['op'])

    @handle_orch_error
    def upgrade_pause(self) -> str:
        return 'Scheduled to pause the upgrade (operation %s)' % self._upgrade_control('upgrade_pause')

    @handle_orch_error
    def upgrade_resume(self) -> str:
        return 'Scheduled to resume the upgrade (operation %s)' % self._upgrade_control('upgrade_resume')

    @handle_orch_error
    def upgrade_stop(self) -> str:
        return 'Scheduled to stop the upgrade (operation %s)' % self._upgrade_control('upgrade_stop')

    @handle_orch_error
    def upgrade_status(self) -> UpgradeStatusSpec:
        """The upgrade in the fold, with the leader's progress from its inventory."""
        _, fold = self._authority()
        spec = UpgradeStatusSpec()
        if fold.upgrade is None:
            return spec
        inv = self._inventory()
        u = inv.get('upgrade') or {}
        mine = u.get('op') == fold.upgrade['op']
        done = set(u.get('done') or []) if mine else set()
        daemons = [d for d in inv['daemons'] if d['daemon_type'] in ('mgr', 'mon', 'osd', 'rgw')]
        spec.in_progress, spec.target_image, spec.which = True, fold.upgrade['image'], 'all'
        spec.is_paused = self._upgrade_paused(fold)
        spec.progress = '%d/%d daemons upgraded' % (len([d for d in daemons if d['doc_name'] in done]), len(daemons))
        spec.services_complete = sorted({d['daemon_type'] for d in daemons} - {d['daemon_type'] for d in daemons if d['doc_name'] not in done})
        if not mine:
            spec.message = 'starting (operation %s)' % fold.upgrade['op']
        elif u.get('error'):
            spec.message = 'paused: %s' % u['error']
        elif u.get('step'):
            spec.message = 'upgrading %s' % u['step']
        return spec

    @handle_orch_error
    def apply(self, specs: Any, no_overwrite: bool = False, continue_on_error: bool = False) -> List[str]:
        """The one spec this backend applies: the keepalived-only ingress of the RGWs."""
        from ceph.deployment.service_spec import IngressSpec
        # host add goes through Ceph's own routing to add_host (plan 03, step 7)
        if specs and all(isinstance(s, HostSpec) for s in specs):
            return orchestrator.raise_if_exception(orchestrator.Orchestrator.apply(self, specs, no_overwrite, continue_on_error))
        if no_overwrite or continue_on_error or len(specs) != 1 or not isinstance(specs[0], IngressSpec):
            raise OrchestratorError('apply is supported by this backend for one keepalived-only ingress spec only')
        return [self._apply_ingress(specs[0])]

    def _apply_ingress(self, spec: Any) -> str:
        import ipaddress
        from ceph.deployment.service_spec import IngressSpec
        p = spec.placement
        if spec.service_id != 'rgw.default' or spec.backend_service != 'rgw.default' or not spec.keepalive_only:
            raise OrchestratorError('the ingress is rgw.default with backend_service rgw.default and keepalive_only: true')
        if p is None or not 0 < len(p.hosts) <= 15 or p.count is not None or p.count_per_host or p.label or p.host_pattern \
                or any(h.network or h.name for h in p.hosts):
            raise OrchestratorError('place the ingress on 1 to 15 named hosts')
        want = IngressSpec(service_id='rgw.default', backend_service='rgw.default', keepalive_only=True, virtual_ip=spec.virtual_ip,
                           placement=p, first_virtual_router_id=spec.first_virtual_router_id, keepalived_password=spec.keepalived_password)
        if spec.to_json() != want.to_json() or getattr(spec, 'preview_only', False):
            raise OrchestratorError('only virtual_ip, placement, first_virtual_router_id and keepalived_password are supported by this backend')
        try:
            vip = ipaddress.ip_interface(spec.virtual_ip or '')
        except ValueError:
            raise OrchestratorError('virtual_ip: an address with its prefix length')
        if vip.version != 4 or '/' not in spec.virtual_ip:
            raise OrchestratorError('virtual_ip: an IPv4 address with its prefix length (keepalived is set up for IPv4 only)')
        vrid = spec.first_virtual_router_id
        if type(vrid) is not int or not 0 < vrid < 256:
            raise OrchestratorError('first_virtual_router_id: 1 to 255')
        pw = spec.keepalived_password
        if pw is not None and not re.match(r'\A[A-Za-z0-9]{1,8}\Z', pw):
            raise OrchestratorError('keepalived_password: 1 to 8 letters and digits')
        self._settle()
        _, fold = self._authority()
        hosts = [h.hostname for h in p.hosts]
        if len(set(hosts)) != len(hosts):
            raise OrchestratorError('a host named twice')
        for h in hosts:
            if h not in fold.hosts or 'rgw.' + h not in fold.daemons:
                raise OrchestratorError('%s has no RGW of the cluster' % h)
            busy = self._unfinished('rgw.' + h, h)
            if busy:
                raise OrchestratorError('rgw.%s has operation %s in progress (orch talos operation %s)' % (h, busy, busy))
            if ipaddress.ip_address(fold.hosts[h]).version != 4:
                raise OrchestratorError('%s has no IPv4 address' % h)
        busy = sorted((set(hosts) | set((fold.ingress or {}).get('hosts') or [])) & fold.maintenance)
        if busy:
            raise OrchestratorError('hosts in maintenance: %s' % ', '.join(busy))
        cur = fold.ingress
        new_password = cur is None
        if cur is not None:
            if str(ipaddress.ip_interface(cur['vip'])) != str(vip) or cur.get('vrid') != vrid:
                raise OrchestratorError('the ingress keeps its VIP %s and router id %s' % (cur['vip'], cur.get('vrid')))
            placed = {h for n, h in fold.daemons.items() if n.startswith('keepalived.')}
            if len(set(hosts) | set(cur['hosts']) | placed) > 15:
                raise OrchestratorError('at most 15 hosts, also old and new together during the change')
            if pw is not None:
                r, out, _ = self.mon_command({'prefix': 'config-key get', 'key': bridge.SECRET_PREFIX + fold.vrrp_secret})
                if r != 0 or out != pw:
                    raise OrchestratorError('the ingress keeps its keepalived_password')
        image = self.get_module_option('container_image_keepalived') or fold.cli_rgw.get('keepalived_image') or ''
        if not ledger.IMAGE_RE.match(image):
            raise OrchestratorError('set mgr/cephadm/container_image_keepalived to the keepalived image by digest')
        if image not in self._approved_images():
            raise OrchestratorError('the operator has not approved %s (cephadm-talos approve --image)' % image)
        op_id = 'op-' + os.urandom(8).hex()
        if new_password:
            secret = pw or ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
            r, _, outs = self.mon_command({'prefix': 'config-key set', 'key': '%singress/%s/vrrp' % (bridge.SECRET_PREFIX, op_id), 'val': secret})
            if r != 0:
                raise OrchestratorError('the VRRP password was not written: %s' % outs)
        op_id = self._accept_cluster('apply_ingress', op_id=op_id, vip=str(vip), vrid=vrid, hosts=hosts, image=image, new_password=new_password)
        return 'Scheduled the ingress on %s (operation %s)' % (', '.join(hosts), op_id)

    @TalosCLICommand.Write('orch talos request')
    def _request(self, request: str, inputs: str, inbuf: Optional[str] = None) -> HandleCommandResult:
        """Run a ceph orch command once per request uuid (cephadm-talos orch): -i gives {"cmd": {...}, "inbuf": ...}"""
        if not UUID_RE.match(request) or not re.match(r'\A[0-9a-f]{64}\Z', inputs):
            return HandleCommandResult(retval=-22, stderr='a request uuid and a SHA-256 inputs hash')
        try:
            req = json.loads(inbuf or '')
            cmd, sub = req['cmd'], req.get('inbuf')
        except (ValueError, KeyError, TypeError):
            return HandleCommandResult(retval=-22, stderr='-i: {"cmd": {...}, "inbuf": ...}')
        if not isinstance(cmd, dict) or not isinstance(cmd.get('prefix'), str) or not cmd['prefix'].startswith('orch ') \
                or cmd['prefix'].startswith('orch talos') or sub is not None and not isinstance(sub, str):
            return HandleCommandResult(retval=-22, stderr='a ceph orch command')
        canonical = json.dumps({'cmd': cmd, 'inbuf': sub}, sort_keys=True, separators=(',', ':'))
        if hashlib.sha256(canonical.encode()).hexdigest() != inputs:
            return HandleCommandResult(retval=-22, stderr='the inputs hash is not the command\'s')
        # one operation per request: several daemons, OSDs or specs at once are refused
        for arg in ('names', 'osd_id'):
            if isinstance(cmd.get(arg), list) and len(cmd[arg]) > 1:
                return HandleCommandResult(retval=-22, stderr='one daemon or OSD per request')
        if sub:
            import yaml
            try:
                docs = [d for d in yaml.safe_load_all(sub) if d]
            except yaml.YAMLError:
                return HandleCommandResult(retval=-22, stderr='the input is not YAML')
            if len(docs) > 1:
                return HandleCommandResult(retval=-22, stderr='one spec per request')
        with _ACCEPT_LOCK:
            try:
                self._settle()
                led, _ = self._authority()
            except OrchestratorError as e:
                return HandleCommandResult(retval=-11, stderr=str(e))  # EAGAIN
            done = [e for _, e in led.executable() if e.get('request') == request]
            if done:
                if done[0].get('inputs') != inputs:
                    return HandleCommandResult(retval=-17, stderr='request %s was another command' % request)  # EEXIST
                return HandleCommandResult(stdout='Accepted before as operation %s (orch talos operation %s)' % (done[0]['id'], done[0]['id']))
            self._request_active = (request, inputs)
            try:
                # a daemon spec (an RGW's with the operator's key) goes to this
                # backend directly: Ceph's orchestrator module logs whole specs
                if cmd['prefix'] == 'orch daemon add' and sub:
                    from ceph.deployment.service_spec import ServiceSpec
                    import yaml
                    try:
                        spec = ServiceSpec.from_json(yaml.safe_load(sub))
                    except Exception as e:
                        return HandleCommandResult(retval=-22, stderr='the spec: %s' % e.__class__.__name__)
                    out = self.add_daemon(spec)
                    err = out.exception_str
                    res = (-22 if err else 0, '\n'.join(out.result or []), err)
                else:
                    res = self.remote('orchestrator', '_handle_command', sub, cmd)
            finally:
                self._request_active = None
        if isinstance(res, tuple):
            return HandleCommandResult(*res)
        return res

    @TalosCLICommand.Write('orch talos agent upgrade')
    def _agent_upgrade(self, image: Optional[str] = None, resume: bool = False) -> HandleCommandResult:
        """Upgrade every agent to an image the operator approved, one host at a time; or resume a paused upgrade"""
        try:
            return HandleCommandResult(stdout=self._accept_agent_upgrade(image, resume))
        except OrchestratorError as e:
            return HandleCommandResult(retval=-22, stderr=str(e))

    def _accept_agent_upgrade(self, image: Optional[str], resume: bool) -> str:
        """An agent upgrade (plan 04, step 2): by digest, approved, from the agent
        image's repository; no other agent or Ceph upgrade unfinished."""
        self._settle()
        led, fold = self._authority()
        running = None
        for _, e in led.executable():
            if e['kind'] in ('upgrade_agent', 'upgrade_start'):
                rec = self._journal(e['id'])
                if rec is None or rec.get('state') not in TERMINAL:
                    running = e
        if resume:
            if image or running is None or running['kind'] != 'upgrade_agent':
                raise OrchestratorError('--resume takes no image, and needs an agent upgrade in progress')
            op = self._accept_cluster('upgrade_agent_resume', upgrade=running['id'])
            return 'Scheduled to resume agent upgrade %s (operation %s)' % (running['id'], op)
        if running is not None:
            raise OrchestratorError('operation %s (%s) is in progress' % (running['id'], running['kind']))
        if not isinstance(image, str) or not ledger.IMAGE_RE.match(image):
            raise OrchestratorError('name the image by its digest: <repository>@sha256:<hex>')
        entries = self.get_store_prefix(STORE_PREFIX)
        cluster, _ = record_from_store(entries, choose_incarnation(entries, getattr(self, '_gid', None)), 'cluster')
        current = ((cluster or {}).get('agent') or {}).get('image') or ''
        if image.split('@')[0] != current.split('@')[0]:
            raise OrchestratorError('the agents run images of %s' % current.split('@')[0])
        if image == current:
            raise OrchestratorError('the agents run %s already' % image)
        if image not in self._approved_images():
            raise OrchestratorError('the operator has not approved %s (cephadm-talos approve --image)' % image)
        op = self._accept_cluster('upgrade_agent', image=image)
        return 'Scheduled to upgrade the agents to %s (operation %s)' % (image, op)

    @TalosCLICommand.Read('orch talos operation')
    def _operation(self, id: str) -> HandleCommandResult:
        """Show an operation this backend accepted: its ledger entry and the leader's journal record"""
        if not re.match(r'\Aop-[0-9a-f]{16}\Z', id):
            return HandleCommandResult(retval=-22, stderr='not an operation id')
        try:
            led, _ = self._authority()
        except Exception as e:
            return HandleCommandResult(retval=-11, stderr=str(e))  # EAGAIN
        entry = [e for _, e in led.executable() if e['id'] == id]
        if not entry:
            return HandleCommandResult(retval=-2, stderr='no accepted operation %s' % id)  # ENOENT
        return HandleCommandResult(stdout=json.dumps({'accepted': entry[0], 'journal': self._journal(id)}, indent=2, sort_keys=True))

    @handle_orch_error
    def get_hosts(self) -> List[HostSpec]:
        return build_hosts(self._inventory())

    @handle_orch_error
    def list_daemons(self, service_name: Optional[str] = None, daemon_type: Optional[str] = None,
                     daemon_id: Optional[str] = None, host: Optional[str] = None,
                     refresh: bool = False) -> List[DaemonDescription]:
        inv = self._inventory()
        if refresh:
            self._poller.poll(inv['hosts'], refresh=True)
        daemons = build_daemons(inv, self._poller.snapshot(), utcnow())
        return filter_daemons(daemons, service_name, daemon_type, daemon_id, host)
