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
import ipaddress
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

from . import bridge, ledger, revocation

TalosCLICommand = CLICommandBase.make_registry_subtype("TalosCLICommand")

TALOS_DIR = '/etc/ceph/talos'
# journal states after which the leader does nothing more for an operation
TERMINAL = ledger.TERMINAL
# no new operation is accepted while more than this many are unfinished (plan 04, step 4)
MAX_UNFINISHED = 500
# compaction (plan 04, step 4): checked this often by the leadership loop; a
# snapshot at most hourly, the delayed deletion and journal pruning hourly
COMPACT_CHECK = 600.0
COMPACT_EVERY = 3600.0
# certificate renewal (plan 04, step 1): checked once a day, renewed this long
# before expiry, warned about when renewal keeps failing; the operator's
# certificate (its public copy, written by the CLI) warned about earlier
CERT_CHECK_INTERVAL = 24 * 3600.0
# the check again soon while a renewal that is due was refused (its host busy)
CERT_RETRY_INTERVAL = 600.0
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
# an unplanned stop not ended after this raises TALOS_HOST_DOWN (plan 04, step 5)
HOST_DOWN_AFTER = datetime.timedelta(minutes=30)
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


def check_not_revoked(peercert: Optional[Dict[str, Any]], revoked: Any, now: Optional[float] = None) -> None:
    """Refuse a verified peer certificate the revoked set names, or one outside
    its validity (plan 04, step 3): the module is the list's issuer and reads
    the set itself, no CRL is parsed."""
    if not peercert or not peercert.get('serialNumber'):
        raise ValueError('no peer certificate')
    serial = int(peercert['serialNumber'], 16)
    if serial in revoked:
        raise ValueError('the peer certificate (serial %d) is revoked' % serial)
    t = time.time() if now is None else now
    if not ssl.cert_time_to_seconds(peercert['notBefore']) <= t <= ssl.cert_time_to_seconds(peercert['notAfter']):
        raise ValueError('the peer certificate is not valid now')


# the header naming the polling module's address: the agent sends its
# going-down reports there, to the mgr its client certificate names (plan 04, step 5)
MODULE_ADDR_HEADER = 'X-Cephadm-Talos-Module'
# the module heartbeats its own host's agent here (plan 04, step 5)
LOOPBACK = '127.0.0.1'


def fetch_record(addr: str, tls: ssl.SSLContext, refresh: bool = False,
                 expect: Optional[Tuple[str, str]] = None, revoked: Any = (), module: str = '') -> Dict[str, Any]:
    """Fetch and validate one agent's status record within an overall deadline; raises on any problem.

    expect is the (fsid, host) the agent's certificate must be issued to;
    revoked the serials it must not have; module this mgr's address."""
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
            check_not_revoked(conn.sock.getpeercert(), revoked)
        conn.request('GET', '/status?refresh=1' if refresh else '/status', headers={MODULE_ADDR_HEADER: module} if module else {})
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
    if not isinstance(rec.get('crl_number', ''), str) or not re.match(r'\A\d{0,40}\Z', rec.get('crl_number', '')) \
            or not isinstance(rec.get('crl_stale', False), bool):
        raise ValueError('invalid revocation list state in status record')
    # the node's boot id, and the id of a stop whose sequences were all cancelled (plan 04, step 5)
    for k, pattern in (('boot', ledger.BOOT_RE), ('stop_cancelled', ledger.STOP_RE)):
        if not isinstance(rec.get(k, ''), str) or rec.get(k) and not pattern.match(rec[k]):
            raise ValueError('invalid %s in status record' % k)
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
                     status='maintenance' if h.get('maintenance') else 'draining' if h.get('drain') else 'moving' if h.get('move') else '')
            for h in inv['hosts']]


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
        # when the poll started, on this process's monotonic clock: a record
        # fetched by it is no older (plan 04, step 5)
        started = time.monotonic()
        for h in hosts:
            try:
                futures[h['name']] = self.executor.submit(self.fetch, h['addr'], refresh)
            except RuntimeError:  # shut down meanwhile
                return
        for name, f in futures.items():
            try:
                rec = f.result()
                if isinstance(rec, dict):
                    rec['fetched_mono'] = started
                obs: Tuple[Optional[Dict[str, Any]], str] = (rec, '')
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
    """The module's client side: an agent's chain verified against the agent
    CA, not its address (plan 04, step 5); every caller checks the peer's
    identity URI SAN and the revoked set after the handshake, so a host that
    moved stays reachable before its certificates name its new address."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=os.path.join(directory, 'agent-ca.crt'))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
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
        Option('talos_compact_after', type='int', default=ledger.COMPACT_AFTER, min=10, max=ledger.COMPACT_AFTER,
               desc='compact the ledger once more entries than this follow its snapshot (lower for tests)'),
        Option('talos_cert_renew_days', type='int', default=30, min=1, desc='renew certificates that expire within this many days'),
        # the validity of the agent CA's revocation list (plan 04, step 3): at
        # most 7 days, the agents' limit; a lower value is for tests
        Option('talos_crl_valid_minutes', type='int', default=revocation.MAX_VALID_MINUTES, min=revocation.MIN_VALID_MINUTES, max=revocation.MAX_VALID_MINUTES,
               desc='validity of the agent CA revocation list, in minutes (shorter for tests)'),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._poller = Poller(self._fetch)
        # the revoked set (serials), read with the ledger every leadership tick
        self._revoked: frozenset = frozenset()
        # the list this module issued last: (number, DER)
        self._crl: Optional[Tuple[int, bytes]] = None

    def _set_health(self, part: str, checks: Dict[str, Any]) -> None:
        """Replace one part's health checks (the certificate check's, the
        revocation list's); set_health_checks replaces them all."""
        with self.__dict__.setdefault('_health_lock', threading.Lock()):
            parts = self.__dict__.setdefault('_health_parts', {})
            parts[part] = checks
            merged: Dict[str, Any] = {}
            for c in parts.values():
                merged.update(c)
            self.set_health_checks(merged)

    def _require_identity(self, peercert: Optional[Dict[str, Any]], fsid: str, role: str, name: Optional[str] = None) -> str:
        """require_identity, and not a revoked or expired certificate."""
        got = require_identity(peercert, fsid, role, name)
        check_not_revoked(peercert, getattr(self, '_revoked', ()))
        return got

    def _fetch(self, addr: str, refresh: bool) -> Dict[str, Any]:
        inv = self._inventory()
        names = [h['name'] for h in inv['hosts'] if h['addr'] == addr]
        if len(names) != 1:
            raise ValueError('address %s is not one inventory host' % addr)
        mine = [h['addr'] for h in inv['hosts'] if h['name'] == self.get_mgr_id()]
        return fetch_record(addr, tls_context(), refresh=refresh, expect=(inv['fsid'], names[0]), revoked=getattr(self, '_revoked', ()),
                            module=mine[0] if len(mine) == 1 else '')

    def _deliver_crl(self, inv: Dict[str, Any]) -> None:
        """Send the list to every inventory host whose poll failed or reported a
        lower number (plan 04, step 3), apart from the poll's authentication:
        the agent's server certificate is checked against the agent CA and
        its identity, not the revoked set (the list is public), so an agent
        whose own certificate was revoked still gets lists. Then report the
        agents whose list is past its nextUpdate."""
        crl = getattr(self, '_crl', None)
        obs = self._poller.snapshot()
        stale = sorted(n for n, (rec, _) in obs.items() if rec is not None and rec.get('crl_stale'))
        self._set_health('crl_stale', {'TALOS_CRL_STALE': {
            'severity': 'warning', 'summary': 'agents hold a revocation list past its nextUpdate', 'count': len(stale),
            'detail': ['the agent of %s' % n for n in stale]}} if stale else {})
        if crl is None:
            return
        number, der = crl
        body = json.dumps({'crl': base64.b64encode(der).decode()}).encode()
        for h in inv['hosts']:
            rec, _ = obs.get(h['name'], (None, ''))
            if rec is not None and int(rec.get('crl_number') or 0) >= number:
                continue
            try:
                self._poller.executor.submit(self._send_crl, inv['fsid'], h, body)
            except RuntimeError:  # shut down meanwhile
                return

    def _send_crl(self, fsid: str, h: Dict[str, Any], body: bytes) -> None:
        try:
            status, reply = bridge.post_json(h['addr'], AGENT_PORT, tls_context(), '/v1/crl', body, REQUEST_TIMEOUT,
                                             lambda cert: require_identity(cert, fsid, 'agent', h['name']))
            if status != 200:
                self.log.info('the agent of %s refused the revocation list: %d %s', h['name'], status, reply[:200].decode(errors='replace'))
        except Exception as e:
            self.log.info('the revocation list was not delivered to %s: %s', h['name'], e)

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
        return led, led.fold(cli_baseline(self.get_store_prefix(STORE_PREFIX)))

    def _journal_index(self) -> Dict[str, Dict[str, Any]]:
        """The leader's journal records of the operations, from every incarnation,
        in one scan: a terminal state wins (shown to the operator and counted
        as finished; it authorizes nothing)."""
        best: Dict[str, Dict[str, Any]] = {}
        for k, v in self.get_store_prefix(STORE_PREFIX).items():
            _, sep, op_id = k.partition('/journal/op/')
            if not sep or '/' in op_id or not ledger.OP_RE.match(op_id):
                continue
            try:
                rec = json.loads(v)
            except ValueError:
                continue
            if isinstance(rec, dict) and (op_id not in best or rec.get('state') in TERMINAL):
                best[op_id] = rec
        return best

    def _journal(self, op_id: str) -> Optional[Dict[str, Any]]:
        """The leader's journal record of an operation, from any incarnation."""
        return self._journal_index().get(op_id)

    def _finished(self, index: Dict[str, Dict[str, Any]], op_id: str) -> bool:
        return (index.get(op_id) or {}).get('state') in TERMINAL

    def _not_backlogged(self, led: ledger.Ledger, index: Dict[str, Dict[str, Any]]) -> None:
        """Backpressure (plan 04, step 4): no new operation while more than
        MAX_UNFINISHED are unfinished; the controls are not refused."""
        n = sum(1 for _, e in led.executable() if not e['id'].startswith('m-') and not self._finished(index, e['id']))
        if n > MAX_UNFINISHED:
            raise OrchestratorError('%d operations are unfinished (more than %d): nothing new is accepted until the leader catches up' % (n, MAX_UNFINISHED))

    def _unfinished(self, daemon: Optional[str], host: str, index: Optional[Dict[str, Dict[str, Any]]] = None) -> Optional[str]:
        """An accepted operation that conflicts and that the leader's journal does
        not show finished: for a daemon, one on that daemon or the removal of its
        host; for a host (daemon None), any on that host."""
        led, _ = self._authority()
        index = self._journal_index() if index is None else index
        for _, e in led.executable():
            if e['id'].startswith('m-'):
                continue
            if daemon is not None and e.get('daemon') is None and e['kind'] not in ledger.HOST_KINDS:
                continue
            if daemon is not None and e.get('daemon') != daemon and not (e['kind'] in ledger.HOST_KINDS and e['host'] == host):
                continue
            if daemon is None and e.get('host') != host:
                continue
            if not self._finished(index, e['id']):
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

    def _drains(self, fold: Any) -> Dict[str, str]:
        """The hosts with a drain (plan 04, step 5) and its operation: the
        fold's, and the leader's records of a stopped drain still finishing its
        step."""
        out = {h: d['op'] for h, d in fold.draining.items()}
        try:
            hosts = self._inventory()['hosts']
        except InventoryError:
            hosts = []
        for h in hosts:
            if isinstance(h.get('drain'), dict):
                out.setdefault(h['name'], str(h['drain'].get('op')))
        return out

    def _not_draining(self, host: str) -> None:
        _, fold = self._authority()
        if host in self._drains(fold):
            raise OrchestratorError('%s is draining (ceph orch host drain stop %s)' % (host, host))

    def _moves(self, fold: Any) -> Dict[str, str]:
        """The hosts with a move (plan 04, step 5) and its operation: the
        fold's, and the leader's records of a move still finishing."""
        out = {h: mv['op'] for h, mv in fold.moving.items()}
        try:
            hosts = self._inventory()['hosts']
        except InventoryError:
            hosts = []
        for h in hosts:
            if isinstance(h.get('move'), dict):
                out.setdefault(h['name'], str(h['move'].get('op')))
        return out

    def _not_moving(self, host: str) -> None:
        _, fold = self._authority()
        if host in self._moves(fold):
            raise OrchestratorError('the address of %s is changing (ceph orch host ls)' % host)

    def _move_record(self, host: str) -> Dict[str, Any]:
        """The leader's record of a host's move, {} without one."""
        try:
            hosts = self._inventory()['hosts']
        except InventoryError:
            return {}
        return next((h['move'] for h in hosts if h['name'] == host and isinstance(h.get('move'), dict)), {})

    def _drain_record(self, host: str) -> Dict[str, Any]:
        """The leader's record of a host's drain, {} without one."""
        try:
            hosts = self._inventory()['hosts']
        except InventoryError:
            return {}
        return next((h['drain'] for h in hosts if h['name'] == host and isinstance(h.get('drain'), dict)), {})

    def _rgw_port(self) -> Optional[int]:
        """The RGWs' port: the newest RGW add's (fold state), else the CLI's, None before any."""
        _, fold = self._authority()
        if fold.rgw_port is not None:
            return int(fold.rgw_port)
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
        # an RGW add rolls the RGWs' certificate: not during a host's move
        if self._moves(fold):
            raise OrchestratorError('host addresses changing: %s' % ', '.join(sorted(self._moves(fold))))
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
        index = self._journal_index()
        self._not_backlogged(led, index)
        busy = self._unfinished(daemon, host, index)
        if busy:
            raise OrchestratorError('%s has operation %s in progress (orch talos operation %s)' % (daemon or host, busy, busy))
        # a mgr's renewal changes its certificates in the state only while its
        # host is in maintenance; the exit renders them (plan 04, step 1)
        if kind not in ('exit_maintenance', 'renew_mgr', 'renew_agent'):
            self._not_in_maintenance(host)
        # a draining host takes no new operation but the renewals (plan 04, step 5)
        if kind not in ('renew_mgr', 'renew_agent'):
            self._not_draining(host)
        # a moving host none: the move reissues its certificates itself
        self._not_moving(host)
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
        def mon(cmd: Dict[str, Any], deadline: float, reduce: Optional[Callable[[str], str]] = None) -> Optional[Tuple[int, str, str]]:
            job = cmds.submit(cmd, reduce)
            if job is None or not job.ev.wait(deadline):
                return None
            if job.too_large:
                return -27, '', 'output too large'  # EFBIG
            return job.r, job.outb, job.outs
        return mon

    def _ledger_batch(self, cmds: bridge.Commands) -> Callable[[List[Dict[str, Any]], float], List[Optional[Tuple[int, str, str]]]]:
        """Mon commands sent together (the ledger's reads by key and its
        removals): at most what the pool takes at once, the rest after those
        answered; None for one without an answer."""
        def batch(items: List[Dict[str, Any]], deadline: float) -> List[Optional[Tuple[int, str, str]]]:
            out: List[Optional[Tuple[int, str, str]]] = [None] * len(items)
            jobs: List[Tuple[int, Any]] = []
            for i, c in enumerate(items):
                job = cmds.submit(c)
                if job is None:  # the pool is full: after the ones sent
                    for _, j in jobs:
                        j.ev.wait(deadline)
                    job = cmds.submit(c)
                if job is not None:
                    jobs.append((i, job))
            end = time.monotonic() + deadline
            for i, job in jobs:
                if job.ev.wait(max(0.0, end - time.monotonic())):
                    out[i] = (-27, '', 'output too large') if job.too_large else (job.r, job.outb, job.outs)
            return out
        return batch

    def _maybe_compact(self, cmds: bridge.Commands, leadership: Any) -> None:
        """Start a compaction run (plan 04, step 4) when one is due, apart from
        the leadership loop so its heartbeats keep going; one at a time."""
        led = getattr(self, '_ledger', None)
        if led is None or not led.ready or time.monotonic() < self.__dict__.get('_compact_next', 0.0):
            return
        run = self.__dict__.get('_compact_thread')
        if run is not None and run.is_alive():
            return
        self._compact_next = time.monotonic() + COMPACT_CHECK
        t = threading.Thread(target=self._compact_logged, args=(led, cmds, leadership), name='talos-compact', daemon=True)
        self._compact_thread = t
        t.start()

    def _compact_logged(self, led: ledger.Ledger, cmds: bridge.Commands, leadership: Any) -> None:
        try:
            self._compact(led, lambda: leadership.still_active(cmds))
        except Exception as e:  # tried again at the next check
            self.log.warning('ledger compaction: %s', e)

    def _compact(self, led: ledger.Ledger, active: Callable[[], bool], now: Optional[datetime.datetime] = None) -> None:
        """One compaction run: the delayed deletion of what the newest snapshot
        covers (with the journal records it makes redundant), then a new
        snapshot when more than COMPACT_AFTER entries follow it, at most hourly."""
        now = now or utcnow()
        mono = time.monotonic()
        if led.snapshot is not None and (led.snapshot_key != self.__dict__.get('_deleted') or mono >= self.__dict__.get('_pruned_next', 0.0)):
            if led.delete(now, active, self._prune_journals):
                self.log.info('ledger: removed what snapshot %s covers', led.snapshot_key)
                self._deleted, self._pruned_next = led.snapshot_key, mono + COMPACT_EVERY
        try:
            after = self.get_module_option('talos_compact_after')
        except Exception:  # a test double without options
            after = None
        after = after if isinstance(after, int) and after > 0 else ledger.COMPACT_AFTER
        if len(led.entries) <= after or mono < self.__dict__.get('_cut_next', 0.0):
            return
        store = self.get_store_prefix(STORE_PREFIX)
        states = {k: v.get('state') for k, v in self._journal_index().items()}
        try:
            cluster = record_from_store(store, choose_incarnation(store, getattr(self, '_gid', None)), 'cluster')[0] or {}
        except InventoryError:
            return
        # an upgrade's start while its steps or the bridge may still read it:
        # a Ceph upgrade's until the leader cleared its record (a finished one
        # still asks `upgrade done`, authorized by the start, until then); an
        # agent upgrade's until finished (its record stays, nothing reads the
        # start after the publication that finishes it)
        pinned = {u['op'] for u in (cluster.get('upgrade'),) if u and u.get('op')}
        pinned |= {u['op'] for u in (cluster.get('agent_upgrade'),) if u and u.get('op') and not u.get('finished')}
        fold = led.fold(cli_baseline(store))
        if fold.upgrade is not None:
            pinned.add(fold.upgrade['op'])
        # a drain's operation while it lasts or the leader's record of it
        # stays: the bridge authorizes its steps by it (plan 04, step 5)
        pinned |= {d['op'] for d in fold.draining.values()}
        pinned |= {mv['op'] for mv in fold.moving.values()}
        try:
            inv = inventory_from_store(store, choose_incarnation(store, getattr(self, '_gid', None)))
            pinned |= {str(h['drain'].get('op')) for h in inv['hosts'] if isinstance(h.get('drain'), dict)}
            # a move's operation until the leader cleared its record (its steps'
            # calls are authorized by it)
            pinned |= {str(h['move'].get('op')) for h in inv['hosts'] if isinstance(h.get('move'), dict)}
        except InventoryError:
            return
        got = led.cut(cli_baseline(store), states, cluster.get('ledger_applied') or '', pinned, now)
        self._cut_next = mono + COMPACT_EVERY
        if got is None or not active():
            return
        if led.publish(got[0], got[1], now):
            self.log.info('ledger: snapshot %s published (%d entries follow it)', got[0], len(led.entries))
            # its deletion, once DELETE_AFTER passed
            self._compact_next = mono + ledger.DELETE_AFTER.total_seconds() + 1

    def _prune_journals(self, covered: Callable[[str], bool]) -> None:
        """Remove, in every incarnation, the journal records of the operations
        the snapshot covers (plan 04, step 4), except what is still read: an
        RGW roll's records while a certificate of its operation is not
        retired, a renewal's until its done entry, a removal's certificates
        until its retire, and this incarnation's grants whose outcome is not
        known. An earlier incarnation's journal goes whole (its takeover
        record last) once nothing else is left in it and a later incarnation
        published its state."""
        store = self.get_store_prefix(STORE_PREFIX)
        _, fold = self._authority()
        live = {cid.split('/')[1] for cid, c in fold.rgw_certs.items() if cid != 'cli' and not c['retired']}
        own = str(getattr(self, '_gid', ''))
        names: Dict[str, List[str]] = {}
        epochs: Dict[str, int] = {}
        published: Set[str] = set()
        for k, v in store.items():
            inc, _, rest = k[len(STORE_PREFIX):].partition('/')
            if rest.startswith('manifest/'):
                published.add(inc)
            if not inc.isdigit() or not rest.startswith('journal/'):
                continue
            names.setdefault(inc, []).append(rest[len('journal/'):])
            if rest == 'journal/takeover':
                try:
                    epochs[inc] = int(json.loads(v)['epoch'])
                except (ValueError, KeyError, TypeError):
                    pass
        gone: List[str] = []
        for inc, recs in names.items():
            left = []
            for name in recs:
                kind, _, rest = name.partition('/')
                base, _, suffix = rest.partition('.')
                prunable = False
                if kind == 'op' and covered(base):
                    try:
                        state = json.loads(store[STORE_PREFIX + inc + '/journal/' + name]).get('state')
                    except (ValueError, AttributeError):
                        state = None
                    # a grant this incarnation still asks the agent about
                    prunable = not (inc == own and state in ('granting', 'uncertain'))
                elif kind == 'roll' and covered(base) and base not in live:
                    step = suffix.split('.')[0]
                    prunable = (step != 'renew' or base in fold.renewals_done) and (step != 'certs' or base in fold.retired_by)
                if prunable:
                    gone.append(MODULE_PREFIX + STORE_PREFIX + inc + '/journal/' + name)
                else:
                    left.append(name)
            later = any(p != inc and p in epochs and epochs[p] > epochs.get(inc, -1) for p in published)
            if inc != own and set(left) <= {'takeover'} and later:
                gone.extend(MODULE_PREFIX + STORE_PREFIX + inc + '/journal/' + n for n in left)
        led = self._ledger
        led.remove_keys([k for k in gone if not k.endswith('/journal/takeover')])
        led.remove_keys([k for k in gone if k.endswith('/journal/takeover')])

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
        issuer: Optional[revocation.Issuer] = None
        nonce = ''
        try:
            while not self._poller.stop.is_set():
                read = None
                try:
                    read = self._read_revoked(bridge_cmds)
                except Exception as e:  # never the leadership loop's end: no list from it, TALOS_CRL
                    self.log.warning('the revoked set: %s', e)
                try:
                    inv = self._inventory()
                    if channel is None:
                        creds = bridge.load_credentials(os.path.join(TALOS_DIR, 'agent-ca.crt'), os.path.join(TALOS_DIR, 'mgr-server.crt'),
                                                        os.path.join(TALOS_DIR, 'mgr-server.key'))
                        c = bridge.Channel(
                            inv['fsid'], self.get_mgr_id(), leadership, bridge_cmds, creds.ctx, creds.server_key,
                            self._require_identity, self.log, self._authority, creds.ca_cert, creds.digest)
                        c.start()
                        channel = c  # only a started channel; a failed start is retried
                        wake = self.__dict__.setdefault('_noout_wake', threading.Event())
                        c.on_down = wake.set
                        self._channel = c
                    else:
                        # a renewed server certificate, once the leader granted its files
                        channel.reload(os.path.join(TALOS_DIR, 'agent-ca.crt'), os.path.join(TALOS_DIR, 'mgr-server.crt'),
                                       os.path.join(TALOS_DIR, 'mgr-server.key'))
                    if leadership.capture():
                        gid, epoch = leadership.captured() or (0, 0)
                        self._gid = gid  # this incarnation's state, once its leader published it
                        self._leadership = leadership
                        if getattr(self, '_ledger', None) is None:
                            self._ledger = ledger.Ledger(self._ledger_mon(bridge_cmds), gid, epoch, self._ledger_batch(bridge_cmds))
                        try:
                            if not self._ledger.ready:
                                self._ledger.open()  # its takeover entry, before anything is accepted
                            else:
                                self._ledger.settle()  # an append the mons did not answer
                        except ledger.LedgerError as e:
                            self.log.warning('the ledger: %s', e)
                        self._maybe_compact(bridge_cmds, leadership)
                        # the list, before and independent of the heartbeat: a
                        # fail-closed agent may refuse it until it has a new list
                        issuer = self._issue_crl(bridge_cmds, issuer, epoch, channel, read)
                        nonce = self._heartbeat(inv, gid, epoch, nonce)
                        self._schedule_cert_check()
                except InventoryError as e:
                    self.log.warning('%s', e)
                except Exception:  # leadership must survive anything
                    self.log.exception('agent channel failed')
                self._poller.stop.wait(bridge.HEARTBEAT_INTERVAL)
        finally:
            self._channel = None
            if channel is not None:
                channel.stop()
            leader_cmds.stop()
            bridge_cmds.stop()

    def _read_revoked(self, cmds: bridge.Commands) -> Tuple[Dict[int, datetime.datetime], List[str]]:
        """Read the whole revoked set (plan 04, step 3): the set and the keys of
        the entries to prune. A failed read raises and keeps the set read
        before for the module's verifiers."""
        revoked, old = revocation.read_revoked(self._ledger_mon(cmds), datetime.datetime.now(datetime.timezone.utc))
        self._revoked = frozenset(revoked)
        return revoked, old

    def _issue_crl(self, cmds: bridge.Commands, issuer: Optional[revocation.Issuer], epoch: int,
                   channel: Optional[bridge.Channel],
                   read: Optional[Tuple[Dict[int, datetime.datetime], List[str]]]) -> Optional[revocation.Issuer]:
        """Prune, issue and publish the list as the leader (plan 04, step 3),
        only from this tick's complete read of the revoked set (read; None when
        it failed): a list from an incomplete set would re-admit revoked
        certificates. TALOS_CRL when it cannot. Returns the leadership's issuer."""
        led = getattr(self, '_ledger', None)
        if led is None or not led.ready or channel is None:
            return issuer
        if read is None:
            self._set_health('crl', {'TALOS_CRL': {'severity': 'warning', 'summary': 'the agent CA revocation list cannot be issued or published',
                                                   'count': 1, 'detail': ['the revoked set cannot be read']}})
            return issuer
        issuer = issuer or revocation.Issuer(epoch)
        try:
            minutes = self.get_module_option('talos_crl_valid_minutes') or revocation.MAX_VALID_MINUTES
            if issuer.tick(self._ledger_mon(cmds), channel.ca_cert, read[0], read[1],
                           datetime.datetime.now(datetime.timezone.utc), int(minutes)):
                self.log.info('revocation list %d issued (%d serials)', issuer.number, len(issuer.serials or ()))
            if issuer.der is not None and issuer.published:
                self._crl = (issuer.number, issuer.der)
            self._set_health('crl', {})
        except Exception as e:
            self.log.warning('the revocation list: %s', e)
            self._set_health('crl', {'TALOS_CRL': {'severity': 'warning', 'summary': 'the agent CA revocation list cannot be issued or published',
                                                   'count': 1, 'detail': [str(e) or e.__class__.__name__]}})
        return issuer

    def _heartbeat(self, inv: Dict[str, Any], gid: int, epoch: int, nonce: str) -> str:
        """Tell the local agent it is the leader's; returns the agent's session
        nonce. Over loopback, not the host's published address (plan 04, step
        5): a move of this host never cuts the leader off from its agent,
        which is checked by its identity as before."""
        if not any(h['name'] == self.get_mgr_id() for h in inv['hosts']):
            raise ValueError('this mgr\'s host %s is not an inventory host' % self.get_mgr_id())
        status, body = bridge.post_json(
            LOOPBACK, AGENT_PORT, tls_context(), '/v1/heartbeat', bridge.heartbeat_body(inv['fsid'], self.get_mgr_id(), gid, epoch, nonce),
            bridge.HEARTBEAT_INTERVAL, lambda cert: self._require_identity(cert, inv['fsid'], 'agent', self.get_mgr_id()))
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
        threading.Thread(target=self._noout_loop, name='talos-noout', daemon=True).start()
        while not self._poller.stop.is_set():
            try:
                inv = self._inventory()
                self._poller.poll(inv['hosts'])
                self._deliver_crl(inv)
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
        index = self._journal_index()
        self._not_backlogged(led, index)
        for _, e in led.executable():
            if e['id'].startswith('m-') or e.get('host') != host or not (e['kind'] in ledger.HOST_KINDS or e.get('device') == device):
                continue
            if not self._finished(index, e['id']):
                raise OrchestratorError('%s has operation %s in progress (orch talos operation %s)' % (host, e['id'], e['id']))
        self._not_in_maintenance(host)
        self._not_draining(host)
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
        self._not_backlogged(led, self._journal_index())
        self._not_draining(host)
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
        index = self._journal_index()
        out = []
        for _, e in entries:
            if e['kind'] != 'remove_osd':
                continue
            rec = index.get(e['id'])
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
        self._not_draining(hostname)
        if fold.upgrade is not None:
            raise OrchestratorError('an upgrade is in progress (operation %s)' % fold.upgrade['op'])
        led, _ = self._authority()
        index = self._journal_index()
        for _, e in led.executable():
            if e['kind'] == 'apply_ingress' and hostname in e['hosts'] + ((fold.ingress or {}).get('hosts') or []):
                if not self._finished(index, e['id']):
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

    @handle_orch_error
    def drain_host(self, hostname: str, force: bool = False, keep_conf_keyring: bool = False, zap_osd_devices: bool = False) -> str:
        """Remove every daemon of a host, one at a time (plan 04, step 5); again
        on a host whose drain paused, resume it."""
        if force or keep_conf_keyring:
            raise OrchestratorError('--force and --keep-conf-keyring are not supported by this backend')
        self._settle()
        led, fold = self._authority()
        if hostname not in fold.hosts:
            raise OrchestratorError('%s is not a host of the cluster' % hostname)
        if hostname in fold.draining:
            d, rec = fold.draining[hostname], self._drain_record(hostname)
            if rec.get('op') != d['op'] or not rec.get('paused'):
                raise OrchestratorError('the drain of %s is in progress (operation %s)' % (hostname, d['op']))
            if bool(zap_osd_devices) != bool(d['zap']):
                raise OrchestratorError('the drain of %s was accepted %s --zap-osd-devices' % (hostname, 'with' if d['zap'] else 'without'))
            op_id = self._accept_control('drain_resume', hostname, drain=d['op'])
            return 'Scheduled to resume the drain of host %s (operation %s)' % (hostname, op_id)
        rec = self._drain_record(hostname)
        if rec.get('stopped') and rec.get('paused'):
            # a stopped drain paused in a removal it must finish: again resumes it
            op_id = self._accept_control('drain_resume', hostname, drain=str(rec.get('op')))
            return 'Scheduled to resume the removal the stopped drain of host %s paused in (operation %s)' % (hostname, op_id)
        others = self._drains(fold)
        if others:
            raise OrchestratorError('%s is draining' % ', '.join(sorted(others)))
        if hostname in fold.maintenance:
            raise OrchestratorError('%s is in maintenance (ceph orch host maintenance exit %s)' % (hostname, hostname))
        if fold.upgrade is not None:
            raise OrchestratorError('an upgrade is in progress (operation %s)' % fold.upgrade['op'])
        agents = self._agent_upgrade_running(led)
        if agents is not None:
            raise OrchestratorError('the agent upgrade %s is in progress' % agents['id'])
        index = self._journal_index()
        for _, e in led.executable():
            if e['kind'] == 'apply_ingress' and not self._finished(index, e['id']):
                raise OrchestratorError('ingress operation %s is in progress' % e['id'])
        on = sorted(n for n, h in fold.daemons.items() if h == hostname)
        # the ingress spec has one owner: a keepalived leaves with the ingress
        if any(n.startswith('keepalived.') for n in on) or hostname in ((fold.ingress or {}).get('hosts') or []):
            raise OrchestratorError('%s is a host of the ingress: apply the ingress without %s first' % (hostname, hostname))
        mons = [n for n in fold.daemons if n.startswith('mon.')]
        if 'mon.' + hostname in on and len(mons) - 1 < 3:
            raise OrchestratorError('%s runs a mon and fewer than three would be left (the rest keep quorum while it goes)' % hostname)
        if 'mgr.' + hostname in on and not [n for n in fold.daemons if n.startswith('mgr.') and n != 'mgr.' + hostname]:
            raise OrchestratorError('%s runs the last mgr' % hostname)
        if hostname == self.get_mgr_id():
            standbys = [m for m in (self.get('mgr_map') or {}).get('standbys', []) if m.get('available', True)]
            if not standbys:
                raise OrchestratorError('%s runs the active mgr and no standby mgr is available' % hostname)
        op_id = self._accept('drain_host', None, hostname, zap=bool(zap_osd_devices))
        return 'Scheduled to drain host %s (operation %s)' % (hostname, op_id)

    @handle_orch_error
    def stop_drain_host(self, hostname: str) -> str:
        """Stop a host's drain: no new step starts, one in progress finishes;
        OSDs marked out stay out."""
        self._settle()
        _, fold = self._authority()
        d = fold.draining.get(hostname)
        if d is None:
            raise OrchestratorError('%s is not draining' % hostname)
        op_id = self._accept_control('drain_stop', hostname, drain=d['op'])
        return 'Scheduled to stop the drain of host %s (operation %s)' % (hostname, op_id)

    @handle_orch_error
    def update_host_addr(self, host: str, addr: str) -> str:
        """Change a host's address (plan 04, step 5): the leader confirms the
        node has it, then moves its daemons one at a time and reissues its
        certificates; again on a paused move, resume it. cephadm only records
        the address its SSH connection uses; here the mons, mgr, OSDs and RGW
        follow."""
        try:
            new = ipaddress.ip_address(addr)
        except ValueError:
            raise OrchestratorError('%s is not an IP address: a Talos node is reached by its address' % addr)
        addr = str(new)
        if not ledger.ADDR_RE.match(addr) or new.is_unspecified or new.is_loopback or new.is_multicast:
            raise OrchestratorError('%s cannot be a host address' % addr)
        self._settle()
        led, fold = self._authority()
        if host not in fold.hosts:
            raise OrchestratorError('%s is not a host of the cluster' % host)
        mv = fold.moving.get(host)
        if mv is not None:
            rec = self._move_record(host)
            if mv['addr'] != addr:
                raise OrchestratorError('the address of %s is changing to %s (operation %s)' % (host, mv['addr'], mv['op']))
            if rec.get('op') != mv['op'] or not rec.get('paused'):
                raise OrchestratorError('the address change of %s is in progress (operation %s)' % (host, mv['op']))
            op_id = self._accept_control('move_resume', host, move=mv['op'])
            return 'Scheduled to resume the address change of host %s to %s (operation %s)' % (host, addr, op_id)
        old = fold.hosts[host]
        if addr == old:
            raise OrchestratorError('%s has the address %s already' % (host, addr))
        others = self._moves(fold)
        if others:
            raise OrchestratorError('the address of %s is changing: one host at a time' % ', '.join(sorted(others)))
        if host in fold.maintenance:
            raise OrchestratorError('%s is in maintenance (ceph orch host maintenance exit %s)' % (host, host))
        if host in self._drains(fold):
            raise OrchestratorError('%s is draining' % host)
        if fold.upgrade is not None:
            raise OrchestratorError('an upgrade is in progress (operation %s)' % fold.upgrade['op'])
        agents = self._agent_upgrade_running(led)
        if agents is not None:
            raise OrchestratorError('the agent upgrade %s is in progress' % agents['id'])
        index = self._journal_index()
        for _, e in led.executable():
            if e['kind'] == 'apply_ingress' and not self._finished(index, e['id']):
                raise OrchestratorError('ingress operation %s is in progress' % e['id'])
            # the RGWs' certificate rolls: one at a time
            if (e['kind'] == 'renew_rgw_cert' or e['kind'] == 'add_daemon' and e['daemon'].startswith('rgw.')) and not self._finished(index, e['id']):
                raise OrchestratorError('operation %s on the RGW certificates is in progress' % e['id'])
        taken = sorted(h for h, a in fold.hosts.items() if h != host and a == addr)
        if taken:
            raise OrchestratorError('%s has the address %s' % (taken[0], addr))
        # Ceph's bind families follow the mons' addresses, keepalived is IPv4 only
        if ipaddress.ip_address(old).version != new.version:
            raise OrchestratorError('%s is not of the family of %s: an address change keeps the family' % (addr, old))
        # its mon leaves the monmap and joins again while the rest keep quorum
        mons = [n for n in fold.daemons if n.startswith('mon.')]
        if 'mon.' + host in fold.daemons and len(mons) < 3:
            raise OrchestratorError('%s runs a mon and the cluster has fewer than three: the rest must keep quorum while it moves' % host)
        if any(n.startswith('osd.') and h == host for n, h in fold.daemons.items()) and bridge.ambiguous(host):
            raise OrchestratorError('host name %s is ambiguous for osd set-group noout' % host)
        # its mgr is failed over before it moves
        if host == self.get_mgr_id():
            standbys = [x for x in (self.get('mgr_map') or {}).get('standbys', []) if x.get('available', True)]
            if not standbys:
                raise OrchestratorError('%s runs the active mgr and no standby mgr is available' % host)
        op_id = self._accept('set_host_addr', None, host, addr=addr)
        return 'Scheduled to change the address of host %s from %s to %s (operation %s)' % (host, old, addr, op_id)

    @_accepting
    def _accept_control(self, kind: str, host: str, **fields: Any) -> str:
        """Accept a drain's control: ahead of queued operations in the leader,
        not refused for a busy host or by backpressure."""
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
            led.append({'id': op_id, 'kind': kind, 'host': host, **fields, **self._request_fields()})
        except ledger.OutcomeUnknown:
            raise OrchestratorError('the mons did not answer: operation %s may have been accepted (orch talos operation %s)' % (op_id, op_id))
        except ledger.LedgerError as e:
            raise OrchestratorError('not accepted: %s' % e)
        return op_id

    @TalosCLICommand.Write('orch talos noout keep')
    def _noout_keep(self, host: str) -> HandleCommandResult:
        """Hand a host's noout the module set over to the operator: the module drops its reasons and never unsets it"""
        return self._noout_command(host, keep=True)

    @TalosCLICommand.Write('orch talos noout release')
    def _noout_release(self, host: str) -> HandleCommandResult:
        """End a host's unplanned stop that the module cannot see ending: its noout reason goes, and the flag with it if no other reason holds and the module set it"""
        return self._noout_command(host, keep=False)

    def _noout_command(self, host: str, keep: bool) -> HandleCommandResult:
        try:
            with _ACCEPT_LOCK:
                self._not_suspended()
                _, fold = self._authority()
                channel = getattr(self, '_channel', None)
                if channel is None:
                    raise OrchestratorError('this mgr does not serve the agent channel yet; try again')
                if not keep and host not in fold.down and ledger.UNPLANNED not in fold.noout_reasons(host):
                    raise OrchestratorError('%s has no unplanned stop' % host)
                why = channel.noout_keep(host) if keep else channel.host_up(host)
                if why is not None:
                    raise OrchestratorError(why)
        except (OrchestratorError, ledger.LedgerError) as e:
            return HandleCommandResult(retval=-22, stderr=str(e))
        if keep:
            return HandleCommandResult(stdout='the noout of %s is the operator\'s: the module never unsets it' % host)
        return HandleCommandResult(stdout='the unplanned stop of %s ended' % host)

    def _noout_tick(self, now: Optional[datetime.datetime] = None) -> None:
        """The noout ownership's pass (plan 04, step 5): every host with an
        unplanned stop, a reason or an open intent is reconciled; a host back
        from its stop (a new boot, or its stop cancelled, and its OSDs up again
        unless it is in maintenance) ends it. Then TALOS_HOST_DOWN and
        TALOS_DRAIN_PAUSED and TALOS_HOST_MOVE_PAUSED."""
        now = now or utcnow()
        channel = getattr(self, '_channel', None)
        led = getattr(self, '_ledger', None)
        if channel is None or led is None or not led.ready:
            return
        _, fold = self._authority()
        obs = self._poller.snapshot()
        up = None
        # when this process first saw each stop: only a status record fetched
        # by a poll started after it shows the host back
        seen = self.__dict__.setdefault('_down_seen', {})
        for key in [k for k in seen if fold.down.get(k[0], {}).get('stop') != k[1]]:
            del seen[key]
        for host in sorted(set(fold.noout) | set(fold.down)):
            osds = [int(n.split('.', 1)[1]) for n, h in fold.daemons.items() if h == host and n.startswith('osd.')]
            d = fold.down.get(host)
            try:
                if d is not None:
                    since = seen.setdefault((host, d['stop']), time.monotonic())
                    rec = obs.get(host, (None, ''))[0]
                    if rec is not None and rec.get('fetched_mono', float('-inf')) <= since:
                        rec = None  # fetched before this module saw the stop: no evidence
                    boot = (rec or {}).get('boot') or ''
                    # a cancellation counts only for the stop recorded (its id
                    # the agent's): a later stop on the same boot has another
                    cancelled = rec is not None and rec.get('stop_cancelled') == d['stop']
                    back = bool(boot) and (boot != d['boot'] or cancelled)
                    if back and osds and host not in fold.maintenance:
                        if up is None:
                            up = {o['osd'] for o in (self.get('osd_map') or {}).get('osds', []) if o.get('up')}
                        back = set(osds) <= up
                    if back:
                        why = channel.host_up(host, d['stop'])
                        if why is not None:
                            self.log.info('noout of %s: %s', host, why)
                        continue
                why = channel.noout_reconcile(host, bool(osds))
                if why is not None:
                    self.log.info('noout of %s: %s', host, why)
            except Exception as e:  # each host stands on its own; tried again next pass
                self.log.warning('noout of %s: %s', host, e)
        _, fold = self._authority()
        checks: Dict[str, Any] = {}
        late = sorted(h for h, d in fold.down.items() if now - ledger._parse_iso(d['at']) > HOST_DOWN_AFTER)
        if late:
            checks['TALOS_HOST_DOWN'] = {
                'severity': 'warning', 'summary': 'hosts went down outside the orchestrator and are not back', 'count': len(late),
                'detail': ['%s went down at %s: noout stays until it is back, the operator clears it (ceph orch talos noout release %s) or the host is removed'
                           % (h, fold.down[h]['at'], h) for h in late]}
        try:
            hosts = self._inventory()['hosts']
        except InventoryError:
            hosts = []
        paused = [(h['name'], h['drain']) for h in hosts if isinstance(h.get('drain'), dict) and h['drain'].get('paused')]
        if paused:
            checks['TALOS_DRAIN_PAUSED'] = {
                'severity': 'warning', 'summary': 'a host drain is paused', 'count': len(paused),
                'detail': ['the drain of %s paused: %s (ceph orch host drain %s resumes it)' % (h, d.get('error', ''), h) for h, d in paused]}
        moves = [(h['name'], h['move']) for h in hosts if isinstance(h.get('move'), dict) and h['move'].get('paused')]
        if moves:
            checks['TALOS_HOST_MOVE_PAUSED'] = {
                'severity': 'warning', 'summary': 'a host address change is paused', 'count': len(moves),
                'detail': ['the move of %s to %s paused: %s (ceph orch host set-addr %s %s resumes it)'
                           % (h, mv.get('to', ''), mv.get('error', ''), h, mv.get('to', '')) for h, mv in moves]}
        self._set_health('lifecycle', checks)

    def _noout_loop(self) -> None:
        """The noout ownership's passes, apart from the leadership loop (mon
        commands may wait): every HEARTBEAT_INTERVAL, and at once after an
        agent reported its node going down."""
        wake = self.__dict__.setdefault('_noout_wake', threading.Event())
        while not self._poller.stop.is_set():
            try:
                self._noout_tick()
            except InventoryError as e:
                self.log.warning('%s', e)
            except Exception:
                self.log.exception('noout pass failed')
            wake.wait(bridge.HEARTBEAT_INTERVAL)
            wake.clear()

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

        # host renewals due, the earliest expiry first: a host takes one at a time
        # (its other renewal refused, tried again soon), so the most urgent goes first
        due: List[Tuple[datetime.datetime, Callable[[], str]]] = []
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
                due.append((min(ends), lambda name=h['name']: self._accept('renew_mgr', 'mgr.' + name, name)))
        # every host's agent certificates (plan 04, step 2)
        for h in hosts or []:
            ends = [cert_not_after(h.get(k)) for k in ('agent_cert', 'agent_client_cert') if h.get(k)]
            if not ends:
                continue
            if min(ends) - now <= CERT_ALERT_BEFORE:
                alerts.append('the agent of %s: certificates expire %s' % (h['name'], min(ends).isoformat()))
            if min(ends) - now <= renew_before:
                due.append((min(ends), lambda name=h['name']: self._accept('renew_agent', None, name)))
        for _, accept in sorted(due, key=lambda d: d[0]):
            self._accept_renewal(accept)
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
        self._set_health('certs', checks)

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
            except Exception as e:  # tried again soon
                self.log.warning('the certificate check: %s', e)
                self._certs_next = min(self._certs_next, time.monotonic() + CERT_RETRY_INTERVAL)
        threading.Thread(target=run, name='talos-certs', daemon=True).start()

    def _accept_renewal(self, accept: Callable[[], str]) -> None:
        """Accept a renewal; one that is refused (its host busy, suspended) is
        tried again by a check soon, not the next day's."""
        try:
            op = accept()
            self.log.info('certificate renewal accepted: operation %s', op)
        except OrchestratorError as e:
            self.log.info('certificate renewal not accepted now, tried again in %d minutes: %s', CERT_RETRY_INTERVAL // 60, e)
            self._certs_next = min(getattr(self, '_certs_next', 0.0) or float('inf'), time.monotonic() + CERT_RETRY_INTERVAL)

    def _accept_rgw_renewal(self) -> str:
        """A renewal of the generated RGW certificate, unless one, an ingress
        apply, an RGW add or a host's move (it rolls the RGWs and holds a
        keepalived off, plan 04 step 5) is unfinished."""
        led, fold = self._authority()
        if self._moves(fold):
            raise OrchestratorError('host addresses changing: %s' % ', '.join(sorted(self._moves(fold))))
        index = self._journal_index()
        for _, e in led.executable():
            if e['kind'] in ('renew_rgw_cert', 'apply_ingress') or e['kind'] == 'add_daemon' and e['daemon'].startswith('rgw.'):
                if not self._finished(index, e['id']):
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
        # the controls of an upgrade in progress are not refused by backpressure
        if kind not in ledger.UPGRADE_CONTROLS + ('upgrade_agent_resume', 'upgrade_agent_stop'):
            self._not_backlogged(led, self._journal_index())
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
        agents = self._agent_upgrade_running(self._authority()[0])
        if agents is not None:
            raise OrchestratorError('the agent upgrade %s is in progress' % agents['id'])
        if fold.maintenance:
            raise OrchestratorError('hosts in maintenance: %s' % ', '.join(sorted(fold.maintenance)))
        if self._drains(fold):
            raise OrchestratorError('hosts draining: %s' % ', '.join(sorted(self._drains(fold))))
        if self._moves(fold):
            raise OrchestratorError('host addresses changing: %s' % ', '.join(sorted(self._moves(fold))))
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
        busy = sorted(set(hosts) & set(self._drains(fold)))
        if busy:
            raise OrchestratorError('hosts draining: %s' % ', '.join(busy))
        if self._moves(fold):
            raise OrchestratorError('host addresses changing: %s' % ', '.join(sorted(self._moves(fold))))
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
            # a compacted operation: the snapshot's lookup table, for 30 days (plan 04, step 4)
            row = None if done else led.lookup(request=request)
            if row is not None:
                done = [row]
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
    def _agent_upgrade(self, image: Optional[str] = None, resume: bool = False, stop: bool = False) -> HandleCommandResult:
        """Upgrade every agent to an image the operator approved, one host at a time; resume a paused upgrade; stop it, rolling back to the image it upgrades from"""
        try:
            return HandleCommandResult(stdout=self._accept_agent_upgrade(image, resume, stop))
        except OrchestratorError as e:
            return HandleCommandResult(retval=-22, stderr=str(e))

    @TalosCLICommand.Write('orch talos revoke')
    def _revoke(self, serial: str, until: Optional[str] = None) -> HandleCommandResult:
        """Revoke a certificate of the agent CA by its serial (decimal, 0x<hex> or colon-separated hex), until a date (ISO 8601; default 3 years)"""
        try:
            n = revocation.parse_serial(serial)
            now = datetime.datetime.now(datetime.timezone.utc)
            end = revocation.parse_iso(until) if until else revocation.add_years(now, revocation.REVOKE_YEARS)
        except ValueError as e:
            return HandleCommandResult(retval=-22, stderr=str(e))
        key = '%s%d' % (revocation.REVOKED_PREFIX, n)
        r, out, err = self.mon_command({'prefix': 'config-key get', 'key': key})
        if r == 0:
            return HandleCommandResult(stdout='serial %d is revoked already: %s' % (n, out))
        if r != -errno.ENOENT:
            return HandleCommandResult(retval=r, stderr='cannot read the revoked set: %s' % err)
        r, _, err = self.mon_command({'prefix': 'config-key set', 'key': key, 'val': revocation.entry(end, 'operator')})
        if r != 0:
            return HandleCommandResult(retval=r, stderr='not revoked: %s' % err)
        return HandleCommandResult(stdout='serial %d revoked until %s; the next revocation list names it' % (n, revocation.iso(end)))

    @TalosCLICommand.Read('orch talos agent upgrade status')
    def _agent_upgrade_show(self) -> HandleCommandResult:
        """Show the last agent upgrade: running, paused, stopping, finished or rolled back"""
        try:
            return HandleCommandResult(stdout=self._agent_upgrade_status())
        except OrchestratorError as e:
            return HandleCommandResult(retval=-22, stderr=str(e))

    def _agent_upgrade_running(self, led: Any) -> Optional[Dict[str, Any]]:
        """The agent upgrade in progress: the leader's record of it until it is
        finished, or an accepted one before the leader recorded it."""
        entries = self.get_store_prefix(STORE_PREFIX)
        try:
            cluster, _ = record_from_store(entries, choose_incarnation(entries, getattr(self, '_gid', None)), 'cluster')
        except InventoryError:
            cluster = None
        rec_up = (cluster or {}).get('agent_upgrade') or {}
        running = None
        index = self._journal_index()
        for _, e in led.executable():
            if e['kind'] == 'upgrade_agent':
                rec = index.get(e['id'])
                if rec_up.get('op') == e['id'] and not rec_up.get('finished') or rec_up.get('op') != e['id'] and (rec is None or rec.get('state') not in TERMINAL):
                    running = e
        return running

    def _agent_upgrade_record(self) -> Dict[str, Any]:
        """The leader's record of the last agent upgrade, {} without one."""
        entries = self.get_store_prefix(STORE_PREFIX)
        try:
            cluster, _ = record_from_store(entries, choose_incarnation(entries, getattr(self, '_gid', None)), 'cluster')
        except InventoryError:
            return {}
        return (cluster or {}).get('agent_upgrade') or {}

    def _agent_upgrade_status(self) -> str:
        """The last agent upgrade as its record shows it: running (or rolling
        back after a stop), paused, finished or stopped."""
        rec = self._agent_upgrade_record()
        if not rec:
            return 'No agent upgrade'
        if rec.get('finished'):
            state = 'stopped, rolled back to %s (gave up %s)' % (rec.get('image'), rec.get('stopped')) if rec.get('stopped') else 'finished'
        elif rec.get('stopped'):
            state = 'stopped, rolling back to %s (gave up %s)' % (rec.get('image'), rec.get('stopped'))
        elif rec.get('stopping'):
            state = 'stopping'
        else:
            state = 'running'
        if rec.get('paused') and not rec.get('finished'):
            state += ', paused: %s' % rec.get('error', '')
        return json.dumps({'operation': rec.get('op'), 'from': rec.get('from'), 'target': rec.get('image'), 'state': state,
                           'step': rec.get('step', ''), 'done': rec.get('done') or []}, indent=2, sort_keys=True)

    def _accept_agent_upgrade(self, image: Optional[str], resume: bool, stop: bool = False) -> str:
        """An agent upgrade (plan 04, step 2): by digest, approved, from the agent
        image's repository; no other agent or Ceph upgrade unfinished. Its
        resume, and its stop: a rollback to the image it upgrades from, which
        must be in the operator's current approval; not of a rollback."""
        self._settle()
        led, fold = self._authority()
        entries = self.get_store_prefix(STORE_PREFIX)
        cluster, _ = record_from_store(entries, choose_incarnation(entries, getattr(self, '_gid', None)), 'cluster')
        running = self._agent_upgrade_running(led)
        if running is None and fold.upgrade is not None:
            running = {'id': fold.upgrade['op'], 'kind': 'upgrade_start'}
        if stop:
            if image or resume or running is None or running['kind'] != 'upgrade_agent':
                raise OrchestratorError('--stop takes no image, and needs an agent upgrade in progress')
            rec = self._agent_upgrade_record()
            ours = rec.get('op') == running['id']
            index = self._journal_index()
            for _, e in led.executable():
                if e['kind'] == 'upgrade_agent_stop' and e['upgrade'] == running['id'] and (not self._finished(index, e['id']) or not ours):
                    raise OrchestratorError('agent upgrade %s is stopping already (operation %s)' % (running['id'], e['id']))
            if ours and (rec.get('stopping') or rec.get('stopped')):
                raise OrchestratorError('agent upgrade %s is stopping already' % running['id'])
            # the image it upgrades from: the record's, else the agents' image the leader records as it
            back = rec.get('from') if ours else ((cluster or {}).get('agent') or {}).get('image')
            if not back or back not in self._approved_images():
                raise OrchestratorError('the operator has not approved %s, the image to roll back to (cephadm-talos approve --image)' % back)
            op = self._accept_cluster('upgrade_agent_stop', upgrade=running['id'])
            return 'Scheduled to stop agent upgrade %s, rolling back to %s (operation %s)' % (running['id'], back, op)
        if resume:
            if image or running is None or running['kind'] != 'upgrade_agent':
                raise OrchestratorError('--resume takes no image, and needs an agent upgrade in progress')
            op = self._accept_cluster('upgrade_agent_resume', upgrade=running['id'])
            return 'Scheduled to resume agent upgrade %s (operation %s)' % (running['id'], op)
        if running is not None:
            raise OrchestratorError('operation %s (%s) is in progress' % (running['id'], running['kind']))
        if self._drains(fold):
            raise OrchestratorError('hosts draining: %s' % ', '.join(sorted(self._drains(fold))))
        if self._moves(fold):
            raise OrchestratorError('host addresses changing: %s' % ', '.join(sorted(self._moves(fold))))
        if not isinstance(image, str) or not ledger.IMAGE_RE.match(image):
            raise OrchestratorError('name the image by its digest: <repository>@sha256:<hex>')
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
            # compacted: the snapshot's lookup table keeps it for 30 days (plan 04, step 4)
            row = led.lookup(ident=id)
            if row is None:
                return HandleCommandResult(retval=-2, stderr='no accepted operation %s' % id)  # ENOENT
            state = row.pop('state', None)
            return HandleCommandResult(stdout=json.dumps({'accepted': row, 'compacted': led.snapshot_key,
                                                          'journal': self._journal(id) or {'state': state}}, indent=2, sort_keys=True))
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
