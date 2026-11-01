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
import hashlib
import http.client
import json
import os
import re
import ssl
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import orchestrator
from ceph.deployment.hostspec import HostSpec
from mgr_module import CLICommandBase, CommandResult, HandleCommandResult, MgrModule
from orchestrator import DaemonDescription, DaemonDescriptionStatus, OrchestratorError, handle_orch_error

from . import bridge, ledger

TalosCLICommand = CLICommandBase.make_registry_subtype("TalosCLICommand")

TALOS_DIR = '/etc/ceph/talos'
# journal states after which the leader does nothing more for an operation
TERMINAL = ('completed', 'nochange', 'failed', 'refused', 'abandoned')
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


def cli_baseline(entries: Dict[str, str]) -> Dict[str, Any]:
    """The inventory of the CLI's sealed state, the root of what the module
    authorizes (ledger.Fold): no incarnation can write it through the bridge."""
    cluster, key = record_from_store(entries, INCARNATION, 'cluster')
    if not isinstance(cluster, dict) or cluster.get('sealed') is not True:
        raise InventoryError('the CLI has not handed the cluster over (%s is not sealed)' % key)
    return inventory_from_store(entries, INCARNATION)


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


class Module(orchestrator.Orchestrator, MgrModule):
    CLICommand = TalosCLICommand

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

    def _authority(self) -> Tuple[ledger.Ledger, ledger.Fold]:
        """This incarnation's ledger and the fold it authorizes; raises without them."""
        led = getattr(self, '_ledger', None)
        if led is None or not led.ready:
            raise OrchestratorError('this mgr has not opened the ledger: it is not the leader yet')
        return led, ledger.Fold(cli_baseline(self.get_store_prefix(STORE_PREFIX)))

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

    def _accept(self, kind: str, daemon: str, host: str) -> str:
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
        # one operation at a time per daemon: a lying journal can only refuse commands
        for _, e in led.executable():
            if e['daemon'] == daemon:
                rec = self._journal(e['id'])
                if rec is None or rec.get('state') not in TERMINAL:
                    raise OrchestratorError('%s has operation %s in progress (orch talos operation %s)' % (daemon, e['id'], e['id']))
        op_id = 'op-' + os.urandom(8).hex()
        try:
            led.append({'id': op_id, 'kind': kind, 'daemon': daemon, 'host': host})
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
                        c = bridge.Channel(
                            inv['fsid'], self.get_mgr_id(), leadership, bridge_cmds,
                            bridge.server_context(os.path.join(TALOS_DIR, 'agent-ca.crt'), os.path.join(TALOS_DIR, 'mgr-server.crt'),
                                                  os.path.join(TALOS_DIR, 'mgr-server.key')),
                            bridge.read(os.path.join(TALOS_DIR, 'mgr-server.key')), require_identity, self.log, self._authority)
                        c.start()
                        channel = c  # only a started channel; a failed start is retried
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
