"""The ledger: the operations this module accepted (plan 03, step 6b, part 3).

The ledger, not the leader's journal, is the module's authority over what was
accepted: the leader writes its journal itself, and the bridge's store calls
cannot reach the ledger. Every entry is one config-key entry below
LEDGER_PREFIX, written once with `config-key set` through the module's own
command pool, never overwritten. Keys sort in the order the operations run:
`<epoch>-<seq>-<id>`, zero-padded.

Right after it captured its incarnation, before accepting anything, a module
writes a takeover entry (sequence 0) with the highest sequence number it found
for every incarnation since the previous takeover entry. Readers walk the
incarnations in epoch order: an entry, takeover entries included, is valid only
if its sequence number is at most the cutoff that the first later valid takeover
entry records for its incarnation (-1 if that entry does not name it), or if no
later valid takeover entry exists. A void takeover entry sets no cutoffs.
"""

import json
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

LEDGER_PREFIX = 'cephadm-talos/ledger/'
ENTRY_VERSION = 1
KEY_RE = re.compile(r'\A(\d{20})-(\d{10})-(takeover|op-[0-9a-f]{16}|m-[0-9a-f]{16})\Z')
OP_RE = re.compile(r'\Aop-[0-9a-f]{16}\Z')
# kinds an operation entry may have; ADDS and REMOVES change the fold
KINDS = ('restart', 'redeploy', 'add_daemon', 'remove_daemon', 'remove_host', 'create_osd', 'remove_osd', 'enter_maintenance', 'exit_maintenance', 'powercycle_host',
         'upgrade_start', 'upgrade_pause', 'upgrade_resume', 'upgrade_stop', 'apply_ingress', 'add_host',
         # renewals the module accepts by itself (plan 04, step 1)
         'renew_mgr', 'renew_rgw_cert',
         # an agent's certificates and the agents' image (plan 04, step 2)
         'renew_agent', 'upgrade_agent', 'upgrade_agent_resume', 'upgrade_agent_stop')
# the upgrade's kinds, operations and module entries: about the cluster, without a host
UPGRADE_CONTROLS = ('upgrade_pause', 'upgrade_resume', 'upgrade_stop')
UPGRADE_KINDS = ('upgrade_start',) + UPGRADE_CONTROLS + ('upgrade_done', 'upgrade_refused')
# entries about the cluster, without a host: the upgrade's and the RGW certificates'
HOSTLESS = UPGRADE_KINDS + ('rgw_cert', 'rgw_cert_done', 'apply_ingress', 'renew_rgw_cert', 'upgrade_agent', 'upgrade_agent_resume', 'upgrade_agent_stop')
VIP_RE = re.compile(r'\A(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}/(?:3[0-2]|[12]?\d)\Z')
IMAGE_RE = re.compile(r'\A[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}\Z')
# kinds that are about a whole host: every other operation on it waits for them
HOST_KINDS = ('remove_host', 'enter_maintenance', 'exit_maintenance', 'powercycle_host', 'add_host')
LABEL_RE = re.compile(r'\A[A-Za-z0-9._-]{1,64}\Z')
ADDR_RE = re.compile(r'\A[0-9A-Fa-f:.]{2,45}\Z')
# kinds that stop a host's daemons, and that start them again
STOPS, STARTS = ('enter_maintenance', 'powercycle_host'), ('exit_maintenance', 'powercycle_host')
# the module's own entries (ids m-<hex>), which carry out a removal: close a
# daemon's generation, retire the daemon, retire a host; end a host's maintenance
MODULE_KINDS = ('close', 'retire', 'retire_host', 'bind', 'confirm', 'close_create', 'drained', 'maintained', 'upgrade_done', 'upgrade_refused',
                'rgw_cert', 'rgw_cert_done', 'mgr_cert', 'mgr_cert_done', 'agent_cert', 'agent_cert_done')
# an RGW serving certificate's id (internal/state RGWCert): generated, the operator's, the CLI's
RGW_CERT_RE = re.compile(r'\A(?:issued/op-[0-9a-f]{16}/[0-9a-f]{16}|user/op-[0-9a-f]{16}|cli)\Z')
DEVICE_RE = re.compile(r'\A/dev/[A-Za-z0-9][A-Za-z0-9._:/-]{0,200}\Z')
SERIAL_RE = re.compile(r'\A[A-Za-z0-9._-]{1,64}\Z')
UUID_RE_OSD = re.compile(r'\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
DAEMON_RE = re.compile(r'\A(mon|mgr|osd|rgw|keepalived)\.([A-Za-z0-9][A-Za-z0-9._-]{0,127})\Z')
HOST_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
UUID_RE = re.compile(r'\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
WRITE_DEADLINE = 10.0


class LedgerError(Exception):
    pass


class OutcomeUnknown(LedgerError):
    """The mons did not answer a write: the operation may exist."""


def entry_key(epoch: int, seq: int, ident: str) -> str:
    return '%s%020d-%010d-%s' % (LEDGER_PREFIX, epoch, seq, ident)


def _int(v: Any) -> bool:
    return type(v) is int and v >= 0


def check_entry(key: str, raw: str) -> Dict[str, Any]:
    """An entry as written by a module; anything else raises LedgerError."""
    m = KEY_RE.match(key[len(LEDGER_PREFIX):]) if key.startswith(LEDGER_PREFIX) else None
    if m is None:
        raise LedgerError('ledger key %r' % key)
    try:
        e = json.loads(raw)
    except ValueError:
        raise LedgerError('ledger entry %s is not JSON' % key)
    if not isinstance(e, dict) or e.get('version') != ENTRY_VERSION or not _int(e.get('gid')) or not _int(e.get('epoch')) \
            or not _int(e.get('seq')) or e['epoch'] != int(m.group(1)) or e['seq'] != int(m.group(2)) or e.get('id') != m.group(3):
        raise LedgerError('ledger entry %s does not match its key' % key)
    if e['id'] == 'takeover':
        cut = e.get('cutoffs')
        if e['seq'] != 0 or e.get('kind') != 'takeover' or not isinstance(cut, dict) \
                or not all(k.isdigit() and _int(v) for k, v in cut.items()):
            raise LedgerError('takeover entry %s' % key)
        return e
    kind, daemon, host = e.get('kind'), e.get('daemon'), e.get('host')
    ok_daemon = isinstance(daemon, str) and DAEMON_RE.match(daemon) is not None
    ok_host = isinstance(host, str) and HOST_RE.match(host) is not None
    if e['seq'] < 1 or not (ok_host or kind in HOSTLESS and 'host' not in e):
        raise LedgerError('entry %s' % key)
    if e['id'].startswith('m-'):
        if kind not in MODULE_KINDS or not isinstance(e.get('of'), str) or not OP_RE.match(e['of']):
            raise LedgerError('module entry %s' % key)
        if kind in ('close', 'retire', 'drained') and not ok_daemon:
            raise LedgerError('module entry %s' % key)
        if (kind in HOSTLESS) != ('host' not in e) or kind in HOSTLESS and daemon is not None:
            raise LedgerError('module entry %s' % key)
        if kind == 'bind' and not (isinstance(e.get('serial'), str) and SERIAL_RE.match(e['serial'])
                                   and isinstance(e.get('link'), str) and e['link'].startswith('/dev/disk/by-id/')
                                   and isinstance(e.get('job'), str) and re.match(r'\A[0-9a-f]{16}\Z', e['job'])):
            raise LedgerError('bind entry %s' % key)
        if kind == 'confirm' and not (ok_daemon and daemon.startswith('osd.') and isinstance(e.get('uuid'), str) and UUID_RE_OSD.match(e['uuid'])):
            raise LedgerError('confirm entry %s' % key)
        if kind == 'rgw_cert' and not (isinstance(e.get('attempt'), str) and re.match(r'\A[0-9a-f]{16}\Z', e['attempt'])):
            raise LedgerError('rgw_cert entry %s' % key)
        if kind == 'rgw_cert_done' and not (isinstance(e.get('keep'), str) and RGW_CERT_RE.match(e['keep'])):
            raise LedgerError('rgw_cert_done entry %s' % key)
        # a renewed mgr's certificates: issued once per renewal, and the renewal
        # whose keys the mgr keeps when the others are retired
        if kind in ('mgr_cert', 'mgr_cert_done') and not (ok_daemon and daemon == 'mgr.' + host):
            raise LedgerError('%s entry %s' % (kind, key))
        if kind == 'mgr_cert' and not (isinstance(e.get('attempt'), str) and re.match(r'\A[0-9a-f]{16}\Z', e['attempt'])):
            raise LedgerError('mgr_cert entry %s' % key)
        if kind == 'mgr_cert_done' and not (isinstance(e.get('keep'), str) and OP_RE.match(e['keep'])):
            raise LedgerError('mgr_cert_done entry %s' % key)
        # a renewed agent's certificates, as a mgr's but by host
        if kind in ('agent_cert', 'agent_cert_done') and daemon is not None:
            raise LedgerError('%s entry %s' % (kind, key))
        if kind == 'agent_cert' and not (isinstance(e.get('attempt'), str) and re.match(r'\A[0-9a-f]{16}\Z', e['attempt'])):
            raise LedgerError('agent_cert entry %s' % key)
        if kind == 'agent_cert_done' and not (isinstance(e.get('keep'), str) and OP_RE.match(e['keep'])):
            raise LedgerError('agent_cert_done entry %s' % key)
        return e
    if kind not in KINDS or (e.get('request') is not None and not (isinstance(e['request'], str) and UUID_RE.match(e['request']))):
        raise LedgerError('operation entry %s' % key)
    # a request's inputs hash only with its request uuid
    if ('inputs' in e) != ('request' in e) or 'inputs' in e and not (isinstance(e['inputs'], str) and re.match(r'\A[0-9a-f]{64}\Z', e['inputs'])):
        raise LedgerError('operation entry %s' % key)
    if (kind in HOSTLESS) != ('host' not in e):
        raise LedgerError('operation entry %s' % key)
    if kind == 'upgrade_start':
        if not isinstance(e.get('image'), str) or not IMAGE_RE.match(e['image']) \
                or set(e) - {'version', 'id', 'kind', 'image', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind == 'apply_ingress':
        hosts = e.get('hosts')
        if not (isinstance(e.get('vip'), str) and VIP_RE.match(e['vip']) and type(e.get('vrid')) is int and 0 < e['vrid'] < 256
                and isinstance(hosts, list) and 0 < len(hosts) <= 15 and len(set(hosts)) == len(hosts)
                and all(isinstance(h, str) and HOST_RE.match(h) for h in hosts)
                and isinstance(e.get('image'), str) and IMAGE_RE.match(e['image']) and type(e.get('new_password')) is bool) \
                or set(e) - {'version', 'id', 'kind', 'vip', 'vrid', 'hosts', 'image', 'new_password', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind == 'renew_rgw_cert':
        if daemon is not None or set(e) - {'version', 'id', 'kind', 'gid', 'epoch', 'seq'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind == 'renew_agent':
        if daemon is not None or set(e) - {'version', 'id', 'kind', 'host', 'gid', 'epoch', 'seq'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind == 'upgrade_agent':
        if daemon is not None or not isinstance(e.get('image'), str) or not IMAGE_RE.match(e['image']) \
                or set(e) - {'version', 'id', 'kind', 'image', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind in ('upgrade_agent_resume', 'upgrade_agent_stop'):
        if daemon is not None or not isinstance(e.get('upgrade'), str) or not OP_RE.match(e['upgrade']) \
                or set(e) - {'version', 'id', 'kind', 'upgrade', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind == 'renew_mgr':
        if not (ok_daemon and daemon == 'mgr.' + host) or set(e) - {'version', 'id', 'kind', 'daemon', 'host', 'gid', 'epoch', 'seq'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind in UPGRADE_CONTROLS:
        if not isinstance(e.get('upgrade'), str) or not OP_RE.match(e['upgrade']) \
                or set(e) - {'version', 'id', 'kind', 'upgrade', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind == 'add_host':
        labels = e.get('labels')
        if daemon is not None or not (isinstance(e.get('addr'), str) and ADDR_RE.match(e['addr'])
                                      and all(isinstance(e.get(c), str) and 0 < len(e[c]) <= 8192 and e[c].startswith('-----BEGIN CERTIFICATE-----')
                                              for c in ('agent_cert', 'agent_client_cert'))
                                      and isinstance(labels, list) and len(labels) <= 32 and all(isinstance(x, str) and LABEL_RE.match(x) for x in labels)) \
                or set(e) - {'version', 'id', 'kind', 'host', 'addr', 'agent_cert', 'agent_client_cert', 'labels', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind in ('remove_host', 'exit_maintenance', 'powercycle_host'):
        if daemon is not None or (kind != 'remove_host' and set(e) - {'version', 'id', 'kind', 'host', 'gid', 'epoch', 'seq', 'request', 'inputs'}):
            raise LedgerError('operation entry %s' % key)
        return e
    if kind == 'enter_maintenance':
        if daemon is not None or type(e.get('force')) is not bool or set(e) - {'version', 'id', 'kind', 'host', 'force', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind == 'create_osd':
        if daemon is not None or not isinstance(e.get('device'), str) or not DEVICE_RE.match(e['device']):
            raise LedgerError('operation entry %s' % key)
        return e
    if not ok_daemon:
        raise LedgerError('operation entry %s' % key)
    t, i = daemon.split('.', 1)
    # mon and mgr ids are their host's name
    if kind == 'add_daemon' and (t not in ('mon', 'mgr', 'rgw') or i != host):
        raise LedgerError('operation entry %s' % key)
    if kind == 'remove_daemon' and (t not in ('mon', 'mgr', 'rgw') or i != host):
        raise LedgerError('operation entry %s' % key)
    # an RGW's add: its port, and the operator's certificate chain (public) if any
    if kind == 'add_daemon' and t == 'rgw' and (type(e.get('port')) is not int or not 0 < e['port'] < 65536
                                                or 'cert' in e and not (isinstance(e['cert'], str) and 0 < len(e['cert']) <= 16384)):
        raise LedgerError('operation entry %s' % key)
    if kind == 'add_daemon' and t != 'rgw' and ('port' in e or 'cert' in e):
        raise LedgerError('operation entry %s' % key)
    if kind == 'remove_osd' and (t != 'osd' or not re.match(r'\A(0|[1-9][0-9]{0,8})\Z', i) or not isinstance(e.get('uuid'), str)
                                 or not UUID_RE_OSD.match(e['uuid']) or type(e.get('zap')) is not bool or type(e.get('force')) is not bool):
        raise LedgerError('operation entry %s' % key)
    if kind in ('restart', 'redeploy', 'add_daemon', 'remove_daemon') and set(e) - {'version', 'id', 'kind', 'daemon', 'host', 'gid', 'epoch', 'seq', 'request', 'inputs', 'port', 'cert'}:
        raise LedgerError('operation entry %s' % key)
    return e


def executable(entries: Dict[str, Dict[str, Any]]) -> List[Tuple[str, Dict[str, Any]]]:
    """The valid entries in the order they run (module docstring)."""
    by_inc: Dict[Tuple[int, int], List[Tuple[str, Dict[str, Any]]]] = {}
    for k, e in entries.items():
        by_inc.setdefault((e['epoch'], e['gid']), []).append((k, e))
    out: List[Tuple[str, Dict[str, Any]]] = []
    cutoffs: Optional[Dict[str, int]] = None  # of the first later valid takeover entry
    for epoch, gid in sorted(by_inc, reverse=True):
        limit = None if cutoffs is None else cutoffs.get(str(gid), -1)
        valid = sorted((k, e) for k, e in by_inc[(epoch, gid)] if limit is None or e['seq'] <= limit)
        for k, e in valid:
            if e['id'] == 'takeover':
                cutoffs = e['cutoffs']
        out = [x for x in valid if x[1]['id'] != 'takeover'] + out
    return out


def takeover_cutoffs(entries: Dict[str, Dict[str, Any]], epoch: int) -> Dict[str, int]:
    """The cutoffs of a new takeover entry at epoch: the highest sequence number
    of every incarnation since the newest valid takeover entry before epoch."""
    valid = {k for k, _ in executable(entries)}
    since = -1
    for k, e in entries.items():
        if e['id'] == 'takeover' and e['epoch'] < epoch and _valid_takeover(entries, k):
            since = max(since, e['epoch'])
    cut: Dict[str, int] = {}
    for k, e in entries.items():
        if since <= e['epoch'] < epoch and (k in valid or e['id'] == 'takeover'):
            cut[str(e['gid'])] = max(cut.get(str(e['gid']), 0), e['seq'])
    return cut


def _valid_takeover(entries: Dict[str, Dict[str, Any]], key: str) -> bool:
    """Whether a takeover entry is valid by the rule of the module docstring."""
    e = entries[key]
    later = sorted((x['epoch'], x['gid'], k) for k, x in entries.items() if x['id'] == 'takeover' and x['epoch'] > e['epoch'])
    for _, _, k in later:
        if _valid_takeover(entries, k):
            return e['seq'] <= entries[k]['cutoffs'].get(str(e['gid']), -1)
    return True


class Fold:
    """The authorized hosts and daemons: the CLI's sealed state, then the
    executable entries in order. An add counts from acceptance and opens a
    generation of the daemon (the add's id; "cli" for the CLI's daemons); a
    close entry closes it, a retire entry takes the daemon out, a retire_host
    entry the host. A host is in maintenance from the acceptance of its enter
    (or powercycle) until the maintained entry of an exit (or that powercycle)."""

    def __init__(self, inventory: Dict[str, Any], entries: List[Tuple[str, Dict[str, Any]]] = ()) -> None:
        self.hosts: Dict[str, str] = {h['name']: h['addr'] for h in inventory['hosts']}
        self.daemons: Dict[str, str] = {}  # "<type>.<id>" -> host
        self.generations: Dict[str, Tuple[str, bool]] = {}  # "<type>.<id>" -> (generation, open)
        self.uuids: Dict[str, str] = {}  # "osd.<id>" -> uuid
        # creations of OSDs: op id -> {'host', 'bind': entry or None, 'confirmed', 'closed'}
        self.creations: Dict[str, Dict[str, Any]] = {}
        self.maintenance = {h['name'] for h in inventory['hosts'] if h.get('maintenance')}
        # the upgrade in progress: {'op', 'image', 'paused'} from its start's
        # acceptance until done, refused, or a stop's acceptance
        self.upgrade: Optional[Dict[str, Any]] = None
        # RGW serving certificates by id, in the order they entered (the CLI's
        # first if the sealed state has an RGW), with the position they entered
        # at; a retired one is no longer released
        self.rgw_certs: Dict[str, Dict[str, Any]] = {}
        # a mgr's renewals in its open generation (op id -> attempt, None until
        # issued), and the operations whose keys are retired: the add's, the
        # CLI's (by host) or a renewal's, by a later mgr_cert_done
        self.mgr_renewals: Dict[str, Dict[str, Optional[str]]] = {}
        self.mgr_retired: Set[str] = set()
        # an agent's renewals (by host: op id -> attempt) and the retired ones;
        # 'cli/<host>' for the CLI's agent keys
        self.agent_renewals: Dict[str, Dict[str, Optional[str]]] = {}
        self.agent_retired: Set[str] = set()
        # the agents' upgrade in progress: its operation, until the leader's
        # state says it ended (the fold sees its acceptance only)
        self.agent_upgrade: Optional[str] = None
        # the CLI's RGW settings, and the ingress VIP (address without prefix)
        self.cli_rgw: Dict[str, Any] = inventory.get('cli_rgw') or {}
        self.vip: Optional[str] = (self.cli_rgw.get('vip') or '').split('/')[0] or None
        # the ingress: the CLI's VIP and router id, then the newest apply's; the
        # secret holding the current VRRP password (the CLI's, or the newest
        # apply that set one)
        self.ingress: Optional[Dict[str, Any]] = None
        if self.cli_rgw.get('vip'):
            self.ingress = {'vip': self.cli_rgw['vip'], 'vrid': self.cli_rgw.get('vrid'), 'op': None,
                            'hosts': [d['host'] for d in inventory['daemons'] if d.get('daemon_type') == 'keepalived' and d.get('daemon_id')]}
        self.vrrp_secret = 'rgw/vrrp'
        if any(d.get('daemon_type') == 'rgw' and d.get('daemon_id') for d in inventory['daemons']):
            self.rgw_certs['cli'] = {'pos': -1, 'retired': False}
        positions: Dict[str, int] = {}
        for d in inventory['daemons']:
            if d.get('daemon_id'):
                name = '%s.%s' % (d['daemon_type'], d['daemon_id'])
                self.daemons[name], self.generations[name] = d['host'], ('cli', True)
                if d.get('osd_uuid'):
                    self.uuids[name] = d['osd_uuid']
        for n, (_, e) in enumerate(entries):
            positions[e['id']] = n
            kind = e['kind']
            if kind == 'add_daemon' and e['host'] in self.hosts:
                self.daemons[e['daemon']], self.generations[e['daemon']] = e['host'], (e['id'], True)
                self.mgr_renewals.pop(e['daemon'], None)
                if e.get('cert'):
                    self.rgw_certs['user/' + e['id']] = {'pos': n, 'retired': False}
            elif kind == 'close' and e['daemon'] in self.generations:
                self.generations[e['daemon']] = (self.generations[e['daemon']][0], False)
            elif kind == 'retire' and e['daemon'].startswith('keepalived.') and e['host'] in (self.ingress or {}).get('hosts', []):
                pass  # a newer ingress places it again: it stays
            elif kind == 'retire':
                self.daemons.pop(e['daemon'], None)
                self.generations.pop(e['daemon'], None)
                self.uuids.pop(e['daemon'], None)
            elif kind == 'retire_host' and not any(h == e['host'] for h in self.daemons.values()):
                self.hosts.pop(e['host'], None)
                self.maintenance.discard(e['host'])
            elif kind == 'add_host' and e['host'] not in self.hosts:
                self.hosts[e['host']] = e['addr']
            elif kind in STOPS and e['host'] in self.hosts:
                self.maintenance.add(e['host'])
            elif kind == 'maintained':
                self.maintenance.discard(e['host'])
            elif kind == 'rgw_cert':
                # counted from its issuing operation's place, like an operator's from its add
                self.rgw_certs.setdefault('issued/%s/%s' % (e['of'], e['attempt']), {'pos': positions.get(e['of'], n), 'retired': False})
            elif kind == 'rgw_cert_done' and e['of'] in positions:
                for cid, c in self.rgw_certs.items():
                    if cid != e['keep'] and c['pos'] < positions[e['of']]:
                        c['retired'] = True
            elif kind == 'renew_mgr' and self.open_generation(e['daemon']) is not None:
                self.mgr_renewals.setdefault(e['daemon'], {})[e['id']] = None
            elif kind == 'mgr_cert' and e['of'] in self.mgr_renewals.get(e['daemon'], {}):
                self.mgr_renewals[e['daemon']][e['of']] = e['attempt']
            elif kind == 'mgr_cert_done':
                self.mgr_retired.update(self.mgr_retiring(e['daemon'], e['keep'], e['host']))
            elif kind == 'renew_agent' and e['host'] in self.hosts:
                self.agent_renewals.setdefault(e['host'], {})[e['id']] = None
            elif kind == 'agent_cert' and e['of'] in self.agent_renewals.get(e['host'], {}):
                self.agent_renewals[e['host']][e['of']] = e['attempt']
            elif kind == 'agent_cert_done':
                self.agent_retired.update(self.agent_retiring(e['host'], e['keep']))
            elif kind == 'upgrade_agent':
                self.agent_upgrade = e['id']
            elif kind == 'apply_ingress':
                self.ingress = {'vip': e['vip'], 'vrid': e['vrid'], 'op': e['id'], 'hosts': list(e['hosts'])}
                self.vip = e['vip'].split('/')[0]
                if e['new_password']:
                    self.vrrp_secret = 'ingress/%s/vrrp' % e['id']
                # a host left out keeps its keepalived until the module retires it
                for h in e['hosts']:
                    if h in self.hosts:
                        self.daemons['keepalived.' + h], self.generations['keepalived.' + h] = h, (e['id'], True)
            elif kind == 'upgrade_start' and self.upgrade is None:
                self.upgrade = {'op': e['id'], 'image': e['image'], 'paused': False}
            elif self.upgrade is not None and e.get('upgrade', e.get('of')) == self.upgrade['op'] and kind in UPGRADE_KINDS:
                if kind in ('upgrade_pause', 'upgrade_resume'):
                    self.upgrade['paused'] = kind == 'upgrade_pause'
                else:
                    self.upgrade = None
            elif kind == 'create_osd' and e['host'] in self.hosts:
                self.creations[e['id']] = {'host': e['host'], 'bind': None, 'confirmed': False, 'closed': False}
            elif kind == 'bind' and e['of'] in self.creations and self.creations[e['of']]['bind'] is None:
                self.creations[e['of']]['bind'] = e
            elif kind == 'confirm' and e['of'] in self.creations and e['daemon'] not in self.daemons:
                c = self.creations[e['of']]
                c['confirmed'] = True
                self.daemons[e['daemon']], self.generations[e['daemon']], self.uuids[e['daemon']] = c['host'], (e['of'], True), e['uuid']
            elif kind == 'close_create' and e['of'] in self.creations:
                self.creations[e['of']]['closed'] = True

    def mgr_retiring(self, name: str, keep: str, host: str) -> Set[str]:
        """What a mgr_cert_done keeping a renewal retires: the mgr's other
        renewals and its generation's keys (the CLI's by host); nothing for a
        renewal retired already."""
        if keep not in self.mgr_renewals.get(name, {}) or keep in self.mgr_retired:
            return set()
        gen = self.open_generation(name)
        return {o for o in self.mgr_renewals[name] if o != keep} | {gen if gen != 'cli' else 'cli/' + host}

    def agent_retiring(self, host: str, keep: str) -> Set[str]:
        """What an agent_cert_done keeping a renewal retires: the host's other
        agent renewals and the CLI's keys."""
        if keep not in self.agent_renewals.get(host, {}) or keep in self.agent_retired:
            return set()
        return {o for o in self.agent_renewals[host] if o != keep} | {'cli/' + host}

    def creating(self, op_id: str) -> Optional[Dict[str, Any]]:
        """An OSD creation that may still use client.bootstrap-osd: bound, neither
        confirmed nor closed."""
        c = self.creations.get(op_id)
        return c if c is not None and c['bind'] is not None and not c['confirmed'] and not c['closed'] else None

    def open_generation(self, name: str) -> Optional[str]:
        """The daemon's current generation while it is open, else None."""
        gen = self.generations.get(name)
        return gen[0] if gen is not None and gen[1] else None

    def has(self, daemon_type: str, daemon_id: Optional[str] = None, host: Optional[str] = None) -> bool:
        for name, h in self.daemons.items():
            t, _, i = name.partition('.')
            if t == daemon_type and (daemon_id is None or i == daemon_id) and (host is None or h == host):
                return True
        return False

    def entity_allowed(self, entity: str) -> bool:
        """Whether `auth get` may release an entity's key."""
        if entity == 'mon.':
            return self.has('mon')
        if entity.startswith('mgr.'):
            return self.has('mgr', entity[len('mgr.'):])
        if entity.startswith('client.rgw.'):
            return self.has('rgw', entity[len('client.rgw.'):])
        return False  # osd.<n>: on its disk; client.bootstrap-osd: step 6c

    def mgr_keys_allowed(self, op: str) -> bool:
        """Whether a mgr's issued keys of an operation may be released: its open
        generation's add or a renewal in it, not retired."""
        if op in self.mgr_retired:
            return False
        for n in self.daemons:
            gen = self.open_generation(n) if n.startswith('mgr.') else None
            if gen is not None and (gen == op or op in self.mgr_renewals.get(n, {})):
                return True
        return False

    def agent_keys_allowed(self, op: str) -> bool:
        """Whether an agent's issued keys of a renewal may be released: a renewal
        of a host in the fold, issued, not retired."""
        return op not in self.agent_retired and any(self.agent_renewals.get(h, {}).get(op) for h in self.hosts)

    def secret_allowed(self, name: str, host: Optional[str]) -> bool:
        """Whether `secret get` may release a secret (host for a host's keys)."""
        if host is not None:
            return self.has('mgr', host=host) and 'cli/' + host not in self.mgr_retired
        if name == 'rgw/server.key':
            return self.has('rgw') and not self.rgw_certs.get('cli', {'retired': True})['retired']
        if name.endswith('/rgw-server.key'):
            c = self.rgw_certs.get(name[:-len('/rgw-server.key')])
            return self.has('rgw') and c is not None and not c['retired']
        if name == 'rgw/vrrp' or name.startswith('ingress/'):
            return self.has('keepalived') and name == self.vrrp_secret
        return False


class Ledger:
    """This incarnation's view of the ledger: what it found when it captured,
    plus what it appended since. Entries a stale module appends after this
    module's takeover entry are void for every reader, so nothing is re-read."""

    def __init__(self, mon: Callable[[Dict[str, Any], float], Optional[Tuple[int, str, str]]], gid: int, epoch: int) -> None:
        # mon runs one mon command and returns (r, out, outs), or None without an answer
        self.mon = mon
        self.gid, self.epoch = gid, epoch
        self.lock = threading.Lock()
        self.entries: Dict[str, Dict[str, Any]] = {}
        self.seq = 0
        self.pending: Optional[Tuple[str, str]] = None  # an append whose outcome is unknown
        self.ready = False

    def _set(self, key: str, value: str) -> None:
        res = self.mon({'prefix': 'config-key set', 'key': key, 'val': value}, WRITE_DEADLINE)
        if res is None:
            raise OutcomeUnknown('no answer from the mons for %s' % key)
        if res[0] != 0:
            raise LedgerError('the mons refused %s: %s' % (key, res[2]))

    def open(self) -> None:
        """Read the ledger and write this incarnation's takeover entry."""
        with self.lock:
            if self.ready:
                return
            if self.pending is None:
                res = self.mon({'prefix': 'config-key dump', 'key': LEDGER_PREFIX}, WRITE_DEADLINE)
                if res is None or res[0] != 0:
                    raise LedgerError('cannot read the ledger')
                found = {}
                for k, v in json.loads(res[1]).items():
                    try:
                        found[k] = check_entry(k, v)
                    except LedgerError:
                        continue  # not a module's entry: no authority
                self.entries = found
                cut = takeover_cutoffs(found, self.epoch)
                key = entry_key(self.epoch, 0, 'takeover')
                value = json.dumps({'version': ENTRY_VERSION, 'id': 'takeover', 'kind': 'takeover', 'gid': self.gid,
                                    'epoch': self.epoch, 'seq': 0, 'cutoffs': cut}, sort_keys=True)
                self.pending = (key, value)
            self._settle()
            self.ready = True

    def _settle(self) -> None:
        """Write the pending append again (same key, same content) until the mons answer."""
        if self.pending is None:
            return
        key, value = self.pending
        try:
            self._set(key, value)
        except OutcomeUnknown:
            raise  # stays pending: written again until the mons answer
        except LedgerError:
            # the mons refused it (size, caps): a refusal does not change on a
            # retry, so neither this write nor an unanswered earlier one landed
            self.pending = None
            raise
        self.entries[key] = check_entry(key, value)
        self.seq = max(self.seq, self.entries[key]['seq'])
        self.pending = None

    def settle(self) -> None:
        """Settle an append whose outcome is unknown; raises while the mons do not answer."""
        with self.lock:
            self._settle()

    def append(self, op: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Accept an operation, or write a module entry (id m-<hex>): one entry,
        after any earlier unknown append is settled."""
        with self.lock:
            if not self.ready:
                raise LedgerError('the ledger is not open')
            self._settle()
            seq = self.seq + 1
            entry = dict(op, version=ENTRY_VERSION, gid=self.gid, epoch=self.epoch, seq=seq)
            key = entry_key(self.epoch, seq, entry['id'])
            value = json.dumps(entry, sort_keys=True)
            check_entry(key, value)
            self.pending = (key, value)
            self._settle()
            return key, self.entries[key]

    def executable(self) -> List[Tuple[str, Dict[str, Any]]]:
        with self.lock:
            return executable(dict(self.entries))
