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

Snapshots (plan 04, step 4): the active module folds the finished operations
into a snapshot at a ledger key K, published once under
`cephadm-talos/ledger-snapshot/<K>/` (chunks, then a manifest naming them with
their sha256), and deletes the entries at or below K at least DELETE_AFTER
later. A snapshot holds the fold at K, the incarnations it covered since the
newest takeover entry at or below K (their highest sequence numbers, which
later takeover cutoffs take as seen) and a lookup table of the covered
operations. A reader takes the snapshot with the highest K whose chunks verify
and which is valid (the first valid takeover entry above K saw every
sequence number it covered), then the entries above K. Entries are read by key:
listed in pages, then fetched in batches of `config-key get`.
"""

import base64
import copy
import datetime
import hashlib
import json
import re
import secrets
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from . import revocation

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
         'renew_agent', 'upgrade_agent', 'upgrade_agent_resume', 'upgrade_agent_stop',
         # a host's drain and its controls (plan 04, step 5)
         'drain_host', 'drain_stop', 'drain_resume')
# the upgrade's kinds, operations and module entries: about the cluster, without a host
UPGRADE_CONTROLS = ('upgrade_pause', 'upgrade_resume', 'upgrade_stop')
UPGRADE_KINDS = ('upgrade_start',) + UPGRADE_CONTROLS + ('upgrade_done', 'upgrade_refused')
# entries about the cluster, without a host: the upgrade's and the RGW certificates'
HOSTLESS = UPGRADE_KINDS + ('rgw_cert', 'rgw_cert_done', 'apply_ingress', 'renew_rgw_cert', 'upgrade_agent', 'upgrade_agent_resume', 'upgrade_agent_stop')
VIP_RE = re.compile(r'\A(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}/(?:3[0-2]|[12]?\d)\Z')
IMAGE_RE = re.compile(r'\A[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}\Z')
# kinds that are about a whole host: every other operation on it waits for them
HOST_KINDS = ('remove_host', 'enter_maintenance', 'exit_maintenance', 'powercycle_host', 'add_host', 'drain_host')
# a drain's controls: run ahead of queued operations, never refused for a busy host
DRAIN_CONTROLS = ('drain_stop', 'drain_resume')
LABEL_RE = re.compile(r'\A[A-Za-z0-9._-]{1,64}\Z')
ADDR_RE = re.compile(r'\A[0-9A-Fa-f:.]{2,45}\Z')
# kinds that stop a host's daemons, and that start them again
STOPS, STARTS = ('enter_maintenance', 'powercycle_host'), ('exit_maintenance', 'powercycle_host')
# the module's own entries (ids m-<hex>), which carry out a removal: close a
# daemon's generation, retire the daemon, retire a host; end a host's maintenance
MODULE_KINDS = ('close', 'retire', 'retire_host', 'bind', 'confirm', 'close_create', 'drained', 'maintained', 'upgrade_done', 'upgrade_refused',
                'rgw_cert', 'rgw_cert_done', 'mgr_cert', 'mgr_cert_done', 'agent_cert', 'agent_cert_done',
                # a drain's end, and the noout ownership with the unplanned stops (plan 04, step 5)
                'drain_done', 'noout_intent', 'noout', 'noout_keep', 'host_down', 'host_up')
# module entries without an operation (of absent), or with one if a leader's
# operation caused them (maintenance's noout)
NOOUT_KINDS = ('noout_intent', 'noout', 'noout_keep', 'host_down', 'host_up')
NO_OF_KINDS = ('noout_keep', 'host_down', 'host_up')
# why the module holds a host's noout: generic names (maintenance, unplanned, move)
REASON_RE = re.compile(r'\A[a-z][a-z0-9_-]{0,31}\Z')
UNPLANNED = 'unplanned'
# a Talos boot id
BOOT_RE = re.compile(r'\A[A-Za-z0-9._-]{1,64}\Z')
ISO_RE = re.compile(r'\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')
# an RGW serving certificate's id (internal/state RGWCert): generated, the operator's, the CLI's
RGW_CERT_RE = re.compile(r'\A(?:issued/op-[0-9a-f]{16}/[0-9a-f]{16}|user/op-[0-9a-f]{16}|cli)\Z')
DEVICE_RE = re.compile(r'\A/dev/[A-Za-z0-9][A-Za-z0-9._:/-]{0,200}\Z')
SERIAL_RE = re.compile(r'\A[A-Za-z0-9._-]{1,64}\Z')
UUID_RE_OSD = re.compile(r'\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
DAEMON_RE = re.compile(r'\A(mon|mgr|osd|rgw|keepalived)\.([A-Za-z0-9][A-Za-z0-9._-]{0,127})\Z')
HOST_RE = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
UUID_RE = re.compile(r'\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
WRITE_DEADLINE = 10.0
# journal states after which the leader does nothing more for an operation
TERMINAL = ('completed', 'nochange', 'failed', 'refused', 'abandoned')

# snapshots (plan 04, step 4)
SNAPSHOT_PREFIX = 'cephadm-talos/ledger-snapshot/'
SNAPSHOT_SCHEMA = 2
SNAPSHOT_KEY_RE = re.compile(r'\Acephadm-talos/ledger-snapshot/(\d{20}-\d{10}-(?:takeover|op-[0-9a-f]{16}|m-[0-9a-f]{16}))/(manifest|[0-9a-f]{16}-\d{1,6})\Z')
# chunks are named <nonce>-<i>, the nonce one per publication: two writers of
# the same cut never write the same chunk key, and a manifest names only its own
# base64 characters per chunk: below the config-key entry limit
SNAPSHOT_CHUNK = 32 << 10
# a compaction cuts once more than this many entries follow the newest snapshot
COMPACT_AFTER = 1000
# the entries a snapshot covers are deleted no earlier than this after its publication
DELETE_AFTER = datetime.timedelta(minutes=10)
# the lookup table keeps a covered operation this long after the cut that covered it
LOOKUP_KEEP = datetime.timedelta(days=30)
# config-key gets (and removals) in flight at once while reading by key
BATCH = 8


class LedgerError(Exception):
    pass


class OutcomeUnknown(LedgerError):
    """The mons did not answer a write: the operation may exist."""


class SnapshotDamaged(LedgerError):
    """A snapshot's manifest exists but its chunks do not verify."""


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
        if kind not in MODULE_KINDS:
            raise LedgerError('module entry %s' % key)
        if kind in NOOUT_KINDS:
            if 'of' in e and (kind in NO_OF_KINDS or not isinstance(e['of'], str) or not OP_RE.match(e['of'])):
                raise LedgerError('module entry %s' % key)
        elif not isinstance(e.get('of'), str) or not OP_RE.match(e['of']):
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
        if kind in ('drain_done',) + NOOUT_KINDS and daemon is not None:
            raise LedgerError('%s entry %s' % (kind, key))
        if kind in ('noout_intent', 'noout') and not (isinstance(e.get('reason'), str) and REASON_RE.match(e['reason'])
                                                      and type(e.get('on')) is bool and (kind == 'noout' or type(e.get('prior')) is bool)):
            raise LedgerError('%s entry %s' % (kind, key))
        if kind == 'host_down' and not (isinstance(e.get('boot'), str) and BOOT_RE.match(e['boot'])
                                        and isinstance(e.get('at'), str) and ISO_RE.match(e['at'])):
            raise LedgerError('host_down entry %s' % key)
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
    if kind == 'drain_host':
        if daemon is not None or type(e.get('zap')) is not bool or set(e) - {'version', 'id', 'kind', 'host', 'zap', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
            raise LedgerError('operation entry %s' % key)
        return e
    if kind in DRAIN_CONTROLS:
        if daemon is not None or not isinstance(e.get('drain'), str) or not OP_RE.match(e['drain']) \
                or set(e) - {'version', 'id', 'kind', 'host', 'drain', 'gid', 'epoch', 'seq', 'request', 'inputs'}:
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


def takeover_cutoffs(entries: Dict[str, Dict[str, Any]], epoch: int, snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, int]:
    """The cutoffs of a new takeover entry at epoch: the highest sequence number
    of every incarnation since the newest valid takeover entry before epoch.
    Entries are those above the snapshot, if any; its covered incarnations
    count as seen."""
    valid = {k for k, _ in executable(entries)}
    since = snapshot['since'] if snapshot else -1
    for k, e in entries.items():
        if e['id'] == 'takeover' and e['epoch'] < epoch and _valid_takeover(entries, k):
            since = max(since, e['epoch'])
    cut: Dict[str, int] = {}
    for gid, (ep, seq) in (snapshot['covered'] if snapshot else {}).items():
        if since <= ep < epoch:
            cut[gid] = max(cut.get(gid, 0), seq)
    for k, e in entries.items():
        if since <= e['epoch'] < epoch and (k in valid or e['id'] == 'takeover'):
            cut[str(e['gid'])] = max(cut.get(str(e['gid']), 0), e['seq'])
    return cut


def snapshot_valid(snapshot: Dict[str, Any], above: Dict[str, Dict[str, Any]]) -> bool:
    """Whether a snapshot is valid against the entries above its key (their
    takeover entries suffice): the first valid takeover entry above it saw
    every sequence number it covered. A stale predecessor's snapshot that
    folded its own late writes is not."""
    takeovers = sorted((e['epoch'], k) for k, e in above.items() if e['id'] == 'takeover' and _valid_takeover(above, k))
    if not takeovers:
        return True
    first = above[takeovers[0][1]]
    return all(first['cutoffs'].get(gid, -1) >= seq for gid, (ep, seq) in snapshot['covered'].items() if ep < first['epoch'])


def cut_key(entries: Dict[str, Dict[str, Any]], states: Dict[str, str], applied: str, pinned: Set[str]) -> Optional[str]:
    """The largest key K among entries (those above the newest snapshot) such
    that every operation entry at or below K is finished (a terminal journal
    state), at or below applied (the published ledger_applied) and not
    pinned, and every module entry at or below K names such an operation or
    one a snapshot covered already. Takeover entries and void entries do not
    hold a cut back. None when nothing can be cut."""
    valid = {k for k, _ in executable(entries)}
    ids = {e['id'] for e in entries.values()}
    ok: Set[str] = set()
    last = None
    for k in sorted(entries):
        e = entries[k]
        if e['id'] == 'takeover' or k not in valid:
            last = k
        elif e['id'].startswith('m-'):
            if e.get('of') is not None and e['of'] not in ok and e['of'] in ids:
                break
            last = k
        elif states.get(e['id']) in TERMINAL and k <= applied and e['id'] not in pinned:
            ok.add(e['id'])
            last = k
        else:
            break
    return last


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

    def __init__(self, inventory: Dict[str, Any], entries: Iterable[Tuple[str, Dict[str, Any]]] = (),
                 snapshot: Optional[Dict[str, Any]] = None) -> None:
        if snapshot is not None:
            self._load(snapshot['state'])
        else:
            self._baseline(inventory)
        positions = self.positions
        offset = self.count
        n = offset - 1
        for n, (_, e) in enumerate(entries, offset):
            self._apply(n, e, positions)
        self.count = n + 1

    # the fold's state, as a snapshot keeps it: sets as sorted lists, tuples as lists
    def state(self, keep: Set[str]) -> Dict[str, Any]:
        """The fold's state for a snapshot, with the positions of the
        operations in keep (those a later entry may still name)."""
        return json.loads(json.dumps({
            'hosts': self.hosts, 'daemons': self.daemons, 'generations': {k: list(v) for k, v in self.generations.items()},
            'uuids': self.uuids, 'creations': self.creations, 'maintenance': sorted(self.maintenance), 'upgrade': self.upgrade,
            'rgw_certs': self.rgw_certs, 'mgr_renewals': self.mgr_renewals, 'mgr_retired': sorted(self.mgr_retired),
            'agent_renewals': self.agent_renewals, 'agent_retired': sorted(self.agent_retired), 'agent_upgrade': self.agent_upgrade,
            'cli_rgw': self.cli_rgw, 'vip': self.vip, 'ingress': self.ingress, 'vrrp_secret': self.vrrp_secret, 'rgw_port': self.rgw_port,
            'renewals_done': sorted(self.renewals_done), 'retired_by': sorted(self.retired_by),
            'draining': self.draining, 'noout': self.noout, 'down': self.down,
            'positions': {o: n for o, n in self.positions.items() if o in keep}, 'count': self.count}))

    def _load(self, st: Dict[str, Any]) -> None:
        st = copy.deepcopy(st)
        self.hosts, self.daemons, self.uuids, self.creations = st['hosts'], st['daemons'], st['uuids'], st['creations']
        self.generations = {k: (v[0], v[1]) for k, v in st['generations'].items()}
        self.maintenance = set(st['maintenance'])
        self.upgrade, self.rgw_certs = st['upgrade'], st['rgw_certs']
        self.mgr_renewals, self.mgr_retired = st['mgr_renewals'], set(st['mgr_retired'])
        self.agent_renewals, self.agent_retired, self.agent_upgrade = st['agent_renewals'], set(st['agent_retired']), st['agent_upgrade']
        self.cli_rgw, self.vip, self.ingress, self.vrrp_secret, self.rgw_port = st['cli_rgw'], st['vip'], st['ingress'], st['vrrp_secret'], st['rgw_port']
        self.renewals_done, self.retired_by = set(st['renewals_done']), set(st['retired_by'])
        self.draining, self.noout, self.down = st['draining'], st['noout'], st['down']
        self.positions = st['positions']
        self.count = st['count']

    def _baseline(self, inventory: Dict[str, Any]) -> None:
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
        # the RGWs' port: the newest RGW add's (None: the CLI's, in its cluster record)
        self.rgw_port: Optional[int] = None
        # renewals with their done entry, and operations with a retire entry:
        # their journal's roll records are no longer read (plan 04, step 4)
        self.renewals_done: Set[str] = set()
        self.retired_by: Set[str] = set()
        # hosts draining (plan 04, step 5): {'op', 'zap'} from the drain's
        # acceptance until its drain_done entry or a drain_stop's acceptance
        self.draining: Dict[str, Dict[str, Any]] = {}
        # the noout ownership by host: the reasons the module holds the flag
        # for, whether the operator owns it (set before the first reason, or
        # handed over), and the intent of a change not completed yet
        # {'reason', 'on', 'prior'}; the CLI's maintenance noout is the module's
        self.noout: Dict[str, Dict[str, Any]] = {
            h['name']: {'reasons': ['maintenance'], 'operator': False, 'intent': None}
            for h in inventory['hosts'] if h.get('maintenance') and h.get('noout')}
        # unplanned stops by host (a Talos reboot or shutdown its agent
        # reported): {'boot', 'at', 'held'}, held once its reason was added
        self.down: Dict[str, Dict[str, Any]] = {}
        # each operation's place in the executable entries, and how many there were
        self.positions: Dict[str, int] = {}
        self.count: int = 0
        for d in inventory['daemons']:
            if d.get('daemon_id'):
                name = '%s.%s' % (d['daemon_type'], d['daemon_id'])
                self.daemons[name], self.generations[name] = d['host'], ('cli', True)
                if d.get('osd_uuid'):
                    self.uuids[name] = d['osd_uuid']

    def _apply(self, n: int, e: Dict[str, Any], positions: Dict[str, int]) -> None:
        positions[e['id']] = n
        kind = e['kind']
        if kind in NOOUT_KINDS or kind in ('drain_host', 'drain_done') + DRAIN_CONTROLS:
            self._apply_host(e)
            return
        if kind == 'add_daemon' and e['daemon'].startswith('rgw.'):
            self.rgw_port = int(e['port'])
        if kind == 'retire':
            self.retired_by.add(e['of'])
        elif kind in ('mgr_cert_done', 'agent_cert_done'):
            self.renewals_done.add(e['of'])
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
            for m in (self.draining, self.noout, self.down):
                m.pop(e['host'], None)
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

    def _apply_host(self, e: Dict[str, Any]) -> None:
        """A drain's entries and the noout ownership's (plan 04, step 5)."""
        kind, host = e['kind'], e['host']
        if host not in self.hosts:
            return
        if kind == 'drain_host':
            self.draining.setdefault(host, {'op': e['id'], 'zap': e['zap']})
        elif kind == 'drain_stop' or kind == 'drain_done':
            if self.draining.get(host, {}).get('op') == e.get('drain', e.get('of')):
                del self.draining[host]
        elif kind == 'host_down':
            self.down[host] = {'boot': e['boot'], 'at': e['at'], 'held': False}
        elif kind == 'host_up':
            self.down.pop(host, None)
        elif kind in ('noout_intent', 'noout', 'noout_keep'):
            st = self.noout.setdefault(host, {'reasons': [], 'operator': False, 'intent': None})
            it = st['intent']
            if kind == 'noout_intent':
                st['intent'] = {'reason': e['reason'], 'on': e['on'], 'prior': e['prior']}
            elif kind == 'noout_keep':
                st['reasons'], st['operator'], st['intent'] = [], False, None
            else:
                ours = it is not None and it['reason'] == e['reason'] and it['on'] == e['on']
                if e['on']:
                    # the first reason: the flag is the operator's if the intent saw it set
                    if not st['reasons']:
                        st['operator'] = bool(ours and it['prior'])
                    st['reasons'] = sorted(set(st['reasons']) | {e['reason']})
                    if e['reason'] == UNPLANNED and host in self.down:
                        self.down[host]['held'] = True
                else:
                    st['reasons'] = [r for r in st['reasons'] if r != e['reason']]
                    if not st['reasons']:
                        st['operator'] = False
                if ours:
                    st['intent'] = None
            if not st['reasons'] and st['intent'] is None:
                del self.noout[host]

    def noout_reasons(self, host: str) -> List[str]:
        return list((self.noout.get(host) or {}).get('reasons') or [])

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


def _iso(t: datetime.datetime) -> str:
    return t.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _parse_iso(v: Any) -> datetime.datetime:
    t = datetime.datetime.fromisoformat(str(v).replace('Z', '+00:00'))
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


# mon(cmd, deadline[, reduce]) -> (r, out, outs), or None without an answer
Mon = Callable[..., Optional[Tuple[int, str, str]]]
# batch(cmds, deadline) -> one answer (or None) per command, sent together
Batch = Callable[[List[Dict[str, Any]], float], List[Optional[Tuple[int, str, str]]]]


class Ledger:
    """This incarnation's view of the ledger: the newest valid snapshot it found
    when it captured, the entries above it, plus what it appended since.
    Entries a stale module appends after this module's takeover entry are void
    for every reader, so nothing is re-read."""

    def __init__(self, mon: Mon, gid: int, epoch: int, batch: Optional[Batch] = None) -> None:
        self.mon = mon
        self.batch = batch or (lambda cmds, deadline: [mon(c, deadline) for c in cmds])
        self.gid, self.epoch = gid, epoch
        self.lock = threading.Lock()
        self.entries: Dict[str, Dict[str, Any]] = {}  # the entries above the snapshot
        self.seq = 0
        self.pending: Optional[Tuple[str, str]] = None  # an append whose outcome is unknown
        self.ready = False
        # the snapshot the entries follow (its content), its key (relative to
        # LEDGER_PREFIX) and when it was published
        self.snapshot: Optional[Dict[str, Any]] = None
        self.snapshot_key = ''
        self.snapshot_at: Optional[datetime.datetime] = None

    def _set(self, key: str, value: str) -> None:
        res = self.mon({'prefix': 'config-key set', 'key': key, 'val': value}, WRITE_DEADLINE)
        if res is None:
            raise OutcomeUnknown('no answer from the mons for %s' % key)
        if res[0] != 0:
            raise LedgerError('the mons refused %s: %s' % (key, res[2]))

    def _list(self, prefix: str) -> List[str]:
        try:
            return sorted(revocation.list_keys(self.mon, prefix))
        except revocation.CRLError as e:
            raise LedgerError(str(e))

    def _get_many(self, keys: List[str]) -> Dict[str, Optional[str]]:
        """config-key get of keys in batches: the value, or None for a key that
        does not exist; raises unless every key was answered."""
        out: Dict[str, Optional[str]] = {}
        for o in range(0, len(keys), BATCH):
            part = keys[o:o + BATCH]
            res = self.batch([{'prefix': 'config-key get', 'key': k} for k in part], WRITE_DEADLINE)
            for k, r in zip(part, res):
                if r is None or r[0] not in (0, -2):
                    raise LedgerError('cannot read %s' % k)
                out[k] = r[1] if r[0] == 0 else None
        if len(out) != len(keys):
            raise LedgerError('the ledger was not read whole')
        return out

    def remove_keys(self, keys: List[str]) -> None:
        for o in range(0, len(keys), BATCH):
            part = keys[o:o + BATCH]
            res = self.batch([{'prefix': 'config-key rm', 'key': k} for k in part], WRITE_DEADLINE)
            for k, r in zip(part, res):
                if r is None or r[0] not in (0, -2):
                    raise LedgerError('cannot remove %s' % k)

    def _read_entries(self, keys: List[str]) -> Dict[str, Dict[str, Any]]:
        """Every listed ledger key read by key; a key gone meanwhile fails the read."""
        found: Dict[str, Dict[str, Any]] = {}
        for k, v in self._get_many(keys).items():
            if v is None:
                raise LedgerError('ledger entry %s went away while the ledger was read' % k)
            try:
                found[k] = check_entry(k, v)
            except LedgerError:
                continue  # not a module's entry: no authority
        return found

    def _snapshots(self) -> Dict[str, Set[str]]:
        """The snapshot keys by cut: K -> the names below it (manifest, chunk numbers)."""
        out: Dict[str, Set[str]] = {}
        for k in self._list(SNAPSHOT_PREFIX):
            m = SNAPSHOT_KEY_RE.match(k)
            if m:
                out.setdefault(m.group(1), set()).add(m.group(2))
        return out

    def _read_snapshot(self, cut: str) -> Optional[Tuple[Dict[str, Any], datetime.datetime]]:
        """A snapshot's content and publication time; None without a manifest;
        SnapshotDamaged when its chunks do not verify."""
        base = SNAPSHOT_PREFIX + cut + '/'
        raw = self._get_many([base + 'manifest'])[base + 'manifest']
        if raw is None:
            return None
        try:
            m = json.loads(raw)
            chunks, sums = m['chunks'], m['sha256']
            if m.get('schema') != SNAPSHOT_SCHEMA or m.get('key') != cut or not isinstance(chunks, list) or not chunks \
                    or not isinstance(sums, list) or len(sums) != len(chunks) or not isinstance(chunks[0], str) \
                    or any(c != chunks[0][:-1] + str(i) for i, c in enumerate(chunks)) or not SNAPSHOT_KEY_RE.match(chunks[0]) \
                    or not chunks[0].startswith(base) or not chunks[0].endswith('-0'):
                raise ValueError('malformed manifest')
            at = _parse_iso(m['at'])
            got = self._get_many(chunks)
            parts = []
            for c, h in zip(chunks, sums):
                v = got[c]
                if v is None or hashlib.sha256(v.encode()).hexdigest() != h:
                    raise ValueError('chunk %s does not match its manifest' % c)
                parts.append(v)
            data = base64.b64decode(''.join(parts), validate=True)
            if len(data) != m['size']:
                raise ValueError('size')
            content = json.loads(data)
            if not isinstance(content, dict) or content.get('version') != SNAPSHOT_SCHEMA or content.get('key') != cut \
                    or not isinstance(content.get('covered'), dict) or type(content.get('since')) is not int or not isinstance(content.get('state'), dict) \
                    or not isinstance(content.get('lookup'), list):
                raise ValueError('malformed content')
        except LedgerError:
            raise
        except (ValueError, KeyError, TypeError) as e:
            raise SnapshotDamaged('ledger snapshot %s: %s' % (cut, e))
        return content, at

    def open(self) -> None:
        """Read the newest valid snapshot and the ledger above it, and write
        this incarnation's takeover entry."""
        with self.lock:
            if self.ready:
                return
            if self.pending is None:
                keys = [k for k in self._list(LEDGER_PREFIX) if k.startswith(LEDGER_PREFIX)]
                snaps = self._snapshots()
                raw: Dict[str, Dict[str, Any]] = {}
                read_above: Optional[str] = None  # every key above it is read

                def ensure(bound: str) -> None:
                    nonlocal read_above
                    todo = [k for k in keys if k > bound and (read_above is None or k <= read_above)]
                    raw.update(self._read_entries(todo))
                    read_above = bound

                chosen: Optional[Tuple[str, Dict[str, Any], datetime.datetime]] = None
                damaged: List[str] = []
                for cut in sorted((c for c, names in snaps.items() if 'manifest' in names), reverse=True):
                    try:
                        got = self._read_snapshot(cut)
                    except SnapshotDamaged:
                        damaged.append(cut)
                        continue
                    if got is None:
                        continue
                    ensure(LEDGER_PREFIX + cut)
                    if snapshot_valid(got[0], {k: e for k, e in raw.items() if k > LEDGER_PREFIX + cut}):
                        chosen = (cut, got[0], got[1])
                        break
                if chosen is None and damaged:
                    # the entries it covered may be deleted: no fold can be trusted
                    raise LedgerError('ledger snapshot %s is damaged and no older one is valid' % damaged[0])
                if chosen is None:
                    ensure('')
                    self.snapshot, self.snapshot_key, self.snapshot_at = None, '', None
                else:
                    self.snapshot_key, self.snapshot, self.snapshot_at = chosen
                base = LEDGER_PREFIX + self.snapshot_key if self.snapshot else ''
                self.entries = {k: e for k, e in raw.items() if k > base}
                cut = takeover_cutoffs(self.entries, self.epoch, self.snapshot)
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
        """The executable entries above the snapshot, in order."""
        with self.lock:
            return executable(dict(self.entries))

    def view(self) -> Tuple[Optional[Dict[str, Any]], List[Tuple[str, Dict[str, Any]]]]:
        """The snapshot and the executable entries above it, read together."""
        with self.lock:
            return self.snapshot, executable(dict(self.entries))

    def fold(self, inventory: Dict[str, Any]) -> Fold:
        snap, ex = self.view()
        return Fold(inventory, ex, snap)

    def covered(self) -> Callable[[str], bool]:
        """Whether an operation id is covered by the snapshot: an operation's
        id with no executable entry above it (finished by definition)."""
        with self.lock:
            if self.snapshot is None:
                return lambda ident: False
            above = frozenset(e['id'] for _, e in executable(dict(self.entries)))
        return lambda ident: OP_RE.match(ident) is not None and ident not in above

    def lookup(self, ident: Optional[str] = None, request: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """A covered operation's row of the snapshot's lookup table, by id or by request uuid."""
        with self.lock:
            rows = (self.snapshot or {}).get('lookup', [])
        for r in rows:
            if ident is not None and r.get('id') == ident or request is not None and r.get('request') == request:
                return dict(r)
        return None

    # --- compaction (plan 04, step 4) --------------------------------------

    def cut(self, inventory: Dict[str, Any], states: Dict[str, str], applied: str, pinned: Set[str],
            now: datetime.datetime) -> Optional[Tuple[str, Dict[str, Any]]]:
        """The next snapshot (its key and content), None when nothing can be cut."""
        with self.lock:
            entries, snap = dict(self.entries), self.snapshot
        k = cut_key(entries, states, applied, pinned)
        if k is None:
            return None
        ex = executable(entries)
        valid = {x for x, _ in ex}
        below = [(x, e) for x, e in ex if x <= k]
        fold = Fold(inventory, below, snap)
        # the incarnations covered since the newest takeover entry at or below k
        since = snap['since'] if snap else -1
        for x, e in entries.items():
            if x <= k and e['id'] == 'takeover' and _valid_takeover(entries, x):
                since = max(since, e['epoch'])
        covered = {g: list(v) for g, v in (snap['covered'] if snap else {}).items() if v[0] >= since}
        for x, e in entries.items():
            if x <= k and e['epoch'] >= since and (x in valid or e['id'] == 'takeover'):
                g = str(e['gid'])
                if g not in covered or e['seq'] > covered[g][1]:
                    covered[g] = [e['epoch'], e['seq']]
        # positions a later entry may still name: an operation's module entries
        # can follow the cut, and a live RGW certificate's issuer
        keep = {e['of'] for x, e in entries.items() if x > k and e['id'].startswith('m-') and e.get('of')}
        keep |= {cid.split('/')[1] for cid, c in fold.rgw_certs.items() if cid != 'cli' and not c['retired']}
        rows = [r for r in (snap or {}).get('lookup', []) if _parse_iso(r['at']) > now - LOOKUP_KEEP]
        for x, e in below:
            if e['id'].startswith('m-'):
                continue
            row = {f: e[f] for f in ('id', 'kind', 'host', 'daemon', 'request', 'inputs') if f in e}
            row.update(key=x[len(LEDGER_PREFIX):], state=states.get(e['id']), at=_iso(now))
            rows.append(row)
        rel = k[len(LEDGER_PREFIX):]
        return rel, {'version': SNAPSHOT_SCHEMA, 'key': rel, 'since': since, 'covered': covered, 'state': fold.state(keep),
                     'lookup': rows, 'gid': self.gid, 'epoch': self.epoch}

    def publish(self, cut: str, content: Dict[str, Any], now: datetime.datetime) -> bool:
        """Publish a snapshot once (chunks, then the manifest) and read the
        ledger above it from then on. A manifest already there is never
        replaced: it is taken if it verifies and is valid. True once this
        ledger follows the snapshot."""
        base = SNAPSHOT_PREFIX + cut + '/'
        try:
            there = self._read_snapshot(cut)
        except SnapshotDamaged:
            return False
        if there is not None:
            content, now = there
            with self.lock:
                above = {k: e for k, e in self.entries.items() if k > LEDGER_PREFIX + cut}
            if not snapshot_valid(content, above):
                return False
        else:
            enc = base64.b64encode(json.dumps(content, sort_keys=True).encode()).decode()
            parts = [enc[o:o + SNAPSHOT_CHUNK] for o in range(0, len(enc), SNAPSHOT_CHUNK)]
            nonce = secrets.token_hex(8)
            names = ['%s%s-%d' % (base, nonce, i) for i in range(len(parts))]
            for k, v in zip(names, parts):
                self._set(k, v)
            manifest = {'schema': SNAPSHOT_SCHEMA, 'key': cut, 'gid': self.gid, 'epoch': self.epoch, 'at': _iso(now),
                        'chunks': names, 'sha256': [hashlib.sha256(v.encode()).hexdigest() for v in parts],
                        'size': len(base64.b64decode(enc))}
            self._set(base + 'manifest', json.dumps(manifest, sort_keys=True))
            now = _parse_iso(manifest['at'])
        with self.lock:
            if self.snapshot is not None and self.snapshot_key >= cut:
                return self.snapshot_key == cut
            self.snapshot, self.snapshot_key, self.snapshot_at = content, cut, now
            self.entries = {k: e for k, e in self.entries.items() if k > LEDGER_PREFIX + cut}
        return True

    def delete(self, now: datetime.datetime, active: Callable[[], bool], prune: Callable[[Callable[[str], bool]], None]) -> bool:
        """Delete what the snapshot made redundant, at least DELETE_AFTER after
        its publication, while this module is confirmed active right before
        (active: a fresh mgr map) and the snapshot is still the highest valid
        one: older snapshots (manifest first), then prune(covered) (the
        journals), then the entries at or below its key. True when it ran."""
        with self.lock:
            snap, cut, at = self.snapshot, self.snapshot_key, self.snapshot_at
        if snap is None or at is None or now - at < DELETE_AFTER:
            return False
        if not active():
            return False
        # the stored snapshot, verified again (manifest and every chunk) and the
        # one this module follows: another writer of the same cut may have
        # replaced or damaged it since
        try:
            stored = self._read_snapshot(cut)
        except SnapshotDamaged:
            return False
        if stored is None or json.dumps(stored[0], sort_keys=True) != json.dumps(snap, sort_keys=True):
            return False
        snaps = self._snapshots()
        keys = [k for k in self._list(LEDGER_PREFIX) if k.startswith(LEDGER_PREFIX)]
        # the takeover entries above it, read now: a later takeover that this
        # snapshot's covered writes are void for makes it invalid
        takeovers = self._read_entries([k for k in keys if k > LEDGER_PREFIX + cut and k.endswith('-takeover')])
        if not snapshot_valid(snap, takeovers):
            return False
        for newer in sorted((c for c, names in snaps.items() if c > cut and 'manifest' in names), reverse=True):
            try:
                got = self._read_snapshot(newer)
            except SnapshotDamaged:
                continue
            if got is not None and snapshot_valid(got[0], {k: e for k, e in takeovers.items() if k > LEDGER_PREFIX + newer}):
                return False  # a newer valid snapshot: this module is not the one to delete
        for older in sorted(c for c in snaps if c < cut):
            names = snaps[older]
            base = SNAPSHOT_PREFIX + older + '/'
            # the manifest answered before any chunk goes: a reader never finds a
            # manifest whose chunks are partly gone
            if 'manifest' in names:
                self.remove_keys([base + 'manifest'])
            self.remove_keys(sorted(base + n for n in names if n != 'manifest'))
        prune(self.covered())
        self.remove_keys([k for k in keys if k <= LEDGER_PREFIX + cut])
        return True
