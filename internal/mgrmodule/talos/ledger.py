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
from typing import Any, Callable, Dict, List, Optional, Tuple

LEDGER_PREFIX = 'cephadm-talos/ledger/'
ENTRY_VERSION = 1
KEY_RE = re.compile(r'\A(\d{20})-(\d{10})-(takeover|op-[0-9a-f]{16}|m-[0-9a-f]{16})\Z')
OP_RE = re.compile(r'\Aop-[0-9a-f]{16}\Z')
# kinds an operation entry may have; ADDS and REMOVES change the fold
KINDS = ('restart', 'redeploy', 'add_daemon', 'remove_daemon', 'remove_host')
# the module's own entries (ids m-<hex>), which carry out a removal: close a
# daemon's generation, retire the daemon, retire a host
MODULE_KINDS = ('close', 'retire', 'retire_host')
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
    if e['seq'] < 1 or not ok_host:
        raise LedgerError('entry %s' % key)
    if e['id'].startswith('m-'):
        if kind not in MODULE_KINDS or not isinstance(e.get('of'), str) or not OP_RE.match(e['of']) \
                or (kind != 'retire_host' and not ok_daemon):
            raise LedgerError('module entry %s' % key)
        return e
    if kind not in KINDS or (e.get('request') is not None and not (isinstance(e['request'], str) and UUID_RE.match(e['request']))):
        raise LedgerError('operation entry %s' % key)
    if kind == 'remove_host':
        if daemon is not None:
            raise LedgerError('operation entry %s' % key)
        return e
    if not ok_daemon:
        raise LedgerError('operation entry %s' % key)
    t, i = daemon.split('.', 1)
    # mon and mgr ids are their host's name
    if kind == 'add_daemon' and (t not in ('mon', 'mgr') or i != host):
        raise LedgerError('operation entry %s' % key)
    if kind == 'remove_daemon' and (t != 'mgr' or i != host):
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
    entry the host."""

    def __init__(self, inventory: Dict[str, Any], entries: List[Tuple[str, Dict[str, Any]]] = ()) -> None:
        self.hosts: Dict[str, str] = {h['name']: h['addr'] for h in inventory['hosts']}
        self.daemons: Dict[str, str] = {}  # "<type>.<id>" -> host
        self.generations: Dict[str, Tuple[str, bool]] = {}  # "<type>.<id>" -> (generation, open)
        for d in inventory['daemons']:
            if d.get('daemon_id'):
                name = '%s.%s' % (d['daemon_type'], d['daemon_id'])
                self.daemons[name], self.generations[name] = d['host'], ('cli', True)
        for _, e in entries:
            kind = e['kind']
            if kind == 'add_daemon' and e['host'] in self.hosts:
                self.daemons[e['daemon']], self.generations[e['daemon']] = e['host'], (e['id'], True)
            elif kind == 'close' and e['daemon'] in self.generations:
                self.generations[e['daemon']] = (self.generations[e['daemon']][0], False)
            elif kind == 'retire':
                self.daemons.pop(e['daemon'], None)
                self.generations.pop(e['daemon'], None)
            elif kind == 'retire_host' and not any(h == e['host'] for h in self.daemons.values()):
                self.hosts.pop(e['host'], None)

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

    def secret_allowed(self, name: str, host: Optional[str]) -> bool:
        """Whether `secret get` may release a secret (host for a host's keys)."""
        if host is not None:
            return self.has('mgr', host=host)
        if name == 'rgw/server.key':
            return self.has('rgw')
        if name == 'rgw/vrrp':
            return self.has('keepalived')
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
