"""Tests of ledger.py, the module's record of accepted operations (plan 03,
step 6b, part 3). Run with hack/mgrmodule-test.sh."""
import json
import unittest

import test_talos  # noqa: F401  (stubs ceph_module before the talos package is imported)

from talos import ledger as lg


def op(epoch, gid, seq, n=0):
    ident = 'op-%016x' % (epoch * 1000 + seq + n)
    e = {'version': 1, 'id': ident, 'kind': 'restart', 'daemon': 'mgr.h1', 'host': 'h1', 'gid': gid, 'epoch': epoch, 'seq': seq}
    return lg.entry_key(epoch, seq, ident), e


def takeover(epoch, gid, cutoffs):
    e = {'version': 1, 'id': 'takeover', 'kind': 'takeover', 'gid': gid, 'epoch': epoch, 'seq': 0, 'cutoffs': {str(k): v for k, v in cutoffs.items()}}
    return lg.entry_key(epoch, 0, 'takeover'), e


def ids(entries):
    return [(e['gid'], e['seq']) for _, e in lg.executable(dict(entries))]


class ExecutableTest(unittest.TestCase):
    def test_order_and_cutoffs(self):
        a1, a2, a3 = op(5, 10, 1), op(5, 10, 2), op(5, 10, 3)
        b0, b1 = takeover(7, 20, {10: 2}), op(7, 20, 1)
        # A's third append landed after B's takeover entry: void for every reader
        self.assertEqual(ids([a1, a2, a3, b0, b1]), [(10, 1), (10, 2), (20, 1)])
        # without a later takeover entry, everything of A counts
        self.assertEqual(ids([a1, a2, a3]), [(10, 1), (10, 2), (10, 3)])

    def test_a_delayed_takeover_entry_changes_nothing(self):
        # B saw A up to 1, but its takeover entry is late; C saw A up to 2 and ran it
        a1, a2 = op(5, 10, 1), op(5, 10, 2)
        c0, c1 = takeover(9, 30, {10: 2}), op(9, 30, 1)
        before = ids([a1, a2, c0, c1])
        b0 = takeover(7, 20, {10: 1})  # lands after C's takeover entry: C does not name B
        self.assertEqual(ids([a1, a2, b0, c0, c1]), before)
        self.assertEqual(before, [(10, 1), (10, 2), (30, 1)])

    def test_a_valid_takeover_governs_the_incarnations_before_it(self):
        a1, a2 = op(5, 10, 1), op(5, 10, 2)
        b0, b1, b2 = takeover(7, 20, {10: 1}), op(7, 20, 1), op(7, 20, 2)
        c0 = takeover(9, 30, {20: 1})
        # A is cut by B (the first later valid takeover), B by C
        self.assertEqual(ids([a1, a2, b0, b1, b2, c0]), [(10, 1), (20, 1)])

    def test_takeover_cutoffs(self):
        a1, a2 = op(5, 10, 1), op(5, 10, 2)
        b0, b1 = takeover(7, 20, {10: 2}), op(7, 20, 1)
        entries = {k: e for k, e in (a1, a2, b0, b1)}
        # since B's takeover entry: B itself, not A (B governs A)
        self.assertEqual(lg.takeover_cutoffs(entries, 9), {'20': 1})
        self.assertEqual(lg.takeover_cutoffs({k: e for k, e in (a1, a2)}, 9), {'10': 2})
        self.assertEqual(lg.takeover_cutoffs({}, 9), {})

    def test_entries_must_match_their_keys(self):
        k, e = op(5, 10, 1)
        lg.check_entry(k, json.dumps(e))
        for bad in (dict(e, seq=2), dict(e, kind='rm'), dict(e, daemon='client.admin'), dict(e, host='../x'), dict(e, version=2),
                    dict(e, id='op-1'), dict(e, request='nope')):
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(bad))
        with self.assertRaises(lg.LedgerError):
            lg.check_entry('cephadm-talos/ledger/x', json.dumps(e))
        tk, te = takeover(7, 20, {10: 1})
        lg.check_entry(tk, json.dumps(te))
        with self.assertRaises(lg.LedgerError):
            lg.check_entry(tk, json.dumps(dict(te, cutoffs={'x': 1})))


class Mons:
    """config-key ls (reduced), get, set and rm over a dict, with the module's
    output limit; `silent` writes are stored but not answered."""

    LIMIT = 256 << 10  # bridge.MAX_OUTPUT

    def __init__(self, kv=None):
        self.kv = dict(kv or {})
        self.silent = 0
        self.sets = []
        self.gets = 0
        self.rms = []

    def __call__(self, cmd, deadline, reduce=None):
        if cmd['prefix'] == 'config-key dump':
            out = json.dumps({k: v for k, v in self.kv.items() if k.startswith(cmd['key'])})
            return (-27, '', '') if len(out) > self.LIMIT else (0, out, '')
        if cmd['prefix'] == 'config-key ls':
            out = json.dumps(sorted(self.kv))
            if reduce is not None:
                out = reduce(out)
            return (-27, '', '') if len(out) > self.LIMIT else (0, out, '')
        if cmd['prefix'] == 'config-key get':
            self.gets += 1
            if cmd['key'] not in self.kv:
                return -2, '', 'ENOENT'
            return 0, self.kv[cmd['key']], ''
        if cmd['prefix'] == 'config-key rm':
            self.rms.append(cmd['key'])
            self.kv.pop(cmd['key'], None)
            return 0, '', ''
        if cmd['prefix'] == 'config-key set':
            self.sets.append(cmd['key'])
            self.kv[cmd['key']] = cmd['val']
            if self.silent:
                self.silent -= 1
                return None
            return 0, '', ''
        raise AssertionError(cmd)


class LedgerTest(unittest.TestCase):
    def test_open_writes_the_takeover_entry_first(self):
        k, e = op(5, 10, 1)
        mons = Mons({k: json.dumps(e), 'cephadm-talos/ledger/garbage': 'x'})
        led = lg.Ledger(mons, 20, 7)
        with self.assertRaises(lg.LedgerError):
            led.append({'id': 'op-%016x' % 1, 'kind': 'restart', 'daemon': 'mgr.h1', 'host': 'h1'})
        led.open()
        self.assertEqual(mons.sets, [lg.entry_key(7, 0, 'takeover')])
        self.assertEqual(json.loads(mons.kv[mons.sets[0]])['cutoffs'], {'10': 1})
        key, entry = led.append({'id': 'op-%016x' % 1, 'kind': 'restart', 'daemon': 'mgr.h1', 'host': 'h1'})
        self.assertEqual((entry['gid'], entry['epoch'], entry['seq']), (20, 7, 1))
        self.assertEqual([x['id'] for _, x in led.executable()], [e['id'], 'op-%016x' % 1])

    def test_an_unknown_append_is_settled_before_the_next(self):
        led = lg.Ledger(Mons(), 20, 7)
        led.open()
        led.mon.silent = 1
        with self.assertRaises(lg.OutcomeUnknown):
            led.append({'id': 'op-%016x' % 1, 'kind': 'restart', 'daemon': 'mgr.h1', 'host': 'h1'})
        # the same key with the same content first, then the next with the next sequence
        _, entry = led.append({'id': 'op-%016x' % 2, 'kind': 'redeploy', 'daemon': 'mgr.h1', 'host': 'h1'})
        k1 = lg.entry_key(7, 1, 'op-%016x' % 1)
        self.assertEqual(led.mon.sets, [lg.entry_key(7, 0, 'takeover'), k1, k1, lg.entry_key(7, 2, 'op-%016x' % 2)])
        self.assertEqual(entry['seq'], 2)

    def test_settle_writes_a_pending_append_without_a_new_one(self):
        led = lg.Ledger(Mons(), 20, 7)
        led.open()
        led.mon.silent = 2
        with self.assertRaises(lg.OutcomeUnknown):
            led.append({'id': 'op-%016x' % 1, 'kind': 'restart', 'daemon': 'mgr.h1', 'host': 'h1'})
        with self.assertRaises(lg.OutcomeUnknown):
            led.settle()
        led.settle()
        self.assertEqual([e['id'] for _, e in led.executable()], ['op-%016x' % 1])

    def test_a_refused_append_is_not_accepted(self):
        class Refusing(Mons):
            def __call__(self, cmd, deadline, reduce=None):
                if cmd['prefix'] == 'config-key set' and 'takeover' not in cmd['key']:
                    return -27, '', 'too big'
                return super().__call__(cmd, deadline, reduce)
        led = lg.Ledger(Refusing(), 20, 7)
        led.open()
        with self.assertRaises(lg.LedgerError):
            led.append({'id': 'op-%016x' % 1, 'kind': 'restart', 'daemon': 'mgr.h1', 'host': 'h1'})
        self.assertEqual(led.executable(), [])
        led.settle()  # nothing pending: a refusal is not written again
        self.assertEqual(led.executable(), [])


class FoldTest(unittest.TestCase):
    def test_rules(self):
        inv = {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}],
               'daemons': [{'daemon_type': 'mon', 'daemon_id': 'h1', 'host': 'h1'}, {'daemon_type': 'mgr', 'daemon_id': 'h1', 'host': 'h1'},
                           {'daemon_type': 'osd', 'daemon_id': '0', 'host': 'h1'}, {'daemon_type': 'osd', 'daemon_id': '', 'host': 'h1'}]}
        f = lg.Fold(inv)
        self.assertTrue(f.entity_allowed('mon.') and f.entity_allowed('mgr.h1'))
        for e in ('mgr.h2', 'osd.0', 'client.bootstrap-osd', 'client.rgw.h1', 'client.admin'):
            self.assertFalse(f.entity_allowed(e), e)
        self.assertTrue(f.secret_allowed('host/h1/mgr-server.key', 'h1'))
        for name, host in (('host/h2/mgr-server.key', 'h2'), ('rgw/server.key', None), ('rgw/vrrp', None)):
            self.assertFalse(f.secret_allowed(name, host), name)


if __name__ == '__main__':
    unittest.main()


def entry(epoch, seq, ident, **kw):
    e = dict({'version': 1, 'id': ident, 'gid': 10, 'epoch': epoch, 'seq': seq}, **kw)
    return lg.entry_key(epoch, seq, ident), e


class GenerationTest(unittest.TestCase):
    INV = {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}, {'name': 'h2', 'addr': '10.0.0.2'}],
           'daemons': [{'daemon_type': 'mgr', 'daemon_id': 'h1', 'host': 'h1'}]}

    def test_adds_close_and_retire(self):
        add = entry(5, 1, 'op-%016x' % 1, kind='add_daemon', daemon='mgr.h2', host='h2')
        rm = entry(5, 2, 'op-%016x' % 2, kind='remove_daemon', daemon='mgr.h2', host='h2')
        close = entry(5, 3, 'm-%016x' % 3, kind='close', of='op-%016x' % 2, daemon='mgr.h2', host='h2')
        retire = entry(5, 4, 'm-%016x' % 4, kind='retire', of='op-%016x' % 2, daemon='mgr.h2', host='h2')
        readd = entry(5, 5, 'op-%016x' % 5, kind='add_daemon', daemon='mgr.h2', host='h2')
        for k, e in (add, rm, close, retire, readd):
            lg.check_entry(k, json.dumps(e))
        f = lg.Fold(self.INV, [add])
        self.assertEqual((f.open_generation('mgr.h1'), f.open_generation('mgr.h2')), ('cli', 'op-%016x' % 1))
        # a removal counts from its retirement; closing ends the generation first
        self.assertEqual(lg.Fold(self.INV, [add, rm]).open_generation('mgr.h2'), 'op-%016x' % 1)
        f = lg.Fold(self.INV, [add, rm, close])
        self.assertTrue('mgr.h2' in f.daemons and f.open_generation('mgr.h2') is None)
        self.assertNotIn('mgr.h2', lg.Fold(self.INV, [add, rm, close, retire]).daemons)
        # a new add is a new generation: nothing of the old one counts
        self.assertEqual(lg.Fold(self.INV, [add, rm, close, retire, readd]).open_generation('mgr.h2'), 'op-%016x' % 5)

    def test_hosts_and_shapes(self):
        rmh = entry(5, 1, 'op-%016x' % 1, kind='remove_host', host='h2')
        reth = entry(5, 2, 'm-%016x' % 2, kind='retire_host', of='op-%016x' % 1, host='h2')
        lg.check_entry(*map(lambda x: x, (rmh[0], json.dumps(rmh[1]))))
        self.assertNotIn('h2', lg.Fold(self.INV, [rmh, reth]).hosts)
        self.assertIn('h2', lg.Fold(self.INV, [rmh]).hosts)
        # an add on a host that is gone does not count
        add = entry(5, 3, 'op-%016x' % 3, kind='add_daemon', daemon='mon.h2', host='h2')
        self.assertNotIn('mon.h2', lg.Fold(self.INV, [rmh, reth, add]).daemons)
        for bad in (dict(kind='add_daemon', daemon='mgr.h1', host='h2'), dict(kind='add_daemon', daemon='osd.1', host='h1'),
                    dict(kind='remove_daemon', daemon='mon.h1', host='h2'), dict(kind='remove_daemon', daemon='osd.1', host='h1'),
                    dict(kind='remove_host', host='h1', daemon='mgr.h1')):
            k, e = entry(5, 9, 'op-%016x' % 9, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))
        k, e = entry(5, 9, 'm-%016x' % 9, kind='restart', daemon='mgr.h1', host='h1')
        with self.assertRaises(lg.LedgerError):
            lg.check_entry(k, json.dumps(e))


class MaintenanceFoldTest(unittest.TestCase):
    def test_from_enter_until_maintained(self):
        inv = dict(GenerationTest.INV, hosts=GenerationTest.INV['hosts'] + [{'name': 'h3', 'addr': '10.0.0.3', 'maintenance': True}])
        enter = entry(5, 1, 'op-%016x' % 1, kind='enter_maintenance', host='h2', force=False)
        exit_ = entry(5, 2, 'op-%016x' % 2, kind='exit_maintenance', host='h2')
        done = entry(5, 3, 'm-%016x' % 3, kind='maintained', of='op-%016x' % 2, host='h2')
        for k, e in (enter, exit_, done):
            lg.check_entry(k, json.dumps(e))
        self.assertEqual(lg.Fold(inv).maintenance, {'h3'})  # the CLI's
        self.assertEqual(lg.Fold(inv, [enter]).maintenance, {'h2', 'h3'})
        # the exit's acceptance leaves it in maintenance: its documents are still gone
        self.assertEqual(lg.Fold(inv, [enter, exit_]).maintenance, {'h2', 'h3'})
        self.assertEqual(lg.Fold(inv, [enter, exit_, done]).maintenance, {'h3'})
        # a powercycle is in maintenance from its acceptance until its own maintained entry
        pc = entry(5, 4, 'op-%016x' % 4, kind='powercycle_host', host='h1')
        pcdone = entry(5, 5, 'm-%016x' % 5, kind='maintained', of='op-%016x' % 4, host='h1')
        lg.check_entry(*map(lambda x: x, (pc[0], json.dumps(pc[1]))))
        self.assertEqual(lg.Fold(inv, [pc]).maintenance, {'h1', 'h3'})
        self.assertEqual(lg.Fold(inv, [pc, pcdone]).maintenance, {'h3'})
        for bad in (dict(kind='powercycle_host', host='h1', force=False), dict(kind='enter_maintenance', host='h2'), dict(kind='enter_maintenance', host='h2', force=1),
                    dict(kind='enter_maintenance', host='h2', force=False, daemon='mgr.h2'), dict(kind='exit_maintenance', host='h2', force=False)):
            k, e = entry(5, 9, 'op-%016x' % 9, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))


class DrainAndNooutFoldTest(unittest.TestCase):
    """plan 04, step 5: a drain's mark, the noout ownership and unplanned stops."""
    INV = {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}, {'name': 'h2', 'addr': '10.0.0.2'},
                     {'name': 'h3', 'addr': '10.0.0.3', 'maintenance': True, 'noout': True}], 'daemons': []}

    def test_a_drain_from_acceptance_until_done_or_stop(self):
        drain = entry(5, 1, 'op-%016x' % 1, kind='drain_host', host='h1', zap=True)
        stop = entry(5, 2, 'op-%016x' % 2, kind='drain_stop', host='h1', drain='op-%016x' % 1)
        done = entry(5, 3, 'm-%016x' % 3, kind='drain_done', of='op-%016x' % 1, host='h1')
        resume = entry(5, 4, 'op-%016x' % 4, kind='drain_resume', host='h1', drain='op-%016x' % 1)
        for k, e in (drain, stop, done, resume):
            lg.check_entry(k, json.dumps(e))
        self.assertEqual(lg.Fold(self.INV, [drain]).draining, {'h1': {'op': 'op-%016x' % 1, 'zap': True}})
        self.assertEqual(lg.Fold(self.INV, [drain, resume]).draining, {'h1': {'op': 'op-%016x' % 1, 'zap': True}})
        self.assertEqual(lg.Fold(self.INV, [drain, stop]).draining, {})
        self.assertEqual(lg.Fold(self.INV, [drain, done]).draining, {})
        # another drain's stop changes nothing
        other = entry(5, 5, 'op-%016x' % 5, kind='drain_stop', host='h1', drain='op-%016x' % 9)
        self.assertIn('h1', lg.Fold(self.INV, [drain, other]).draining)
        for bad in (dict(kind='drain_host', host='h1'), dict(kind='drain_host', host='h1', zap=1), dict(kind='drain_host', zap=False),
                    dict(kind='drain_stop', host='h1'), dict(kind='drain_stop', host='h1', drain='x'), dict(kind='drain_host', host='h1', zap=False, daemon='mon.h1')):
            k, e = entry(5, 9, 'op-%016x' % 9, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))

    def noout(self, seq, kind, host='h1', **kw):
        k, e = entry(5, seq, 'm-%016x' % seq, kind=kind, host=host, **kw)
        lg.check_entry(k, json.dumps(e))
        return k, e

    def test_the_noout_ownership(self):
        f = lg.Fold(self.INV)
        # the CLI's maintenance noout is the module's
        self.assertEqual(f.noout, {'h3': {'reasons': ['maintenance'], 'operator': False, 'intent': None}})
        intent = self.noout(1, 'noout_intent', reason='maintenance', on=True, prior=False, of='op-%016x' % 7)
        done = self.noout(2, 'noout', reason='maintenance', on=True, of='op-%016x' % 7)
        self.assertEqual(lg.Fold(self.INV, [intent]).noout['h1'], {'reasons': [], 'operator': False, 'intent': {'reason': 'maintenance', 'on': True, 'prior': False}})
        self.assertEqual(lg.Fold(self.INV, [intent, done]).noout['h1'], {'reasons': ['maintenance'], 'operator': False, 'intent': None})
        # a flag already set at the first reason is the operator's
        seen = self.noout(1, 'noout_intent', reason='maintenance', on=True, prior=True)
        self.assertTrue(lg.Fold(self.INV, [seen, done]).noout['h1']['operator'])
        # a second reason, then both go: the record goes with the last
        down = self.noout(3, 'host_down', boot='b-1', stop='b-1.aa.1', at='2026-11-04T10:00:00Z')
        plus = self.noout(4, 'noout', reason='unplanned', on=True)
        f = lg.Fold(self.INV, [intent, done, down, plus])
        self.assertEqual((f.noout['h1']['reasons'], f.down['h1']), (['maintenance', 'unplanned'], {'boot': 'b-1', 'stop': 'b-1.aa.1', 'at': '2026-11-04T10:00:00Z', 'held': True}))
        minus = self.noout(5, 'noout', reason='maintenance', on=False)
        up = self.noout(6, 'host_up')
        unintent = self.noout(7, 'noout_intent', reason='unplanned', on=False, prior=True)
        last = self.noout(8, 'noout', reason='unplanned', on=False)
        f = lg.Fold(self.INV, [intent, done, down, plus, minus, up, unintent, last])
        self.assertEqual((f.noout.get('h1'), f.down), (None, {}))
        # keep: the reasons go, the module never unsets
        keep = self.noout(9, 'noout_keep')
        self.assertNotIn('h1', lg.Fold(self.INV, [intent, done, keep]).noout)
        # the snapshot keeps all of it
        st = lg.Fold(self.INV, [entry(5, 0, 'op-%016x' % 20, kind='drain_host', host='h2', zap=False), intent, done, down]).state(set())
        g = lg.Fold(self.INV, [], {'state': st})
        self.assertEqual((g.draining, g.noout, g.down), (st['draining'], st['noout'], st['down']))
        for bad in (dict(kind='noout', host='h1', reason='Maint', on=True), dict(kind='noout', host='h1', reason='maintenance'),
                    dict(kind='noout_intent', host='h1', reason='maintenance', on=True), dict(kind='host_down', host='h1', boot='b', at='2026-11-04T10:00:00Z'),
                    dict(kind='host_up', host='h1', of='op-%016x' % 1), dict(kind='noout_keep', host='h1', daemon='mon.h1'),
                    dict(kind='drain_done', host='h1')):
            k, e = entry(5, 9, 'm-%016x' % 9, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))
        # a module entry without an operation does not hold a cut back
        led = lg.Ledger(Mons(), 20, 7)
        led.open()
        k1, _ = led.append({'id': 'op-%016x' % 1, 'kind': 'restart', 'daemon': 'mgr.h1', 'host': 'h1'})
        k2, _ = led.append({'id': 'm-%016x' % 2, 'kind': 'host_up', 'host': 'h1'})
        self.assertEqual(lg.cut_key(dict(led.entries), {'op-%016x' % 1: 'completed'}, k2, set()), k2)


class UpgradeFoldTest(unittest.TestCase):
    IMG = 'quay.io/ceph/ceph@sha256:' + 'cd' * 32

    def test_from_start_until_done_or_stop(self):
        inv = GenerationTest.INV
        start = entry(5, 1, 'op-%016x' % 1, kind='upgrade_start', image=self.IMG)
        pause = entry(5, 2, 'op-%016x' % 2, kind='upgrade_pause', upgrade='op-%016x' % 1)
        resume = entry(5, 3, 'op-%016x' % 3, kind='upgrade_resume', upgrade='op-%016x' % 1)
        done = entry(5, 4, 'm-%016x' % 4, kind='upgrade_done', of='op-%016x' % 1)
        stop = entry(5, 4, 'op-%016x' % 4, kind='upgrade_stop', upgrade='op-%016x' % 1)
        for k, e in (start, pause, resume, done, stop):
            lg.check_entry(k, json.dumps(e))
        self.assertEqual(lg.Fold(inv, [start]).upgrade, {'op': 'op-%016x' % 1, 'image': self.IMG, 'paused': False})
        self.assertTrue(lg.Fold(inv, [start, pause]).upgrade['paused'])
        self.assertFalse(lg.Fold(inv, [start, pause, resume]).upgrade['paused'])
        self.assertIsNone(lg.Fold(inv, [start, done]).upgrade)
        self.assertIsNone(lg.Fold(inv, [start, stop]).upgrade)
        # a second start beside the first does not replace it
        second = entry(5, 5, 'op-%016x' % 5, kind='upgrade_start', image=self.IMG)
        self.assertEqual(lg.Fold(inv, [start, second]).upgrade['op'], 'op-%016x' % 1)
        for bad in (dict(kind='upgrade_start', image='quay.io/ceph/ceph:v20'), dict(kind='upgrade_start', image=self.IMG, host='h1'),
                    dict(kind='upgrade_pause'), dict(kind='upgrade_stop', upgrade='op-1')):
            k, e = entry(5, 9, 'op-%016x' % 9, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))
        k, e = entry(5, 9, 'm-%016x' % 9, kind='upgrade_done', of='op-%016x' % 1, host='h1')
        with self.assertRaises(lg.LedgerError):
            lg.check_entry(k, json.dumps(e))


class RGWCertFoldTest(unittest.TestCase):
    INV = {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}, {'name': 'h2', 'addr': '10.0.0.2'}],
           'daemons': [{'daemon_type': 'rgw', 'daemon_id': 'h1', 'host': 'h1'}], 'cli_rgw': {'vip': '10.0.0.200/24', 'port': 443}}

    def test_certificates_enter_and_retire(self):
        a = entry(5, 1, 'op-%016x' % 1, kind='add_daemon', daemon='rgw.h2', host='h2', port=443)
        issued = entry(5, 2, 'm-%016x' % 2, kind='rgw_cert', of='op-%016x' % 1, attempt='ab' * 8)
        b = entry(5, 3, 'op-%016x' % 3, kind='add_daemon', daemon='rgw.h1', host='h1', port=443, cert='-----BEGIN CERTIFICATE-----')
        done = entry(5, 4, 'm-%016x' % 4, kind='rgw_cert_done', of='op-%016x' % 1, keep='issued/op-%016x/%s' % (1, 'ab' * 8))
        for k, e in (a, issued, b, done):
            lg.check_entry(k, json.dumps(e))
        f = lg.Fold(self.INV, [a, issued, b])
        self.assertEqual(f.vip, '10.0.0.200')
        self.assertEqual(sorted(f.rgw_certs), ['cli', 'issued/op-%016x/%s' % (1, 'ab' * 8), 'user/op-%016x' % 3])
        self.assertTrue(f.secret_allowed('rgw/server.key', None))
        self.assertTrue(f.secret_allowed('user/op-%016x/rgw-server.key' % 3, None))
        # done for op 1 retires what entered before op 1 (the CLI's), not op 3's queued certificate
        f = lg.Fold(self.INV, [a, issued, b, done])
        self.assertFalse(f.secret_allowed('rgw/server.key', None))
        self.assertTrue(f.secret_allowed('issued/op-%016x/%s/rgw-server.key' % (1, 'ab' * 8), None))
        self.assertTrue(f.secret_allowed('user/op-%016x/rgw-server.key' % 3, None))
        self.assertFalse(f.secret_allowed('user/op-%016x/rgw-server.key' % 9, None))
        for bad in (dict(kind='add_daemon', daemon='rgw.h2', host='h2'), dict(kind='add_daemon', daemon='rgw.h2', host='h2', port=0),
                    dict(kind='add_daemon', daemon='mgr.h2', host='h2', port=443), dict(kind='add_daemon', daemon='rgw.h1', host='h2', port=443)):
            k, e = entry(5, 9, 'op-%016x' % 9, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))


class MgrRenewalFoldTest(unittest.TestCase):
    """A mgr's renewed keys (plan 04, step 1): released from issuance until a
    later renewal's mgr_cert_done retires them; the add's and the CLI's keys
    with the first done."""
    INV = {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}, {'name': 'h2', 'addr': '10.0.0.2'}],
           'daemons': [{'daemon_type': 'mgr', 'daemon_id': 'h1', 'host': 'h1'}]}

    def test_two_renewals(self):
        add = entry(5, 1, 'op-%016x' % 1, kind='add_daemon', daemon='mgr.h2', host='h2')
        r1 = entry(5, 2, 'op-%016x' % 2, kind='renew_mgr', daemon='mgr.h2', host='h2')
        c1 = entry(5, 3, 'm-%016x' % 3, kind='mgr_cert', of='op-%016x' % 2, daemon='mgr.h2', host='h2', attempt='ab' * 8)
        d1 = entry(5, 4, 'm-%016x' % 4, kind='mgr_cert_done', of='op-%016x' % 2, daemon='mgr.h2', host='h2', keep='op-%016x' % 2)
        r2 = entry(5, 5, 'op-%016x' % 5, kind='renew_mgr', daemon='mgr.h2', host='h2')
        c2 = entry(5, 6, 'm-%016x' % 6, kind='mgr_cert', of='op-%016x' % 5, daemon='mgr.h2', host='h2', attempt='cd' * 8)
        d2 = entry(5, 7, 'm-%016x' % 7, kind='mgr_cert_done', of='op-%016x' % 5, daemon='mgr.h2', host='h2', keep='op-%016x' % 5)
        cli = entry(5, 8, 'op-%016x' % 8, kind='renew_mgr', daemon='mgr.h1', host='h1')
        cc = entry(5, 9, 'm-%016x' % 9, kind='mgr_cert', of='op-%016x' % 8, daemon='mgr.h1', host='h1', attempt='ef' * 8)
        cd = entry(5, 10, 'm-%016x' % 10, kind='mgr_cert_done', of='op-%016x' % 8, daemon='mgr.h1', host='h1', keep='op-%016x' % 8)
        for k, e in (add, r1, c1, d1, r2, c2, d2, cli, cc, cd):
            lg.check_entry(k, json.dumps(e))
        f = lg.Fold(self.INV, [add, r1, c1])
        self.assertTrue(f.mgr_keys_allowed('op-%016x' % 1) and f.mgr_keys_allowed('op-%016x' % 2))
        self.assertEqual(f.mgr_renewals['mgr.h2']['op-%016x' % 2], 'ab' * 8)
        # the first done retires the add's keys, keeps the renewal's
        f = lg.Fold(self.INV, [add, r1, c1, d1, r2])
        self.assertFalse(f.mgr_keys_allowed('op-%016x' % 1))
        self.assertTrue(f.mgr_keys_allowed('op-%016x' % 2) and f.mgr_keys_allowed('op-%016x' % 5))
        # the second renewal's done retires the first renewal's keys
        f = lg.Fold(self.INV, [add, r1, c1, d1, r2, c2, d2])
        self.assertFalse(f.mgr_keys_allowed('op-%016x' % 2))
        self.assertTrue(f.mgr_keys_allowed('op-%016x' % 5))
        # the CLI's mgr: its host keys until its renewal's done
        f = lg.Fold(self.INV, [cli, cc])
        self.assertTrue(f.secret_allowed('host/h1/mgr-server.key', 'h1'))
        f = lg.Fold(self.INV, [cli, cc, cd])
        self.assertFalse(f.secret_allowed('host/h1/mgr-server.key', 'h1'))
        self.assertTrue(f.mgr_keys_allowed('op-%016x' % 8))
        # a renewal of a mgr that is not in the fold counts for nothing
        ghost = entry(5, 11, 'op-%016x' % 11, kind='renew_mgr', daemon='mgr.h9', host='h9')
        self.assertFalse(lg.Fold(self.INV, [ghost]).mgr_keys_allowed('op-%016x' % 11))
        for bad in (dict(kind='renew_mgr', daemon='mgr.h1', host='h2'), dict(kind='renew_mgr', host='h1'),
                    dict(kind='renew_mgr', daemon='mgr.h1', host='h1', port=443), dict(kind='renew_rgw_cert', host='h1')):
            k, e = entry(5, 12, 'op-%016x' % 12, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))
        k, e = entry(5, 13, 'op-%016x' % 13, kind='renew_rgw_cert')
        lg.check_entry(k, json.dumps(e))


class AgentRenewalFoldTest(unittest.TestCase):
    """An agent's renewed keys (plan 04, step 2), and the agents' upgrade kinds."""

    def test_renewals_and_kinds(self):
        inv = {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}], 'daemons': []}
        r1 = entry(5, 1, 'op-%016x' % 1, kind='renew_agent', host='h1')
        c1 = entry(5, 2, 'm-%016x' % 2, kind='agent_cert', of='op-%016x' % 1, host='h1', attempt='ab' * 8)
        d1 = entry(5, 3, 'm-%016x' % 3, kind='agent_cert_done', of='op-%016x' % 1, host='h1', keep='op-%016x' % 1)
        r2 = entry(5, 4, 'op-%016x' % 4, kind='renew_agent', host='h1')
        c2 = entry(5, 5, 'm-%016x' % 5, kind='agent_cert', of='op-%016x' % 4, host='h1', attempt='cd' * 8)
        d2 = entry(5, 6, 'm-%016x' % 6, kind='agent_cert_done', of='op-%016x' % 4, host='h1', keep='op-%016x' % 4)
        up = entry(5, 7, 'op-%016x' % 7, kind='upgrade_agent', image='registry/agent@sha256:' + 'ab' * 32)
        res = entry(5, 8, 'op-%016x' % 8, kind='upgrade_agent_resume', upgrade='op-%016x' % 7)
        stop = entry(5, 10, 'op-%016x' % 10, kind='upgrade_agent_stop', upgrade='op-%016x' % 7)
        for k, e in (r1, c1, d1, r2, c2, d2, up, res, stop):
            lg.check_entry(k, json.dumps(e))
        self.assertFalse(lg.Fold(inv, [r1]).agent_keys_allowed('op-%016x' % 1))  # not issued yet
        f = lg.Fold(inv, [r1, c1, d1, r2, c2])
        self.assertTrue(f.agent_keys_allowed('op-%016x' % 1) and f.agent_keys_allowed('op-%016x' % 4))
        self.assertIn('cli/h1', f.agent_retired)
        f = lg.Fold(inv, [r1, c1, d1, r2, c2, d2])
        self.assertFalse(f.agent_keys_allowed('op-%016x' % 1))
        self.assertTrue(f.agent_keys_allowed('op-%016x' % 4))
        for bad in (dict(kind='renew_agent', host='h1', daemon='mgr.h1'), dict(kind='renew_agent'),
                    dict(kind='upgrade_agent', image='registry/agent:latest'), dict(kind='upgrade_agent', image='r@sha256:' + 'ab' * 32, host='h1'),
                    dict(kind='upgrade_agent_resume', upgrade='x'), dict(kind='upgrade_agent_stop', upgrade='x'),
                    dict(kind='upgrade_agent_stop', upgrade='op-%016x' % 7, host='h1'), dict(kind='upgrade_agent_stop')):
            k, e = entry(5, 9, 'op-%016x' % 9, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))


class IngressFoldTest(unittest.TestCase):
    IMG = 'quay.io/ceph/keepalived@sha256:' + 'cd' * 32

    def test_hosts_password_and_retirement(self):
        inv = {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}, {'name': 'h2', 'addr': '10.0.0.2'}],
               'daemons': [{'daemon_type': 'rgw', 'daemon_id': h, 'host': h} for h in ('h1', 'h2')]}
        a = entry(5, 1, 'op-%016x' % 1, kind='apply_ingress', vip='10.0.0.200/24', vrid=50, hosts=['h1', 'h2'], image=self.IMG, new_password=True)
        b = entry(5, 2, 'op-%016x' % 2, kind='apply_ingress', vip='10.0.0.200/24', vrid=50, hosts=['h1'], image=self.IMG, new_password=False)
        r = entry(5, 3, 'm-%016x' % 3, kind='retire', of='op-%016x' % 2, daemon='keepalived.h2', host='h2')
        for k, e in (a, b, r):
            lg.check_entry(k, json.dumps(e))
        f = lg.Fold(inv, [a])
        self.assertEqual((f.vip, f.ingress['hosts'], f.vrrp_secret), ('10.0.0.200', ['h1', 'h2'], 'ingress/op-%016x/vrrp' % 1))
        self.assertTrue(f.secret_allowed('ingress/op-%016x/vrrp' % 1, None))
        self.assertFalse(f.secret_allowed('rgw/vrrp', None))
        # left out: kept until retired; an apply without a password keeps the current one
        f = lg.Fold(inv, [a, b])
        self.assertIn('keepalived.h2', f.daemons)
        self.assertEqual(f.vrrp_secret, 'ingress/op-%016x/vrrp' % 1)
        self.assertNotIn('keepalived.h2', lg.Fold(inv, [a, b, r]).daemons)
        for bad in (dict(kind='apply_ingress', vip='10.0.0.200', vrid=50, hosts=['h1'], image=self.IMG, new_password=True),
                    dict(kind='apply_ingress', vip='10.0.0.200/24', vrid=0, hosts=['h1'], image=self.IMG, new_password=True),
                    dict(kind='apply_ingress', vip='10.0.0.200/24', vrid=50, hosts=[], image=self.IMG, new_password=True),
                    dict(kind='apply_ingress', vip='10.0.0.200/24', vrid=50, hosts=['h1', 'h1'], image=self.IMG, new_password=True),
                    dict(kind='apply_ingress', vip='10.0.0.200/24', vrid=50, hosts=['h1'], image='keepalived:2', new_password=True),
                    dict(kind='apply_ingress', vip='10.0.0.200/24', vrid=50, hosts=['h1'], image=self.IMG, new_password=True, host='h1')):
            k, e = entry(5, 9, 'op-%016x' % 9, **bad)
            with self.assertRaises(lg.LedgerError, msg=bad):
                lg.check_entry(k, json.dumps(e))


class SnapshotTest(unittest.TestCase):
    """Compaction (plan 04, step 4): the cut, snapshots, their readers and the
    delayed deletion."""
    INV = {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}, {'name': 'h2', 'addr': '10.0.0.2'}],
           'daemons': [{'daemon_type': 'mgr', 'daemon_id': 'h1', 'host': 'h1'}, {'daemon_type': 'rgw', 'daemon_id': 'h1', 'host': 'h1'}],
           'cli_rgw': {'port': 443}}
    NOW = __import__('datetime').datetime(2026, 11, 4, tzinfo=__import__('datetime').timezone.utc)

    def opened(self, mons, gid, epoch):
        led = lg.Ledger(mons, gid, epoch)
        led.open()
        return led

    def restart(self, led, n, daemon='mgr.h1', host='h1'):
        return led.append({'id': 'op-%016x' % n, 'kind': 'restart', 'daemon': daemon, 'host': host})

    @staticmethod
    def state(fold):
        st = fold.state(set())
        st.pop('positions')
        return st

    def test_the_cut(self):
        led = self.opened(Mons(), 20, 7)
        k1, _ = self.restart(led, 1)
        k2, _ = self.restart(led, 2)
        m1, _ = led.append({'id': 'm-%016x' % 1, 'kind': 'close', 'of': 'op-%016x' % 1, 'daemon': 'mgr.h1', 'host': 'h1'})
        k3, _ = self.restart(led, 3)
        k4, _ = self.restart(led, 4)
        m4, _ = led.append({'id': 'm-%016x' % 4, 'kind': 'close', 'of': 'op-%016x' % 4, 'daemon': 'mgr.h1', 'host': 'h1'})
        done = {'op-%016x' % i: 'completed' for i in (1, 2, 3)}
        entries = dict(led.entries)
        last = max(entries)
        self.assertEqual(lg.cut_key(entries, done, last, set()), k3)
        # not past the published ledger_applied, an unfinished one or a pinned one
        self.assertEqual(lg.cut_key(entries, done, k2, set()), m1)
        self.assertEqual(lg.cut_key(entries, dict(done, **{'op-%016x' % 2: 'granting'}), last, set()), k1)
        self.assertEqual(lg.cut_key(entries, done, last, {'op-%016x' % 1}), lg.entry_key(7, 0, 'takeover'))
        # a module entry naming an operation that is not cut holds the cut back
        self.assertEqual(lg.cut_key(entries, dict(done, **{'op-%016x' % 4: 'completed'}), last, set()), m4)
        self.assertEqual(lg.cut_key(entries, done, last, set()), k3)
        self.assertIsNone(lg.cut_key({}, done, last, set()))

    def test_a_snapshot_folds_as_the_whole_ledger(self):
        mons = Mons()
        led = self.opened(mons, 20, 7)
        add, _ = led.append({'id': 'op-%016x' % 1, 'kind': 'add_daemon', 'daemon': 'rgw.h2', 'host': 'h2', 'port': 8443})
        self.restart(led, 2)  # unfinished: the cut stops before it
        # the add's certificate entries follow the cut: its position is kept
        led.append({'id': 'm-%016x' % 3, 'kind': 'rgw_cert', 'of': 'op-%016x' % 1, 'attempt': 'ab' * 8})
        led.append({'id': 'm-%016x' % 4, 'kind': 'rgw_cert_done', 'of': 'op-%016x' % 1, 'keep': 'issued/op-%016x/%s' % (1, 'ab' * 8)})
        whole = lg.Fold(self.INV, led.executable())
        states = {'op-%016x' % 1: 'completed'}
        rel, content = led.cut(self.INV, states, max(led.entries), set(), self.NOW)
        self.assertEqual(lg.LEDGER_PREFIX + rel, add)
        self.assertEqual(content['state']['positions'], {'op-%016x' % 1: 0})
        self.assertEqual(content['covered'], {'20': [7, 1]})
        self.assertTrue(led.publish(rel, content, self.NOW))
        self.assertTrue(all(k > add for k in led.entries))
        f = led.fold(self.INV)
        self.assertEqual(self.state(f), self.state(whole))
        self.assertEqual(f.rgw_port, 8443)
        self.assertTrue(f.rgw_certs['cli']['retired'] and not f.rgw_certs['issued/op-%016x/%s' % (1, 'ab' * 8)]['retired'])
        # a successor reads the snapshot and the entries above it: the same fold,
        # positions continued, and the cutoffs it would have set from the whole ledger
        succ = self.opened(mons, 30, 9)
        self.assertEqual(succ.snapshot_key, rel)
        self.assertEqual(self.state(succ.fold(self.INV)), self.state(whole))
        later = self.opened(Mons({k: v for k, v in mons.kv.items() if not k.startswith(lg.SNAPSHOT_PREFIX)}), 31, 9)
        self.assertEqual(json.loads(mons.kv[lg.entry_key(9, 0, 'takeover')])['cutoffs'], json.loads(later.mon.kv[lg.entry_key(9, 0, 'takeover')])['cutoffs'])
        self.assertEqual(json.loads(mons.kv[lg.entry_key(9, 0, 'takeover')])['cutoffs'], {'20': 4})
        self.assertEqual(succ.lookup(ident='op-%016x' % 1)['state'], 'completed')
        self.assertTrue(succ.covered()('op-%016x' % 1))
        self.assertFalse(succ.covered()('op-%016x' % 2))

    def test_a_takeover_after_a_snapshot(self):
        mons = Mons()
        a = self.opened(mons, 10, 5)
        for i in (1, 2, 3):
            self.restart(a, i)
        rel, content = a.cut(self.INV, {'op-%016x' % i: 'completed' for i in (1, 2)}, max(a.entries), set(), self.NOW)
        self.assertTrue(a.publish(rel, content, self.NOW))
        b = self.opened(mons, 20, 7)
        self.assertEqual(json.loads(mons.kv[lg.entry_key(7, 0, 'takeover')])['cutoffs'], {'10': 3})
        self.restart(b, 4)
        # B's snapshot covers B's takeover: A is no longer covered, and C's
        # takeover need not name it
        rel, content = b.cut(self.INV, {'op-%016x' % i: 'completed' for i in (1, 2, 3, 4)}, max(b.entries), set(), self.NOW)
        self.assertEqual(content['since'], 7)
        self.assertEqual(content['covered'], {'20': [7, 1]})
        self.assertTrue(b.publish(rel, content, self.NOW))
        c = self.opened(mons, 30, 9)
        self.assertEqual(c.snapshot_key, rel)
        self.assertEqual(json.loads(mons.kv[lg.entry_key(9, 0, 'takeover')])['cutoffs'], {'20': 1})
        d = self.opened(mons, 40, 11)
        self.assertEqual(d.snapshot_key, rel)  # C's cutoffs do not name A: still valid
        self.assertEqual([e['id'] for _, e in d.executable()], [])

    def test_late_writes_and_a_stale_snapshot(self):
        mons = Mons()
        a = self.opened(mons, 10, 5)
        for i in (1, 2, 3):
            self.restart(a, i)
        b = self.opened(mons, 20, 7)
        self.restart(b, 4)
        # A, stale, appends after B's takeover and cuts its own late write
        late, _ = self.restart(a, 5)
        done = {'op-%016x' % i: 'completed' for i in range(1, 6)}
        rel, content = a.cut(self.INV, done, late, set(), self.NOW)
        self.assertEqual(lg.LEDGER_PREFIX + rel, late)
        self.assertTrue(a.publish(rel, content, self.NOW))
        # rejected by every reader: B's takeover saw A only up to 3
        c = self.opened(mons, 30, 9)
        self.assertIsNone(c.snapshot)
        self.assertEqual([e['id'] for _, e in c.executable()], ['op-%016x' % i for i in (1, 2, 3, 4)])
        # nor does its writer delete for it
        removed = []
        self.assertFalse(a.delete(self.NOW + lg.DELETE_AFTER * 2, lambda: True, removed.append))
        self.assertEqual((removed, mons.rms), ([], []))
        # B's valid snapshot; a late write of A at or below it is ignored
        rel, content = b.cut(self.INV, done, max(b.entries), set(), self.NOW)
        self.assertTrue(b.publish(rel, content, self.NOW))
        self.restart(a, 6)
        d = self.opened(mons, 40, 11)
        self.assertEqual(d.snapshot_key, rel)
        self.assertEqual(self.state(d.fold(self.INV)), self.state(lg.Fold(self.INV, c.executable())))
        self.assertNotIn('op-%016x' % 6, [e['id'] for _, e in d.executable()])

    def test_deletion_waits_and_is_fenced(self):
        mons = Mons()
        led = self.opened(mons, 20, 7)
        for i in (1, 2, 3):
            self.restart(led, i)
        done = {'op-%016x' % i: 'completed' for i in (1, 2, 3)}
        first, content = led.cut(self.INV, {'op-%016x' % 1: 'completed'}, max(led.entries), set(), self.NOW)
        self.assertTrue(led.publish(first, content, self.NOW))
        k4, _ = self.restart(led, 4)
        rel, content = led.cut(self.INV, done, max(led.entries), set(), self.NOW)
        self.assertTrue(led.publish(rel, content, self.NOW))
        pruned = []
        # not before DELETE_AFTER, nor without a fresh confirmation of leadership
        self.assertFalse(led.delete(self.NOW + lg.DELETE_AFTER / 2, lambda: True, pruned.append))
        self.assertFalse(led.delete(self.NOW + lg.DELETE_AFTER, lambda: False, pruned.append))
        self.assertEqual((pruned, mons.rms), ([], []))
        self.assertTrue(led.delete(self.NOW + lg.DELETE_AFTER, lambda: True, pruned.append))
        self.assertEqual(sorted(k for k in mons.kv if k.startswith(lg.LEDGER_PREFIX)), [k4])
        self.assertEqual({k.split('/')[2] for k in mons.kv if k.startswith(lg.SNAPSHOT_PREFIX)}, {rel})
        # the older snapshot's manifest went before its chunks
        older = [k for k in mons.rms if k.startswith(lg.SNAPSHOT_PREFIX)]
        self.assertTrue(older[0].endswith('/manifest'))
        [covered] = pruned
        self.assertTrue(covered('op-%016x' % 3) and not covered('op-%016x' % 4) and not covered('m-%016x' % 1))
        # a successor reads the same
        succ = self.opened(mons, 30, 9)
        self.assertEqual(([e['id'] for _, e in succ.executable()], succ.snapshot_key), (['op-%016x' % 4], rel))

    def test_a_damaged_snapshot(self):
        mons = Mons()
        led = self.opened(mons, 20, 7)
        for i in (1, 2, 3):
            self.restart(led, i)
        first, content = led.cut(self.INV, {'op-%016x' % 1: 'completed'}, max(led.entries), set(), self.NOW)
        self.assertTrue(led.publish(first, content, self.NOW))
        rel, content = led.cut(self.INV, {'op-%016x' % i: 'completed' for i in (1, 2, 3)}, max(led.entries), set(), self.NOW)
        self.assertTrue(led.publish(rel, content, self.NOW))
        chunk = json.loads(mons.kv[lg.SNAPSHOT_PREFIX + rel + '/manifest'])['chunks'][0]
        mons.kv[chunk] = mons.kv[chunk][:-4] + 'AAAA'
        # the older one, while the entries above it are there
        succ = self.opened(mons, 30, 9)
        self.assertEqual(succ.snapshot_key, first)
        self.assertEqual([e['id'] for _, e in succ.executable()], ['op-%016x' % 2, 'op-%016x' % 3])
        # without it, nothing can be trusted: refused
        del mons.kv[lg.SNAPSHOT_PREFIX + first + '/manifest']
        with self.assertRaises(lg.LedgerError):
            self.opened(mons, 40, 11)

    def test_reading_by_key_past_the_output_limit(self):
        mons = Mons()
        led = self.opened(mons, 20, 7)
        for i in range(1, 3001):
            self.restart(led, i)
        self.assertEqual(mons({'prefix': 'config-key dump', 'key': lg.LEDGER_PREFIX}, 1)[0], -27)
        succ = self.opened(mons, 30, 9)
        self.assertEqual(len(succ.executable()), 3000)
        self.assertEqual(json.loads(mons.kv[lg.entry_key(9, 0, 'takeover')])['cutoffs'], {'20': 3000})
        # a listed key that cannot be read fails the read
        class Losing(Mons):
            def __call__(self, cmd, deadline, reduce=None):
                if cmd['prefix'] == 'config-key get' and cmd['key'].endswith('%016x' % 7):
                    return None
                return super().__call__(cmd, deadline, reduce)
        with self.assertRaises(lg.LedgerError):
            self.opened(Losing(mons.kv), 40, 11)

    def test_two_writers_of_one_cut(self):
        """Codex round 1: a predecessor that found no manifest writes the same
        cut after its successor published it; its chunks never overwrite the
        successor's, and deletion verifies the stored snapshot first."""
        mons = Mons()
        led = self.opened(mons, 20, 7)
        for i in (1, 2, 3):
            self.restart(led, i)
        done = {'op-%016x' % i: 'completed' for i in (1, 2, 3)}
        rel, content = led.cut(self.INV, done, max(led.entries), set(), self.NOW)
        self.assertTrue(led.publish(rel, content, self.NOW))
        # the other writer saw no manifest, wrote its chunks and died before its manifest
        other = lg.Ledger(mons, 10, 5)
        other.ready = True
        other._read_snapshot = lambda cut: None
        real = other._set

        def set_(key, value):
            if key.endswith('/manifest'):
                raise lg.OutcomeUnknown('gone')
            real(key, value)
        other._set = set_
        theirs = dict(content, lookup=[{'id': 'x', 'at': lg._iso(self.NOW)}])
        with self.assertRaises(lg.OutcomeUnknown):
            other.publish(rel, theirs, self.NOW)
        self.assertEqual(len([k for k in mons.kv if k.startswith(lg.SNAPSHOT_PREFIX + rel + '/') and not k.endswith('/manifest')]), 2)
        self.assertEqual(self.opened(mons, 30, 9).snapshot_key, rel)
        # a damaged stored snapshot: nothing is deleted for it
        chunk = json.loads(mons.kv[lg.SNAPSHOT_PREFIX + rel + '/manifest'])['chunks'][0]
        good = mons.kv[chunk]
        mons.kv[chunk] = good[:-4] + 'AAAA'
        self.assertFalse(led.delete(self.NOW + lg.DELETE_AFTER, lambda: True, lambda covered: None))
        self.assertEqual(mons.rms, [])
        # nor for a manifest another writer replaced
        mons.kv[chunk] = good
        saved = mons.kv[lg.SNAPSHOT_PREFIX + rel + '/manifest']
        del mons.kv[lg.SNAPSHOT_PREFIX + rel + '/manifest']
        other._set, other._read_snapshot = real, lg.Ledger._read_snapshot.__get__(other)
        other.publish(rel, theirs, self.NOW)  # its own manifest replaces the successor's
        self.assertFalse(led.delete(self.NOW + lg.DELETE_AFTER, lambda: True, lambda covered: None))
        self.assertEqual(mons.rms, [])
        mons.kv[lg.SNAPSHOT_PREFIX + rel + '/manifest'] = saved
        self.assertTrue(led.delete(self.NOW + lg.DELETE_AFTER, lambda: True, lambda covered: None))
