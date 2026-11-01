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
    """config-key dump and set over a dict; `silent` writes are stored but not answered."""

    def __init__(self, kv=None):
        self.kv = dict(kv or {})
        self.silent = 0
        self.sets = []

    def __call__(self, cmd, deadline):
        if cmd['prefix'] == 'config-key dump':
            return 0, json.dumps({k: v for k, v in self.kv.items() if k.startswith(cmd['key'])}), ''
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
            def __call__(self, cmd, deadline):
                if cmd['prefix'] == 'config-key set' and 'takeover' not in cmd['key']:
                    return -27, '', 'too big'
                return super().__call__(cmd, deadline)
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
