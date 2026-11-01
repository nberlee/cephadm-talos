"""Tests of bridge.py, the module's side of the agent channel (plan 03, step 1).
Run with hack/mgrmodule-test.sh."""
import base64
import datetime
import http.client
import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
import os

import test_talos  # noqa: F401  (stubs ceph_module before the talos package is imported)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from talos import bridge as b
from talos import ledger as lg
from talos import module as m


def inventory(*daemons):
    """An inventory of hosts h1 and h2 with daemons "<type>.<id>@<host>"."""
    ds = []
    for d in daemons:
        name, host = d.split('@')
        t, i = name.split('.', 1)
        ds.append({'doc_name': 'x', 'host': host, 'daemon_type': t, 'daemon_id': i, 'service_name': t})
    return {'hosts': [{'name': 'h1', 'addr': '10.0.0.1'}, {'name': 'h2', 'addr': '10.0.0.2'}], 'daemons': ds}


class FakeLedger:
    ready = True

    def __init__(self, entries=()):
        self.entries = list(entries)

    def executable(self):
        return list(self.entries)

    def settle(self):
        pass


def authority(*daemons):
    """What the module authorizes: a mon, mgr, rgw and keepalived on h1 unless named."""
    inv = inventory(*(daemons or ('mon.h1@h1', 'mgr.h1@h1', 'rgw.h1@h1', 'keepalived.h1@h1')))
    return lambda: (FakeLedger(), lg.Fold(inv))


class Log:
    def exception(self, *a):
        pass


class Mons:
    """A fake send_command. Answers mgr dump from `maps` (the last repeats; None:
    no answer yet), anything else at once, or keeps those results pending when late."""

    def __init__(self, maps=None):
        self.maps = list(maps or [])
        self.sent = []      # (thread name, prefix)
        self.pending = []
        self.late = False
        self.keys = []      # answer to config-key ls
        self.kv = None      # a config-key store for get, set, rm and ls, if set
        self.auth_rm = []
        self.osds = []      # osd dump's osds
        self.safe = []      # osd safe-to-destroy's safe ids
        self.osd_calls = []
        self.metadata = {}  # osd metadata by id
        self.monmap = []    # quorum_status's monmap names
        self.quorum = []    # quorum_status's quorum_names
        self.mon_rm = []

    def send(self, res, cmd):
        prefix = json.loads(cmd)['prefix']
        self.sent.append((threading.current_thread().name, prefix))
        if self.late and prefix != 'mgr dump':
            self.pending.append(res)
            return
        if prefix == 'mgr dump':
            mm = self.maps.pop(0) if len(self.maps) > 1 else self.maps[0]
            if mm is None:
                self.pending.append(res)
                return
            res.complete(0, json.dumps(mm), '')
        elif self.kv is not None and prefix in ('config-key get', 'config-key set', 'config-key rm', 'config-key ls'):
            c = json.loads(cmd)
            if prefix == 'config-key get':
                res.complete(0, self.kv[c['key']], '') if c['key'] in self.kv else res.complete(-2, '', 'not found')
            elif prefix == 'config-key set':
                self.kv[c['key']] = c['val']
                res.complete(0, '', '')
            elif prefix == 'config-key rm':
                self.kv.pop(c['key'], None)
                res.complete(0, '', '')
            else:
                res.complete(0, json.dumps(sorted(self.kv)), '')
        elif prefix == 'osd safe-to-destroy':
            res.complete(0, json.dumps({'safe_to_destroy': self.safe, 'active': [], 'missing_stats': [], 'stored_pgs': []}), '')
        elif prefix in ('osd out', 'osd purge-actual'):
            self.osd_calls.append(prefix)
            res.complete(0, '', '')
        elif prefix == 'osd dump':
            res.complete(0, json.dumps({'osds': self.osds}), '')
        elif prefix == 'osd metadata':
            i = json.loads(cmd)['id']
            res.complete(0, json.dumps(self.metadata[i]), '') if i in self.metadata else res.complete(-2, '', 'no metadata')
        elif prefix == 'quorum_status':
            res.complete(0, json.dumps({'monmap': {'mons': [{'name': n} for n in self.monmap]}, 'quorum_names': self.quorum}), '')
        elif prefix == 'mon rm':
            name = json.loads(cmd)['name']
            self.mon_rm.append(name)
            self.monmap = [n for n in self.monmap if n != name]
            self.quorum = [n for n in self.quorum if n != name]
            res.complete(0, '', '')
        elif prefix == 'auth rm':
            self.auth_rm.append(json.loads(cmd)['entity'])
            res.complete(0, '', '')
        elif prefix == 'config-key ls':
            res.complete(0, json.dumps(self.keys), '')
        else:
            res.complete(0, json.dumps({'status': 'HEALTH_OK'}), '')

    def commands(self, n, name='t'):
        c = b.Commands(self.send, lambda: b.Job({}), n, name)
        return c


def mgrmap(gid, name, epoch=5):
    return {'active_gid': gid, 'active_name': name, 'epoch': epoch, 'available': True}


def key_pair():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    return key, pem


def challenge(**kw):
    req = {'version': 1, 'fsid': 'f1', 'session': 'ab' * 16, 'host': 'h3', 'revision': 7, 'operation': 'op-1',
           'inputs_hash': 'cd' * 32, 'challenge': 'ef' * 16}
    req.update(kw)
    return req


def wait_until(cond, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


class CommandsTest(unittest.TestCase):
    def test_sent_from_persistent_workers_and_bounded(self):
        mons = Mons()
        mons.late = True
        cmds = mons.commands(2, 'w')
        self.addCleanup(cmds.stop)
        j1, j2 = cmds.submit({'prefix': 'health'}), cmds.submit({'prefix': 'status'})
        self.assertTrue(wait_until(lambda: len(mons.sent) == 2))
        self.assertIsNone(cmds.submit({'prefix': 'health'}), 'a third outstanding command was accepted')
        self.assertTrue(all(t.startswith('w-') for t, _ in mons.sent), mons.sent)
        mons.pending[0].complete(0, 'x', '')
        self.assertTrue(wait_until(lambda: j1.ev.is_set() or j2.ev.is_set()))
        self.assertTrue(wait_until(lambda: cmds.submit({'prefix': 'health'}) is not None), 'a completed command kept its slot')


class DeadlineBudgetTest(unittest.TestCase):
    def test_a_bridge_answer_fits_in_its_connection(self):
        self.assertLess(b.MAX_BRIDGE_DEADLINE + 2, b.REQUEST_DEADLINE)


class CommandsStopTest(unittest.TestCase):
    def test_no_work_after_stop(self):
        mons = Mons()
        cmds = mons.commands(2)
        cmds.stop()
        self.assertIsNone(cmds.submit({'prefix': 'health'}))


class LeadershipTest(unittest.TestCase):
    def lead(self, activation, maps):
        mons = Mons(maps)
        cmds = mons.commands(2)
        self.addCleanup(cmds.stop)
        return b.Leadership('h1', activation, cmds), mons

    def test_candidate_from_the_activation_map_only(self):
        lead, _ = self.lead(mgrmap(10, 'other'), [mgrmap(42, 'h1')])
        self.assertIsNone(lead.candidate)
        self.assertFalse(lead.capture(), 'captured without having been activated as h1')

    def test_capture_needs_the_mons_to_agree(self):
        lead, _ = self.lead(mgrmap(42, 'h1', 9), [mgrmap(10, 'other'), None, mgrmap(42, 'h1', 11)])
        self.assertFalse(lead.capture())  # another mgr is active
        self.assertFalse(lead.capture())  # no answer within the deadline
        self.assertTrue(lead.capture())
        self.assertEqual(lead.captured(), (42, 11))

    def test_a_successor_with_the_same_name_is_not_adopted(self):
        lead, _ = self.lead(mgrmap(42, 'h1'), [mgrmap(43, 'h1')])
        self.assertFalse(lead.capture())
        lead2, _ = self.lead(mgrmap(42, 'h1'), [mgrmap(42, 'h1'), mgrmap(43, 'h1')])
        self.assertTrue(lead2.capture())
        self.assertFalse(lead2.still_active())


class ConfirmTest(unittest.TestCase):
    def channel(self, maps, activation=None):
        key, pem = key_pair()
        mons = Mons(maps)
        cmds = mons.commands(2)
        self.addCleanup(cmds.stop)
        lead = b.Leadership('h1', activation or mgrmap(42, 'h1'), cmds)
        return b.Channel('f1', 'h1', lead, mons.commands(2), None, pem, m.require_identity, Log(), authority()), lead, key

    def test_refused_until_captured(self):
        ch, lead, _ = self.channel([mgrmap(10, 'other')])
        lead.capture()
        self.assertEqual(ch.confirm(challenge())[0], 503)

    def test_refused_when_no_longer_active(self):
        ch, lead, _ = self.channel([mgrmap(42, 'h1'), mgrmap(50, 'h2')])
        self.assertTrue(lead.capture())
        self.assertEqual(ch.confirm(challenge())[0], 409)

    def test_signed_answer_for_exactly_this_challenge(self):
        ch, lead, key = self.channel([mgrmap(42, 'h1')])
        self.assertTrue(lead.capture())
        code, reply = ch.confirm(challenge())
        self.assertEqual(code, 200)
        payload = base64.b64decode(reply['payload'])
        key.public_key().verify(base64.b64decode(reply['signature']), payload, ec.ECDSA(hashes.SHA256()))
        self.assertEqual(json.loads(payload), {'version': 1, 'fsid': 'f1', 'mgr': 'h1', 'gid': 42, 'epoch': 5, 'session': 'ab' * 16,
                                               'host': 'h3', 'revision': 7, 'operation': 'op-1', 'inputs_hash': 'cd' * 32,
                                               'challenge': 'ef' * 16})

    def test_request_checks(self):
        self.assertEqual(b.check_confirm_request(challenge(), 'f1', 'h3')['host'], 'h3')
        for bad, peer in ((challenge(fsid='f2'), 'h3'), (challenge(), 'h4'), (challenge(version=2), 'h3'),
                          (challenge(revision=-1), 'h3'), (challenge(revision=True), 'h3'), (challenge(session='xyz'), 'h3'),
                          (challenge(challenge='00'), 'h3'), (challenge(inputs_hash='ab'), 'h3'), (challenge(operation='a/b'), 'h3'),
                          (dict(challenge(), extra=1), 'h3'), ({k: v for k, v in challenge().items() if k != 'session'}, 'h3'),
                          ([], 'h3')):
            with self.assertRaises(ValueError, msg=repr(bad)):
                b.check_confirm_request(bad, 'f1', peer)


class BridgeTest(unittest.TestCase):
    def channel(self, n=b.BRIDGE_COMMANDS):
        lmons = Mons([mgrmap(42, 'h1')])
        lcmds = lmons.commands(2)
        self.addCleanup(lcmds.stop)
        lead = b.Leadership('h1', mgrmap(42, 'h1'), lcmds)
        self.assertTrue(lead.capture())
        mons = Mons([mgrmap(42, 'h1')])  # the bridge's own fresh check before a change
        cmds = mons.commands(n, 'bridge')
        self.addCleanup(cmds.stop)
        return b.Channel('f1', 'h1', lead, cmds, None, b'', m.require_identity, Log(), authority()), mons

    def call(self, ch, **kw):
        req = {'version': 1, 'call': 'health', 'args': {}, 'deadline': 5, 'dispatch_id': '12' * 8}
        req.update(kw)
        return ch.bridge(req)

    def test_allowlist_and_shapes(self):
        ch, mons = self.channel()
        code, reply = self.call(ch)
        self.assertEqual((code, reply['outcome'], reply['r']), (200, 'done', 0))
        for i, kw in enumerate(({'call': 'auth get'}, {'args': {'x': 1}}, {'deadline': 0}, {'deadline': 11}, {'deadline': True},
                                {'dispatch_id': 'nothex'}, {'version': 2}, {'extra': 1})):
            kw.setdefault('dispatch_id', '%016x' % (100 + i))
            self.assertEqual(self.call(ch, **kw)[0], 400, kw)
        self.assertEqual([p for _, p in mons.sent], ['health'])  # refused calls never reach the mons
        self.assertTrue(all(t.startswith('bridge-') for t, _ in mons.sent))

    def test_store_and_key_calls(self):
        k = 'mgr/cephadm/talos/inc/4242/rec/1/hosts.0'
        good = {
            'config-key keys': ({'prefix': 'mgr/cephadm/talos/inc/4242/', 'after': ''}, {'prefix': 'config-key ls', 'format': 'json'}),
            'config-key get': ({'key': k}, {'prefix': 'config-key get', 'key': k}),
            'config-key set': ({'key': k, 'value': 'abc='}, {'prefix': 'config-key set', 'key': k, 'val': 'abc='}),
            'config-key rm': ({'key': k}, {'prefix': 'config-key rm', 'key': k}),
            'entry limit': ({}, {'prefix': 'config get', 'who': 'mon', 'key': 'mon_config_key_max_entry_size', 'format': 'json'}),
            'auth get': ({'entity': 'osd.12'}, {'prefix': 'auth get', 'entity': 'osd.12', 'format': 'json'}),
            'auth get-or-create': ({'entity': 'client.rgw.h1-a', 'operation': 'op-%016x' % 1}, {'prefix': 'auth get-or-create', 'entity': 'client.rgw.h1-a',
                                                                  'caps': ['mon', 'allow rw', 'osd', 'allow rwx', 'mgr', 'allow rw'],
                                                                  'format': 'json'}),
        }
        for call, (args, cmd) in good.items():
            self.assertEqual(b.ALLOWLIST[call](args), cmd, call)
        b.ALLOWLIST['auth get']({'entity': 'client.bootstrap-osd', 'operation': 'op-%016x' % 1})
        for e in ('mon.', 'mgr.h1', 'osd.0', 'client.rgw.h2'):
            b.ALLOWLIST['auth get']({'entity': e})
        bad = [
            ('config-key keys', {'prefix': 'mgr/cephadm/', 'after': ''}),
            ('config-key keys', {'prefix': 'mgr/cephadm/talos/inc', 'after': ''}),
            ('config-key keys', {'prefix': 'mgr/cephadm/talos/../x/', 'after': ''}),
            ('config-key keys', {'prefix': 'mgr/cephadm/talos/inc/4242/'}),
            ('config-key keys', {'prefix': 'mgr/cephadm/talos/inc/4242/', 'after': 'mgr/cephadm/talos/inc/1/x'}),
            ('config-key keys', {'prefix': 'mgr/cephadm/talos/inc/4242/', 'after': 7}),
            ('config-key get', {'key': 'mgr/cephadm/talos/inc/'}),
            ('config-key get', {'key': 'mgr/cephadm/cert_store.cert.x'}),
            ('config-key set', {'key': 'mgr/cephadm/inventory', 'value': 'x'}),
            ('config-key set', {'key': 'mgr/cephadm/talos/a/../../b', 'value': 'x'}),
            ('config-key set', {'key': 'mgr/cephadm/talos//a', 'value': 'x'}),
            ('config-key set', {'key': 'mgr/cephadm/talos/a/', 'value': 'x'}),
            ('config-key set', {'key': k, 'value': 1}),
            ('config-key set', {'key': k, 'value': 'x' * (b.MAX_VALUE + 1)}),
            ('config-key set', {'key': k}),
            ('config-key set', {'key': 'mgr/cephadm/talos/' + 'a' * 300, 'value': 'x'}),
            ('config-key rm', {'key': 'config/global/x'}),
            ('config-key rm', {'key': k, 'value': 'x'}),
            ('entry limit', {'who': 'osd'}),
            ('auth get', {'entity': 'client.admin'}),
            ('auth get', {'entity': 'client.rgw.H1'}),
            ('auth get', {'entity': 'osd.01'}),
            ('auth get', {'entity': 'mgr.h1', 'caps': []}),
            ('auth get-or-create', {'entity': 'client.admin', 'operation': 'op-%016x' % 1}),
            ('auth get-or-create', {'entity': 'osd.1', 'operation': 'op-%016x' % 1}),
            ('auth get-or-create', {'entity': 'mon.', 'operation': 'op-%016x' % 1}),
            ('auth get-or-create', {'entity': 'mgr.h1', 'operation': 'op-%016x' % 1, 'caps': ['mon', 'allow *']}),
            ('auth get-or-create', {'entity': 'mgr.h1'}),
            ('auth get-or-create', {'entity': 'mgr.h1', 'operation': 'op-1'}),
        ]
        for call, args in bad:
            with self.assertRaises(ValueError, msg=(call, args)):
                b.ALLOWLIST[call](args)
        # the caps given out are copies: a caller cannot change the table
        b.ALLOWLIST['auth get-or-create']({'entity': 'mgr.h1', 'operation': 'op-%016x' % 1})['caps'].append('x')
        self.assertEqual(b.CREATE_CAPS['mgr'][-1], 'allow *')

    def test_secrets(self):
        ch, mons = self.channel()
        for i, name in enumerate(('host/h1/mgr-server.key', 'host/h1/mgr-client.key', 'rgw/server.key', 'rgw/vrrp')):
            self.assertEqual(b.ALLOWLIST['secret get']({'name': name}), {'prefix': 'config-key get', 'key': b.SECRET_PREFIX + name})
            code, reply = self.call(ch, call='secret get', args={'name': name}, dispatch_id='%016x' % (300 + i))
            self.assertEqual((code, reply['outcome']), (200, 'done'), name)
        self.assertEqual(ch.outcome('%016x' % 300)[0], 404)  # a secret is not kept once answered
        sent = len(mons.sent)
        # the CA keys and the agents' keys never; a host's mgr keys only where the fold has a mgr
        for i, name in enumerate(('agent-ca.key', 'rgw/ca.key', 'host/h1/agent-server.key', 'host/h1/agent-client.key',
                                  'host/h2/mgr-server.key', 'host/../mgr-server.key', 'host/h1/../agent-ca.key', 7)):
            code, _ = self.call(ch, call='secret get', args={'name': name}, dispatch_id='%016x' % (400 + i))
            self.assertEqual(code, 400, name)
        self.assertEqual(self.call(ch, call='secret get', args={'name': 'rgw/vrrp', 'x': 1}, dispatch_id='%016x' % 410)[0], 400)
        # nor through the store calls
        for i, call in enumerate(('config-key get', 'config-key set', 'config-key rm')):
            args = {'key': b.SECRET_PREFIX + 'agent-ca.key'}
            if call == 'config-key set':
                args['value'] = 'x'
            self.assertEqual(self.call(ch, call=call, args=args, dispatch_id='%016x' % (420 + i))[0], 400, call)
        code, reply = self.call(ch, call='config-key keys', args={'prefix': b.SECRET_PREFIX, 'after': ''}, dispatch_id='%016x' % 430)
        self.assertEqual(code, 400)
        self.assertEqual(len(mons.sent), sent)

    def test_credentials_follow_the_fold(self):
        ch, mons = self.channel()
        ch.authority = authority('mgr.h1@h1')  # no mon, rgw or keepalived
        for i, (call, args) in enumerate((('secret get', {'name': 'rgw/server.key'}), ('secret get', {'name': 'rgw/vrrp'}),
                                          ('auth get', {'entity': 'mon.'}), ('auth get', {'entity': 'client.rgw.h1'}),
                                          ('auth get', {'entity': 'mgr.h2'}), ('auth get', {'entity': 'osd.0'}),
                                          ('auth get', {'entity': 'client.bootstrap-osd'}),
                                          ('auth get-or-create', {'entity': 'mgr.h1', 'operation': 'op-%016x' % 1}))):
            self.assertEqual(self.call(ch, call=call, args=args, dispatch_id='%016x' % (700 + i))[0], 400, (call, args))
        for i, (call, args) in enumerate((('auth get', {'entity': 'mgr.h1'}), ('secret get', {'name': 'host/h1/mgr-server.key'}))):
            self.assertEqual(self.call(ch, call=call, args=args, dispatch_id='%016x' % (720 + i))[1]['outcome'], 'done', call)
        # a credential goes out only while this incarnation is active
        mons.maps = [mgrmap(43, 'h2')]
        self.assertEqual(self.call(ch, call='auth get', args={'entity': 'mgr.h1'}, dispatch_id='%016x' % 730)[0], 409)
        # without a ledger, nothing
        def none():
            raise ValueError('not open')
        ch.authority = none
        self.assertEqual(self.call(ch, call='auth get', args={'entity': 'mgr.h1'}, dispatch_id='%016x' % 731)[0], 503)

    def test_a_credential_is_never_kept(self):
        ch, mons = self.channel()
        mons.late = True
        code, reply = self.call(ch, call='auth get', args={'entity': 'mgr.h1'}, deadline=0.05, dispatch_id='%016x' % 740)
        self.assertEqual(reply, {'outcome': 'unknown'})
        self.assertTrue(wait_until(lambda: mons.pending))
        mons.pending[0].complete(0, '[{"key": "secret"}]', '')
        time.sleep(0.05)
        self.assertEqual(ch.outcome('%016x' % 740)[0], 404)  # a late completion is not fetched past the check

    def test_the_ledger_in_pages(self):
        ch, mons = self.channel()
        entries = [('cephadm-talos/ledger/%020d-%010d-op-%016x' % (5, i, i), {'id': 'op-%016x' % i, 'pad': 'x' * 1000}) for i in range(1, 400)]
        ch.authority = lambda: (FakeLedger(entries), lg.Fold(inventory()))
        got, after = [], ''
        while True:
            code, reply = self.call(ch, call='ledger', args={'after': after}, dispatch_id='%016x' % (800 + len(got)))
            self.assertEqual((code, reply['outcome']), (200, 'done'))
            page = json.loads(reply['out'])
            got += [k for k, _ in page['entries']]
            if not page['more']:
                break
            after = got[-1]
        self.assertEqual(got, [k for k, _ in entries])
        self.assertEqual([p for _, p in mons.sent if p != 'mgr dump'], [])  # answered by the module

    def test_keys_below_the_prefix_in_pages(self):
        ch, mons = self.channel()
        base = 'mgr/cephadm/talos/inc/42/'
        mine = sorted(base + 'rec/%d/orphan.%d' % (i, j) for i in range(100) for j in range(60))  # 6000 keys, about 280 KiB
        mons.keys = ['mgr/cephadm/inventory', 'mgr/cephadm/talos/inc/420/manifest/1', 'config/global/x'] + mine[::-1]
        got, after, pages = [], '', 0
        while True:
            code, reply = self.call(ch, call='config-key keys', args={'prefix': base, 'after': after}, dispatch_id='%016x' % (500 + pages))
            self.assertEqual((code, reply['outcome'], reply['r']), (200, 'done', 0), reply)
            self.assertLess(len(reply['out']), b.MAX_OUTPUT)
            page = json.loads(reply['out'])
            got += page['keys']
            pages += 1
            if not page['more']:
                break
            after = page['keys'][-1]
        self.assertEqual(got, mine)
        self.assertGreater(pages, 1)
        self.assertEqual(mons.sent[-1][1], 'config-key ls')  # keys only: no value reaches the mgr
        mons.keys = {'not': 'a list'}
        code, reply = self.call(ch, call='config-key keys', args={'prefix': base, 'after': ''}, dispatch_id='ce' * 8)
        self.assertEqual((reply['outcome'], reply['r']), ('done', -22))

    def test_answered_calls_are_not_kept_long(self):
        ch, mons = self.channel()
        k = 'mgr/cephadm/talos/inc/42/manifest/1'
        for i in range(2 * b.MAX_RECORDS):  # reads are dropped once answered
            self.assertEqual(self.call(ch, call='config-key get', args={'key': k}, dispatch_id='%016x' % i)[0], 200)
        self.assertEqual(ch.outcome('%016x' % 0)[0], 404)
        self.assertEqual(self.call(ch, call='config-key rm', args={'key': k}, dispatch_id='ef' * 8)[1]['outcome'], 'done')
        self.assertEqual(ch.outcome('ef' * 8)[1]['outcome'], 'done')  # a write's answer may have been lost
        old = b.ANSWERED_KEEP
        b.ANSWERED_KEEP = 0.0
        self.addCleanup(setattr, b, 'ANSWERED_KEEP', old)
        time.sleep(0.01)
        self.assertEqual(ch.outcome('ef' * 8)[0], 404)
        # an unknown outcome stays for LATE_KEEP after it completes
        mons.late = True
        self.assertEqual(self.call(ch, call='config-key rm', args={'key': k}, deadline=0.01, dispatch_id='fe' * 8)[1]['outcome'], 'unknown')
        self.assertTrue(wait_until(lambda: mons.pending))
        mons.pending[0].complete(0, '', '')
        self.assertTrue(wait_until(lambda: ch.outcome('fe' * 8)[1]['outcome'] == 'done'))
        time.sleep(0.01)
        self.assertEqual(ch.outcome('fe' * 8)[1]['outcome'], 'done')

    def test_refused_until_captured(self):
        mons = Mons([mgrmap(10, 'other')])
        cmds = mons.commands(2)
        self.addCleanup(cmds.stop)
        lead = b.Leadership('h1', mgrmap(10, 'other'), cmds)
        ch = b.Channel('f1', 'h1', lead, cmds, None, b'', m.require_identity, Log(), authority())
        self.assertEqual(self.call(ch)[0], 503)

    def test_a_dispatch_id_runs_once(self):
        ch, mons = self.channel()
        rm = {'call': 'config-key rm', 'args': {'key': 'mgr/cephadm/talos/inc/42/x'}}
        self.assertEqual(self.call(ch, dispatch_id='aa' * 8, **rm)[1]['outcome'], 'done')
        self.assertEqual(self.call(ch, dispatch_id='aa' * 8, **rm)[0], 409)  # also after an immediate completion
        self.assertEqual(ch.outcome('aa' * 8)[1]['outcome'], 'done')
        # concurrent reuse: exactly one runs
        mons.late = True
        codes = []
        ts = [threading.Thread(target=lambda: codes.append(self.call(ch, deadline=0.05, dispatch_id='bb' * 8)[0])) for _ in range(5)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(sorted(codes), [200, 409, 409, 409, 409])
        self.assertTrue(wait_until(lambda: len([p for _, p in mons.sent if p != 'mgr dump']) == 2), mons.sent)

    def test_deadline_unknown_then_outcome(self):
        ch, mons = self.channel()
        mons.late = True
        code, reply = self.call(ch, deadline=0.01, dispatch_id='ab' * 8)
        self.assertEqual((code, reply), (200, {'outcome': 'unknown'}))
        self.assertEqual(ch.outcome('ab' * 8), (200, {'outcome': 'unknown'}))
        self.assertTrue(wait_until(lambda: mons.pending))
        mons.pending[0].complete(0, 'late out', '')
        self.assertTrue(wait_until(lambda: ch.outcome('ab' * 8)[1]['outcome'] == 'done'))
        self.assertEqual(ch.outcome('ab' * 8), (200, {'outcome': 'done', 'r': 0, 'out': 'late out', 'outs': ''}))
        self.assertEqual(ch.outcome('cd' * 8)[0], 404)

    def test_pending_calls_keep_their_slot_and_record(self):
        ch, mons = self.channel(n=2)
        mons.late = True
        old = b.LATE_KEEP
        b.LATE_KEEP = 0.0
        self.addCleanup(setattr, b, 'LATE_KEEP', old)
        for i in range(2):
            self.assertEqual(self.call(ch, deadline=0.01, dispatch_id='%016x' % i)[1]['outcome'], 'unknown')
        time.sleep(0.02)
        self.assertEqual(self.call(ch, deadline=0.01, dispatch_id='%016x' % 9)[0], 429)  # expiry frees nothing pending
        self.assertEqual(ch.outcome('%016x' % 0)[0], 200)
        self.assertTrue(wait_until(lambda: len(mons.pending) == 2))
        mons.pending[0].complete(0, '', '')
        self.assertTrue(wait_until(lambda: self.call(ch, deadline=0.01, dispatch_id='%016x' % 10)[0] == 200))
        # completed outcomes do expire
        self.assertTrue(wait_until(lambda: ch.outcome('%016x' % 0)[0] == 404))

    def test_kept_outcomes_are_bounded(self):
        ch, mons = self.channel()
        rm = {'call': 'config-key rm', 'args': {'key': 'mgr/cephadm/talos/inc/42/x'}}
        for i in range(b.MAX_RECORDS):
            self.assertEqual(self.call(ch, dispatch_id='%016x' % i, **rm)[0], 200)
        # answered outcomes make room, oldest first
        self.assertEqual(self.call(ch, dispatch_id='%016x' % 999, **rm)[0], 200)
        self.assertEqual(ch.outcome('%016x' % 0)[0], 404)
        self.assertEqual(ch.outcome('%016x' % 1)[0], 200)
        # unknown outcomes do not
        mons.late = True
        for k in list(ch.records):
            del ch.records[k]
        for i in range(b.MAX_RECORDS):
            ch.records['%016x' % (2000 + i)] = b.Record()
        self.assertEqual(self.call(ch, dispatch_id='%016x' % 998, deadline=0.01, **rm)[0], 429)

    def test_changes_only_while_active_and_below_the_own_incarnation(self):
        ch, mons = self.channel()
        own, other = 'mgr/cephadm/talos/inc/42/rec/1/x', 'mgr/cephadm/talos/inc/41/rec/1/x'
        for i, (call, args) in enumerate((('config-key set', {'key': other, 'value': 'v'}), ('config-key rm', {'key': other}),
                                          ('config-key set', {'key': 'mgr/cephadm/talos/inc/cli/manifest/1', 'value': 'v'}),
                                          ('config-key rm', {'key': 'mgr/cephadm/talos/inc/420/x'}))):
            self.assertEqual(self.call(ch, call=call, args=args, dispatch_id='%016x' % (600 + i))[0], 400, (call, args))
        self.assertEqual(self.call(ch, call='config-key get', args={'key': other}, dispatch_id='%016x' % 610)[0], 200)  # reads stay cluster-wide
        self.assertEqual(self.call(ch, call='config-key set', args={'key': own, 'value': 'v'}, dispatch_id='%016x' % 611)[1]['outcome'], 'done')
        # another mgr became active: no change goes out, reads still do
        mons.maps = [mgrmap(43, 'h2')]
        before = [p for _, p in mons.sent if p != 'mgr dump']
        for i, (call, args) in enumerate((('config-key set', {'key': own, 'value': 'v'}), ('config-key rm', {'key': own}),
                                          ('auth get-or-create', {'entity': 'mgr.h1', 'operation': 'op-%016x' % 1}))):
            self.assertEqual(self.call(ch, call=call, args=args, dispatch_id='%016x' % (620 + i))[0], 409, call)
        self.assertEqual([p for _, p in mons.sent if p != 'mgr dump'], before)
        self.assertEqual(self.call(ch, call='health', args={}, dispatch_id='%016x' % 630)[0], 200)
        # no answer from the mons: refused, not sent
        mons.maps = [None]
        old = b.MGR_DUMP_DEADLINE
        b.MGR_DUMP_DEADLINE = 0.05
        self.addCleanup(setattr, b, 'MGR_DUMP_DEADLINE', old)
        self.assertEqual(self.call(ch, call='config-key rm', args={'key': own}, dispatch_id='%016x' % 631)[0], 409)

    def test_large_output_is_not_kept_in_full(self):
        ch, mons = self.channel()
        send = mons.send
        mons.send = lambda res, cmd: send(res, cmd) if json.loads(cmd)['prefix'] == 'mgr dump' else res.complete(0, 'x' * (b.MAX_OUTPUT + 1), '')
        cmds = b.Commands(mons.send, lambda: b.Job({}), 1, 'big')
        self.addCleanup(cmds.stop)
        ch.commands = cmds
        reply = self.call(ch, dispatch_id='ee' * 8, call='config-key rm', args={'key': 'mgr/cephadm/talos/inc/42/x'})[1]
        self.assertEqual((reply['outcome'], reply['r']), ('done', 0))
        self.assertNotIn('out', reply)
        kept = ch.records['ee' * 8].job
        self.assertEqual((kept.outb, kept.outs, kept.too_large), ('', '', True))


def pki():
    """A CA, an agent client certificate and a mgr server certificate for 127.0.0.1."""
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ca')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(1).not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
                         critical=True)
          .sign(ca_key, hashes.SHA256()))

    def leaf(uri, usage, ip=False):
        k = ec.generate_private_key(ec.SECP256R1())
        sans = [x509.UniformResourceIdentifier(uri)]
        if ip:
            import ipaddress
            sans.append(x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
        c = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uri)])).issuer_name(ca_name)
             .public_key(k.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=1))
             .add_extension(x509.SubjectAlternativeName(sans), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
             .add_extension(x509.ExtendedKeyUsage([usage]), critical=False).sign(ca_key, hashes.SHA256()))
        return (c.public_bytes(serialization.Encoding.PEM),
                k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))

    d = tempfile.mkdtemp()
    files = {}
    for name, data in (('ca.crt', ca.public_bytes(serialization.Encoding.PEM)),
                       ('ca.key', ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                                       serialization.NoEncryption()))) + \
            tuple(zip(('srv.crt', 'srv.key'), leaf('cephadm-talos://f1/mgr/h1', ExtendedKeyUsageOID.SERVER_AUTH, True))) + \
            tuple(zip(('cli.crt', 'cli.key'), leaf('cephadm-talos://f1/agent/h1', ExtendedKeyUsageOID.CLIENT_AUTH))):
        files[name] = os.path.join(d, name)
        with open(files[name], 'wb') as f:
            f.write(data)
    return files


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.files = pki()
        lmons = Mons([mgrmap(42, 'h1')])
        lcmds = lmons.commands(2)
        self.addCleanup(lcmds.stop)
        lead = b.Leadership('h1', mgrmap(42, 'h1'), lcmds)
        self.assertTrue(lead.capture())
        ctx = b.server_context(self.files['ca.crt'], self.files['srv.crt'], self.files['srv.key'])
        mons = Mons([mgrmap(42, 'h1')])
        cmds = mons.commands(2)
        self.addCleanup(cmds.stop)
        self.ch = b.Channel('f1', 'h1', lead, cmds, ctx, b.read(self.files['srv.key']), m.require_identity, Log(), authority())
        self.port, self.bridge_port = free_port(), free_port()
        self.ch.start(self.port, self.bridge_port)
        self.addCleanup(self.ch.stop)

    def request(self, method, path, port=None, body=None):
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.files['ca.crt'])
        ctx.load_cert_chain(self.files['cli.crt'], self.files['cli.key'])
        conn = http.client.HTTPSConnection('127.0.0.1', port or self.port, context=ctx, timeout=5)
        try:
            conn.request(method, path, body=body, headers={'Content-Type': 'application/json'} if body else {})
            return conn.getresponse().status
        finally:
            conn.close()

    def get(self, path, port=None):
        return self.request('GET', path, port)

    def test_the_bridge_is_on_loopback_only(self):
        self.assertEqual(self.ch.bridge_server.server_address[0], '127.0.0.1')
        self.assertEqual(self.ch.server.server_address[0], '0.0.0.0')
        call = json.dumps({'version': 1, 'call': 'health', 'args': {}, 'deadline': 5, 'dispatch_id': 'ab' * 8})
        # the public port answers confirmations only, the loopback port the bridge only
        self.assertEqual(self.request('POST', '/v1/bridge', body=call), 404)
        self.assertEqual(self.get('/v1/bridge/' + 'ab' * 8), 404)
        self.assertEqual(self.request('POST', '/v1/bridge', self.bridge_port, call), 200)
        self.assertEqual(self.get('/v1/bridge/' + 'cd' * 8, self.bridge_port), 404)  # unknown id, but served
        self.assertEqual(self.request('POST', '/v1/confirm', self.bridge_port, json.dumps(challenge(host='h1'))), 404)

    def test_a_silent_connection_does_not_block_others(self):
        silent = socket.create_connection(('127.0.0.1', self.port))
        self.addCleanup(silent.close)
        start = time.monotonic()
        self.assertEqual(self.get('/v1/bridge/' + 'ab' * 8), 404)
        self.assertLess(time.monotonic() - start, 2)

    def test_stop_closes_open_connections(self):
        silent = socket.create_connection(('127.0.0.1', self.port))
        self.addCleanup(silent.close)
        time.sleep(0.1)
        start = time.monotonic()
        self.ch.stop()
        self.assertLess(time.monotonic() - start, 3)
        silent.settimeout(3)
        self.assertEqual(silent.recv(1), b'')  # closed by the server
        for port in (self.port, self.bridge_port):
            with self.assertRaises(OSError):
                self.get('/v1/bridge/' + 'ab' * 8, port)


class ServerCloseTest(unittest.TestCase):
    def test_a_connection_after_close_all_is_refused(self):
        srv = b.Server(('127.0.0.1', 0), object, ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
        self.addCleanup(srv.server_close)
        srv.close_all()
        a, c = socket.socketpair()
        self.addCleanup(c.close)
        srv.process_request(a, ('127.0.0.1', 1))
        self.assertEqual(len(srv.open), 0)
        c.settimeout(2)
        self.assertEqual(c.recv(1), b'')  # closed at once
        self.assertTrue(srv.admit.acquire(blocking=False))  # its admission was returned


class PostJSONTest(unittest.TestCase):
    def test_a_silent_handshake_is_cut_at_the_deadline(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        start = time.monotonic()
        with self.assertRaises(Exception):
            b.post_json('127.0.0.1', srv.getsockname()[1], ssl.create_default_context(), '/x', b'{}', 0.5, lambda c: None)
        self.assertLess(time.monotonic() - start, 1.0)

    def test_absolute_deadline(self):
        """A peer that trickles bytes forever cannot hold the caller past the deadline."""
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        stop = threading.Event()

        def trickle():
            c, _ = srv.accept()
            while not stop.is_set():
                try:
                    c.send(b'\x16')
                except OSError:
                    return
                time.sleep(0.1)
        threading.Thread(target=trickle, daemon=True).start()
        self.addCleanup(stop.set)
        self.addCleanup(srv.close)
        start = time.monotonic()
        with self.assertRaises(Exception):
            b.post_json('127.0.0.1', port, ssl.create_default_context(), '/x', b'{}', 0.5, lambda c: None)
        self.assertLess(time.monotonic() - start, 2)


if __name__ == '__main__':
    unittest.main()


class LedgerCallsTest(unittest.TestCase):
    def setUp(self):
        import test_ledger
        lmons = Mons([mgrmap(42, 'h1')])
        lcmds = lmons.commands(2)
        self.addCleanup(lcmds.stop)
        lead = b.Leadership('h1', mgrmap(42, 'h1'), lcmds)
        self.assertTrue(lead.capture())
        self.mons = Mons([mgrmap(42, 'h1')])
        self.mons.kv = {}
        cmds = self.mons.commands(4, 'bridge')
        self.addCleanup(cmds.stop)
        files = pki()
        self.ca = open(files['ca.crt'], 'rb').read()
        self.mons.kv[b.SECRET_PREFIX + 'agent-ca.key'] = open(files['ca.key']).read()
        self.led = lg.Ledger(test_ledger.Mons(), 42, 5)
        self.led.open()
        inv = inventory('mon.h1@h1', 'mgr.h1@h1')
        self.ch = b.Channel('f1', 'h1', lead, cmds, None, b'', m.require_identity, Log(), lambda: (self.led, lg.Fold(inv, self.led.executable())), self.ca)
        self.n = 0

    def call(self, call, **args):
        self.n += 1
        return self.ch.bridge({'version': 1, 'call': call, 'args': args, 'deadline': 5, 'dispatch_id': '%016x' % (900 + self.n)})

    def accept(self, kind, daemon, host):
        op = {'id': 'op-%016x' % (100 + self.n), 'kind': kind, 'host': host}
        if kind == 'create_osd':
            op['device'] = '/dev/sdb'
        self.n += 1
        if daemon:
            op['daemon'] = daemon
        return self.led.append(op)[1]['id']

    def test_a_mgr_from_add_to_retirement(self):
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID
        add = self.accept('add_daemon', 'mgr.h2', 'h2')
        code, reply = self.call('mgr cert', operation=add)
        self.assertEqual((code, reply['outcome']), (200, 'done'), reply)
        out = json.loads(reply['out'])
        srv = x509.load_pem_x509_certificate(out['server_cert'].encode())
        cli = x509.load_pem_x509_certificate(out['client_cert'].encode())
        san = srv.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.UniformResourceIdentifier), ['cephadm-talos://f1/mgr/h2'])
        self.assertEqual(san.get_values_for_type(x509.DNSName), ['h2'])
        self.assertEqual([str(i) for i in san.get_values_for_type(x509.IPAddress)], ['10.0.0.2'])
        self.assertEqual(list(cli.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value), [ExtendedKeyUsageOID.CLIENT_AUTH])
        # the keys are secrets of this attempt, matching the certificates
        prefix = '%sissued/%s/%s/' % (b.SECRET_PREFIX, add, out['attempt'])
        key = serialization.load_pem_private_key(self.mons.kv[prefix + 'mgr-server.key'].encode(), password=None)
        self.assertEqual(key.public_key().public_numbers(), srv.public_key().public_numbers())
        name = 'issued/%s/%s/mgr-server.key' % (add, out['attempt'])
        self.assertEqual(self.call('secret get', name=name)[1]['outcome'], 'done')
        self.assertEqual(self.call('secret get', name='issued/op-%016x/%s/mgr-server.key' % (7, out['attempt']))[0], 400)
        self.assertEqual(self.call('auth get-or-create', entity='mgr.h2', operation=add)[1]['outcome'], 'done')
        self.assertEqual(self.ch.outcome('%016x' % (900 + self.n))[0], 404)  # never kept
        # not for the CLI's mgr, nor under another operation
        self.assertEqual(self.call('auth get-or-create', entity='mgr.h1', operation=add)[0], 400)
        # not for a restart, nor for a mon's add
        self.assertEqual(self.call('mgr cert', operation=self.accept('restart', 'mgr.h1', 'h1'))[0], 400)
        self.assertEqual(self.call('mgr cert', operation=self.accept('add_daemon', 'mon.h1', 'h1'))[0], 400)
        # the removal: a mutation not answered yet holds it, with the generation closed
        rm = self.accept('remove_daemon', 'mgr.h2', 'h2')
        stuck = b.Job({})
        self.ch._track('mgr.h2', stuck)
        self.assertEqual(self.call('retire', operation=rm)[0], 409)
        self.assertEqual(self.call('auth get-or-create', entity='mgr.h2', operation=add)[0], 400)
        self.assertEqual(self.call('mgr cert', operation=add)[0], 400)
        stuck.complete(0, '', '')
        # an auth rm without an answer is tracked: the retirement waits for it
        self.mons.late = True
        self.assertEqual(self.call('retire', operation=rm)[0], 503)
        self.assertEqual(self.call('retire', operation=rm)[0], 409)
        self.mons.late = False
        self.mons.pending[0].complete(0, '', '')
        self.mons.auth_rm.append('mgr.h2')  # the late answer was that removal
        self.assertTrue(wait_until(lambda: not self.ch._pending('mgr.h2')))
        self.assertEqual(self.call('retire', operation=rm)[1]['outcome'], 'done')
        self.assertEqual(self.mons.auth_rm, ['mgr.h2', 'mgr.h2'])
        self.assertFalse([k for k in self.mons.kv if k.startswith(b.SECRET_PREFIX + 'issued/')])
        self.assertEqual([e['kind'] for _, e in self.led.executable() if e['id'].startswith('m-')], ['close', 'retire'])
        self.assertEqual(self.call('retire', operation=rm)[1]['outcome'], 'done')  # once
        self.assertEqual(self.mons.auth_rm, ['mgr.h2', 'mgr.h2'])
        for call, args in (('secret get', {'name': name}), ('auth get', {'entity': 'mgr.h2'})):
            self.assertEqual(self.call(call, **args)[0], 400, call)
        # then the host, now without daemons
        rmh = self.accept('remove_host', None, 'h2')
        self.assertEqual(self.call('retire host', operation=rmh)[1]['outcome'], 'done')
        self.assertNotIn('h2', self.ch.authority()[1].hosts)
        # a host with daemons is not retired
        self.assertEqual(self.call('retire host', operation=self.accept('remove_host', None, 'h1'))[0], 400)

    def test_the_cli_keys_of_a_removed_mgr_go_too(self):
        for k in ('host/h1/mgr-server.key', 'host/h1/mgr-client.key', 'host/h1/agent-server.key'):
            self.mons.kv[b.SECRET_PREFIX + k] = 'x'
        for i in range(6000):  # a listing larger than the output limit
            self.mons.kv['mgr/cephadm/talos/inc/42/rec/%d/orphan.%d' % (i, i)] = 'x'
        rm = self.accept('remove_daemon', 'mgr.h1', 'h1')
        self.assertEqual(self.call('retire', operation=rm)[1]['outcome'], 'done')
        self.assertEqual(sorted(k for k in self.mons.kv if '/host/' in k), [b.SECRET_PREFIX + 'host/h1/agent-server.key'])


class ApprovalCallTest(unittest.TestCase):
    def test_the_newest_approval(self):
        ch, mons = BridgeTest.channel(self)
        mons.kv = {}
        call = lambda n: ch.bridge({'version': 1, 'call': 'approval', 'args': {}, 'deadline': 5, 'dispatch_id': '%016x' % n})
        self.assertEqual(call(1)[1]['out'], '')
        for serial in (1, 2, 10):
            mons.kv['cephadm-talos/approvals/%020d' % serial] = '{"serial": %d}' % serial
        mons.kv['cephadm-talos/approvals/x'] = 'not one'
        self.assertEqual(call(2)[1]['out'], '{"serial": 10}')
        self.assertEqual(ch.bridge({'version': 1, 'call': 'approval', 'args': {'x': 1}, 'deadline': 5, 'dispatch_id': '%016x' % 3})[0], 400)


class CreationTest(LedgerCallsTest):
    def test_an_osd_from_bind_to_confirmation(self):
        create = self.accept('create_osd', None, 'h1')
        self.led.entries  # noqa
        # bootstrap-osd only once the creation is bound
        self.assertEqual(self.call('auth get', entity='client.bootstrap-osd', operation=create)[0], 400)
        bind = dict(operation=create, serial='QM00003', link='/dev/disk/by-id/ata-QEMU_HARDDISK_QM00003', job='0123456789abcdef')
        self.assertEqual(self.call('bind disk', **bind)[1]['outcome'], 'done')
        self.assertEqual(self.call('bind disk', **bind)[1]['outcome'], 'done')  # the same again
        self.assertEqual(self.call('bind disk', **dict(bind, serial='QM00009'))[0], 400)
        self.assertEqual(self.call('auth get', entity='client.bootstrap-osd', operation=create)[1]['outcome'], 'done')
        # confirmed only when the OSD is up and its metadata names the host and disk
        self.assertEqual(self.call('confirm osd', operation=create, osd=7)[0], 409)
        uuid = '8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f'
        self.mons.osds = [{'osd': 7, 'uuid': uuid, 'up': 1}]
        self.mons.metadata[7] = {'hostname': 'h2', 'device_ids': 'sdb=QEMU_HARDDISK_QM00003'}
        self.assertEqual(self.call('confirm osd', operation=create, osd=7)[0], 409)
        self.mons.metadata[7] = {'hostname': 'h1', 'device_ids': 'sdb=QEMU_HARDDISK_QM00004'}
        self.assertEqual(self.call('confirm osd', operation=create, osd=7)[0], 409)
        self.mons.metadata[7] = {'hostname': 'h1', 'device_ids': 'sdb=QEMU_HARDDISK_QM00003'}
        self.assertEqual(self.call('confirm osd', operation=create, osd=7)[1]['outcome'], 'done')
        fold = self.ch.authority()[1]
        self.assertEqual((fold.daemons.get('osd.7'), fold.uuids.get('osd.7')), ('h1', uuid))
        # confirmed: no more bootstrap-osd, no close
        self.assertEqual(self.call('auth get', entity='client.bootstrap-osd', operation=create)[0], 400)
        self.assertEqual(self.call('close create', operation=create)[0], 400)

    def test_a_closed_creation_releases_nothing(self):
        create = self.accept('create_osd', None, 'h1')
        self.call('bind disk', operation=create, serial='QM00003', link='/dev/disk/by-id/ata-x_QM00003', job='0123456789abcdef')
        self.assertEqual(self.call('close create', operation=create)[1]['outcome'], 'done')
        self.assertEqual(self.call('auth get', entity='client.bootstrap-osd', operation=create)[0], 400)
        self.assertEqual(self.call('confirm osd', operation=create, osd=7)[0], 400)
        # not for another kind of operation
        self.assertEqual(self.call('auth get', entity='client.bootstrap-osd', operation=self.accept('restart', 'mgr.h1', 'h1'))[0], 400)

    def test_device_ids(self):
        for ids, ok in (('sda=QEMU_HARDDISK_QM00001', True), ('sda=QM00001', True), ('nvme0n1=Micron_MTFD_QM00001_1', True),
                        ('sda=QEMU_HARDDISK_QM000012', False), ('sda=QEMU_HARDDISK_XQM00001', False), ('', False),
                        ('sdb=OTHER,sda=QEMU_HARDDISK_QM00001', True)):
            self.assertEqual(b.device_matches(ids, 'QM00001'), ok, ids)


class MonRemovalTest(unittest.TestCase):
    setUp, call, accept = LedgerCallsTest.setUp, LedgerCallsTest.call, LedgerCallsTest.accept

    def test_mon_rm_keeps_a_quorum_and_retires_without_auth_rm(self):
        inv = inventory('mon.h1@h1', 'mon.h2@h2', 'mgr.h1@h1')
        self.ch.authority = lambda: (self.led, lg.Fold(inv, self.led.executable()))
        rm = self.accept('remove_daemon', 'mon.h2', 'h2')
        # h1 is down: the quorum without h2 would be empty
        self.mons.monmap, self.mons.quorum = ['h1', 'h2'], ['h2']
        self.assertEqual(self.call('mon rm', operation=rm)[0], 409)
        self.assertEqual(self.mons.mon_rm, [])
        # one of two healthy mons can go (unlike mon ok-to-stop)
        self.mons.quorum = ['h1', 'h2']
        self.assertEqual(self.call('mon rm', operation=rm)[1]['outcome'], 'done')
        self.assertEqual((self.mons.mon_rm, self.mons.monmap), (['h2'], ['h1']))
        # once out of the monmap it is done, without another mon rm
        self.assertEqual(self.call('mon rm', operation=rm)[1]['outcome'], 'done')
        self.assertEqual(self.mons.mon_rm, ['h2'])
        self.assertEqual(self.call('retire', operation=rm)[1]['outcome'], 'done')
        self.assertEqual(self.mons.auth_rm, [])
        self.assertNotIn('mon.h2', self.ch.authority()[1].daemons)
        # only for a mon's removal
        other = self.accept('remove_daemon', 'mgr.h1', 'h1')
        self.assertEqual(self.call('mon rm', operation=other)[0], 400)


class RemovalTest(LedgerCallsTest):
    UUID = '8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f'

    def setUp(self):
        super().setUp()
        inv = inventory('mon.h1@h1', 'mgr.h1@h1', 'osd.3@h1')
        inv['daemons'][-1]['osd_uuid'] = self.UUID
        self.ch.authority = lambda: (self.led, lg.Fold(inv, self.led.executable()))

    def remove(self, force=False, uuid=None):
        op = {'id': 'op-%016x' % (300 + self.n), 'kind': 'remove_osd', 'daemon': 'osd.3', 'host': 'h1', 'uuid': uuid or self.UUID, 'zap': True, 'force': force}
        self.n += 1
        return self.led.append(op)[1]['id']

    def test_out_drain_and_retire(self):
        rm = self.remove()
        self.mons.osds = [{'osd': 3, 'uuid': self.UUID, 'up': 1}]
        self.assertEqual(self.call('osd out', operation=rm)[1]['outcome'], 'done')
        # not safe to destroy yet: no drained entry, no retirement
        self.assertEqual(self.call('drain', operation=rm)[0], 409)
        self.assertEqual(self.call('retire', operation=rm)[0], 400)
        self.mons.safe = [3]
        # nor while it is in (an empty OSD is safe to destroy)
        self.mons.osds = [{'osd': 3, 'uuid': self.UUID, 'up': 1, 'in': 1}]
        self.assertEqual(self.call('drain', operation=rm)[0], 409)
        self.mons.osds = [{'osd': 3, 'uuid': self.UUID, 'up': 1, 'in': 0}]
        self.assertEqual(self.call('drain', operation=rm)[1]['outcome'], 'done')
        # it must be down before the purge
        self.assertEqual(self.call('retire', operation=rm)[0], 409)
        # stopped, safe-to-destroy cannot tell any more in a degraded cluster:
        # the drained entry is the check; an OSD marked in again is not purged
        self.mons.safe = []
        self.mons.osds = [{'osd': 3, 'uuid': self.UUID, 'up': 0, 'in': 1}]
        for call in ('osd out', 'drain', 'retire'):
            self.assertEqual(self.call(call, operation=rm)[0], 409, call)
        self.assertEqual(self.mons.osd_calls, ['osd out'])  # not out again
        self.mons.osds = [{'osd': 3, 'uuid': self.UUID, 'up': 0, 'in': 0}]
        self.assertEqual(self.call('retire', operation=rm)[1]['outcome'], 'done')
        self.assertEqual(self.mons.osd_calls, ['osd out', 'osd purge-actual'])
        self.assertNotIn('osd.3', self.ch.authority()[1].daemons)
        # once
        self.assertEqual(self.call('retire', operation=rm)[1]['outcome'], 'done')
        self.assertEqual(self.mons.osd_calls, ['osd out', 'osd purge-actual'])

    def test_force_skips_the_safety_check_and_a_gone_id_finishes(self):
        rm = self.remove(force=True)
        self.mons.osds = [{'osd': 3, 'uuid': self.UUID, 'up': 1}]
        self.assertEqual(self.call('drain', operation=rm)[1]['outcome'], 'done')
        self.mons.osds = []  # an earlier purge landed
        self.assertEqual(self.call('retire', operation=rm)[1]['outcome'], 'done')
        self.assertEqual(self.mons.osd_calls, [])

    def test_another_osd_under_the_id_is_left_alone(self):
        rm = self.remove()
        self.mons.osds = [{'osd': 3, 'uuid': '00000000-0000-0000-0000-000000000000', 'up': 0}]
        for call in ('osd out', 'drain', 'retire'):
            self.assertEqual(self.call(call, operation=rm)[0], 400, call)
        self.assertEqual(self.mons.osd_calls, [])
        # nor a removal naming another uuid than the fold's
        other = self.remove(uuid='11111111-1111-1111-1111-111111111111')
        self.assertEqual(self.call('osd out', operation=other)[0], 400)
