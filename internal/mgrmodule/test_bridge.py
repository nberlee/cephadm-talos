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
from talos import module as m


class Log:
    def exception(self, *a):
        pass


class Mons:
    """A fake send_command. Answers mgr dump from `maps` (the last repeats; None:
    no answer yet), anything else at once, or keeps every result pending when late."""

    def __init__(self, maps=None):
        self.maps = list(maps or [])
        self.sent = []      # (thread name, prefix)
        self.pending = []
        self.late = False
        self.keys = []      # answer to config-key ls

    def send(self, res, cmd):
        prefix = json.loads(cmd)['prefix']
        self.sent.append((threading.current_thread().name, prefix))
        if self.late:
            self.pending.append(res)
            return
        if prefix == 'mgr dump':
            mm = self.maps.pop(0) if len(self.maps) > 1 else self.maps[0]
            if mm is None:
                self.pending.append(res)
                return
            res.complete(0, json.dumps(mm), '')
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
        return b.Channel('f1', 'h1', lead, mons.commands(2), None, pem, m.require_identity, Log()), lead, key

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
        self.assertEqual(json.loads(payload), {'version': 1, 'fsid': 'f1', 'mgr': 'h1', 'gid': 42, 'session': 'ab' * 16,
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
        mons = Mons()
        cmds = mons.commands(n, 'bridge')
        self.addCleanup(cmds.stop)
        return b.Channel('f1', 'h1', lead, cmds, None, b'', m.require_identity, Log()), mons

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
            'auth get-or-create': ({'entity': 'client.rgw.h1-a'}, {'prefix': 'auth get-or-create', 'entity': 'client.rgw.h1-a',
                                                                  'caps': ['mon', 'allow rw', 'osd', 'allow rwx', 'mgr', 'allow rw'],
                                                                  'format': 'json'}),
        }
        for call, (args, cmd) in good.items():
            self.assertEqual(b.ALLOWLIST[call](args), cmd, call)
        for e in ('mon.', 'mgr.h1', 'osd.0', 'client.rgw.h2', 'client.bootstrap-osd'):
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
            ('auth get-or-create', {'entity': 'client.admin'}),
            ('auth get-or-create', {'entity': 'osd.1'}),
            ('auth get-or-create', {'entity': 'mon.'}),
            ('auth get-or-create', {'entity': 'mgr.h1', 'caps': ['mon', 'allow *']}),
        ]
        for call, args in bad:
            with self.assertRaises(ValueError, msg=(call, args)):
                b.ALLOWLIST[call](args)
        # the caps given out are copies: a caller cannot change the table
        b.ALLOWLIST['auth get-or-create']({'entity': 'mgr.h1'})['caps'].append('x')
        self.assertEqual(b.CREATE_CAPS['mgr'][-1], 'allow *')

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
        ch = b.Channel('f1', 'h1', lead, cmds, None, b'', m.require_identity, Log())
        self.assertEqual(self.call(ch)[0], 503)

    def test_a_dispatch_id_runs_once(self):
        ch, mons = self.channel()
        rm = {'call': 'config-key rm', 'args': {'key': 'mgr/cephadm/talos/x'}}
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
        self.assertTrue(wait_until(lambda: len(mons.sent) == 2), mons.sent)

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
        rm = {'call': 'config-key rm', 'args': {'key': 'mgr/cephadm/talos/x'}}
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

    def test_large_output_is_not_kept_in_full(self):
        ch, mons = self.channel()
        mons.send = lambda res, cmd: res.complete(0, 'x' * (b.MAX_OUTPUT + 1), '')
        cmds = b.Commands(mons.send, lambda: b.Job({}), 1, 'big')
        self.addCleanup(cmds.stop)
        ch.commands = cmds
        reply = self.call(ch, dispatch_id='ee' * 8, call='auth get-or-create', args={'entity': 'mgr.h1'})[1]
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
    for name, data in (('ca.crt', ca.public_bytes(serialization.Encoding.PEM)),) + \
            tuple(zip(('srv.crt', 'srv.key'), leaf('cephadm-talos://f1/mgr/h1', ExtendedKeyUsageOID.SERVER_AUTH, True))) + \
            tuple(zip(('cli.crt', 'cli.key'), leaf('cephadm-talos://f1/agent/h1', ExtendedKeyUsageOID.CLIENT_AUTH))):
        files[name] = os.path.join(d, name)
        with open(files[name], 'wb') as f:
            f.write(data)
    return files


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.files = pki()
        lmons = Mons([mgrmap(42, 'h1')])
        lcmds = lmons.commands(2)
        self.addCleanup(lcmds.stop)
        lead = b.Leadership('h1', mgrmap(42, 'h1'), lcmds)
        ctx = b.server_context(self.files['ca.crt'], self.files['srv.crt'], self.files['srv.key'])
        mons = Mons()
        cmds = mons.commands(2)
        self.addCleanup(cmds.stop)
        self.ch = b.Channel('f1', 'h1', lead, cmds, ctx, b.read(self.files['srv.key']), m.require_identity, Log())
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        self.port = s.getsockname()[1]
        s.close()
        self.ch.start(self.port)
        self.addCleanup(self.ch.stop)

    def get(self, path):
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.files['ca.crt'])
        ctx.load_cert_chain(self.files['cli.crt'], self.files['cli.key'])
        conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=5)
        try:
            conn.request('GET', path)
            return conn.getresponse().status
        finally:
            conn.close()

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
        with self.assertRaises(OSError):
            self.get('/v1/bridge/' + 'ab' * 8)


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
