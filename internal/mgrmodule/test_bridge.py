"""Tests of bridge.py, the module's side of the agent channel (plan 03, step 1).
Run with hack/mgrmodule-test.sh."""
import base64
import json
import threading
import time
import unittest

import test_talos  # noqa: F401  (stubs ceph_module before the talos package is imported)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from talos import bridge as b


class Log:
    def exception(self, *a):
        pass


class Mons:
    """A fake send_command: answers per prefix, optionally late."""

    def __init__(self, maps):
        self.maps = maps  # list of mgr dump answers, the last one repeats
        self.calls = []
        self.late = False
        self.pending = []

    def __call__(self, cmd, deadline):
        self.calls.append(cmd['prefix'])
        out = b.Outcome()
        if self.late:
            self.pending.append(out)
            out.ev.wait(min(deadline, 0.05))
            return out
        if cmd['prefix'] == 'mgr dump':
            m = self.maps.pop(0) if len(self.maps) > 1 else self.maps[0]
            if m is None:
                out.ev.wait(min(deadline, 0.05))  # no answer within the deadline
                return out
            out.complete(0, json.dumps(m), '')
        else:
            out.complete(0, json.dumps({'status': 'HEALTH_OK'}), '')
        return out


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


class LeadershipTest(unittest.TestCase):
    def test_capture_only_when_the_mons_show_this_mgr_active(self):
        mons = Mons([mgrmap(10, 'other'), None, mgrmap(42, 'h1', 9)])
        lead = b.Leadership('h1', mons)
        self.assertFalse(lead.capture())  # another mgr is active
        self.assertFalse(lead.capture())  # no answer from the mons
        self.assertTrue(lead.capture())
        self.assertEqual(lead.captured(), (42, 9))
        n = len(mons.calls)
        self.assertTrue(lead.capture())   # captured once, no more lookups
        self.assertEqual(len(mons.calls), n)

    def test_still_active_needs_a_fresh_map_with_the_captured_gid(self):
        mons = Mons([mgrmap(42, 'h1'), mgrmap(42, 'h1'), mgrmap(43, 'h1'), None])
        lead = b.Leadership('h1', mons)
        self.assertTrue(lead.capture())
        self.assertTrue(lead.still_active())
        self.assertFalse(lead.still_active())  # restarted under another gid
        self.assertFalse(lead.still_active())  # mons do not answer


class ConfirmTest(unittest.TestCase):
    def channel(self, maps):
        key, pem = key_pair()
        lead = b.Leadership('h1', Mons(maps))
        ch = b.Channel('f1', 'h1', lead, Mons([mgrmap(42, 'h1')]), None, pem, None, Log())
        return ch, lead, key

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
        conf = json.loads(payload)
        self.assertEqual(conf, {'version': 1, 'fsid': 'f1', 'mgr': 'h1', 'gid': 42, 'session': 'ab' * 16, 'host': 'h3',
                                'revision': 7, 'operation': 'op-1', 'inputs_hash': 'cd' * 32, 'challenge': 'ef' * 16})

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
    def channel(self):
        lead = b.Leadership('h1', Mons([mgrmap(42, 'h1')]))
        self.assertTrue(lead.capture())
        mons = Mons([mgrmap(42, 'h1')])
        return b.Channel('f1', 'h1', lead, mons, None, b'', None, Log()), mons

    def call(self, ch, **kw):
        req = {'version': 1, 'call': 'health', 'args': {}, 'deadline': 5, 'dispatch_id': '12' * 8}
        req.update(kw)
        return ch.bridge(req)

    def test_allowlist_and_shapes(self):
        ch, mons = self.channel()
        code, reply = self.call(ch)
        self.assertEqual((code, reply['outcome'], reply['r']), (200, 'done', 0))
        for kw in ({'call': 'auth get'}, {'args': {'x': 1}}, {'deadline': 0}, {'deadline': 61}, {'deadline': True},
                   {'dispatch_id': 'nothex'}, {'version': 2}, {'extra': 1}):
            self.assertEqual(self.call(ch, **kw)[0], 400, kw)
        self.assertEqual(mons.calls, ['health'])  # refused calls never reach the mons

    def test_refused_until_captured(self):
        lead = b.Leadership('h1', Mons([mgrmap(10, 'other')]))
        ch = b.Channel('f1', 'h1', lead, Mons([]), None, b'', None, Log())
        self.assertEqual(self.call(ch)[0], 503)

    def test_deadline_unknown_then_late_result(self):
        ch, mons = self.channel()
        mons.late = True
        code, reply = self.call(ch, deadline=0.01, dispatch_id='ab' * 8)
        self.assertEqual((code, reply), (200, {'outcome': 'unknown'}))
        self.assertEqual(ch.late_result('ab' * 8), (200, {'outcome': 'unknown'}))
        self.assertEqual(self.call(ch, dispatch_id='ab' * 8)[0], 409)  # a dispatch id is used once
        mons.pending[0].complete(0, 'late out', '')
        self.assertEqual(ch.late_result('ab' * 8), (200, {'outcome': 'done', 'r': 0, 'out': 'late out', 'outs': ''}))
        self.assertEqual(ch.late_result('cd' * 8)[0], 404)

    def test_outstanding_calls_are_bounded(self):
        ch, mons = self.channel()
        mons.late = True
        for i in range(b.MAX_BRIDGE_CALLS):
            self.assertEqual(self.call(ch, deadline=0.01, dispatch_id='%016x' % i)[1]['outcome'], 'unknown')
        self.assertEqual(self.call(ch, deadline=0.01, dispatch_id='%016x' % 99)[0], 429)
        mons.pending[0].complete(0, '', '')
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and self.call(ch, deadline=0.01, dispatch_id='%016x' % 100)[0] == 429:
            time.sleep(0.01)
        self.assertLess(time.monotonic(), deadline, 'a completed late call did not free its slot')
        self.assertTrue(threading.active_count() > 0)


if __name__ == '__main__':
    unittest.main()
