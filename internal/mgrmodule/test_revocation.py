"""Tests of revocation.py and the module's checks against the revoked set
(plan 04, step 3). Run with hack/mgrmodule-test.sh."""
import base64
import datetime
import http.server
import json
import os
import ssl
import tempfile
import threading
import unittest

import test_talos  # noqa: F401  (stubs ceph_module before the talos package is imported)
from cryptography import x509

from talos import bridge as b
from talos import module as m
from talos import revocation as rv

NOW = datetime.datetime(2026, 11, 3, 12, 0, tzinfo=datetime.timezone.utc)


class KV:
    """A config-key store answering the commands the issuer sends."""

    def __init__(self) -> None:
        self.kv = {}
        self.silent = False

    def __call__(self, cmd, deadline):
        if self.silent:
            return None
        p, k = cmd['prefix'], cmd.get('key')
        if p == 'config-key dump':
            return 0, json.dumps({x: v for x, v in self.kv.items() if x.startswith(k)}), ''
        if p == 'config-key get':
            return (0, self.kv[k], '') if k in self.kv else (-2, '', 'ENOENT')
        if p == 'config-key set':
            self.kv[k] = cmd['val']
            return 0, '', ''
        if p == 'config-key rm':
            self.kv.pop(k, None)
            return 0, '', ''
        raise AssertionError(cmd)


def ca():
    cert, key = b.new_rgw_ca('f1')  # a CA as the CLI makes the agent CA: CRL signing allowed
    return cert.encode(), key


def crl(der):
    return x509.load_der_x509_crl(der)


class RevokedSetTest(unittest.TestCase):
    def test_entries_kept_until_a_day_after_not_after(self):
        dump = {
            rv.REVOKED_PREFIX + '7': rv.entry(NOW + datetime.timedelta(days=30), 'renewal'),
            rv.REVOKED_PREFIX + '8': rv.entry(NOW - datetime.timedelta(hours=12), 'renewal'),  # within the extra day
            rv.REVOKED_PREFIX + '9': rv.entry(NOW - datetime.timedelta(days=2), 'renewal'),   # pruned
            rv.REVOKED_PREFIX + '10': 'not json',                                             # kept, never dropped by a reader
            rv.REVOKED_PREFIX + 'x': rv.entry(NOW, 'bad key'),
        }
        revoked, old = rv.parse_revoked(dump, NOW)
        self.assertEqual(sorted(revoked), [7, 8, 10])
        self.assertEqual(old, [rv.REVOKED_PREFIX + '9'])

    def test_serials_as_the_operator_gives_them(self):
        self.assertEqual(rv.parse_serial('255'), 255)
        self.assertEqual(rv.parse_serial('0xff'), 255)
        self.assertEqual(rv.parse_serial('00:FF'), 255)
        for bad in ('0', '-1', 'zz', '0x' + 'f' * 50):
            with self.assertRaises(ValueError):
                rv.parse_serial(bad)

    def test_a_predecessors_write_after_a_takeover_counts(self):
        """Revocations are config-key entries apart from the ledger: an entry a
        stale module writes after a successor's takeover is in the set (no
        takeover cutoff applies to it)."""
        kv = KV()
        kv.kv[rv.REVOKED_PREFIX + '42'] = rv.entry(NOW + datetime.timedelta(days=1), 'removal op-1')
        revoked, _ = rv.read_revoked(kv, NOW)
        self.assertIn(42, revoked)
        kv.silent = True
        with self.assertRaises(rv.CRLError):
            rv.read_revoked(kv, NOW)


class CheckCertTest(unittest.TestCase):
    def test_only_the_agent_cas_for_that_host_and_role(self):
        cert, key = ca()
        other, other_key = ca()
        certs = b.issue_mgr_certs(cert, key.encode(), 'f1', 'h1', '10.0.0.1', 'agent')
        serial, _ = rv.check_cert(certs['client_cert'], cert, 'f1', 'agent', 'h1')
        self.assertEqual(serial, x509.load_pem_x509_certificate(certs['client_cert'].encode()).serial_number)
        for args in ((other, 'f1', 'agent', 'h1'), (cert, 'f2', 'agent', 'h1'), (cert, 'f1', 'mgr', 'h1'), (cert, 'f1', 'agent', 'h2')):
            with self.assertRaises(ValueError):
                rv.check_cert(certs['client_cert'], *args)
        with self.assertRaises(ValueError):
            rv.check_cert('garbage', cert, 'f1', 'agent', 'h1')


class IssuerTest(unittest.TestCase):
    def setUp(self):
        self.cert, key = ca()
        self.kv = KV()
        self.kv.kv['cephadm-talos/secrets/agent-ca.key'] = key

    def published(self):
        return rv.published({k: v for k, v in self.kv.kv.items() if k.startswith(rv.CRL_PREFIX)})

    def test_issue_number_publication_and_reissue(self):
        old = rv.CHUNK
        rv.CHUNK = 64  # several chunks
        self.addCleanup(setattr, rv, 'CHUNK', old)
        until = NOW + datetime.timedelta(days=30)
        iss = rv.Issuer(9)
        self.assertTrue(iss.tick(self.kv, self.cert, {5: until, 6: until}, [], NOW, 168))
        number, der = self.published()
        self.assertEqual(number, (9 << 32) + 1)
        c = crl(der)
        self.assertEqual(sorted(r.serial_number for r in c), [5, 6])
        self.assertEqual(c.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number, number)
        self.assertEqual(c.next_update_utc - c.last_update_utc, datetime.timedelta(days=7))
        self.assertTrue(c.is_signature_valid(x509.load_pem_x509_certificate(self.cert).public_key()))
        manifest = json.loads(self.kv.kv[rv.CRL_MANIFEST])
        self.assertGreater(len(manifest['chunks']), 1)
        # unchanged and fresh: nothing new
        self.assertFalse(iss.tick(self.kv, self.cert, {5: until, 6: until}, [], NOW + datetime.timedelta(hours=1), 168))
        # the set changed: the next number, the older chunks gone
        self.assertTrue(iss.tick(self.kv, self.cert, {5: until}, [], NOW + datetime.timedelta(hours=2), 168))
        number2, der2 = self.published()
        self.assertEqual(number2, number + 1)
        self.assertFalse([k for k in self.kv.kv if k.startswith('%s%d/' % (rv.CRL_PREFIX, number))])
        # daily, also unchanged; the option shortens the validity
        self.assertTrue(iss.tick(self.kv, self.cert, {5: until}, [], NOW + datetime.timedelta(days=1, hours=3), 2))
        c = crl(self.published()[1])
        self.assertEqual(c.next_update_utc - c.last_update_utc, datetime.timedelta(hours=2))
        # never more than 7 days
        iss2 = rv.Issuer(9)
        iss2.counter = 50
        iss2.tick(self.kv, self.cert, {}, [], NOW, 1000)
        c = crl(self.published()[1])
        self.assertEqual(c.next_update_utc - c.last_update_utc, datetime.timedelta(days=7))

    def test_pruning(self):
        k = rv.REVOKED_PREFIX + '9'
        self.kv.kv[k] = rv.entry(NOW - datetime.timedelta(days=3), 'old')
        revoked, old = rv.read_revoked(self.kv, NOW)
        rv.Issuer(1).tick(self.kv, self.cert, revoked, old, NOW, 168)
        self.assertNotIn(k, self.kv.kv)

    def test_a_predecessors_late_list_does_not_supersede(self):
        until = NOW + datetime.timedelta(days=30)
        pred, succ = rv.Issuer(9), rv.Issuer(10)
        pred.tick(self.kv, self.cert, {5: until}, [], NOW, 168)
        succ.tick(self.kv, self.cert, {5: until, 6: until}, [], NOW, 168)
        self.assertEqual(self.published()[0], (10 << 32) + 1)
        # the predecessor issues again later: still a lower number
        pred.tick(self.kv, self.cert, {5: until, 7: until}, [], NOW + datetime.timedelta(minutes=1), 168)
        self.assertLess(pred.number, succ.number)
        # and its write landed after the successor's: a lower number in the manifest
        parts, manifest = rv.chunks(pred.der, pred.number)
        self.kv.kv.update(parts)
        self.kv.kv[rv.CRL_MANIFEST] = manifest
        self.assertEqual(self.published()[0], pred.number)
        # the successor sees it and publishes its own again
        self.assertFalse(succ.tick(self.kv, self.cert, {5: until, 6: until}, [], NOW + datetime.timedelta(minutes=2), 168))
        self.assertEqual(self.published()[0], succ.number)

    def test_a_stale_module_never_replaces_a_successors_list(self):
        until = NOW + datetime.timedelta(days=30)
        pred, succ = rv.Issuer(9), rv.Issuer(10)
        succ.tick(self.kv, self.cert, {5: until}, [], NOW, 168)
        # the predecessor's first list after the successor's: issued, not published
        self.assertTrue(pred.tick(self.kv, self.cert, {5: until, 6: until}, [], NOW, 168))
        self.assertEqual(self.published()[0], succ.number)
        self.assertTrue([k for k in self.kv.kv if k.startswith('%s%d/' % (rv.CRL_PREFIX, succ.number))])

    def test_no_ca_key_is_an_error(self):
        del self.kv.kv['cephadm-talos/secrets/agent-ca.key']
        with self.assertRaises(rv.CRLError):
            rv.Issuer(1).tick(self.kv, self.cert, {}, [], NOW, 168)

    def test_the_go_verifier_reads_the_number_as_issued(self):
        """The number exceeds 2^53: the manifest carries it as a string."""
        rv.Issuer(1 << 20).tick(self.kv, self.cert, {}, [], NOW, 168)
        self.assertIsInstance(json.loads(self.kv.kv[rv.CRL_MANIFEST])['number'], str)


def agent_pki():
    """An agent CA, an agent server certificate for 127.0.0.1 and a mgr client certificate, as files."""
    cert, key = ca()
    srv = b.issue_mgr_certs(cert, key.encode(), 'f1', 'h1', '127.0.0.1', 'agent')
    cli = b.issue_mgr_certs(cert, key.encode(), 'f1', 'h1', '127.0.0.1', 'mgr')
    d = tempfile.mkdtemp()
    files = {}
    for name, data in (('agent-ca.crt', cert.decode()), ('srv.crt', srv['server_cert']), ('srv.key', srv['server_key']),
                       ('mgr-client.crt', cli['client_cert']), ('mgr-client.key', cli['client_key'])):
        files[name] = os.path.join(d, name)
        with open(files[name], 'w') as f:
            f.write(data)
    files['dir'] = d
    files['serial'] = x509.load_pem_x509_certificate(srv['server_cert'].encode()).serial_number
    return files


class ModuleChecksTest(unittest.TestCase):
    def test_check_not_revoked(self):
        cert = {'serialNumber': '2A', 'notBefore': 'Jan  1 00:00:00 2026 GMT', 'notAfter': 'Jan  1 00:00:00 2030 GMT'}
        now = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc).timestamp()
        m.check_not_revoked(cert, {41}, now)
        with self.assertRaises(ValueError):
            m.check_not_revoked(cert, {42}, now)
        with self.assertRaises(ValueError):  # expired
            m.check_not_revoked(cert, set(), datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc).timestamp())
        with self.assertRaises(ValueError):
            m.check_not_revoked(None, set(), now)

    def test_the_poll_refuses_a_revoked_agent(self):
        files = agent_pki()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(files['srv.crt'], files['srv.key'])
        ctx.load_verify_locations(files['agent-ca.crt'])
        ctx.verify_mode = ssl.CERT_REQUIRED
        rec = json.dumps(test_talos.record({}, observed='2026-11-03T12:00:00Z')).encode()

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', str(len(rec)))
                self.end_headers()
                self.wfile.write(rec)

        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        old = m.AGENT_PORT
        m.AGENT_PORT = srv.server_address[1]
        self.addCleanup(setattr, m, 'AGENT_PORT', old)
        tls = m.tls_context(files['dir'])
        self.assertEqual(m.fetch_record('127.0.0.1', tls, expect=('f1', 'h1'))['schema'], 2)
        with self.assertRaises(ValueError):
            m.fetch_record('127.0.0.1', m.tls_context(files['dir']), expect=('f1', 'h1'), revoked={files['serial']})

    def test_the_status_record_reports_the_list(self):
        rec = test_talos.record({}, observed='2026-11-03T12:00:00Z')
        rec.update(crl_number=str((9 << 32) + 1), crl_stale=True)
        self.assertTrue(m.validate_record(dict(rec))['crl_stale'])
        for bad in ({'crl_number': 7}, {'crl_number': 'x'}, {'crl_stale': 'yes'}):
            with self.assertRaises(ValueError):
                m.validate_record(dict(rec, **bad))


class ServersRefuseRevokedTest(unittest.TestCase):
    """The module's servers on 4722 and 4723 refuse a revoked agent on every request."""

    def test_both_ports(self):
        import test_bridge as tb
        files = tb.pki()
        lmons = tb.Mons([tb.mgrmap(42, 'h1')])
        lcmds = lmons.commands(2)
        self.addCleanup(lcmds.stop)
        lead = b.Leadership('h1', tb.mgrmap(42, 'h1'), lcmds)
        self.assertTrue(lead.capture())
        mons = tb.Mons([tb.mgrmap(42, 'h1')])
        cmds = mons.commands(2)
        self.addCleanup(cmds.stop)
        mod = object.__new__(m.Module)
        mod._revoked = frozenset()
        ctx = b.server_context(files['ca.crt'], files['srv.crt'], files['srv.key'])
        ch = b.Channel('f1', 'h1', lead, cmds, ctx, b.read(files['srv.key']), mod._require_identity, tb.Log(), tb.authority())
        port, bport = tb.free_port(), tb.free_port()
        ch.start(port, bport)
        self.addCleanup(ch.stop)
        serial = x509.load_pem_x509_certificate(open(files['cli.crt'], 'rb').read()).serial_number
        call = json.dumps({'version': 1, 'call': 'health', 'args': {}, 'deadline': 5, 'dispatch_id': 'ab' * 8})
        t = tb.ServerTest()
        t.files, t.port = files, port
        self.assertEqual(t.request('POST', '/v1/bridge', bport, call), 200)
        self.assertEqual(t.request('POST', '/v1/confirm', port, json.dumps(tb.challenge(host='h1'))), 200)
        mod._revoked = frozenset({serial})
        call = json.dumps({'version': 1, 'call': 'health', 'args': {}, 'deadline': 5, 'dispatch_id': 'cd' * 8})
        for p, path, body in ((bport, '/v1/bridge', call), (port, '/v1/confirm', json.dumps(tb.challenge(host='h1')))):
            try:
                status = t.request('POST', path, p, body)
            except ConnectionResetError:  # the refusal closes before the body is read
                status = 403
            self.assertEqual(status, 403, path)


class RevokeCommandTest(unittest.TestCase):
    def test_written_once_with_a_default_of_three_years(self):
        mod = object.__new__(m.Module)
        kv = KV()
        mod.mon_command = lambda cmd: kv(cmd, 1)
        out = m.Module._revoke(mod, '0x2a')
        self.assertEqual(out.retval, 0, out.stderr)
        until = rv.parse_iso(json.loads(kv.kv[rv.REVOKED_PREFIX + '42'])['not_after'])
        self.assertGreater(until - datetime.datetime.now(datetime.timezone.utc), datetime.timedelta(days=3 * 365 - 2))
        before = kv.kv[rv.REVOKED_PREFIX + '42']
        self.assertEqual(m.Module._revoke(mod, '42', until='2030-01-01T00:00:00Z').retval, 0)
        self.assertEqual(kv.kv[rv.REVOKED_PREFIX + '42'], before)  # never changed
        self.assertEqual(m.Module._revoke(mod, '43', until='2030-01-01T00:00:00Z').retval, 0)
        self.assertEqual(json.loads(kv.kv[rv.REVOKED_PREFIX + '43'])['not_after'], '2030-01-01T00:00:00Z')
        self.assertEqual(m.Module._revoke(mod, 'nope').retval, -22)


class DeliveryTest(unittest.TestCase):
    """The poll sends the list to every host whose poll failed or reported a
    lower number, and reports stale agents."""

    def test_to_failed_and_behind_hosts(self):
        mod = object.__new__(m.Module)
        mod._poller = m.Poller(lambda addr, refresh: {})
        self.addCleanup(mod._poller.shutdown)
        number = (9 << 32) + 2
        mod._crl = (number, b'der')
        health = {}
        mod.set_health_checks = lambda checks: health.update(now=checks)
        mod._poller.observations = {
            'h1': ({'crl_number': str(number), 'crl_stale': False}, ''),
            'h2': ({'crl_number': str(number - 1), 'crl_stale': True}, ''),
            'h3': (None, 'connection refused'),
        }
        sent = []
        mod._send_crl = lambda fsid, h, body: sent.append((h['name'], json.loads(body)))
        inv = {'fsid': 'f1', 'hosts': [{'name': n, 'addr': a} for n, a in (('h1', '10.0.0.1'), ('h2', '10.0.0.2'), ('h3', '10.0.0.3'))]}
        m.Module._deliver_crl(mod, inv)
        mod._poller.executor.shutdown(wait=True)
        self.assertEqual(sorted(n for n, _ in sent), ['h2', 'h3'])
        self.assertEqual(base64.b64decode(sent[0][1]['crl']), b'der')
        self.assertEqual(health['now']['TALOS_CRL_STALE']['detail'], ['the agent of h2'])


if __name__ == '__main__':
    unittest.main()
