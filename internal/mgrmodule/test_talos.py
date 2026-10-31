"""Unit tests of the talos mgr module against Ceph's own orchestrator code.

Run with hack/mgrmodule-test.sh <ceph source>: it puts Ceph's pybind and
python-common on the path. The compiled Ceph bindings are stubbed.
"""
import datetime
import shutil
import socket
import ssl
import subprocess
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest

stub = types.ModuleType('ceph_module')
for n in ('BaseMgrModule', 'BaseMgrStandbyModule', 'BasePyOSDMap', 'BasePyOSDMapIncremental', 'BasePyCRUSH'):
    setattr(stub, n, type(n, (), {}))
sys.modules['ceph_module'] = stub
for n in ('cephfs', 'rados', 'rbd'):
    sys.modules[n] = types.ModuleType(n)

from orchestrator import DaemonDescriptionStatus as S  # noqa: E402

from talos import module as m  # noqa: E402

NOW = datetime.datetime(2026, 10, 28, 12, 0, tzinfo=datetime.timezone.utc)


def store_entries(inv, seq=1, chunk=60 << 10, incarnation='cli'):
    """The module store entries internal/store writes for an inventory record,
    keyed as get_store_prefix returns them (without mgr/cephadm/)."""
    import base64
    import hashlib
    data = (inv if isinstance(inv, str) else json.dumps(inv)).encode()
    enc = base64.b64encode(data).decode()
    base = 'talos/inc/%s/' % incarnation
    entries, chunks = {}, []
    for i in range(max(1, -(-len(enc) // chunk))):
        key = '%srec/%d/inventory.%d' % (base, seq, i)
        entries[key] = enc[i * chunk:(i + 1) * chunk]
        chunks.append('mgr/cephadm/' + key)
    entries['%smanifest/%020d' % (base, seq)] = json.dumps({
        'schema': 1, 'incarnation': incarnation, 'seq': seq,
        'records': {'inventory': {'chunks': chunks, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}}})
    return entries


def inventory(**extra):
    inv = {
        'schema': 1, 'revision': 3, 'updated_at': '2026-10-28T11:59:00.123456789Z', 'fsid': 'f',
        'image': 'quay.io/ceph/ceph@sha256:a', 'ceph_version': '20.2.4',
        'hosts': [{'name': 'h1', 'addr': '10.5.0.2'}, {'name': 'h2', 'addr': '10.5.0.3'},
                  {'name': 'h3', 'addr': '10.5.0.4', 'maintenance': True}],
        'daemons': [
            {'doc_name': 'ceph-f-mon-h1', 'host': 'h1', 'daemon_type': 'mon', 'daemon_id': 'h1', 'service_name': 'mon', 'desired_image': 'quay.io/ceph/ceph@sha256:a'},
            {'doc_name': 'ceph-f-osd-h1-sda', 'host': 'h1', 'daemon_type': 'osd', 'daemon_id': '0', 'service_name': 'osd', 'desired_image': 'quay.io/ceph/ceph@sha256:a'},
            {'doc_name': 'ceph-f-osd-h1-sdb', 'host': 'h1', 'daemon_type': 'osd', 'daemon_id': 'pending-ceph-f-osd-h1-sdb', 'service_name': 'osd', 'desired_image': 'quay.io/ceph/ceph@sha256:a'},
            {'doc_name': 'ceph-f-osd-h1-sdc', 'host': 'h1', 'daemon_type': 'osd', 'daemon_id': 'pending-ceph-f-osd-h1-sdc', 'service_name': 'osd', 'desired_image': 'quay.io/ceph/ceph@sha256:a'},
            {'doc_name': 'ceph-f-vip-h2', 'host': 'h2', 'daemon_type': 'keepalived', 'daemon_id': 'h2', 'service_name': 'ingress.rgw.default', 'desired_image': 'quay.io/ceph/keepalived:2.2.4'},
            {'doc_name': 'ceph-f-mgr-h3', 'host': 'h3', 'daemon_type': 'mgr', 'daemon_id': 'h3', 'service_name': 'mgr', 'desired_image': 'quay.io/ceph/ceph@sha256:a'},
        ],
    }
    inv.update(extra)
    return inv


def record(containers, observed=NOW):
    return {'schema': 2, 'hostname': 'h', 'talos_version': 'v1.15.0', 'observed_at': observed, 'containers': containers}


class StatusMapping(unittest.TestCase):
    def status(self, c, host=None, daemon=None, obs=None):
        d = daemon or {'doc_name': 'x'}
        if obs is None:
            obs = (record({'x': c} if c is not None else {}), '')
        return m.daemon_status(d, host or {'name': 'h'}, obs, NOW)[0]

    def test_table(self):
        self.assertEqual(self.status({'state': 'running'}), S.running)
        for st in ('pending', 'pulling', 'starting'):
            self.assertEqual(self.status({'state': st}), S.starting)
        for st in ('exited', 'backoff'):
            self.assertEqual(self.status({'state': st}), S.error)
        self.assertEqual(self.status({'state': 'stopping'}), S.stopped)
        self.assertEqual(self.status({'instances': True}), S.stopped)
        self.assertEqual(self.status(None), S.error)
        self.assertEqual(self.status({'state': 'running'}, host={'maintenance': True}), S.stopped)
        self.assertEqual(self.status({'state': 'running'}, daemon={'doc_name': 'x', 'local_only': True}), S.stopped)
        self.assertEqual(self.status(None, obs=(None, 'connection refused')), S.unknown)
        stale = record({'x': {'state': 'running'}}, observed=NOW - datetime.timedelta(minutes=3))
        self.assertEqual(self.status(None, obs=(stale, '')), S.unknown)


class Daemons(unittest.TestCase):
    def test_one_bad_host_keeps_every_row(self):
        obs = {
            'h1': (record({'ceph-f-mon-h1': {'state': 'running', 'image_digest': 'sha256:run'},
                           'ceph-f-osd-h1-sda': {'state': 'running'}}), ''),
            'h2': (None, 'status record larger than 32768 bytes'),
        }
        daemons = m.build_daemons(inventory(), obs, NOW)
        self.assertEqual(len(daemons), 6)
        by = {d.name(): d for d in daemons}
        self.assertEqual(by['mon.h1'].status, S.running)
        self.assertEqual(by['mon.h1'].container_image_digests, ['sha256:run'])
        self.assertEqual(by['keepalived.h2'].status, S.unknown)
        self.assertIn('larger than', by['keepalived.h2'].status_desc)
        self.assertEqual(by['keepalived.h2'].container_image_name, 'quay.io/ceph/keepalived:2.2.4')
        self.assertIsNone(by['keepalived.h2'].version)
        self.assertEqual(by['keepalived.h2'].service_name(), 'ingress.rgw.default')
        self.assertEqual(by['mgr.h3'].status, S.stopped)

    def test_pending_osds_render(self):
        daemons = m.build_daemons(inventory(), {}, NOW)
        pend = [d for d in daemons if d.daemon_id.startswith('pending-')]
        self.assertEqual({d.name() for d in pend}, {'osd.pending-ceph-f-osd-h1-sdb', 'osd.pending-ceph-f-osd-h1-sdc'})
        for d in pend:
            self.assertIn('numeric OSD ID not yet known', d.status_desc)
            js = d.to_json()
            self.assertEqual(js['daemon_name'], d.name())

    def test_orch_ps_table(self):
        # Ceph's own `orch ps` handler, fed by our daemon list
        from orchestrator import OrchResult
        from orchestrator.module import OrchestratorCli
        from mgr_module import HandleCommandResult  # noqa: F401

        daemons = m.build_daemons(inventory(), {}, NOW)

        class Backend:
            def list_daemons(self, *args, **kwargs):
                return OrchResult(daemons)

        handler = getattr(OrchestratorCli._list_daemons, '__wrapped__', OrchestratorCli._list_daemons)
        out = handler(Backend()).stdout
        for name in ('osd.pending-ceph-f-osd-h1-sdb', 'osd.pending-ceph-f-osd-h1-sdc', 'keepalived.h2', 'mon.h1'):
            self.assertIn(name, out)

    def test_filters(self):
        daemons = m.build_daemons(inventory(), {}, NOW)
        self.assertEqual(len(m.filter_daemons(daemons, daemon_type='osd')), 3)
        self.assertEqual(len(m.filter_daemons(daemons, host='h1')), 4)
        self.assertEqual(len(m.filter_daemons(daemons, service_name='ingress.rgw.default')), 1)
        self.assertEqual([d.name() for d in m.filter_daemons(daemons, daemon_type='osd', daemon_id='0')], ['osd.0'])

    def test_hosts(self):
        hosts = m.build_hosts(inventory())
        self.assertEqual([(h.hostname, h.addr, h.status) for h in hosts],
                         [('h1', '10.5.0.2', ''), ('h2', '10.5.0.3', ''), ('h3', '10.5.0.4', 'maintenance')])


class Inventory(unittest.TestCase):
    def test_invalid_inventory_fails(self):
        for bad in ('not json', {'schema': 2, 'hosts': [], 'daemons': []}, {'schema': 1, 'hosts': []},
                    inventory(daemons=[{'doc_name': 'x'}])):
            with self.assertRaises(m.InventoryError):
                m.inventory_from_store(store_entries(bad))

    def test_valid_inventory(self):
        self.assertEqual(m.inventory_from_store(store_entries(inventory()))['revision'], 3)

    def test_store_reading(self):
        entries = store_entries(inventory(), seq=5, chunk=40)
        entries.update(store_entries(inventory(revision=9), seq=7, chunk=40))
        self.assertEqual(m.inventory_from_store(entries)['revision'], 9)  # the latest manifest
        with self.assertRaises(m.InventoryError):
            m.inventory_from_store({})
        with self.assertRaises(m.InventoryError):
            m.inventory_from_store(store_entries(inventory(), incarnation='other'))
        broken = store_entries(inventory(), chunk=40)
        first = sorted(k for k in broken if '/rec/' in k)[0]
        broken[first] = broken[first][:-4] + 'AAAA'
        with self.assertRaises(m.InventoryError):
            m.inventory_from_store(broken)

    def test_malformed_manifests(self):
        good = store_entries(inventory())
        key = next(k for k in good if '/manifest/' in k)
        manifest = json.loads(good[key])
        chunk = manifest['records']['inventory']['chunks'][0]
        bad = ['[]', '"x"', 'null']
        for change in (
                lambda mf: mf.update(seq=True),
                lambda mf: mf.update(seq='1'),
                lambda mf: mf.update(records=[]),
                lambda mf: mf.update(records={'inventory': []}),
                lambda mf: mf['records']['inventory'].update(chunks='abc'),
                lambda mf: mf['records']['inventory'].update(chunks=[]),
                lambda mf: mf['records']['inventory'].update(chunks=[1]),
                lambda mf: mf['records']['inventory'].update(sha256=None),
                lambda mf: mf['records']['inventory'].update(size='12'),
                lambda mf: mf['records']['inventory'].update(chunks=[chunk + 'x'])):
            mf = json.loads(good[key])
            change(mf)
            bad.append(json.dumps(mf))
        for text in bad:
            with self.subTest(manifest=text):
                with self.assertRaises(m.InventoryError):
                    m.inventory_from_store(dict(good, **{key: text}))
        with self.assertRaises(m.InventoryError):
            m.inventory_from_store(dict(good, **{chunk[len('mgr/cephadm/'):]: None}))

    def test_available_details(self):
        entries = store_entries(inventory(cert_expiry='2029-10-28T00:00:00Z'))
        mod = object.__new__(m.Module)
        mod.get_store_prefix = lambda prefix: {k: v for k, v in entries.items() if k.startswith(prefix)}
        old = m.utcnow
        # updated_at is 11:59:00.123 and the clock says 12:00:00
        m.utcnow = lambda: NOW
        try:
            ok, why, details = m.Module.available(mod)
        finally:
            m.utcnow = old
        self.assertTrue(ok, why)
        self.assertEqual(details['inventory_revision'], 3)
        self.assertEqual(details['inventory_age_seconds'], 59)
        self.assertEqual(details['agent_cert_expiry'], '2029-10-28T00:00:00Z')


class ChooseIncarnation(unittest.TestCase):
    def test_choice(self):
        cli = store_entries(inventory(revision=1))
        self.assertEqual(m.choose_incarnation(cli, None), 'cli')
        # a leader that published: the highest epoch wins over the CLI and over gids
        e = dict(cli)
        e.update(store_entries(inventory(revision=2), incarnation='90'))
        e['talos/inc/90/journal/takeover'] = json.dumps({'version': 1, 'epoch': 3})
        e.update(store_entries(inventory(revision=3), incarnation='42'))
        e['talos/inc/42/journal/takeover'] = json.dumps({'version': 1, 'epoch': 8})
        self.assertEqual(m.choose_incarnation(e, None), '42')
        self.assertEqual(m.inventory_from_store(e, m.choose_incarnation(e, None))['revision'], 3)
        # this mgr's own, once published
        self.assertEqual(m.choose_incarnation(e, 90), '90')
        # a journal without a publication is no state
        e['talos/inc/77/journal/takeover'] = json.dumps({'version': 1, 'epoch': 20})
        self.assertEqual(m.choose_incarnation(e, 77), '42')


class ExitStates(unittest.TestCase):
    def test_completed_and_failed(self):
        d = {'doc_name': 'ceph-f-job-x', 'host': 'h1'}
        for state, code, want, desc in (('completed', 0, m.DaemonDescriptionStatus.stopped, 'completed'),
                                        ('failed', 3, m.DaemonDescriptionStatus.error, 'failed (exit 3)')):
            rec = m.validate_record(record({'ceph-f-job-x': {'state': state, 'exit_code': code}}, NOW.isoformat()))
            status, got, _ = m.daemon_status(d, {}, (rec, ''), NOW)
            self.assertEqual((status, got), (want, desc))


class ReportedVersion(unittest.TestCase):
    def test_version_from_the_daemon(self):
        inv = inventory()
        d = inv['daemons'][0]
        rec = m.validate_record(record({d['doc_name']: {'state': 'running', 'version': '20.2.5'}}, NOW.isoformat()))
        dd = {x.daemon_name: x for x in m.build_daemons(inv, {d['host']: (rec, '')}, NOW)}
        self.assertEqual(dd['%s.%s' % (d['daemon_type'], d['daemon_id'])].version, '20.2.5')
        with self.assertRaises(ValueError):
            m.validate_record(record({d['doc_name']: {'state': 'running', 'version': 20}}, NOW.isoformat()))


class BadParts(unittest.TestCase):
    def test_malformed_container_rejects_only_that_host(self):
        with self.assertRaises(ValueError):
            m.validate_record({'schema': 2, 'observed_at': '2026-10-28T12:00:00Z', 'containers': {'x': []}})
        with self.assertRaises(ValueError):
            m.validate_record({'schema': 2, 'observed_at': '2026-10-28T12:00:00Z', 'containers': {'x': {'restarts': 'two'}}})
        with self.assertRaises(ValueError):
            m.validate_record({'schema': 2, 'observed_at': '2026-10-28T12:00:00Z', 'containers': {'x': {'exit_code': '3'}}})
        with self.assertRaises(ValueError):
            m.validate_record({'schema': 1, 'observed_at': '2026-10-28T12:00:00Z', 'containers': {}})

        calls = []

        def fetch(addr, refresh):
            calls.append(addr)
            if addr == '10.5.0.3':
                return m.validate_record({'schema': 2, 'observed_at': '2026-10-28T12:00:00Z', 'containers': {'x': []}})
            return m.validate_record({'schema': 2, 'observed_at': NOW.isoformat(), 'containers': {'ceph-f-mon-h1': {'state': 'running'}}})

        p = m.Poller(fetch)
        self.addCleanup(p.shutdown)
        p.poll(inventory()['hosts'])
        daemons = m.build_daemons(inventory(), p.snapshot(), NOW)
        self.assertEqual(len(daemons), 6)
        by = {d.name(): d for d in daemons}
        self.assertEqual(by['mon.h1'].status, S.running)
        self.assertEqual(by['keepalived.h2'].status, S.unknown)

    def test_invalid_inventory_types(self):
        for bad in (inventory(updated_at='yesterday'), inventory(updated_at=123), inventory(cert_expiry=123),
                    inventory(hosts=[{'name': 'h1', 'addr': 1}]),
                    inventory(hosts=[{'name': 'h1', 'addr': 'a'}, {'name': 'h1', 'addr': 'b'}]),
                    inventory(hosts=[{'name': 'h1', 'addr': 'a'}])):  # daemons on unknown hosts
            with self.assertRaises(m.InventoryError):
                m.inventory_from_store(store_entries(bad))


@unittest.skipUnless(shutil.which('openssl'), 'needs openssl')
class OversizedRecord(unittest.TestCase):
    def test_oversized_agent_response_keeps_other_hosts(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                        '-keyout', d + '/k.pem', '-out', d + '/c.pem', '-days', '1', '-subj', '/CN=127.0.0.1',
                        '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv.load_cert_chain(d + '/c.pem', d + '/k.pem')
        lsock = socket.socket()
        lsock.bind(('127.0.0.1', 0))
        lsock.listen()
        self.addCleanup(lsock.close)
        port = lsock.getsockname()[1]
        body = b'{"pad": "' + b'x' * (m.MAX_RECORD + 10) + b'"}'

        def serve():
            conn, _ = lsock.accept()
            with srv.wrap_socket(conn, server_side=True) as c:
                c.recv(4096)
                c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n' % len(body) + body)

        threading.Thread(target=serve, daemon=True).start()
        client = ssl.create_default_context(cafile=d + '/c.pem')
        old = m.AGENT_PORT
        m.AGENT_PORT = port
        self.addCleanup(lambda: setattr(m, 'AGENT_PORT', old))

        def fetch(addr, refresh):
            if addr == '10.5.0.3':  # the oversized agent
                return m.fetch_record('127.0.0.1', client)
            return m.validate_record({'schema': 2, 'observed_at': NOW.isoformat(), 'containers': {'ceph-f-mon-h1': {'state': 'running'}}})

        p = m.Poller(fetch)
        self.addCleanup(p.shutdown)
        p.poll(inventory()['hosts'])
        self.assertIn('larger than', p.snapshot()['h2'][1])
        daemons = m.build_daemons(inventory(), p.snapshot(), NOW)
        self.assertEqual(len(daemons), 6)
        by = {d.name(): d for d in daemons}
        self.assertEqual(by['mon.h1'].status, S.running)
        self.assertEqual(by['keepalived.h2'].status, S.unknown)


class OverlappingPolls(unittest.TestCase):
    def test_polls_do_not_interleave(self):
        order = []
        slow = threading.Event()

        def fetch(addr, refresh):
            order.append(('start', refresh))
            if not refresh:
                slow.wait(1)
            order.append(('end', refresh))
            return m.validate_record({'schema': 2, 'observed_at': NOW.isoformat(), 'containers': {'r' if refresh else 'b': {}}})

        p = m.Poller(fetch)
        self.addCleanup(p.shutdown)
        bg = threading.Thread(target=p.poll, args=([{'name': 'h1', 'addr': 'a'}],))
        bg.start()
        time.sleep(0.1)
        p.poll([{'name': 'h1', 'addr': 'a'}], refresh=True)  # waits for the background cycle
        bg.join()
        self.assertEqual(order, [('start', False), ('end', False), ('start', True), ('end', True)])
        self.assertIn('r', p.snapshot()['h1'][0]['containers'])  # the newer refresh wins


@unittest.skipUnless(shutil.which('openssl'), 'needs openssl')
class Deadline(unittest.TestCase):
    def test_trickling_headers_hit_the_deadline(self):
        self.trickle(header=True)

    def test_trickling_agent_hits_the_deadline(self):
        self.trickle(header=False)

    def test_trickling_body_with_connection_close(self):
        self.trickle(header=False, close=True)

    def trickle(self, header, close=False):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                        '-keyout', d + '/k.pem', '-out', d + '/c.pem', '-days', '1', '-subj', '/CN=127.0.0.1',
                        '-addext', 'subjectAltName=IP:127.0.0.1'], check=True, capture_output=True)
        srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv.load_cert_chain(d + '/c.pem', d + '/k.pem')
        lsock = socket.socket()
        lsock.bind(('127.0.0.1', 0))
        lsock.listen()
        self.addCleanup(lsock.close)
        port = lsock.getsockname()[1]
        stop = threading.Event()

        def serve():
            conn, _ = lsock.accept()
            with srv.wrap_socket(conn, server_side=True) as c:
                c.recv(4096)
                if not header:
                    c.sendall(b'HTTP/1.1 200 OK\r\n' + (b'Connection: close\r\n' if close else b'') + b'Content-Length: 10000\r\n\r\n')
                while not stop.is_set():  # one byte every 0.5s: never idle long enough for a socket timeout
                    try:
                        c.sendall(b'H' if header else b'{')
                    except OSError:
                        return
                    time.sleep(0.5)

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        self.addCleanup(stop.set)
        client = ssl.create_default_context(cafile=d + '/c.pem')
        old = (m.AGENT_PORT, m.REQUEST_TIMEOUT)
        m.AGENT_PORT, m.REQUEST_TIMEOUT = port, 2.0
        self.addCleanup(lambda: setattr(m, 'AGENT_PORT', old[0]) or setattr(m, 'REQUEST_TIMEOUT', old[1]))
        start = time.monotonic()
        with self.assertRaises((TimeoutError, socket.timeout, OSError)):
            m.fetch_record('127.0.0.1', client)
        self.assertLess(time.monotonic() - start, 4)


class Records(unittest.TestCase):
    def test_validate(self):
        rec = m.validate_record({'schema': 2, 'observed_at': '2026-10-28T12:00:00.123456789Z', 'containers': {}})
        self.assertEqual(rec['observed_at'].microsecond, 123456)
        for bad in ({'schema': 2, 'observed_at': 'x', 'containers': {}}, {'schema': 1, 'containers': {}}, []):
            with self.assertRaises(ValueError):
                m.validate_record(bad)


class PollerShutdown(unittest.TestCase):
    def test_shutdown_during_a_slow_poll(self):
        release = threading.Event()

        def fetch(addr, refresh):
            release.wait(2)  # an unreachable agent, bounded by its timeout
            raise OSError('timed out')

        p = m.Poller(fetch)
        t = threading.Thread(target=p.poll, args=([{'name': 'h1', 'addr': 'a'}],))
        t.start()
        time.sleep(0.1)
        start = time.monotonic()
        p.shutdown()
        t.join(5)
        self.assertFalse(t.is_alive())
        self.assertLess(time.monotonic() - start, 5)
        p.poll([{'name': 'h1', 'addr': 'a'}])  # no further polls after shutdown
        self.assertEqual(p.snapshot().get('h1', (None, ''))[1], 'timed out')


if __name__ == '__main__':
    unittest.main()


class IdentityTest(unittest.TestCase):
    def cert(self, *uris):
        return {'subjectAltName': [('DNS', 'h1')] + [('URI', u) for u in uris]}

    def test_identity(self):
        c = self.cert('cephadm-talos://f1/agent/h1', 'spiffe://x/y')
        self.assertEqual(m.cert_identity(c), ('f1', 'agent', 'h1'))
        self.assertEqual(m.require_identity(c, 'f1', 'agent', 'h1'), 'h1')
        self.assertEqual(m.require_identity(c, 'f1', 'agent'), 'h1')
        # Go lowercases the scheme and drops an empty fragment when it parses a certificate; so does this
        self.assertEqual(m.cert_identity(self.cert('cephadm-talos://f1/agent/h1#')), ('f1', 'agent', 'h1'))
        self.assertEqual(m.cert_identity(self.cert('CEPHADM-TALOS://f1/agent/h1')), ('f1', 'agent', 'h1'))

    def test_refused(self):
        c = self.cert('cephadm-talos://f1/agent/h1')
        for fsid, role, name in (('f2', 'agent', 'h1'), ('f1', 'mgr', 'h1'), ('f1', 'agent', 'h2')):
            with self.assertRaises(ValueError):
                m.require_identity(c, fsid, role, name)
        for bad in (None, {}, self.cert(), self.cert('cephadm-talos://f1/agent/h1', 'cephadm-talos://f1/agent/h2'),
                    self.cert('cephadm-talos://f1/agent'), self.cert('cephadm-talos://f1/agent/h1/x'),
                    self.cert('cephadm-talos:///agent/h1'), self.cert('cephadm-talos://f1/agent/h1?x=1'),
                    self.cert('cephadm-talos://f1/agent/h1?'), self.cert('cephadm-talos://f1/agent/h1#x'),
                    self.cert('cephadm-talos://f1/agent/%68%31'), self.cert('cephadm-talos://f1:1/agent/h1'),
                    self.cert('cephadm-talos://f1/agent/h1/'),
                    self.cert('cephadm-talos://f1/agent/h1', 'CEPHADM-TALOS://f1/mgr/h2'),
                    self.cert('cephadm-talos://f1/agent/h1', 'cephadm-talos:f1/mgr/h2'),
                    self.cert('cephadm-talos://f1/agent/h1', 'cephadm-talos:/f1/mgr/h2'),
                    self.cert('cephadm-talos://f1/agent/h1', 'cephadm-talos:'),
                    self.cert('cephadm-talos://f1/agent/_node')):
            with self.assertRaises(ValueError):
                m.cert_identity(bad)
