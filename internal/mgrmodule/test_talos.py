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
import re
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


class _Library(types.ModuleType):
    """A stand-in for a Ceph library binding: any name is a class (Python
    before 3.14 evaluates the annotations that use them)."""

    def __getattr__(self, name: str) -> type:
        if name.startswith('__'):
            raise AttributeError(name)
        return type(name, (Exception,), {})


for n in ('cephfs', 'rados', 'rbd'):
    sys.modules[n] = _Library(n)

from orchestrator import DaemonDescriptionStatus as S  # noqa: E402

from talos import module as m  # noqa: E402

# the suspension gate reads a config-key through the mons, which the module
# doubles here do not answer: off, except in the test that checks it
_not_suspended = m.Module._not_suspended
m.Module._not_suspended = lambda self: None

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


class InterfaceTest(unittest.TestCase):
    def test_overrides_keep_the_orchestrators_parameters(self):
        """Ceph's orchestrator CLI calls these methods with the interface's
        arguments: an override must accept every one of them."""
        import inspect
        import orchestrator
        for name, ours in vars(m.Module).items():
            theirs = getattr(orchestrator.Orchestrator, name, None)
            if name.startswith('_') or not callable(ours) or theirs is None:
                continue
            want = list(inspect.signature(theirs).parameters)
            have = list(inspect.signature(ours).parameters)
            self.assertEqual(have, want, name)


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
    def test_boot_and_cancelled_stop(self):
        # plan 04, step 5: the node's boot id and a boot whose stop was cancelled
        rec = m.validate_record(dict(record({}, '2026-10-28T12:00:00Z'), boot='b-2', stop_cancelled='b-2.aa.1'))
        self.assertEqual((rec['boot'], rec['stop_cancelled']), ('b-2', 'b-2.aa.1'))
        for bad in ({'boot': 3}, {'boot': 'a b'}, {'stop_cancelled': 'x/y'}):
            with self.assertRaises(ValueError, msg=bad):
                m.validate_record(dict(record({}, '2026-10-28T12:00:00Z'), **bad))

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


def state_entries(inv, cluster, incarnation='cli', seq=1, **more):
    """The store entries of a published state with an inventory and a cluster
    record (and more records, such as hosts and daemons)."""
    import base64
    import hashlib
    base = 'talos/inc/%s/' % incarnation
    entries, recs = {}, {}
    for name, obj in (('inventory', inv), ('cluster', cluster)) + tuple(more.items()):
        data = json.dumps(obj).encode()
        key = '%srec/%d/%s.0' % (base, seq, name)
        entries[key] = base64.b64encode(data).decode()
        recs[name] = {'chunks': ['mgr/cephadm/' + key], 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
    entries['%smanifest/%020d' % (base, seq)] = json.dumps({'schema': 1, 'incarnation': incarnation, 'seq': seq, 'records': recs})
    return entries


class Acceptance(unittest.TestCase):
    def module(self, sealed=True, active=True, inv=None):
        from talos import ledger as lg
        import test_ledger
        entries = state_entries(inv or inventory(), {'fsid': 'f', 'sealed': sealed})
        mod = object.__new__(m.Module)
        mod.get_store_prefix = lambda prefix: {k: v for k, v in entries.items() if k.startswith(prefix)}
        mod._ledger = lg.Ledger(test_ledger.Mons(), 20, 7)
        mod._ledger.open()

        class Lead:
            def still_active(self):
                return active
        mod._leadership = Lead()
        return mod, entries

    def test_restart_and_redeploy_are_accepted_once_at_a_time(self):
        mod, entries = self.module()
        res = m.Module.daemon_action(mod, 'restart', 'mon.h1')
        self.assertEqual(res.exception_str, '')
        op_id = res.result.split('operation ')[1].rstrip(')')
        [(_, e)] = mod._ledger.executable()
        self.assertEqual((e['id'], e['kind'], e['daemon'], e['host']), (op_id, 'restart', 'mon.h1', 'h1'))
        # another operation on the same daemon waits until the leader finished this one
        self.assertTrue(m.Module.daemon_action(mod, 'redeploy', 'mon.h1').exception_str)
        entries['talos/inc/20/journal/op/' + op_id] = json.dumps({'state': 'completed'})
        self.assertFalse(m.Module.daemon_action(mod, 'redeploy', 'mon.h1').exception_str)
        out = m.Module._operation(mod, op_id)
        self.assertEqual(out.retval, 0)
        self.assertEqual(json.loads(out.stdout)['journal']['state'], 'completed')
        self.assertEqual(m.Module._operation(mod, 'op-%016x' % 1).retval, -2)

    def test_an_unsettled_append_blocks_acceptance(self):
        mod, entries = self.module()
        mod._ledger.mon.silent = 2
        self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mon.h1').exception_str)  # outcome unknown
        # still unknown: no second operation on the same daemon goes in beside it
        self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mon.h1').exception_str)
        self.assertEqual(len(mod._ledger.executable()), 0)
        # settled: the first one counts, and blocks the next on that daemon
        mod._ledger.settle()
        self.assertEqual(len(mod._ledger.executable()), 1)
        self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mon.h1').exception_str)

    def test_refused_before_acceptance(self):
        mod, _ = self.module()
        for args in (('stop', 'mgr.h3'), ('reconfig', 'mgr.h3'), ('restart', 'mgr.h9'), ('restart', 'client.admin')):
            self.assertTrue(m.Module.daemon_action(mod, *args).exception_str, args)
        self.assertTrue(m.Module.daemon_action(mod, 'redeploy', 'mgr.h3', image='quay.io/ceph/ceph:v20').exception_str)
        self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mgr.h3', force=True).exception_str)
        self.assertEqual(mod._ledger.executable(), [])
        # not sealed, or no longer active: nothing is accepted
        for mod in (self.module(sealed=False)[0], self.module(active=False)[0]):
            self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mgr.h3').exception_str)
            self.assertEqual(mod._ledger.executable(), [])

    def test_nothing_is_accepted_while_the_cluster_is_suspended(self):
        session = '0b8f3a52-7c1e-4d3a-9f6e-2a4b5c6d7e8f'
        for answer, accepted in (((-2, '', 'ENOENT'), True), ((0, json.dumps({'session': session}), ''), False),
                                 ((-110, '', 'timed out'), False)):
            mod, _ = self.module()
            mod._not_suspended = types.MethodType(_not_suspended, mod)
            mod.mon_command = lambda cmd, a=answer: a if cmd == {'prefix': 'config-key get', 'key': m.SUSPENSION_KEY} else (-22, '', '')
            res = m.Module.daemon_action(mod, 'restart', 'mon.h1')
            self.assertEqual(not res.exception_str, accepted, (answer, res.exception_str))
            self.assertEqual(len(mod._ledger.executable()), 1 if accepted else 0)
            if answer[0] == 0:
                self.assertIn(session, res.exception_str)


def cert_until(days):
    """A self-signed certificate (PEM) that expires in days."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 't')])
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=days)).sign(key, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.PEM).decode()


class CertCheck(unittest.TestCase):
    """The daily certificate check (plan 04, step 1)."""

    renew_days = None

    def module(self, operator_days=None, rgw=None):
        hosts = [{'name': 'h1', 'addr': '10.0.0.1', 'mgr_server_cert': cert_until(10), 'mgr_client_cert': cert_until(1000)},
                 {'name': 'h2', 'addr': '10.0.0.2', 'mgr_server_cert': cert_until(1000), 'mgr_client_cert': cert_until(1000)},
                 {'name': 'h3', 'addr': '10.0.0.3', 'mgr_server_cert': cert_until(5), 'mgr_client_cert': cert_until(1000)}]
        daemons = [{'type': 'mgr', 'id': h, 'host': h} for h in ('h1', 'h2', 'h3')]
        daemons += [{'type': 'rgw', 'id': h, 'host': h, 'cert': c} for h, c in (rgw or {}).items()]
        cluster = {'fsid': 'f', 'sealed': True}
        if rgw:
            cluster['rgw'] = {'port': 443, 'certs': [{'id': 'issued/op-%016x/%s' % (1, 'ab' * 8), 'cert': cert_until(20)},
                                                     {'id': 'user/op-%016x' % 2, 'cert': cert_until(20), 'user': True}]}
        mod, entries = Acceptance.module(self)
        entries.update(state_entries(inventory(), cluster, hosts=hosts, daemons=daemons))
        mod.get_mgr_id = lambda: 'h2'
        mod._rgw_port = lambda: None
        mod.get_module_option = lambda name: self.renew_days
        import logging
        mod._logger = logging.getLogger('test')
        self.health = {}
        mod.set_health_checks = lambda checks: self.health.update({'now': checks})
        op_cert = cert_until(operator_days) if operator_days is not None else None

        def mon(cmd):
            if cmd.get('key') == m.OPERATOR_CERT_KEY and op_cert:
                return 0, op_cert, ''
            return -2, '', 'not found'
        mod.mon_command = mon
        return mod, entries

    def test_mgr_renewals_and_warnings(self):
        mod, entries = self.module(operator_days=30)
        m.Module._check_certs(mod)
        ops = [(e['kind'], e.get('daemon'), e['host']) for _, e in mod._ledger.executable()]
        # h1's server certificate within 30 days, h3's within 7 (and h3 in maintenance: renewed in the state)
        self.assertEqual(sorted(ops), [('renew_mgr', 'mgr.h1', 'h1'), ('renew_mgr', 'mgr.h3', 'h3')])
        checks = self.health['now']
        self.assertIn('TALOS_OPERATOR_CERT_EXPIRING', checks)
        self.assertEqual(checks['TALOS_CERT_RENEWAL']['count'], 1)  # h3's
        # again: the unfinished renewals are not accepted twice
        m.Module._check_certs(mod)
        self.assertEqual(len(mod._ledger.executable()), 2)
        # the threshold setting renews earlier: h2's certificates too
        self.renew_days = 2000
        m.Module._check_certs(mod)
        self.assertIn(('renew_mgr', 'mgr.h2', 'h2'), [(e['kind'], e.get('daemon'), e['host']) for _, e in mod._ledger.executable()])
        # it moves renewal only: the 7 day warning stays
        self.assertEqual(self.health['now']['TALOS_CERT_RENEWAL']['count'], 1)
        self.renew_days = 1
        mod, _ = self.module()
        m.Module._check_certs(mod)
        self.assertEqual(self.health['now']['TALOS_CERT_RENEWAL']['count'], 1)  # h3's, 5 days, though not yet due

    def test_rgw_renewal_for_generated_certificates_only(self):
        mod, entries = self.module(rgw={'h1': 'issued/op-%016x/%s' % (1, 'ab' * 8), 'h2': 'user/op-%016x' % 2})
        m.Module._check_certs(mod)
        kinds = [e['kind'] for _, e in mod._ledger.executable()]
        self.assertEqual(kinds.count('renew_rgw_cert'), 1)
        self.assertIn('TALOS_RGW_CERT_EXPIRING', self.health['now'])  # the operator's, not renewed
        m.Module._check_certs(mod)
        self.assertEqual([e['kind'] for _, e in mod._ledger.executable()].count('renew_rgw_cert'), 1)

    def test_an_rgw_serving_the_operators_certificate_is_not_renewed(self):
        mod, entries = self.module(rgw={'h2': 'user/op-%016x' % 2})
        cluster_user = next(c for c in m.record_from_store(entries, 'cli', 'cluster')[0]['rgw']['certs'] if c.get('user'))['cert']
        mod._rgw_port = lambda: 443
        old = m.served_leaf
        m.served_leaf = lambda addr, port, timeout=5.0: m.leaf_der(cluster_user)
        self.addCleanup(setattr, m, 'served_leaf', old)
        m.Module._check_certs(mod)
        self.assertNotIn('renew_rgw_cert', [e['kind'] for _, e in mod._ledger.executable()])
        self.assertFalse(any('rgw' in d for d in self.health['now'].get('TALOS_CERT_RENEWAL', {}).get('detail', [])))
        self.assertEqual(self.health['now']['TALOS_RGW_CERT_EXPIRING']['count'], 1)


class AgentRenewalAndUpgrade(unittest.TestCase):
    """plan 04, step 2: agents' certificates in the daily check; the agent upgrade command."""
    IMG = 'registry/agent@sha256:' + 'ab' * 32

    def module(self, approved=()):
        hosts = [{'name': 'h1', 'addr': '10.0.0.1', 'agent_cert': cert_until(10), 'agent_client_cert': cert_until(1000)},
                 {'name': 'h2', 'addr': '10.0.0.2', 'agent_cert': cert_until(1000), 'agent_client_cert': cert_until(1000)}]
        mod, entries = Acceptance.module(self)
        entries.update(state_entries(inventory(), {'fsid': 'f', 'sealed': True, 'agent': {'image': 'registry/agent@sha256:' + 'cd' * 32}},
                                     hosts=hosts, daemons=[]))
        mod.get_mgr_id = lambda: 'h2'
        mod._rgw_port = lambda: None
        mod.get_module_option = lambda name: None
        mod.set_health_checks = lambda checks: None
        mod.mon_command = lambda cmd: (-2, '', '')
        mod._approved_images = lambda: list(approved)
        import logging
        mod._logger = logging.getLogger('test')
        return mod, entries

    def test_the_daily_check_renews_an_agent(self):
        mod, _ = self.module()
        m.Module._check_certs(mod)
        self.assertEqual([(e['kind'], e['host']) for _, e in mod._ledger.executable()], [('renew_agent', 'h1')])
        self.assertFalse(hasattr(mod, '_certs_next'))  # nothing refused: the next check is the daily one
        # refused while its host is busy (here, its own renewal unfinished): checked again in 10 minutes, not the next day
        import time
        mod._certs_next = time.monotonic() + m.CERT_CHECK_INTERVAL
        m.Module._check_certs(mod)
        self.assertLessEqual(mod._certs_next, time.monotonic() + m.CERT_RETRY_INTERVAL)
        self.assertEqual(len(mod._ledger.executable()), 1)

    def test_the_earliest_expiry_goes_first_on_a_host(self):
        # h1's mgr and agent certificates both due, the one expiring first goes first: an agent renewal
        # (a host's) waits for any unfinished operation on its host, a mgr renewal only for its mgr's
        for mgr_days, agent_days, accepted in ((20, 10, ['renew_agent', 'renew_mgr']), (10, 20, ['renew_mgr'])):
            mod, entries = self.module()
            hosts, _ = m.record_from_store(entries, 'cli', 'hosts')
            hosts[0].update(mgr_server_cert=cert_until(mgr_days), mgr_client_cert=cert_until(1000), agent_cert=cert_until(agent_days))
            entries.update(state_entries(inventory(), {'fsid': 'f', 'sealed': True, 'agent': {'image': 'registry/agent@sha256:' + 'cd' * 32}},
                                         hosts=hosts, daemons=[{'type': 'mgr', 'id': 'h1', 'host': 'h1'}]))
            m.Module._check_certs(mod)
            self.assertEqual([e['kind'] for _, e in mod._ledger.executable()], accepted)

    def test_the_upgrade_command(self):
        mod, entries = self.module()
        for image in ('registry/agent:latest', 'other/agent@sha256:' + 'ab' * 32, 'registry/agent@sha256:' + 'cd' * 32, self.IMG):
            res = m.Module._agent_upgrade(mod, image)
            self.assertNotEqual(res.retval, 0, image)  # tag, repository, current, not approved
        mod._approved_images = lambda: [self.IMG]
        res = m.Module._agent_upgrade(mod, self.IMG)
        self.assertEqual(res.retval, 0, res.stderr)
        [(_, up)] = mod._ledger.executable()
        self.assertEqual((up['kind'], up['image']), ('upgrade_agent', self.IMG))
        self.assertNotEqual(m.Module._agent_upgrade(mod, self.IMG).retval, 0)  # one at a time
        self.assertIn('agent upgrade', m.Module.upgrade_start(mod, 'quay.io/ceph/ceph@sha256:' + 'ef' * 32, None, None, None, None, None).exception_str)
        res = m.Module._agent_upgrade(mod, None, True)
        self.assertEqual(res.retval, 0, res.stderr)
        self.assertEqual(mod._ledger.executable()[-1][1]['upgrade'], up['id'])
        # the leader recorded it and finished its operation: in progress until its record is finished
        entries['talos/inc/20/journal/op/' + up['id']] = json.dumps({'state': 'completed'})
        entries.update(state_entries(inventory(), {'fsid': 'f', 'sealed': True, 'agent': {'image': 'registry/agent@sha256:' + 'cd' * 32},
                                                   'agent_upgrade': {'op': up['id'], 'image': self.IMG, 'finished': False}}, hosts=[], daemons=[]))
        self.assertEqual(m.Module._agent_upgrade(mod, None, True).retval, 0)
        entries.update(state_entries(inventory(), {'fsid': 'f', 'sealed': True, 'agent': {'image': self.IMG},
                                                   'agent_upgrade': {'op': up['id'], 'image': self.IMG, 'finished': True}}, hosts=[], daemons=[]))
        self.assertNotEqual(m.Module._agent_upgrade(mod, None, True).retval, 0)  # nothing to resume

    def test_the_stop(self):
        mod, entries = self.module()
        cur = 'registry/agent@sha256:' + 'cd' * 32
        self.assertNotEqual(m.Module._agent_upgrade(mod, None, False, True).retval, 0)  # nothing to stop
        mod._approved_images = lambda: [self.IMG]
        self.assertEqual(m.Module._agent_upgrade(mod, self.IMG).retval, 0)
        [(_, up)] = mod._ledger.executable()
        # the image it upgrades from must be approved
        res = m.Module._agent_upgrade(mod, None, False, True)
        self.assertIn('roll back', res.stderr)
        mod._approved_images = lambda: [self.IMG, cur]
        self.assertNotEqual(m.Module._agent_upgrade(mod, self.IMG, False, True).retval, 0)  # no image with --stop
        res = m.Module._agent_upgrade(mod, None, False, True)
        self.assertEqual(res.retval, 0, res.stderr)
        stop = mod._ledger.executable()[-1][1]
        self.assertEqual((stop['kind'], stop['upgrade']), ('upgrade_agent_stop', up['id']))
        self.assertNotEqual(m.Module._agent_upgrade(mod, None, False, True).retval, 0)  # stopping already
        # the leader turned it into a rollback: shown so, and not stopped again
        for jid in (up['id'], stop['id']):
            entries['talos/inc/20/journal/op/' + jid] = json.dumps({'state': 'completed'})
        entries.update(state_entries(inventory(), {'fsid': 'f', 'sealed': True, 'agent': {'image': cur},
                                                   'agent_upgrade': {'op': up['id'], 'from': cur, 'image': cur, 'stopped': self.IMG, 'finished': False}}, hosts=[], daemons=[]))
        self.assertNotEqual(m.Module._agent_upgrade(mod, None, False, True).retval, 0)
        self.assertIn('rolling back', m.Module._agent_upgrade_show(mod).stdout)
        self.assertEqual(m.Module._agent_upgrade(mod, None, True).retval, 0)  # a paused rollback resumes
        entries.update(state_entries(inventory(), {'fsid': 'f', 'sealed': True, 'agent': {'image': cur},
                                                   'agent_upgrade': {'op': up['id'], 'from': cur, 'image': cur, 'stopped': self.IMG, 'finished': True}}, hosts=[], daemons=[]))
        self.assertIn('stopped, rolled back', m.Module._agent_upgrade_show(mod).stdout)
        self.assertNotEqual(m.Module._agent_upgrade(mod, None, False, True).retval, 0)  # nothing to stop


class AddAndRemove(unittest.TestCase):
    def module(self, inv=None):
        mod, entries = Acceptance.module(self, inv=inv)
        mod.get_mgr_id = lambda: 'h3'
        return mod, entries

    def spec(self, typ, placement):
        from ceph.deployment.service_spec import PlacementSpec, ServiceSpec
        return ServiceSpec(typ, placement=PlacementSpec.from_string(placement))

    def ops(self, mod):
        return [(e['kind'], e.get('daemon'), e['host']) for _, e in mod._ledger.executable()]

    def test_daemon_add(self):
        mod, _ = self.module()
        res = m.Module.add_daemon(mod, self.spec('mgr', 'h2'))
        self.assertEqual(res.exception_str, '')
        self.assertIn('mgr.h2', res.result[0])
        for spec in (self.spec('mgr', 'h2'), self.spec('mon', 'h1'), self.spec('mon', 'h9'), self.spec('rgw', 'h2'),
                     self.spec('mon', 'h1 h2'), self.spec('mon', '2 h2'), self.spec('mon', 'label:x'), self.spec('mon', 'h2:10.0.0.0/24'),
                     self.spec('mon', 'h2=other')):
            self.assertTrue(m.Module.add_daemon(mod, spec).exception_str, spec)
        self.assertTrue(m.Module.add_daemon(mod, self.spec('mon', 'h2')).result)
        self.assertEqual(self.ops(mod), [('add_daemon', 'mgr.h2', 'h2'), ('add_daemon', 'mon.h2', 'h2')])
        # a spec field this backend does not take, also one only a newer Ceph has, is refused, not ignored
        from ceph.deployment.service_spec import ServiceSpec
        for extra in ({'config': {'a': 'b'}}, {'spec': {'termination_grace_period_seconds': 120}}):
            try:
                spec = ServiceSpec.from_json(dict({'service_type': 'mgr', 'placement': {'hosts': ['h1']}}, **extra))
            except Exception:
                continue  # an older Ceph refuses it itself
            self.assertTrue(m.Module.add_daemon(mod, spec).exception_str, extra)

    def test_daemon_rm_and_host_rm(self):
        mod, entries = self.module()
        # the active mgr (h3), the last mon (h1) and everything but mons and mgrs are refused
        for names in (['mgr.h3'], ['mon.h1'], ['mgr.h9'], ['osd.0'], ['keepalived.h2']):
            self.assertTrue(m.Module.remove_daemons(mod, names).exception_str, names)
        m.Module.add_daemon(mod, self.spec('mgr', 'h2'))
        [(_, add)] = mod._ledger.executable()
        entries['talos/inc/20/journal/op/' + add['id']] = json.dumps({'state': 'completed'})
        res = m.Module.remove_daemons(mod, ['mgr.h2'])
        self.assertEqual(res.exception_str, '')
        # a host: not with daemons, not the active mgr's, not with --offline
        for args in (('h1',), ('h3',), ('h9',), ('h2', False, True)):
            self.assertTrue(m.Module.remove_host(mod, *args).exception_str, args)
        # h2 still has its mgr in the fold until the removal is retired
        self.assertTrue(m.Module.remove_host(mod, 'h2').exception_str)
        self.assertEqual([k for k, _, _ in self.ops(mod)], ['add_daemon', 'remove_daemon'])

    def test_daemon_rm_of_a_mon(self):
        mod, entries = self.module()
        m.Module.add_daemon(mod, self.spec('mon', 'h2'))
        [(_, add)] = mod._ledger.executable()
        entries['talos/inc/20/journal/op/' + add['id']] = json.dumps({'state': 'completed'})
        # not both: the cluster would have no mon left
        self.assertTrue(m.Module.remove_daemons(mod, ['mon.h1', 'mon.h2']).exception_str)
        res = m.Module.remove_daemons(mod, ['mon.h1'])
        self.assertEqual(res.exception_str, '')
        self.assertEqual(self.ops(mod)[-1], ('remove_daemon', 'mon.h1', 'h1'))


class Maintenance(unittest.TestCase):
    def module(self):
        mod, entries = AddAndRemove.module(self)
        mod.get = lambda what: {'standbys': [{'name': 'h1', 'available': True}]} if what == 'mgr_map' else None
        return mod, entries

    def finish(self, entries, op_id):
        entries['talos/inc/20/journal/op/' + op_id] = json.dumps({'state': 'completed'})

    def test_enter_and_exit(self):
        mod, entries = self.module()
        # h3 is in maintenance in the CLI's state; unknown hosts and Ceph's override are refused
        for args in (('h3',), ('h9',), ('h1', False, True)):
            self.assertTrue(m.Module.enter_host_maintenance(mod, *args).exception_str, args)
        self.assertEqual(m.Module.enter_host_maintenance(mod, 'h1', True).exception_str, '')
        [(_, enter)] = mod._ledger.executable()
        self.assertEqual((enter['kind'], enter['host'], enter['force']), ('enter_maintenance', 'h1', True))
        # nothing else on h1 meanwhile, before or after the enter finished
        self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mon.h1').exception_str)
        self.finish(entries, enter['id'])
        for res in (m.Module.daemon_action(mod, 'restart', 'mon.h1'), m.Module.add_daemon(mod, AddAndRemove.spec(self, 'mgr', 'h1')),
                    m.Module.remove_osds(mod, ['0']), m.Module.enter_host_maintenance(mod, 'h1')):
            self.assertTrue(res.exception_str)
        self.assertTrue(m.Module.exit_host_maintenance(mod, 'h1', True).exception_str)
        self.assertTrue(m.Module.exit_host_maintenance(mod, 'h2').exception_str)
        self.assertEqual(m.Module.exit_host_maintenance(mod, 'h1').exception_str, '')
        self.assertEqual([e['kind'] for _, e in mod._ledger.executable()], ['enter_maintenance', 'exit_maintenance'])

    def test_powercycle(self):
        mod, entries = self.module()
        for args in (('h1',), ('h3', True), ('h9', True)):
            self.assertTrue(m.Module.hardware_powercycle(mod, *args).exception_str, args)
        self.assertEqual(m.Module.hardware_powercycle(mod, 'h1', True).exception_str, '')
        [(_, pc)] = mod._ledger.executable()
        self.assertEqual((pc['kind'], pc['host']), ('powercycle_host', 'h1'))
        self.finish(entries, pc['id'])
        # in maintenance until its maintained entry: nothing else on h1
        self.assertTrue(m.Module.enter_host_maintenance(mod, 'h1').exception_str)
        self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mon.h1').exception_str)

    def test_the_active_mgr_needs_a_standby(self):
        mod, _ = self.module()
        mod.get_mgr_id = lambda: 'h2'
        mod.get = lambda what: {'standbys': []}
        self.assertIn('standby', m.Module.enter_host_maintenance(mod, 'h2').exception_str)


class Upgrade(unittest.TestCase):
    IMG = 'quay.io/ceph/ceph@sha256:' + 'cd' * 32

    def module(self, approved=()):
        import base64
        mod, entries = AddAndRemove.module(self)
        key = 'cephadm-talos/approvals/%020d' % 1
        signed = json.dumps({'payload': base64.b64encode(json.dumps({'images': list(approved)}).encode()).decode(), 'signature': 'x'})
        mod.mon_command = lambda cmd: (0, json.dumps([key]), '') if cmd['prefix'] == 'config-key ls' else (0, signed, '')
        mod.get = lambda what: {'standbys': [{'name': 'h1', 'available': True}]}
        return mod, entries

    def test_start_needs_an_approved_digest_of_the_repository(self):
        mod, _ = self.module()
        for args in (('quay.io/ceph/ceph:v20.2.5',), ('docker.io/x/ceph@sha256:' + 'cd' * 32,), (self.IMG,)):
            self.assertTrue(m.Module.upgrade_start(mod, args[0], None, None, None, None, None).exception_str, args)
        mod, _ = self.module(approved=[self.IMG])
        self.assertTrue(m.Module.upgrade_start(mod, self.IMG, '20.2.5', None, None, None, None).exception_str)
        # Ceph 21's `orch upgrade start` passes the CRUSH bucket filter too
        self.assertIn('only --image', m.Module.upgrade_start(mod, self.IMG, None, None, None, None, None, 'rack', 'r1').exception_str)
        # h3 is in maintenance in the CLI's state: refused until it is out
        self.assertIn('maintenance', m.Module.upgrade_start(mod, self.IMG, None, None, None, None, None).exception_str)

    def test_controls_and_status(self):
        mod, entries = self.module(approved=[self.IMG])
        inv = inventory()
        inv['hosts'][2].pop('maintenance')
        mod, entries = AddAndRemove.module(self, inv)
        base = self.module(approved=[self.IMG])[0]
        mod.mon_command, mod.get = base.mon_command, base.get
        self.assertTrue(m.Module.upgrade_pause(mod).exception_str)  # none in progress
        res = m.Module.upgrade_start(mod, self.IMG, None, None, None, None, None)
        self.assertEqual(res.exception_str, '')
        [(_, start)] = mod._ledger.executable()
        # a second start, maintenance and powercycle wait for it
        self.assertTrue(m.Module.upgrade_start(mod, self.IMG, None, None, None, None, None).exception_str)
        self.assertTrue(m.Module.enter_host_maintenance(mod, 'h1').exception_str)
        self.assertTrue(m.Module.hardware_powercycle(mod, 'h1', True).exception_str)
        st = m.Module.upgrade_status(mod).result
        self.assertTrue(st.in_progress and st.target_image == self.IMG and not st.is_paused)
        self.assertTrue(m.Module.upgrade_resume(mod).exception_str)  # not paused
        self.assertEqual(m.Module.upgrade_pause(mod).exception_str, '')
        self.assertTrue(m.Module.upgrade_status(mod).result.is_paused)
        self.assertEqual(m.Module.upgrade_stop(mod).exception_str, '')
        self.assertFalse(m.Module.upgrade_status(mod).result.in_progress)
        kinds = [(e['kind'], e.get('upgrade')) for _, e in mod._ledger.executable()]
        self.assertEqual(kinds, [('upgrade_start', None), ('upgrade_pause', start['id']), ('upgrade_stop', start['id'])])


class RGWs(unittest.TestCase):
    def module(self):
        mod, entries = AddAndRemove.module(self)
        self.written = {}
        mod.mon_command = lambda cmd: (self.written.__setitem__(cmd['key'], cmd['val']) or 0, '', '')
        return mod, entries

    def spec(self, host='h2', port=None, cert=None, **kw):
        from ceph.deployment.service_spec import PlacementSpec, RGWSpec
        return RGWSpec(service_id='default', placement=PlacementSpec.from_string(host), rgw_frontend_port=port,
                       rgw_frontend_ssl_certificate=cert, **kw)

    def operator_pem(self):
        from talos import bridge as b
        ca, ca_key = b.new_rgw_ca('f')
        cert, key = b.issue_rgw_cert(ca.encode(), ca_key.encode(), [], ['s3.example.com'])
        return cert + key

    def test_add_with_a_generated_or_the_operators_certificate(self):
        mod, _ = self.module()
        for spec in (self.spec(port=8443, rgw_realm='r'), self.spec(host='h9'), self.spec(host='h1 h2'), self.spec(cert='nonsense')):
            self.assertTrue(m.Module.add_daemon(mod, spec).exception_str, spec)
        self.assertEqual(m.Module.add_daemon(mod, self.spec()).exception_str, '')
        [(_, first)] = mod._ledger.executable()
        self.assertEqual((first['daemon'], first['port']), ('rgw.h2', 443))
        self.assertNotIn('cert', first)
        # the port is the first RGW's
        self.assertIn('443', m.Module.add_daemon(mod, self.spec(host='h1', port=8443)).exception_str)
        res = m.Module.add_daemon(mod, self.spec(host='h1', cert=self.operator_pem()))
        self.assertEqual(res.exception_str, '')
        second = mod._ledger.executable()[-1][1]
        # the key is a secret of the operation, the chain in the entry
        self.assertIn('BEGIN CERTIFICATE', second['cert'])
        self.assertNotIn('PRIVATE KEY', second['cert'])
        [(key, val)] = self.written.items()
        self.assertEqual(key, 'cephadm-talos/secrets/user/%s/rgw-server.key' % second['id'])
        self.assertIn('PRIVATE KEY', val)

    def test_the_operators_certificate_in_cephs_newer_spec_form(self):
        """Ceph 21 moves the bundle into ssl_cert and ssl_key when ssl is set."""
        from ceph.deployment.service_spec import ServiceSpec
        mod, _ = self.module()
        pem = self.operator_pem()
        spec = ServiceSpec.from_json({'service_type': 'rgw', 'service_id': 'default', 'placement': {'hosts': ['h2']},
                                      'spec': {'ssl': True, 'rgw_frontend_ssl_certificate': pem}})
        self.assertEqual(m.Module.add_daemon(mod, spec).exception_str, '')
        [(_, e)] = mod._ledger.executable()
        self.assertIn('BEGIN CERTIFICATE', e['cert'])
        self.assertIn('PRIVATE KEY', list(self.written.values())[0])
        # a field this backend does not take, and a certificate without its key
        for bad in ({'ssl': True, 'rgw_exit_timeout_secs': 30}, {'rgw_exit_timeout_secs': 0}, {'rgw_frontend_port': 0}, {'ssl_cert': 'x'}):
            try:
                spec = ServiceSpec.from_json({'service_type': 'rgw', 'service_id': 'default', 'placement': {'hosts': ['h1']}, 'spec': bad})
            except Exception:
                continue  # an older Ceph refuses it itself
            self.assertTrue(m.Module.add_daemon(mod, spec).exception_str, bad)

    def test_rm_waits_for_the_ingress_to_leave_the_host(self):
        mod, entries = self.module()
        # h2 runs keepalived.h2 in the CLI's state: its RGW stays
        m.Module.add_daemon(mod, self.spec())
        [(_, add)] = mod._ledger.executable()
        entries['talos/inc/20/journal/op/' + add['id']] = json.dumps({'state': 'completed'})
        self.assertIn('keepalived', m.Module.remove_daemons(mod, ['rgw.h2']).exception_str)


class Ingress(unittest.TestCase):
    IMG = 'quay.io/ceph/keepalived@sha256:' + 'cd' * 32

    def module(self, approved=(IMG,), password='abc', rgws=('h1', 'h2')):
        import base64
        inv = inventory()
        inv['daemons'] += [{'doc_name': 'ceph-f-rgw-' + h, 'host': h, 'daemon_type': 'rgw', 'daemon_id': h, 'service_name': 'rgw.default',
                            'desired_image': 'quay.io/ceph/ceph@sha256:a'} for h in rgws]
        mod, entries = AddAndRemove.module(self, inv)
        self.written = {}
        key = 'cephadm-talos/approvals/%020d' % 1
        signed = json.dumps({'payload': base64.b64encode(json.dumps({'images': list(approved)}).encode()).decode(), 'signature': 'x'})

        def mon(cmd):
            if cmd['prefix'] == 'config-key ls':
                return 0, json.dumps([key]), ''
            if cmd['prefix'] == 'config-key set':
                self.written[cmd['key']] = cmd['val']
                return 0, '', ''
            if cmd['key'] == key:
                return 0, signed, ''
            return 0, password, ''
        mod.mon_command = mon
        mod.get_module_option = lambda name: self.IMG
        return mod, entries

    def spec(self, hosts='h1 h2', vip='10.5.0.200/24', **kw):
        from ceph.deployment.service_spec import IngressSpec, PlacementSpec
        return IngressSpec(service_id='rgw.default', backend_service='rgw.default', keepalive_only=True, virtual_ip=vip,
                           placement=PlacementSpec.from_string(hosts), **kw)

    def test_apply_the_keepalived_only_ingress(self):
        mod, _ = self.module()
        # the CLI's sealed state has keepalived.h2 without a VIP of its own record: first apply
        for spec in (self.spec(hosts='h3'), self.spec(vip='10.5.0.200'), self.spec(vip='fd00::1/64'), self.spec(first_virtual_router_id=300),
                     self.spec(keepalived_password='way-too-long'), self.spec(enable_haproxy_protocol=True)):
            self.assertTrue(m.Module.apply(mod, [spec]).exception_str, spec)
        res = m.Module.apply(mod, [self.spec()])
        self.assertEqual(res.exception_str, '')
        [(_, e)] = mod._ledger.executable()
        self.assertEqual((e['kind'], e['vip'], e['vrid'], e['hosts'], e['image'], e['new_password']),
                         ('apply_ingress', '10.5.0.200/24', 50, ['h1', 'h2'], self.IMG, True))
        [(k, pw)] = self.written.items()
        self.assertEqual(k, 'cephadm-talos/secrets/ingress/%s/vrrp' % e['id'])
        self.assertTrue(re.match(r'\A[A-Za-z0-9]{8}\Z', pw))
        # later: the same VIP and router id; the password kept, or the same one
        self.assertTrue(m.Module.apply(mod, [self.spec(vip='10.5.0.201/24')]).exception_str)
        self.assertTrue(m.Module.apply(mod, [self.spec(first_virtual_router_id=51)]).exception_str)
        self.assertTrue(m.Module.apply(mod, [self.spec(keepalived_password='other')]).exception_str)
        self.assertEqual(m.Module.apply(mod, [self.spec(hosts='h1', keepalived_password='abc')]).exception_str, '')
        self.assertFalse(mod._ledger.executable()[-1][1]['new_password'])

    def test_not_on_a_host_in_maintenance(self):
        mod, _ = self.module(rgws=('h1', 'h2', 'h3'))
        self.assertIn('maintenance', m.Module.apply(mod, [self.spec(hosts='h1 h3')]).exception_str)

    def test_the_keepalived_image_must_be_approved(self):
        mod, _ = self.module(approved=())
        self.assertIn('approved', m.Module.apply(mod, [self.spec()]).exception_str)


class HostAdd(unittest.TestCase):
    CERT = '-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n'

    def module(self, records):
        mod, entries = AddAndRemove.module(self)

        def mon(cmd):
            k = cmd['key'][len('cephadm-talos/enroll/'):]
            return (0, json.dumps(records[k]), '') if k in records else (-2, '', 'not found')
        mod.mon_command = mon
        return mod, entries

    def test_an_enrolled_node(self):
        from ceph.deployment.hostspec import HostSpec
        rec = {'version': 1, 'name': 'h4', 'addr': '10.5.0.5', 'agent_cert': self.CERT, 'agent_client_cert': self.CERT}
        mod, _ = self.module({'h4': rec})
        for spec in (HostSpec('h5', '10.5.0.6'), HostSpec('h4', '10.5.0.9'), HostSpec('h1', '10.5.0.2'),
                     HostSpec('h4', '10.5.0.5', labels=['bad label']), HostSpec('h4', '10.5.0.5', status='maintenance')):
            self.assertTrue(m.Module.add_host(mod, spec).exception_str, spec)
        res = m.Module.add_host(mod, HostSpec('h4', '10.5.0.5', labels=['rgw']))
        self.assertEqual(res.exception_str, '')
        [(_, e)] = mod._ledger.executable()
        self.assertEqual((e['kind'], e['host'], e['addr'], e['labels'], e['agent_cert']), ('add_host', 'h4', '10.5.0.5', ['rgw'], self.CERT))
        _, fold = mod._authority()
        self.assertEqual(fold.hosts['h4'], '10.5.0.5')
        # Ceph's own routing of `orch host add` reaches it (h4 is a host now)
        self.assertIn('already', m.Module.apply(mod, [HostSpec('h4', '10.5.0.5')]).exception_str)


class Requests(unittest.TestCase):
    UUID = '0f8fad5b-d9cb-469f-a165-70867728950e'

    def body(self, cmd, sub=None):
        import hashlib
        b = {'cmd': cmd, 'inbuf': sub}
        return json.dumps(b), hashlib.sha256(json.dumps(b, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

    def test_once_per_request(self):
        mod, _ = Acceptance.module(self)
        calls = []

        def remote(module, method, sub, cmd):
            calls.append(cmd['prefix'])
            r = m.Module.daemon_action(mod, 'restart', cmd['name'])
            return 0 if not r.exception_str else -22, r.result or '', r.exception_str
        mod.remote = remote
        cmd = {'prefix': 'orch daemon', 'action': 'restart', 'name': 'mon.h1'}
        inbuf, h = self.body(cmd)
        res = m.Module._request(mod, self.UUID, h, inbuf)
        self.assertEqual(res.retval, 0, res.stderr)
        [(_, e)] = mod._ledger.executable()
        self.assertEqual((e['request'], e['inputs']), (self.UUID, h))
        # again, through any mgr: the same operation, the command not run again
        res = m.Module._request(mod, self.UUID, h, inbuf)
        self.assertIn(e['id'], res.stdout)
        self.assertEqual(calls, ['orch daemon'])
        # the same uuid for another command, a wrong hash, several daemons
        other, oh = self.body(dict(cmd, name='mgr.h3'))
        self.assertEqual(m.Module._request(mod, self.UUID, oh, other).retval, -17)
        self.assertEqual(m.Module._request(mod, self.UUID, 'ab' * 32, inbuf).retval, -22)
        many, mh = self.body({'prefix': 'orch daemon rm', 'names': ['mgr.h1', 'mgr.h2']})
        self.assertEqual(m.Module._request(mod, '1f8fad5b-d9cb-469f-a165-70867728950e', mh, many).retval, -22)
        self.assertEqual(len(mod._ledger.executable()), 1)

    def test_a_daemon_spec_goes_to_the_backend_directly(self):
        mod, _ = RGWs.module(self)
        mod.remote = lambda *a: self.fail('through the orchestrator module, which logs whole specs')
        pem = RGWs.operator_pem(self)
        spec = 'service_type: rgw\nservice_id: default\nplacement:\n  hosts: [h2]\nspec:\n  rgw_frontend_ssl_certificate: |\n' + \
            ''.join('    %s\n' % line for line in pem.strip().splitlines())
        inbuf, h = self.body({'prefix': 'orch daemon add'}, spec)
        res = m.Module._request(mod, self.UUID, h, inbuf)
        self.assertEqual(res.retval, 0, res.stderr)
        [(_, e)] = mod._ledger.executable()
        self.assertEqual((e['daemon'], e['request']), ('rgw.h2', self.UUID))
        self.assertIn('BEGIN CERTIFICATE', e['cert'])
        # two specs in one request
        two, th = self.body({'prefix': 'orch apply'}, 'service_type: mon\n---\nservice_type: mgr\n')
        self.assertEqual(m.Module._request(mod, '2f8fad5b-d9cb-469f-a165-70867728950e', th, two).retval, -22)


class Conflicts(unittest.TestCase):
    def test_a_host_removal_and_daemons_on_that_host_exclude_each_other(self):
        inv = inventory()
        inv['hosts'].append({'name': 'h4', 'addr': '10.5.0.5'})
        mod, entries = AddAndRemove.module(self, inv)
        # h4 has no daemons: its removal goes in, then no add on h4 beside it
        self.assertEqual(m.Module.remove_host(mod, 'h4').exception_str, '')
        self.assertTrue(m.Module.add_daemon(mod, AddAndRemove.spec(self, 'mgr', 'h4')).exception_str)
        self.assertEqual([e['kind'] for _, e in mod._ledger.executable()], ['remove_host'])

    def test_a_batch_removal_accepts_all_or_nothing(self):
        mod, entries = AddAndRemove.module(self)
        for host in ('h1', 'h2'):
            m.Module.add_daemon(mod, AddAndRemove.spec(self, 'mgr', host))
        first, second = [e['id'] for _, e in mod._ledger.executable()]
        entries['talos/inc/20/journal/op/' + first] = json.dumps({'state': 'completed'})
        # mgr.h2's add is not finished: neither removal goes in
        self.assertTrue(m.Module.remove_daemons(mod, ['mgr.h1', 'mgr.h2']).exception_str)
        self.assertEqual(len(mod._ledger.executable()), 2)


class CreateOSDs(unittest.TestCase):
    def dg(self, host, *paths, **kw):
        from ceph.deployment.drive_group import DeviceSelection, DriveGroupSpec
        from ceph.deployment.service_spec import PlacementSpec
        return DriveGroupSpec(placement=PlacementSpec(host_pattern=host), data_devices=DeviceSelection(paths=list(paths)), **kw)

    def test_one_osd_on_one_disk(self):
        mod, _ = AddAndRemove.module(self)
        res = m.Module.create_osds(mod, self.dg('h2', '/dev/sdb'))
        self.assertEqual(res.exception_str, '')
        [(_, e)] = mod._ledger.executable()
        self.assertEqual((e['kind'], e['host'], e['device']), ('create_osd', 'h2', '/dev/sdb'))
        # not beside an unfinished one on the same disk; not elsewhere than one host
        for dg in (self.dg('h2', '/dev/sdb'), self.dg('h9', '/dev/sdb'), self.dg('h*', '/dev/sdb'), self.dg('h2', '/dev/sdb', '/dev/sdc'),
                   self.dg('h2', 'sdb'), self.dg('h2', '/dev/sdc', encrypted=True)):
            self.assertTrue(m.Module.create_osds(mod, dg).exception_str, dg)
        self.assertTrue(m.Module.create_osds(mod, self.dg('h2', '/dev/sdc'), skip_validation=True).exception_str)
        for kw in ({'preview_only': True}, {'crush_device_class': 'ssd'}, {'data_allocate_fraction': 0.5}, {'block_db_size': '10G'},
                   {'osd_id_claims': {'h2': ['3']}}, {'extra_entrypoint_args': ['--x']}):
            self.assertTrue(m.Module.create_osds(mod, self.dg('h2', '/dev/sdd', **kw)).exception_str, kw)
        self.assertEqual(m.Module.create_osds(mod, self.dg('h2', '/dev/sdc')).exception_str, '')


class RemoveOSDs(unittest.TestCase):
    def test_remove_and_status(self):
        inv = inventory()
        inv['daemons'][1]['osd_uuid'] = '8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f'  # osd.0 on h1
        mod, entries = AddAndRemove.module(self, inv)
        for args, kw in ((['9'], {}), (['0'], {'replace': True}), (['0'], {'no_destroy': True}), (['0', '0'], {})):
            self.assertTrue(m.Module.remove_osds(mod, args, **kw).exception_str, (args, kw))
        res = m.Module.remove_osds(mod, ['0'], zap=True)
        self.assertEqual(res.exception_str, '')
        [(_, e)] = mod._ledger.executable()
        self.assertEqual((e['kind'], e['daemon'], e['uuid'], e['zap'], e['force']), ('remove_osd', 'osd.0', '8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f', True, False))
        [st] = m.Module.remove_osds_status(mod).result
        self.assertEqual((st['osd_id'], st['hostname'], st['zap'], st['drain_status']), (0, 'h1', True, 'draining'))
        self.assertTrue(m.Module.remove_osds(mod, ['0']).exception_str)  # in progress
        entries['talos/inc/20/journal/op/' + e['id']] = json.dumps({'state': 'completed'})
        self.assertEqual(m.Module.remove_osds_status(mod).result, [])


class BatchAfterAnUnknownAppend(unittest.TestCase):
    def test_settled_before_the_checks(self):
        inv = inventory()
        inv['daemons'][1]['osd_uuid'] = '8f2c0a4e-1d3b-4c5a-9e6f-7a8b9c0d1e2f'
        mod, _ = AddAndRemove.module(self, inv)
        mod._ledger.mon.silent = 1
        self.assertTrue(m.Module.remove_osds(mod, ['0']).exception_str)  # outcome unknown
        # the retry settles the first, then finds it in progress
        self.assertTrue(m.Module.remove_osds(mod, ['0'], zap=True).exception_str)
        self.assertEqual(len(mod._ledger.executable()), 1)


class UpgradePausedByTheLeader(unittest.TestCase):
    def test_resume_after_a_failed_step(self):
        inv = inventory()
        inv['hosts'][2].pop('maintenance')
        mod, entries = AddAndRemove.module(self, inv)
        base = Upgrade.module(self, approved=[Upgrade.IMG])[0]
        mod.mon_command, mod.get = base.mon_command, base.get
        self.assertEqual(m.Module.upgrade_start(mod, Upgrade.IMG, None, None, None, None, None).exception_str, '')
        [(_, start)] = mod._ledger.executable()
        paused = dict(inv, upgrade={'op': start['id'], 'image': Upgrade.IMG, 'version': '20.2.5', 'paused': True,
                                    'error': 'mon.h1 not done within 10m0s', 'done': []})
        mod._inventory = lambda: paused
        st = m.Module.upgrade_status(mod).result
        self.assertTrue(st.is_paused and 'not done' in st.message)
        self.assertEqual(m.Module.upgrade_resume(mod).exception_str, '')


class Compaction(unittest.TestCase):
    """Plan 04, step 4: backpressure, the lookup table, journal pruning."""
    NOW = __import__('datetime').datetime(2026, 11, 4, tzinfo=__import__('datetime').timezone.utc)

    def test_backpressure_spares_the_controls(self):
        from talos import ledger as lg
        mod, entries = Upgrade.module(self, approved=[Upgrade.IMG])
        mod._ledger.append({'id': 'op-%016x' % 9999, 'kind': 'upgrade_start', 'image': Upgrade.IMG})
        for i in range(m.MAX_UNFINISHED):
            mod._ledger.append({'id': 'op-%016x' % i, 'kind': 'restart', 'daemon': 'mgr.h3', 'host': 'h3'})
        res = m.Module.daemon_action(mod, 'restart', 'mon.h1')
        self.assertIn('unfinished', res.exception_str)
        with self.assertRaisesRegex(m.OrchestratorError, 'unfinished'):
            m.Module._accept_create(mod, 'h1', '/dev/vdb')
        # the upgrade's controls go in
        self.assertEqual(m.Module.upgrade_pause(mod).exception_str, '')
        # once the leader catches up, new operations are accepted again
        for i in range(10):
            entries['talos/inc/20/journal/op/op-%016x' % i] = json.dumps({'state': 'completed'})
        self.assertEqual(m.Module.daemon_action(mod, 'restart', 'mon.h1').exception_str, '')
        self.assertEqual(lg.TERMINAL, m.TERMINAL)

    def compacted(self):
        """A module whose ledger has a snapshot covering a request's restart."""
        import hashlib
        mod, entries = Acceptance.module(self)
        mod._gid = 20
        cmd = {'prefix': 'orch daemon', 'action': 'restart', 'name': 'mon.h1'}
        inbuf = json.dumps({'cmd': cmd, 'inbuf': None})
        h = hashlib.sha256(json.dumps({'cmd': cmd, 'inbuf': None}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        led = mod._ledger
        key, op = led.append({'id': 'op-%016x' % 1, 'kind': 'restart', 'daemon': 'mon.h1', 'host': 'h1', 'request': Requests.UUID, 'inputs': h})
        entries['talos/inc/20/journal/op/' + op['id']] = json.dumps({'state': 'completed'})
        states = {op['id']: 'completed'}
        rel, content = led.cut(m.cli_baseline(entries), states, key, set(), self.NOW)
        self.assertTrue(led.publish(rel, content, self.NOW))
        self.assertEqual(led.executable(), [])
        return mod, entries, op, inbuf, h

    def test_operation_and_request_over_the_lookup_table(self):
        from talos import ledger as lg
        mod, entries, op, inbuf, h = self.compacted()
        mod.remote = lambda *a: self.fail('run again')
        res = m.Module._request(mod, Requests.UUID, h, inbuf)
        self.assertEqual(res.retval, 0, res.stderr)
        self.assertIn(op['id'], res.stdout)
        other = json.dumps({'cmd': {'prefix': 'orch daemon', 'action': 'restart', 'name': 'mgr.h3'}, 'inbuf': None})
        import hashlib
        oh = hashlib.sha256(json.dumps(json.loads(other), sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(m.Module._request(mod, Requests.UUID, oh, other).retval, -17)
        out = m.Module._operation(mod, op['id'])
        self.assertEqual(out.retval, 0, out.stderr)
        shown = json.loads(out.stdout)
        self.assertEqual((shown['accepted']['kind'], shown['journal']['state']), ('restart', 'completed'))
        # the journal pruned, the table still has its state
        del entries['talos/inc/20/journal/op/' + op['id']]
        self.assertEqual(json.loads(m.Module._operation(mod, op['id']).stdout)['journal'], {'state': 'completed'})
        # 30 days after the cut that covered it, a later cut drops it
        key, nxt = mod._ledger.append({'id': 'op-%016x' % 2, 'kind': 'restart', 'daemon': 'mon.h1', 'host': 'h1'})
        rel, content = mod._ledger.cut(m.cli_baseline(entries), {nxt['id']: 'completed'}, key, set(), self.NOW + lg.LOOKUP_KEEP)
        self.assertTrue(mod._ledger.publish(rel, content, self.NOW + lg.LOOKUP_KEEP))
        self.assertEqual(m.Module._operation(mod, op['id']).retval, -2)
        self.assertEqual(m.Module._operation(mod, nxt['id']).retval, 0)

    def test_pruning_across_incarnations(self):
        from talos import ledger as lg
        mod, entries, op, _, _ = self.compacted()
        led = mod._ledger
        above, _ = led.append({'id': 'op-%016x' % 3, 'kind': 'restart', 'daemon': 'mon.h1', 'host': 'h1'})
        cov = op['id']
        rgw = 'op-%016x' % 7  # covered, its certificate still in use: not in this ledger, so made live by hand
        j20, j10 = 'talos/inc/20/journal/', 'talos/inc/10/journal/'
        recs = {
            j20 + 'takeover': json.dumps({'epoch': 7}), j20 + 'op/' + cov: '{}', j20 + 'op/' + cov + '.rev': json.dumps({'state': 'completed'}),
            j20 + 'op/' + cov + '.prep': json.dumps({'state': 'uncertain'}),  # this incarnation still asks the agent
            j20 + 'op/op-%016x' % 3: '{}', j20 + 'roll/' + cov + '.plan': '{}', j20 + 'roll/' + rgw + '.roll.h1': '{}',
            j20 + 'roll/' + cov + '.renew': '{}', j20 + 'req/x': '{}',
            j10 + 'takeover': json.dumps({'epoch': 5}), j10 + 'op/' + cov: '{}', j10 + 'op/' + cov + '.prep': json.dumps({'state': 'uncertain'}),
            'talos/inc/30/journal/takeover': json.dumps({'epoch': 9}), 'talos/inc/30/journal/op/op-%016x' % 3: '{}',
        }
        # 10's takeover record stays until a later incarnation published
        entries.update(recs)
        mod._prune_journals(led.covered())
        self.assertNotIn('mgr/cephadm/' + j10 + 'takeover', led.mon.rms)
        led.mon.rms.clear()
        recs['talos/inc/20/manifest/%020d' % 1] = '{}'
        entries.update(recs)
        fold = led.fold(m.cli_baseline(entries))
        fold.rgw_certs['issued/%s/%s' % (rgw, 'ab' * 8)] = {'pos': 0, 'retired': False}
        mod._authority = lambda: (led, fold)
        mod._prune_journals(led.covered())
        gone = {k[len('mgr/cephadm/'):] for k in led.mon.rms}
        self.assertEqual(gone, {j20 + 'op/' + cov, j20 + 'op/' + cov + '.rev', j20 + 'roll/' + cov + '.plan',
                                j10 + 'op/' + cov, j10 + 'op/' + cov + '.prep', j10 + 'takeover'})
        # the takeover record went last; 30 has published nothing and keeps its own
        self.assertEqual(led.mon.rms[-1], 'mgr/cephadm/' + j10 + 'takeover')
        # the renewal's record goes with its done entry
        fold.renewals_done.add(cov)
        led.mon.rms.clear()
        mod._prune_journals(led.covered())
        self.assertIn('mgr/cephadm/' + j20 + 'roll/' + cov + '.renew', led.mon.rms)
        self.assertTrue(above > lg.LEDGER_PREFIX)

    def test_a_compaction_run(self):
        from talos import ledger as lg
        mod, entries = Acceptance.module(self)
        mod._gid = 20
        mod._logger = types.SimpleNamespace(info=lambda *a: None, warning=lambda *a: None)
        led = mod._ledger
        for i in range(1, 6):
            led.append({'id': 'op-%016x' % i, 'kind': 'restart', 'daemon': 'mon.h1', 'host': 'h1'})
            entries['talos/inc/20/journal/op/op-%016x' % i] = json.dumps({'state': 'completed'})
        applied = max(led.entries)
        entries.update(state_entries(inventory(), {'fsid': 'f', 'sealed': True, 'ledger_applied': applied}, incarnation='20'))
        old = lg.COMPACT_AFTER
        lg.COMPACT_AFTER = 3
        try:
            m.Module._compact(mod, led, lambda: True, self.NOW)
            self.assertEqual(lg.LEDGER_PREFIX + led.snapshot_key, applied)
            self.assertEqual(led.mon.rms, [])  # deleted only later
            m.Module._compact(mod, led, lambda: True, self.NOW + lg.DELETE_AFTER)
        finally:
            lg.COMPACT_AFTER = old
        self.assertFalse([k for k in led.mon.kv if k.startswith(lg.LEDGER_PREFIX)])
        self.assertIn('mgr/cephadm/talos/inc/20/journal/op/op-%016x' % 1, led.mon.rms)

    def test_an_upgrade_start_stays_pinned_until_its_record_is_cleared(self):
        """Codex round 1: a finished upgrade still asks `upgrade done` until
        the leader cleared its record; an agent upgrade's start is unpinned
        once finished."""
        from talos import ledger as lg
        img = 'quay.io/ceph/ceph@sha256:' + 'cd' * 32
        for record, cut in (({'upgrade': {'op': 'op-%016x' % 1, 'finished': True}}, False), ({}, True),
                            ({'agent_upgrade': {'op': 'op-%016x' % 1, 'finished': False}}, False),
                            ({'agent_upgrade': {'op': 'op-%016x' % 1, 'finished': True}}, True)):
            mod, entries = Acceptance.module(self)
            mod._gid = 20
            mod._logger = types.SimpleNamespace(info=lambda *a: None, warning=lambda *a: None)
            led = mod._ledger
            led.append({'id': 'op-%016x' % 1, 'kind': 'upgrade_start', 'image': img})
            led.append({'id': 'm-%016x' % 1, 'kind': 'upgrade_done', 'of': 'op-%016x' % 1})
            for i in range(2, 6):
                led.append({'id': 'op-%016x' % i, 'kind': 'restart', 'daemon': 'mon.h1', 'host': 'h1'})
            for i in range(1, 6):
                entries['talos/inc/20/journal/op/op-%016x' % i] = json.dumps({'state': 'completed'})
            entries.update(state_entries(inventory(), dict({'fsid': 'f', 'sealed': True, 'ledger_applied': max(led.entries)}, **record), incarnation='20'))
            old = lg.COMPACT_AFTER
            lg.COMPACT_AFTER = 3
            try:
                m.Module._compact(mod, led, lambda: True, self.NOW)
            finally:
                lg.COMPACT_AFTER = old
            covered = led.snapshot is not None and lg.LEDGER_PREFIX + led.snapshot_key >= lg.entry_key(7, 1, 'op-%016x' % 1)
            self.assertEqual(covered, cut, record)


def drain_inventory(**extra):
    """Hosts h1 to h5 (h5 in maintenance); four mons, mgrs on h1 and h2, an OSD
    and an RGW on h1, a keepalived on h4."""
    def d(t, i, host, **kw):
        return dict({'doc_name': 'ceph-f-%s-%s' % (t, i), 'host': host, 'daemon_type': t, 'daemon_id': i, 'service_name': t}, **kw)
    inv = inventory()
    inv['hosts'] = [{'name': 'h%d' % i, 'addr': '10.5.0.%d' % i} for i in range(1, 6)]
    inv['hosts'][4]['maintenance'] = True
    inv['daemons'] = [d('mon', 'h%d' % i, 'h%d' % i) for i in range(1, 5)] + [
        d('mgr', 'h1', 'h1'), d('mgr', 'h2', 'h2'), d('osd', '0', 'h1', osd_uuid='00000000-0000-4000-8000-000000000000'),
        d('rgw', 'h1', 'h1', service_name='rgw.default'), d('keepalived', 'h4', 'h4', service_name='ingress.rgw.default')]
    inv.update(extra)
    return inv


class Drain(unittest.TestCase):
    """plan 04, step 5: `ceph orch host drain` and `drain stop`."""

    def module(self, inv=None, standbys=True):
        mod, entries = Acceptance.module(self, inv=inv or drain_inventory())
        mod._gid = 20
        mod.get_mgr_id = lambda: 'h1'
        mod.get = lambda what: {'standbys': [{'name': 'h2', 'available': True}] if standbys else []} if what == 'mgr_map' else None
        return mod, entries

    def record(self, entries, inv, **drain):
        """The leader's published state with h1's drain record."""
        inv = json.loads(json.dumps(inv))
        inv['hosts'][0]['drain'] = drain
        entries.update(state_entries(inv, {'fsid': 'f', 'sealed': True}, incarnation='20'))

    def test_refusals(self):
        mod, _ = self.module()
        for args in (('h1', True), ('h1', False, True), ('h9',), ('h5',), ('h4',)):
            self.assertTrue(m.Module.drain_host(mod, *args).exception_str, args)
        # three mons: none can go; the last mgr; the active mgr without a standby
        three = drain_inventory()
        three['daemons'] = [x for x in three['daemons'] if x['doc_name'] != 'ceph-f-mon-h4']
        self.assertIn('three', m.Module.drain_host(self.module(three)[0], 'h2').exception_str)
        lonely = drain_inventory()
        lonely['daemons'] = [x for x in lonely['daemons'] if x['doc_name'] != 'ceph-f-mgr-h2']
        self.assertIn('last mgr', m.Module.drain_host(self.module(lonely)[0], 'h1').exception_str)
        self.assertIn('standby', m.Module.drain_host(self.module(standbys=False)[0], 'h1').exception_str)
        # an upgrade or an ingress apply unfinished
        mod, _ = self.module()
        mod._ledger.append({'id': 'op-%016x' % 1, 'kind': 'upgrade_start', 'image': Upgrade.IMG})
        self.assertIn('upgrade', m.Module.drain_host(mod, 'h1').exception_str)
        mod, _ = self.module()
        mod._ledger.append({'id': 'op-%016x' % 2, 'kind': 'apply_ingress', 'vip': '10.5.0.100/24', 'vrid': 51, 'hosts': ['h4'],
                            'image': Upgrade.IMG, 'new_password': False})
        self.assertIn('ingress', m.Module.drain_host(mod, 'h1').exception_str)
        self.assertEqual(mod._ledger.executable()[-1][1]['kind'], 'apply_ingress')

    def test_drain_stop_and_resume(self):
        inv = drain_inventory()
        del inv['hosts'][4]['maintenance']
        mod, entries = self.module(inv)
        res = m.Module.drain_host(mod, 'h1', zap_osd_devices=True)
        self.assertEqual(res.exception_str, '')
        [(_, drain)] = mod._ledger.executable()
        self.assertEqual((drain['kind'], drain['host'], drain['zap']), ('drain_host', 'h1', True))
        entries['talos/inc/20/journal/op/' + drain['id']] = json.dumps({'state': 'completed'})
        # nothing new on h1 meanwhile, no other drain, no maintenance, no upgrade
        for res in (m.Module.add_daemon(mod, AddAndRemove.spec(self, 'mgr', 'h1')), m.Module.daemon_action(mod, 'restart', 'mon.h1'),
                    m.Module.remove_osds(mod, ['0']), m.Module.enter_host_maintenance(mod, 'h1'), m.Module.drain_host(mod, 'h2'),
                    m.Module.drain_host(mod, 'h1', zap_osd_devices=True)):
            self.assertTrue(res.exception_str)
        with self.assertRaisesRegex(m.OrchestratorError, 'draining'):
            m.Module._accept_create(mod, 'h1', '/dev/vdb')
        mod._approved_images = lambda: [Upgrade.IMG]
        self.assertIn('draining', m.Module.upgrade_start(mod, Upgrade.IMG, None, None, None, None, None).exception_str)
        # paused by the leader: drain again resumes it, with the same --zap-osd-devices
        self.record(entries, inv, op=drain['id'], step='', paused=True, error='osd.0: no answer')
        self.assertTrue(m.Module.drain_host(mod, 'h1').exception_str)
        self.assertEqual(m.Module.drain_host(mod, 'h1', zap_osd_devices=True).exception_str, '')
        self.assertEqual(mod._ledger.executable()[-1][1]['kind'], 'drain_resume')
        self.assertEqual(m.Module.get_hosts(mod).result[0].status, 'draining')
        # stop: the fold drops the mark at once, the leader's record still holds h1
        self.assertTrue(m.Module.stop_drain_host(mod, 'h2').exception_str)
        self.assertEqual(m.Module.stop_drain_host(mod, 'h1').exception_str, '')
        stop = mod._ledger.executable()[-1][1]
        self.assertEqual((stop['kind'], stop['drain']), ('drain_stop', drain['id']))
        self.assertEqual(mod._authority()[1].draining, {})
        self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mon.h1').exception_str)
        self.assertTrue(m.Module.stop_drain_host(mod, 'h1').exception_str)
        # a stopped drain paused in a removal it must finish: drain again resumes it
        self.record(entries, inv, op=drain['id'], step='mgr.h1', stopped=True, paused=True, error='retire refused')
        self.assertEqual(m.Module.drain_host(mod, 'h1').exception_str, '')
        resume = mod._ledger.executable()[-1][1]
        self.assertEqual((resume['kind'], resume['drain']), ('drain_resume', drain['id']))
        self.assertTrue(m.Module.drain_host(mod, 'h2').exception_str)  # h1 still draining
        # the record cleared: h1 takes operations again
        entries.update(state_entries(inv, {'fsid': 'f', 'sealed': True}, incarnation='20', seq=2))
        self.assertEqual(m.Module.daemon_action(mod, 'restart', 'mon.h1').exception_str, '')


class Lifecycle(unittest.TestCase):
    """plan 04, step 5: the noout pass, coming back, health checks, noout keep and release."""

    class Channel:
        def __init__(self):
            self.calls = []

        def host_up(self, host, boot=None):
            self.calls.append(('up', host, boot))

        def noout_reconcile(self, host, osds):
            self.calls.append(('reconcile', host, osds))

        def noout_keep(self, host):
            self.calls.append(('keep', host))

    def module(self, inv=None):
        mod, entries = Drain.module(self, inv)
        mod._channel = self.Channel()
        mod._poller = m.Poller(lambda *a: {})
        self.addCleanup(mod._poller.shutdown)
        self.health = {}
        mod.set_health_checks = lambda c: self.health.update({'checks': c})
        mod._logger = types.SimpleNamespace(info=lambda *a: None, warning=lambda *a: None, exception=lambda *a: None)
        return mod, entries

    def down(self, mod, host='h1', boot='b-1', at='2026-11-04T10:00:00Z', stop='b-1.aa.1'):
        mod._ledger.append({'id': 'm-%016x' % len(mod._ledger.entries), 'kind': 'host_down', 'host': host, 'boot': boot, 'stop': stop, 'at': at})

    def test_coming_back(self):
        now = datetime.datetime(2026, 11, 4, 10, 10, tzinfo=datetime.timezone.utc)
        mod, _ = self.module()
        self.down(mod)
        osd_up = [False]
        mod.get = lambda what: {'osds': [{'osd': 0, 'up': osd_up[0]}]} if what == 'osd_map' else None
        seen = datetime.datetime(2026, 11, 4, 10, 5, tzinfo=datetime.timezone.utc)
        fresh = time.monotonic() + 3600  # fetched after the module saw the stop
        for rec, back in (({'boot': 'b-1', 'observed_at': seen, 'fetched_mono': fresh}, False), (None, False), ({'boot': 'b-2', 'observed_at': seen, 'fetched_mono': fresh}, False),
                          # the cancellation of an earlier stop on the same boot (a cached
                          # poll): not this stop's, whatever the clocks say
                          ({'boot': 'b-1', 'stop_cancelled': 'b-1.aa.0', 'observed_at': seen, 'fetched_mono': fresh}, False)):
            mod._channel.calls = []
            mod._poller.observations = {'h1': (rec, '')}
            m.Module._noout_tick(mod, now)
            self.assertEqual(mod._channel.calls, [('reconcile', 'h1', True)], rec)
        osd_up[0] = True
        # another boot, or this stop cancelled, in a record fetched before the
        # module saw the stop (the poller's cache): no evidence
        for rec in ({'boot': 'b-0', 'observed_at': seen, 'fetched_mono': 0.0},
                    {'boot': 'b-1', 'stop_cancelled': 'b-1.aa.1', 'observed_at': seen, 'fetched_mono': 0.0}, {'boot': 'b-0', 'observed_at': seen}):
            mod._channel.calls = []
            mod._poller.observations = {'h1': (rec, '')}
            m.Module._noout_tick(mod, now)
            self.assertEqual(mod._channel.calls, [('reconcile', 'h1', True)], rec)
        # a new boot with its OSDs up again, or the stop cancelled
        for rec in ({'boot': 'b-2', 'observed_at': seen, 'fetched_mono': fresh}, {'boot': 'b-1', 'stop_cancelled': 'b-1.aa.1', 'observed_at': seen, 'fetched_mono': fresh}):
            mod._channel.calls = []
            mod._poller.observations = {'h1': (rec, '')}
            m.Module._noout_tick(mod, now)
            self.assertEqual(mod._channel.calls, [('up', 'h1', 'b-1.aa.1')], rec)
        # a host in maintenance is back with its new boot: its OSDs stay stopped
        self.down(mod, 'h5')
        osd_up[0] = False
        mod._channel.calls = []
        mod._poller.observations = {'h5': ({'boot': 'b-9', 'observed_at': seen, 'fetched_mono': fresh}, '')}
        m.Module._noout_tick(mod, now)
        self.assertIn(('up', 'h5', 'b-1.aa.1'), mod._channel.calls)

    def test_the_poll_stamps_when_it_started(self):
        p = m.Poller(lambda addr, refresh: {'boot': 'b-1'})
        self.addCleanup(p.shutdown)
        before = time.monotonic()
        p.poll([{'name': 'h1', 'addr': '10.5.0.1'}])
        rec = p.snapshot()['h1'][0]
        self.assertTrue(before <= rec['fetched_mono'] <= time.monotonic())

    def test_health(self):
        mod, entries = self.module()
        mod.get = lambda what: {'osds': []}
        self.down(mod, at='2026-11-04T10:00:00Z')
        m.Module._noout_tick(mod, datetime.datetime(2026, 11, 4, 10, 29, tzinfo=datetime.timezone.utc))
        self.assertNotIn('TALOS_HOST_DOWN', self.health['checks'])
        m.Module._noout_tick(mod, datetime.datetime(2026, 11, 4, 10, 31, tzinfo=datetime.timezone.utc))
        self.assertIn('noout release h1', self.health['checks']['TALOS_HOST_DOWN']['detail'][0])
        Drain.record(self, entries, drain_inventory(), op='op-%016x' % 1, paused=True, error='mon rm refused')
        m.Module._noout_tick(mod, datetime.datetime(2026, 11, 4, 10, 31, tzinfo=datetime.timezone.utc))
        self.assertIn('mon rm refused', self.health['checks']['TALOS_DRAIN_PAUSED']['detail'][0])

    def test_keep_and_release(self):
        mod, _ = self.module()
        self.assertEqual(m.Module._noout_release(mod, 'h1').retval, -22)  # no unplanned stop
        self.down(mod)
        self.assertEqual(m.Module._noout_release(mod, 'h1').retval, 0)
        self.assertEqual(m.Module._noout_keep(mod, 'h2').retval, 0)
        self.assertEqual(mod._channel.calls, [('up', 'h1', None), ('keep', 'h2')])


class Move(unittest.TestCase):
    """plan 04, step 5: `ceph orch host set-addr`."""

    def module(self, inv=None, standbys=True):
        return Drain.module(self, inv or drain_inventory(), standbys)

    def record(self, entries, inv, **move):
        """The leader's published state with h2's move record."""
        inv = json.loads(json.dumps(inv))
        inv['hosts'][1]['move'] = move
        entries.update(state_entries(inv, {'fsid': 'f', 'sealed': True}, incarnation='20'))

    def test_refusals(self):
        mod, _ = self.module()
        for host, addr, why in (('h9', '10.5.0.9', 'not a host'), ('h2', 'host.example', 'not an IP'), ('h2', '10.5.0.2', 'already'),
                                ('h2', '10.5.0.3', 'h3 has the address'), ('h2', 'fd00::9', 'family'), ('h5', '10.5.0.9', 'maintenance'),
                                ('h2', '127.0.0.1', 'cannot be')):
            self.assertIn(why, m.Module.update_host_addr(mod, host, addr).exception_str, (host, addr))
        # a mon host with fewer than three mons
        two = drain_inventory()
        two['daemons'] = [x for x in two['daemons'] if x['doc_name'] not in ('ceph-f-mon-h3', 'ceph-f-mon-h4')]
        self.assertIn('three', m.Module.update_host_addr(self.module(two)[0], 'h2', '10.5.0.9').exception_str)
        # the active mgr's host without a standby
        self.assertIn('standby', m.Module.update_host_addr(self.module(standbys=False)[0], 'h1', '10.5.0.9').exception_str)
        # an upgrade, an ingress apply unfinished; a drain
        mod, _ = self.module()
        mod._ledger.append({'id': 'op-%016x' % 1, 'kind': 'upgrade_start', 'image': Upgrade.IMG})
        self.assertIn('upgrade', m.Module.update_host_addr(mod, 'h2', '10.5.0.9').exception_str)
        mod, _ = self.module()
        mod._ledger.append({'id': 'op-%016x' % 2, 'kind': 'apply_ingress', 'vip': '10.5.0.100/24', 'vrid': 51, 'hosts': ['h4'],
                            'image': Upgrade.IMG, 'new_password': False})
        self.assertIn('ingress', m.Module.update_host_addr(mod, 'h2', '10.5.0.9').exception_str)
        mod, _ = self.module()
        mod._ledger.append({'id': 'op-%016x' % 3, 'kind': 'drain_host', 'host': 'h2', 'zap': False})
        self.assertIn('draining', m.Module.update_host_addr(mod, 'h2', '10.5.0.9').exception_str)
        self.assertEqual([e['kind'] for _, e in mod._ledger.executable()], ['drain_host'])

    def test_accepted_once_and_resumed_when_paused(self):
        inv = drain_inventory()
        del inv['hosts'][4]['maintenance']
        mod, entries = self.module(inv)
        res = m.Module.update_host_addr(mod, 'h2', '10.5.0.9')
        self.assertEqual(res.exception_str, '')
        [(_, mv)] = mod._ledger.executable()
        self.assertEqual((mv['kind'], mv['host'], mv['addr']), ('set_host_addr', 'h2', '10.5.0.9'))
        entries['talos/inc/20/journal/op/' + mv['id']] = json.dumps({'state': 'completed'})
        fold = mod._authority()[1]
        # pending: not yet the host's address, its certificates still the old one's
        self.assertEqual((fold.hosts['h2'], fold.moving['h2']['moved']), ('10.5.0.2', False))
        # nothing else on h2 meanwhile, renewals included; no other move, upgrade or ingress
        for res in (m.Module.daemon_action(mod, 'restart', 'mon.h2'), m.Module.enter_host_maintenance(mod, 'h2'),
                    m.Module.drain_host(mod, 'h2'), m.Module.update_host_addr(mod, 'h3', '10.5.0.8'),
                    m.Module.update_host_addr(mod, 'h2', '10.5.0.9'), m.Module.update_host_addr(mod, 'h2', '10.5.0.8')):
            self.assertTrue(res.exception_str)
        with self.assertRaisesRegex(m.OrchestratorError, 'changing'):
            m.Module._accept(mod, 'renew_agent', None, 'h2')
        mod._approved_images = lambda: [Upgrade.IMG]
        self.assertIn('changing', m.Module.upgrade_start(mod, Upgrade.IMG, None, None, None, None, None).exception_str)
        # confirmed by the leader: the fold's address, renewals of the move for its certificates
        mod._ledger.append({'id': 'm-%016x' % 1, 'kind': 'addr_moved', 'of': mv['id'], 'host': 'h2'})
        fold = mod._authority()[1]
        self.assertEqual(fold.hosts['h2'], '10.5.0.9')
        self.assertIn(mv['id'], fold.agent_renewals['h2'])
        self.assertIn(mv['id'], fold.mgr_renewals['mgr.h2'])
        # paused by the leader: set-addr again with the same address resumes it
        self.record(entries, inv, op=mv['id'], **{'from': '10.5.0.2'}, to='10.5.0.9', step='mgr', paused=True, error='mgr: failed')
        self.assertEqual(m.Module.get_hosts(mod).result[1].status, 'moving')
        self.assertIn('changing to 10.5.0.9', m.Module.update_host_addr(mod, 'h2', '10.5.0.8').exception_str)
        self.assertEqual(m.Module.update_host_addr(mod, 'h2', '10.5.0.9').exception_str, '')
        resume = mod._ledger.executable()[-1][1]
        self.assertEqual((resume['kind'], resume['move']), ('move_resume', mv['id']))
        # its end: the fold and the leader's record cleared, h2 takes operations again
        mod._ledger.append({'id': 'm-%016x' % 2, 'kind': 'addr_set', 'of': mv['id'], 'host': 'h2'})
        self.assertTrue(m.Module.daemon_action(mod, 'restart', 'mon.h2').exception_str)  # the record still there
        entries.update(state_entries(inv, {'fsid': 'f', 'sealed': True}, incarnation='20', seq=2))
        self.assertEqual(m.Module.daemon_action(mod, 'restart', 'mon.h2').exception_str, '')

    def test_a_paused_move_is_reported(self):
        mod, entries = self.module()
        self.record(entries, drain_inventory(), op='op-%016x' % 9, **{'from': '10.5.0.2'}, to='10.5.0.9', step='confirm', paused=True,
                    error='confirm: failed the node of h2 does not have the address 10.5.0.9')
        checks = {}
        mod.set_health_checks = checks.update
        mod._channel = types.SimpleNamespace(noout_reconcile=lambda *a: None, host_up=lambda *a: None)
        mod._poller = types.SimpleNamespace(snapshot=lambda: {})
        m.Module._noout_tick(mod)
        self.assertIn('ceph orch host set-addr h2 10.5.0.9', checks['TALOS_HOST_MOVE_PAUSED']['detail'][0])
