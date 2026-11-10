"""Real local VLESS/Reality transport and native profile-lease regressions.

The server fixture echoes/answers requested destinations itself and never dials
them. All keys are generated for each run. Existing frozen suites are reused as
helpers but remain unchanged. Run on Linux with both explicit fixture binaries.
"""
import base64
import copy
import json
import os
import pathlib
import queue
import signal
import subprocess
import tempfile
import threading
import time
import unittest

from test_sandbox_profile_leases import Driver
from test_sandbox_selection_recovery import Events


PROBE = r'''
import json, os, secrets, socket, struct, time
instance = secrets.token_hex(16)
sockets = {}
def exact(s, count):
    output = b''
    while len(output) < count:
        part = s.recv(count - len(output))
        if not part: raise OSError('unexpected echo EOF')
        output += part
    return output
def exchange(name, host, family, kind, data):
    s = sockets.get(name)
    try:
        if s is None:
            s = socket.socket(family, kind)
            s.settimeout(1)
            s.connect((host, 443))
            sockets[name] = s
        if kind == socket.SOCK_STREAM:
            s.sendall(struct.pack('!H', len(data)) + data)
            length = struct.unpack('!H', exact(s, 2))[0]
            return length == len(data) and exact(s, length) == data
        s.sendall(data)
        return s.recv(512) == data
    except OSError:
        if s is not None: s.close()
        sockets.pop(name, None)
        return False
for seq in range(2000):
    message = ('issue48-app-' + instance + '-' + str(seq)).encode()
    result = dict(pid=os.getpid(), netns=os.readlink('/proc/self/ns/net'), instance=instance, seq=seq)
    for suffix, host, family in [('4', '198.51.100.44', socket.AF_INET), ('6', '2001:db8::44', socket.AF_INET6)]:
        for name, kind in [('tcp', socket.SOCK_STREAM), ('udp', socket.SOCK_DGRAM)]:
            result[name + suffix] = exchange(name + suffix, host, family, kind, message)
    result['addresses'] = []
    if all(result[key] for key in ('tcp4', 'tcp6', 'udp4', 'udp6')):
        try:
            result['addresses'] = sorted({record[4][0] for record in socket.getaddrinfo('sandbox.invalid', 443)})
        except OSError:
            pass
    result['env'] = dict(os.environ)
    result['fds'] = {}
    for fd in os.listdir('/proc/self/fd'):
        try: result['fds'][fd] = os.readlink('/proc/self/fd/' + fd)
        except FileNotFoundError: pass
    print('PROBE ' + json.dumps(result), flush=True)
    time.sleep(.08)
'''

FLOW_KEYS = ('tcp4', 'tcp6', 'udp4', 'udp6')

INNER_TLS_PROBE = r'''
import socket, ssl, struct
def exact(s, count):
    data = b''
    while len(data) < count:
        part = s.recv(count - len(data))
        if not part: raise RuntimeError('unexpected inner TLS EOF')
        data += part
    return data
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # this local fixture generates a synthetic certificate
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
with socket.create_connection(('198.51.100.44', 8443), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname='inner-fixture.invalid') as stream:
        for _ in range(3):
            payload = b'issue48-inner-tls-' * 2000
            stream.sendall(struct.pack('!H', len(payload)) + payload)
            length = struct.unpack('!H', exact(stream, 2))[0]
            if length != len(payload) or exact(stream, length) != payload:
                raise RuntimeError('inner TLS payload corrupted')
print('INNER_TLS_OK', flush=True)
'''


class Reality:
    def __init__(self, flow=''):
        self.proc = subprocess.Popen([os.environ['HIDDIFY_REALITY_SERVER'], '-flow', flow],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        self.ready = queue.Queue()
        self.events = []
        self.errors = []
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.error_reader = threading.Thread(target=lambda: self.errors.append(self.proc.stderr.read()), daemon=True)
        self.reader.start()
        self.error_reader.start()
        try:
            event = self.ready.get(timeout=10)
            if event.get('kind') != 'ready':
                raise AssertionError(f'Reality fixture exited: {event}; {self.errors}')
            self.outbound = event['outbound']
        except BaseException:
            self.close()
            raise

    def read(self):
        for line in self.proc.stdout:
            event = json.loads(line)
            if event['kind'] == 'ready':
                self.ready.put(event)
            else:
                with self.lock:
                    self.events.append(event)
        self.ready.put({'kind': 'exit', 'code': self.proc.poll()})

    def application_events(self):
        with self.lock:
            return [dict(event) for event in self.events if event.get('kind') == 'traffic'
                    and base64.b64decode(event.get('payload', '')).startswith(b'issue48-app-')]

    def dns_events(self):
        with self.lock:
            return [dict(event) for event in self.events if event.get('kind') == 'traffic'
                    and event.get('destination') == '203.0.113.53:53']

    def close(self):
        if not self.proc.stdin.closed:
            try:
                self.proc.stdin.close()
            except BrokenPipeError:
                pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)
        self.reader.join(1)
        self.error_reader.join(1)
        self.proc.stdout.close()
        self.proc.stderr.close()


def profile(outbound, extras=()):
    return json.dumps({'outbounds': [copy.deepcopy(outbound), *extras], 'route': {'final': 'proxy'}})


def descendants(pid):
    """Go may spawn helpers on any OS thread, not only its main thread."""
    pending, seen = [pid], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        try:
            tasks = list(pathlib.Path(f'/proc/{current}/task').glob('*/children'))
        except FileNotFoundError:
            continue
        for task in tasks:
            try:
                pending.extend(int(value) for value in task.read_text().split())
            except FileNotFoundError:
                pass
    return seen - {pid}


@unittest.skipUnless(os.environ.get('HIDDIFY_SANDBOX_DRIVER') and os.environ.get('HIDDIFY_REALITY_SERVER'),
                     'explicit Linux native driver and local Reality server required')
class RealityProfileLeases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A broken fixture must fail visibly before feature assertions. These
        # real handshakes pass on the unmodified engine before tests are frozen.
        for flow in ('', 'xtls-rprx-vision'):
            for fingerprint in ('chrome', 'firefox', 'edge', 'safari', 'ios', 'android'):
                result = subprocess.run([os.environ['HIDDIFY_REALITY_SERVER'], '-self-check', '-flow', flow,
                                         '-fingerprint', fingerprint], capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise AssertionError(f'Reality fixture preflight ({flow!r}, {fingerprint}) failed: {result.stdout}\n{result.stderr}')
                events = [json.loads(line) for line in result.stdout.splitlines()]
                if not any(event.get('kind') == 'self-check' and event.get('ok') for event in events):
                    raise AssertionError(f'Reality fixture omitted success: {events}')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hiddify-reality-lease-')
        self.addCleanup(self.temp.cleanup)
        self.routes = self.host_routes()
        self.driver = Driver(self.temp.name)
        self.addCleanup(self.driver.close)
        self.events = Events(self.driver)
        self.driver.send('launch', command=['/usr/bin/python3', '-c', PROBE])
        self.first = self.probe(False, 0)
        self.identity = self.application_identity(self.first)
        self.assertNotIn('HIDDIFY_CORE_SECRET', self.first['env'])
        self.assertTrue(all(not value.startswith('socket:') for value in self.first['fds'].values()),
                        'no-profile app inherited a host socket')

    @staticmethod
    def host_routes():
        return [subprocess.check_output(['ip', '-j', family, 'route', 'show', 'table', 'main'])
                for family in ('-4', '-6')]

    def tearDown(self):
        self.assertEqual(self.routes, self.host_routes(), 'host routes changed')

    def server(self, flow=''):
        result = Reality(flow)
        self.addCleanup(result.close)
        return result

    @staticmethod
    def application_identity(event):
        return event['pid'], event['netns'], event['instance']

    def same_application(self, event):
        self.assertEqual(self.application_identity(event), self.identity, 'network change replaced the application')

    def probe(self, online, mark, after=-1):
        return self.events.wait(lambda event: event.get('kind') == 'probe' and event['seq'] > after
                                and all(event[key] == online for key in FLOW_KEYS), mark, timeout=15)

    def activate(self, outbound, action='start', extras=(), require_success=True):
        mark = self.events.mark()
        request = self.driver.send(action, profile=profile(outbound, extras))
        reply = self.events.reply(request, mark)
        if require_success:
            self.assertEqual(reply['error'], '<nil>', 'ordinary core rejected valid fixture profile')
        return self.events.mark()

    def quiet(self, server):
        # Attribute only payloads from this app; ordinary core health checks use
        # the same endpoint but must not be mistaken for leaked child traffic.
        time.sleep(.2)
        count = len(server.application_events())
        time.sleep(.4)
        self.assertEqual(len(server.application_events()), count, 'revoked endpoint still received app traffic')

    def assert_offline_samples(self, mark, after, count=3):
        # A sample already in progress when revocation begins can contain the
        # old flow. Require a fully offline observation, then consecutive later
        # observations; quiet() separately checks endpoint traffic cessation.
        first = self.probe(False, mark, after)
        self.same_application(first)
        current = first['seq']
        for _ in range(count - 1):
            event = self.events.wait(lambda event: event.get('kind') == 'probe' and event['seq'] > current,
                                     mark, timeout=15)
            self.same_application(event)
            self.assertFalse(any(event[key] for key in FLOW_KEYS), 'rejected profile granted application traffic')
            current = event['seq']
        return current

    def assert_online(self, server, mark, after=-1):
        deadline = time.monotonic() + 20
        expected = {(network, target) for network in ('tcp', 'udp')
                    for target in ('198.51.100.44:443', '[2001:db8::44]:443')}
        while True:
            event = self.probe(True, mark, after)
            payload = ('issue48-app-' + event['instance'] + '-' + str(event['seq'])).encode()
            # A probe can straddle replacement. Require all its successful
            # exchanges to have reached this exact replacement endpoint.
            received = {(item['network'], item['destination']) for item in server.application_events()
                        if base64.b64decode(item['payload']) == payload}
            if received == expected:
                break
            after = event['seq']
            if time.monotonic() > deadline:
                self.fail(f'expected endpoint did not receive complete current probe: {received}')
        self.same_application(event)
        self.assertEqual(event['addresses'], ['198.51.100.44', '2001:db8::44'], 'DNS did not use Reality worker')
        self.assertTrue(server.dns_events(), 'numeric remote DNS was never reached through VLESS')
        traffic = server.application_events()
        self.assertTrue(any(item['network'] == 'tcp' for item in traffic))
        self.assertTrue(any(item['network'] == 'udp' for item in traffic))
        return event

    def test_empty_flow_carries_ipv4_ipv6_tcp_xudp_and_dns(self):
        server = self.server()
        self.assert_online(server, self.activate(server.outbound), self.first['seq'])

    def test_vision_carries_ipv4_ipv6_tcp_xudp_and_dns(self):
        server = self.server('xtls-rprx-vision')
        self.assert_online(server, self.activate(server.outbound), self.first['seq'])

    def test_default_packet_encoding_is_xudp(self):
        server = self.server('xtls-rprx-vision')
        outbound = copy.deepcopy(server.outbound)
        del outbound['packet_encoding']
        self.assert_online(server, self.activate(outbound), self.first['seq'])

    def test_vision_carries_large_inner_tls_stream(self):
        server = self.server('xtls-rprx-vision')
        self.assert_online(server, self.activate(server.outbound), self.first['seq'])
        mark = self.events.mark()
        request = self.driver.send('launch', command=['/usr/bin/python3', '-c', INNER_TLS_PROBE])
        output = ''
        index = mark
        while True:
            event = self.events.wait(lambda item: item.get('id') == request, index, timeout=20)
            index = len(self.events.items)
            output += event.get('stdout', '')
            if event.get('state') == 3 or event.get('kind') == 'stream_end':
                self.assertIn('INNER_TLS_OK\n', output)
                self.assertEqual(event.get('exit_code', 0), 0, event)
                break

    def test_stop_then_new_profile_restores_same_application(self):
        a, b = self.server(), self.server('xtls-rprx-vision')
        online = self.assert_online(a, self.activate(a.outbound), self.first['seq'])
        mark = self.events.mark()
        request = self.driver.send('stop')
        self.assertEqual(self.events.reply(request, mark)['error'], '<nil>')
        offline = self.assert_offline_samples(mark, online['seq'])
        self.quiet(a)
        self.assert_online(b, self.activate(b.outbound), offline)
        self.quiet(a)

    def test_reload_replaces_live_tcp_udp_flows_without_restarting_application(self):
        a, b = self.server('xtls-rprx-vision'), self.server()
        online = self.assert_online(a, self.activate(a.outbound), self.first['seq'])
        mark = self.activate(b.outbound, 'reload')
        self.assert_online(b, mark, online['seq'] + 1)
        self.quiet(a)

    def test_failed_reload_keeps_old_application_offline(self):
        server = self.server()
        online = self.assert_online(server, self.activate(server.outbound), self.first['seq'])
        mark = self.events.mark()
        request = self.driver.send('reload', profile='{"outbounds": [')
        self.assertNotEqual(self.events.reply(request, mark)['error'], '<nil>')
        self.assert_offline_samples(mark, online['seq'])
        self.quiet(server)

    def test_worker_sigkill_revokes_flows_and_keeps_application_alive(self):
        server = self.server('xtls-rprx-vision')
        online = self.assert_online(server, self.activate(server.outbound), self.first['seq'])
        workers = []
        for pid in descendants(self.driver.proc.pid):
            try:
                args = pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                if b'__tunnel' in args:
                    workers.append(pid)
            except FileNotFoundError:
                pass
        self.assertEqual(len(workers), 1, 'exactly one proxy worker must own this session')
        mark = self.events.mark()
        os.kill(workers[0], signal.SIGKILL)
        self.assert_offline_samples(mark, online['seq'])
        self.quiet(server)

    def test_core_death_stops_reality_application_traffic(self):
        server = self.server('xtls-rprx-vision')
        self.assert_online(server, self.activate(server.outbound), self.first['seq'])
        self.driver.proc.kill()
        self.driver.proc.wait(timeout=5)
        self.quiet(server)

    def test_wrong_reality_authentication_never_grants_application_traffic(self):
        server = self.server('xtls-rprx-vision')
        for field in ('public_key', 'short_id', 'server_name', 'uuid'):
            with self.subTest(field=field):
                outbound = copy.deepcopy(server.outbound)
                if field == 'public_key':
                    outbound['tls']['reality'][field] = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
                elif field == 'short_id':
                    old = outbound['tls']['reality'][field]
                    outbound['tls']['reality'][field] = ('1' if old[0] != '1' else '2') + old[1:]
                elif field == 'server_name':
                    outbound['tls'][field] = 'wrong-reality-fixture.invalid'
                else:
                    outbound[field] = '00000000-0000-4000-8000-000000000001'
                mark = self.activate(outbound, 'restart')
                after = self.events.wait(lambda event: event.get('kind') == 'probe', mark)['seq']
                self.assert_offline_samples(mark, after)
                self.assertEqual(server.application_events(), [], 'failed authentication passed app payload')

    def test_direct_selection_never_restores_network(self):
        server = self.server()
        online = self.assert_online(server, self.activate(server.outbound), self.first['seq'])
        direct = {'type': 'direct', 'tag': 'proxy'}
        self.assert_offline_samples(self.activate(direct, 'restart'), online['seq'])
        self.quiet(server)

    def test_unsupported_profile_options_are_not_silently_removed(self):
        server = self.server('xtls-rprx-vision')
        variants = {
            'direct_detour': {'detour': 'bypass'},
            'custom_dialer': {'bind_interface': 'lo'},
            'v2ray_transport': {'transport': {'type': 'ws', 'path': '/fixture'}},
            'native_udp': {'packet_encoding': ''},
            'packetaddr': {'packet_encoding': 'packetaddr'},
            'multiplex': {'multiplex': {'enabled': True}},
        }
        for name, fields in variants.items():
            with self.subTest(option=name):
                outbound = {**copy.deepcopy(server.outbound), **fields}
                mark = self.activate(outbound, 'restart', extras=[{'type': 'direct', 'tag': 'bypass'}], require_success=False)
                after = self.events.wait(lambda event: event.get('kind') == 'probe', mark)['seq']
                self.assert_offline_samples(mark, after)
                self.assertEqual(server.application_events(), [], 'unsupported profile granted app payload')


if __name__ == '__main__':
    unittest.main(verbosity=2)
