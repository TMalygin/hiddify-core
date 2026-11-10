"""Active-profile contract, using real native lifecycle and authenticated RPC.

The driver is built from tests/fixtures/sandbox_profile_driver before running.
The inherited Proxy fixture only echoes locally; it never dials destinations.
"""
import contextlib
import http.server
import json
import os
import pathlib
import queue
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from test_rootless_sandbox import Proxy


PROBE = r'''
import json, os, socket, time
tcp = udp = None
def exchange(udp_mode, data):
    global tcp, udp
    s = udp if udp_mode else tcp
    try:
        if s is None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp_mode else socket.SOCK_STREAM)
            s.settimeout(.2)
            s.connect(('198.51.100.44', 443))
            if udp_mode: udp = s
            else: tcp = s
        s.sendall(data)
        return s.recv(256) == data
    except OSError:
        if s is not None: s.close()
        if udp_mode: udp = None
        else: tcp = None
        return False
for seq in range(2000):
    message = ('profile-flow-%d' % seq).encode()
    result = dict(pid=os.getpid(), netns=os.readlink('/proc/self/ns/net'), seq=seq,
                  tcp=exchange(False, message), udp=exchange(True, message))
    result['env'] = dict(os.environ)
    result['fds'] = {}
    for fd in os.listdir('/proc/self/fd'):
        try: result['fds'][fd] = os.readlink('/proc/self/fd/' + fd)
        except FileNotFoundError: pass
    print('PROBE ' + json.dumps(result), flush=True)
    time.sleep(.07)
'''


class Driver:
    def __init__(self, directory):
        self.proc = subprocess.Popen([os.environ['HIDDIFY_SANDBOX_DRIVER']], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env={**os.environ, 'HIDDIFY_SANDBOX_TEST_DIR': directory,
                                          'HIDDIFY_ADMIN_BG_DATA': directory + '/admin',
                                          'HIDDIFY_TUNNEL_DATA': directory + '/tunnel',
                                          'HIDDIFY_CORE_SECRET': 'fixture-secret-must-not-reach-child'})
        self.events = queue.Queue()
        self.history = []
        self.output = []
        self.errors = []
        self.sequence = 0
        self.child_output = ''
        threading.Thread(target=self.read, daemon=True).start()
        threading.Thread(target=lambda: self.errors.append(self.proc.stderr.read()), daemon=True).start()
        self.wait(lambda e: e.get('kind') == 'ready')

    def read(self):
        for line in self.proc.stdout:
            if not line.startswith('EVENT '):
                self.output.append(line)
                continue
            event = json.loads(line[6:])
            self.events.put(event)
            if event.get('stdout'):
                self.child_output += event['stdout']
                while '\n' in self.child_output:
                    line, self.child_output = self.child_output.split('\n', 1)
                    if line.startswith('PROBE '):
                        self.events.put({'kind': 'probe', **json.loads(line[6:])})
        self.events.put({'kind': 'driver_exit', 'code': self.proc.poll()})

    def send(self, action, **kwargs):
        self.sequence += 1
        self.proc.stdin.write(json.dumps(dict(action=action, id=self.sequence, **kwargs)) + '\n')
        self.proc.stdin.flush()
        return self.sequence

    def wait(self, predicate, timeout=15):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            try:
                event = self.events.get(timeout=max(.01, until-time.monotonic()))
            except queue.Empty:
                break
            self.history.append(event)
            if predicate(event):
                return event
            if event.get('kind') in ('stream_end', 'driver_exit'):
                raise AssertionError(f'unexpected endpoint termination: {event}; events={self.history[-8:]}')
        raise AssertionError(f'event deadline; events={self.history[-8:]}; output={self.output[-5:]}; errors={self.errors}')

    def reply(self, request):
        return self.wait(lambda e: e.get('kind') == 'reply' and e.get('id') == request)

    def network(self, state, after=0):
        return self.wait(lambda e: e.get('kind') == 'sandbox' and e.get('state') == state
                         and e.get('revision', 0) >= after)

    def probe(self, online, after=-1):
        return self.wait(lambda e: e.get('kind') == 'probe' and e['seq'] > after
                         and e['tcp'] == online and e['udp'] == online)

    def close(self):
        if not self.proc.stdin.closed:
            with contextlib.suppress(BrokenPipeError): self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)
        self.proc.stdout.close()
        self.proc.stderr.close()


def profile(proxy, **options):
    outbound = dict(type='socks', tag='proxy', server='127.0.0.1', server_port=proxy.port, version='5')
    outbound.update(options)
    return json.dumps({'outbounds': [outbound], 'route': {'final': 'proxy'}})


@unittest.skipUnless(os.environ.get('HIDDIFY_SANDBOX_DRIVER'), 'explicit Linux host integration driver required')
class ProfileLeases(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hiddify-profile-lease-')
        self.addCleanup(self.temp.cleanup)
        self.a, self.b = Proxy(), Proxy()
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)
        self.routes = [subprocess.check_output(['ip', '-j', family, 'route', 'show', 'table', 'main'])
                       for family in ('-4', '-6')]
        self.driver = Driver(self.temp.name)
        self.addCleanup(self.driver.close)

    def tearDown(self):
        self.assertEqual(self.routes, [subprocess.check_output(['ip', '-j', family, 'route', 'show', 'table', 'main'])
                                      for family in ('-4', '-6')], 'host routing changed')

    def launch(self):
        self.driver.send('launch', command=['/usr/bin/python3', '-c', PROBE])
        self.driver.network(0)
        first = self.driver.probe(False)
        self.assertNotIn('HIDDIFY_CORE_SECRET', first['env'])
        self.assertLessEqual(set(first['fds']), {'0', '1', '2'})
        return first

    def activate(self, proxy, action='start'):
        return self.activate_profile(profile(proxy), action)

    def activate_profile(self, content, action='start'):
        request = self.driver.send(action, profile=content)
        # RPC notification and native reply may be delivered in either order.
        until = time.monotonic() + 15
        ready = reply = None
        while time.monotonic() < until and (ready is None or reply is None):
            event = self.driver.wait(lambda e: e.get('kind') == 'reply' and e.get('id') == request
                                     or e.get('kind') == 'sandbox' and e.get('state') == 1)
            if event['kind'] == 'reply': reply = event
            else: ready = event
        self.assertIsNotNone(ready)
        self.assertIsNotNone(reply)
        self.assertEqual(reply['error'], '<nil>')
        return ready

    def assert_quiet(self, proxy):
        time.sleep(.15)  # queued packets before revocation may still be consumed
        count = len(proxy.events)
        time.sleep(.35)
        self.assertEqual(len(proxy.events), count, 'old profile continued receiving child traffic')

    def test_disconnect_keeps_process_alive_offline_and_reconnect_restores_it(self):
        first = self.launch()
        ready = self.activate(self.a)
        online = self.driver.probe(True, first['seq'])
        self.assertEqual((online['pid'], online['netns']), (first['pid'], first['netns']))
        request = self.driver.send('stop')
        self.assertEqual(self.driver.reply(request)['error'], '<nil>')
        offline = self.driver.probe(False, online['seq'])
        self.assertEqual((offline['pid'], offline['netns']), (first['pid'], first['netns']))
        self.assert_quiet(self.a)
        next_ready = self.activate(self.b)
        self.assertGreater(next_ready['revision'], ready['revision'])
        again = self.driver.probe(True, offline['seq'])
        self.assertEqual(again['pid'], first['pid'])
        self.assertTrue(self.b.events)
        self.assert_quiet(self.a)

    def test_restart_switches_proxy_without_restarting_application(self):
        first = self.launch()
        old = self.activate(self.a)
        online = self.driver.probe(True)
        new = self.activate(self.b, 'restart')
        self.assertGreater(new['revision'], old['revision'])
        again = self.driver.probe(True, online['seq'] + 2)
        self.assertEqual(again['pid'], first['pid'])
        self.assertTrue(self.b.events)
        self.assert_quiet(self.a)

    def test_failed_reload_does_not_restore_old_network_permission(self):
        first = self.launch()
        self.activate(self.a)
        online = self.driver.probe(True)
        request = self.driver.send('reload', profile='{"outbounds": [')
        self.assertNotEqual(self.driver.reply(request)['error'], '<nil>')
        offline = self.driver.probe(False, online['seq'])
        self.assertEqual(offline['pid'], first['pid'])
        self.assert_quiet(self.a)
        self.activate(self.b, 'reload')
        self.assertEqual(self.driver.probe(True, offline['seq'])['pid'], first['pid'])

    def test_direct_selected_in_profile_is_offline_and_does_not_kill_app(self):
        first = self.launch()
        self.activate(self.a)
        online = self.driver.probe(True)
        direct = json.dumps({'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}})
        request = self.driver.send('restart', profile=direct)
        self.driver.reply(request)
        offline = self.driver.probe(False, online['seq'])
        self.assertEqual(offline['pid'], first['pid'])
        self.assert_quiet(self.a)

    def test_plaintext_rpc_cannot_launch_even_an_isolated_process(self):
        request = self.driver.send('launch', command=['/usr/bin/printf', 'UNAUTHORIZED'], unauthenticated=True)
        event = self.driver.wait(lambda e: e.get('kind') == 'stream_end' and e.get('id') == request)
        self.assertIn(event['code'], ('Unauthenticated', 'PermissionDenied'))
        self.assertFalse(any('UNAUTHORIZED' in e.get('stdout', '') for e in self.driver.history))

    def test_proxy_selection_revokes_direct_and_replaces_only_the_worker(self):
        first = self.launch()
        a, b = json.loads(profile(self.a))['outbounds'][0], json.loads(profile(self.b))['outbounds'][0]
        a['tag'], b['tag'] = 'a', 'b'
        content = json.dumps({'outbounds': [a, b, {'type': 'direct', 'tag': 'direct'},
                                           {'type': 'selector', 'tag': 'select', 'outbounds': ['a', 'b', 'direct'], 'default': 'a'}],
                              'route': {'final': 'select'}})
        self.activate_profile(content)
        online = self.driver.probe(True)
        self.driver.reply(self.driver.send('select', group='select', outbound='direct'))
        offline = self.driver.probe(False, online['seq'])
        self.assertEqual(offline['pid'], first['pid'])
        self.assert_quiet(self.a)
        self.driver.reply(self.driver.send('select', group='select', outbound='b'))
        self.assertEqual(self.driver.probe(True, offline['seq'])['pid'], first['pid'])
        self.assertTrue(self.b.events)

    def test_direct_detour_is_not_silently_removed_from_selected_proxy(self):
        first = self.launch()
        content = json.loads(profile(self.a, detour='bypass'))
        content['outbounds'].append({'type': 'direct', 'tag': 'bypass'})
        self.driver.reply(self.driver.send('start', profile=json.dumps(content)))
        offline = self.driver.probe(False, first['seq'] + 2)
        self.assertEqual(offline['pid'], first['pid'])
        self.assertEqual(self.a.events, [])

    def test_managed_dns_and_ipv6_use_the_profile_worker(self):
        code = r'''
import json, socket, time
for _ in range(60):
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo('sandbox.invalid', 443)})
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET6, kind) as s:
                s.settimeout(1)
                s.connect(('2001:db8::44', 443))
                s.sendall(b'managed-ipv6')
                assert s.recv(64) == b'managed-ipv6'
        print('PROBE ' + json.dumps({'dns': addresses, 'ipv6': True}), flush=True)
        break
    except OSError: time.sleep(.1)
else: raise SystemExit(1)
'''
        self.driver.send('launch', command=['/usr/bin/python3', '-c', code])
        self.driver.network(0)
        self.activate(self.a)
        result = self.driver.wait(lambda e: e.get('kind') == 'probe' and 'dns' in e)
        self.assertEqual(result['dns'], ['198.51.100.44', '2001:db8::44'])
        self.assertTrue(result['ipv6'])
        destinations = {(kind, host, port) for kind, host, port, _ in self.a.events}
        self.assertIn(('tcp', '203.0.113.53', 53), destinations)
        self.assertIn(('tcp', '2001:db8::44', 443), destinations)
        self.assertIn(('udp', '2001:db8::44', 443), destinations)

    def test_worker_crash_leaves_application_offline_until_explicit_profile_restart(self):
        first = self.launch()
        self.activate(self.a)
        online = self.driver.probe(True)
        pending = [self.driver.proc.pid]
        workers = []
        while pending:
            pid = pending.pop()
            try:
                children = pathlib.Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
                pending.extend(int(value) for value in children)
                command = pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                if b'__tunnel' in command: workers.append(pid)
            except FileNotFoundError:
                pass
        self.assertEqual(len(workers), 1, 'one separate proxy worker per application session')
        os.kill(workers[0], signal.SIGKILL)
        offline = self.driver.probe(False, online['seq'])
        self.assertEqual(offline['pid'], first['pid'])
        self.assert_quiet(self.a)
        self.activate(self.b, 'restart')
        self.assertEqual(self.driver.probe(True, offline['seq'])['pid'], first['pid'])

    def test_core_crash_stops_child_traffic(self):
        self.launch()
        self.activate(self.a)
        self.driver.probe(True)
        self.driver.proc.kill()
        self.driver.proc.wait(timeout=5)
        self.assert_quiet(self.a)

    def test_cancelled_start_cannot_grant_a_stale_profile(self):
        first = self.launch()
        entered, release = threading.Event(), threading.Event()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                entered.set()
                release.wait(10)
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"version":3,"rules":[]}')

            def log_message(self, *args): pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(release.set)
        delayed = json.loads(profile(self.a))
        # This download is in the ordinary core, to stall its startup. The
        # restricted worker must never import this DIRECT outbound or rule set.
        delayed['outbounds'].append({'type': 'direct', 'tag': 'fixture-download'})
        delayed['route']['rule_set'] = [{'type': 'remote', 'tag': 'delayed', 'format': 'source',
                                        'download_detour': 'fixture-download',
                                        'url': f'http://127.0.0.1:{server.server_port}/rules'}]
        start = self.driver.send('start', profile=json.dumps(delayed))
        self.assertTrue(entered.wait(8), 'controlled core startup never reached the local rule server')
        stop = self.driver.send('stop')
        self.driver.reply(stop)
        self.assertEqual(self.driver.probe(False, first['seq'])['pid'], first['pid'])
        release.set()
        self.activate(self.b)
        self.assertEqual(self.driver.probe(True)['pid'], first['pid'])
        self.assertEqual(self.a.events, [], 'cancelled old configuration was ever given a worker')


if __name__ == '__main__':
    unittest.main(verbosity=2)
