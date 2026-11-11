"""Opt-in Linux integration checks for installed, natively sandboxed Chromium browsers.

HIDDIFY_CHROMIUM_DRIVER selects the issue-51 test fixture. The core, browser
homes and TLS identity are temporary. All network responses come from local
test fixtures. Neither DevTools nor a GUI/display connection is required.
"""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.parse import quote
import uuid

from test_rootless_sandbox import address, exact
from test_sandbox_profile_leases import profile
from test_sandbox_storage import Driver, descendants


BROWSERS = {
    'chrome': ('/opt/google/chrome/chrome', '/opt/google/chrome'),
    'brave': ('/usr/lib/brave-browser/brave', ''),
}
NORMAL_FLAGS = ['--headless=new', '--no-first-run', '--no-default-browser-check',
                '--disable-background-networking']
TEST_IP = '198.51.100.73'
TEST_PORT = 18051
JS_DOCUMENT = ('<title>initial</title><script>'
               'const end=performance.now()+600; while(performance.now()<end){};'
               'document.title=["renderer","executed"].join("-")</script>')


def process_info(pid):
    directory = Path('/proc') / str(pid)
    fields = dict(line.split(':', 1) for line in (directory/'status').read_text().splitlines() if ':' in line)
    return {'pid': pid, 'capabilities': int(fields['CapEff'], 16), 'nnp': int(fields['NoNewPrivs']),
            'seccomp': int(fields['Seccomp']), 'filters': int(fields['Seccomp_filters']),
            'levels': len(fields['NSpid'].split()),
            'namespaces': {kind: os.readlink(directory/'ns'/kind) for kind in ('pid', 'net', 'user')}}


def observe_renderer(driver, binary):
    browser, renderers = None, []
    for pid in descendants(driver.proc.pid):
        try:
            # Chromium may rewrite argv as a single process title.
            args = (Path('/proc')/str(pid)/'cmdline').read_bytes().replace(b'\0', b' ').split()
            if not args or args[0] != os.fsencode(binary):
                continue
            if b'--type=renderer' in args:
                renderers.append(process_info(pid))
            elif b'--headless=new' in args and not any(a.startswith(b'--type=') for a in args):
                browser = process_info(pid)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            # A process may exit or still be changing its credentials.
            continue
    if browser:
        for renderer in renderers:
            if renderer['filters'] > browser['filters']:
                return browser, renderer
    return None


class BrowserProxy:
    """Answer HTTP at one documentation-only destination; never forward traffic."""
    def __init__(self, nonce):
        self.nonce = nonce
        self.waiting = threading.Event()
        self.executed = threading.Event()
        self.closed = threading.Event()
        self.requests = []
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(.2)
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.closed.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                continue
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        with conn, contextlib.suppress(OSError, EOFError, ValueError, IndexError):
            conn.settimeout(12)
            version, methods = exact(conn, 2)
            if version != 5 or 0 not in exact(conn, methods):
                return
            conn.sendall(b'\x05\x00')
            version, command, _ = exact(conn, 3)
            host, port = address(lambda n: exact(conn, n))
            if version != 5 or command != 1 or (host, port) != (TEST_IP, TEST_PORT):
                conn.sendall(b'\x05\x05\x00\x01' + b'\0'*6)
                return
            conn.sendall(b'\x05\x00\x00\x01' + b'\0'*6)
            header = bytearray()
            while b'\r\n\r\n' not in header and len(header) < 16384:
                part = conn.recv(4096)
                if not part:
                    return
                header.extend(part)
            request = bytes(header).split(b'\r\n', 1)[0].split()
            if len(request) < 2 or request[0] != b'GET':
                return
            path = request[1].decode('ascii')
            self.requests.append(path)
            if path == '/ran/'+self.nonce:
                self.executed.set()
                conn.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
                return
            if path == '/brave/'+self.nonce:
                body = ('<script>fetch("/ran/"+' + repr(self.nonce) + ')</script>').encode()
            elif path == '/page/'+self.nonce:
                body = ('<title>online</title><script>const r=new XMLHttpRequest();'
                        'try{r.open("GET","/hold/'+self.nonce+'",false);r.send();'
                        'document.title="unexpected-response"}catch(e){'
                        'document.title=["network","revoked"].join("-")}</script>').encode()
            elif path == '/hold/'+self.nonce:
                self.waiting.set()
                # Leave the established HTTP flow open until the core revokes
                # its profile. The proxy never manufactures the network error.
                self.closed.wait(25)
                return
            else:
                return
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-store\r\n'
                             b'Connection: close\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)

    def close(self):
        self.closed.set()
        self.listener.close()
        self.thread.join(1)


@unittest.skipUnless(os.environ.get('HIDDIFY_CHROMIUM_DRIVER'),
                     'explicit Chromium native RPC fixture required')
class ChromiumSandbox(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='hiddify-chromium-')
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        home = directory/'host-home'
        home.mkdir(mode=0o700)
        with mock.patch.dict(os.environ, {'HIDDIFY_STORAGE_DRIVER': os.environ['HIDDIFY_CHROMIUM_DRIVER']}):
            self.driver = Driver(directory, host_home=home)
        self.addCleanup(self.driver.close)

    def launch(self, command, root='', identity='browser-test', opted_in=True):
        mark = self.driver.mark()
        request = self.driver.send('launch', command=command, executable_root=root,
                                   application_id=identity, chromium_sandbox=opted_in)
        return request, mark

    def result(self, request, mark, timeout=25):
        end = self.driver.wait(lambda e: e.get('id') == request and e.get('kind') == 'stream_end',
                               mark, timeout=timeout)
        events = [e for e in self.driver.events[mark:] if e.get('id') == request]
        return (end, [e['exit_code'] for e in events if e.get('state') == 3],
                ''.join(e.get('stdout', '') for e in events),
                ''.join(e.get('stderr', '') for e in events))

    def service(self, action, **options):
        mark = self.driver.mark()
        request = self.driver.send(action, **options)
        event = self.driver.wait(lambda e: e.get('kind') == 'reply' and e.get('id') == request, mark)
        self.assertEqual(event['error'], '<nil>', event)

    def test_legacy_console_and_version_are_unchanged(self):
        result = self.result(*self.launch(['/usr/bin/true'], identity='', opted_in=False))
        self.assertEqual(result[1], [0], result)
        for name, (binary, root) in BROWSERS.items():
            with self.subTest(browser=name):
                result = self.result(*self.launch([binary, '--version'], root, name, opted_in=False))
                self.assertEqual(result[1], [0], result)
                self.assertRegex(result[2], r'\d+\.\d+\.\d+')

    def test_opt_in_rejects_unknown_commands_wrappers_missing_identity_and_unsafe_arguments(self):
        chrome, chrome_root = BROWSERS['chrome']
        brave, _ = BROWSERS['brave']
        # --version exits before browser startup on the old core, so even the
        # rejected argument cases never create a renderer without a sandbox.
        for command, root, identity in [
            (['/usr/bin/true'], '', 'unknown-app'), ([brave, '--version'], '', ''),
            (['/usr/bin/brave', '--version'], '', 'wrapper'),
            ([chrome_root+'/google-chrome', '--version'], chrome_root, 'wrapper'),
            ([chrome, '--version'], '', 'wrong-root'),
            ([brave, '--no-sandbox', '--version'], '', 'unsafe-args'),
            ([brave, '--remote-debugging-port=0', '--version'], '', 'debug-args'),
        ]:
            with self.subTest(command=command, root=root, identity=identity):
                end, exits, stdout, _ = self.result(*self.launch(command, root, identity))
                self.assertIn(end['code'], ('InvalidArgument', 'FailedPrecondition', 'PermissionDenied'), end)
                self.assertEqual((exits, stdout), ([], ''))

    def observe(self, request, mark, binary):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.driver.mark()
            if any(e.get('kind') == 'stream_end' and e.get('id') == request for e in self.driver.events[mark:]):
                break
            with contextlib.suppress(FileNotFoundError, ProcessLookupError, PermissionError):
                result = observe_renderer(self.driver, binary)
                if result:
                    return result
            time.sleep(.04)

    def check_attestation(self, observed):
        self.assertIsNotNone(observed, 'no live renderer with an additional seccomp filter was observed')
        browser, renderer = observed
        for proc in (browser, renderer):
            self.assertEqual((proc['capabilities'], proc['nnp'], proc['seccomp']), (0, 1, 2), proc)
        self.assertGreaterEqual(browser['filters'], 1, browser)
        self.assertGreater(renderer['filters'], browser['filters'], observed)
        self.assertGreater(renderer['levels'], browser['levels'], observed)
        for kind in ('net', 'pid', 'user'):
            self.assertNotEqual(browser['namespaces'][kind], renderer['namespaces'][kind], observed)

    def test_chrome_renders_javascript_in_a_separately_sandboxed_process(self):
        binary, root = BROWSERS['chrome']
        url = 'data:text/html,' + quote(JS_DOCUMENT, safe='')
        request, mark = self.launch([binary, *NORMAL_FLAGS, '--dump-dom', url], root, 'chrome')
        observed = self.observe(request, mark, binary)
        end, exits, stdout, stderr = self.result(request, mark)
        self.assertEqual(exits, [0], f'{end}: {stderr[-3000:]}')
        self.assertIn('<title>renderer-executed</title>', stdout)
        self.check_attestation(observed)

    def test_brave_renders_javascript_in_a_separately_sandboxed_process(self):
        # This installed Brave renders the page but has no reliable --dump-dom
        # completion. A unique HTTP request from its script proves execution.
        binary, root = BROWSERS['brave']
        nonce = uuid.uuid4().hex
        proxy = BrowserProxy(nonce)
        self.addCleanup(proxy.close)
        self.service('start', profile=profile(proxy))
        url = f'http://{TEST_IP}:{TEST_PORT}/brave/{nonce}'
        request, mark = self.launch([binary, *NORMAL_FLAGS, url], root, 'brave')
        try:
            observed = self.observe(request, mark, binary)
            self.check_attestation(observed)
            self.assertTrue(proxy.executed.wait(12), 'Brave did not execute the page JS')
            self.assertIn('/brave/'+nonce, proxy.requests)
            self.assertIn('/ran/'+nonce, proxy.requests)
        finally:
            self.driver.cancel(request)
            self.driver.end(request, mark)
            self.service('stop')

    def test_offline_browser_cannot_load_an_actual_host_loopback_http_server(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<title>direct-host-response</title>')

            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        binary, root = BROWSERS['chrome']
        url = 'http://127.0.0.1:%d/host-only' % server.server_port
        _, exits, stdout, stderr = self.result(*self.launch([binary, *NORMAL_FLAGS, '--dump-dom', url], root))
        self.assertEqual(exits, [0], stderr[-3000:])
        self.assertNotIn('<title>direct-host-response</title>', stdout)
        self.assertEqual(seen, [])

    def test_profile_serves_http_only_through_proxy_then_revokes_the_live_flow(self):
        nonce = uuid.uuid4().hex
        proxy = BrowserProxy(nonce)
        self.addCleanup(proxy.close)
        self.service('start', profile=profile(proxy))
        binary, root = BROWSERS['chrome']
        target = f'http://{TEST_IP}:{TEST_PORT}/page/{nonce}'
        request, mark = self.launch([binary, *NORMAL_FLAGS, '--dump-dom', target], root)
        deadline = time.monotonic()+20
        while not proxy.waiting.wait(.05) and time.monotonic() < deadline:
            self.driver.mark()
            if any(e.get('kind') == 'stream_end' and e.get('id') == request for e in self.driver.events[mark:]):
                break
        self.assertTrue(proxy.waiting.is_set(), 'browser did not establish both HTTP flows via synthetic SOCKS')
        self.service('stop')
        _, exits, stdout, stderr = self.result(request, mark)
        self.assertEqual(exits, [0], stderr[-3000:])
        self.assertIn('<title>network-revoked</title>', stdout)
        self.assertIn('/page/'+nonce, proxy.requests)
        self.assertIn('/hold/'+nonce, proxy.requests)


if __name__ == '__main__':
    unittest.main(verbosity=2)
