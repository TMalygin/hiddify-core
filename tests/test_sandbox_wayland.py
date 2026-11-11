"""Authenticated, offline GUI acceptance against the real core on Linux x86_64.

Set HIDDIFY_WAYLAND_DRIVER to an executable HiddifyCli next to its lib, or to
an AppImage with HIDDIFY_WAYLAND_APPIMAGE=1. Requires grpcio-tools, Pillow,
openssl, Weston 15+ (including weston-screenshooter and weston-simple-shm),
installed Chrome and Brave and rootless bwrap. The only parent display used
is a temporary headless Weston. No production control RPC takes a socket path.
"""
import base64
import contextlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import os
from pathlib import Path
import queue
import secrets
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import quote

from test_sandbox_storage import descendants, pidfd_exited


BROWSERS = {'chrome': ('/opt/google/chrome/chrome', '/opt/google/chrome'),
            'brave': ('/usr/lib/brave-browser/brave', '')}
BASE_FLAGS = ['--no-first-run', '--no-default-browser-check', '--disable-background-networking']


def wait_for(check, message, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.05)
    raise AssertionError(message)


def stop_process(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


class VirtualDisplay:
    def __init__(self, stack, directory, env):
        from PIL import Image, ImageChops
        self.image = Image
        self.runtime = directory / 'parent-runtime'
        self.runtime.mkdir(mode=0o700)
        self.socket = self.runtime / 'parent'
        self.env = dict(env, XDG_RUNTIME_DIR=str(self.runtime), WAYLAND_DISPLAY='parent')
        self.output = directory / 'captures'
        self.output.mkdir(mode=0o700)
        self.log = directory / 'virtual-display.log'
        log = stack.enter_context(self.log.open('wb'))
        # This is a synthetic display with just the test's clients. The
        # private Weston started by the core must never inherit --debug.
        parent = os.environ.get('HIDDIFY_WAYLAND_TEST_PARENT_BIN', '/usr/bin/weston')
        self.proc = subprocess.Popen([parent, '--backend=headless', '--renderer=pixman',
                                      '--shell=kiosk', '--socket=parent', '--width=1280', '--height=900',
                                      '--fake-seat', '--idle-time=0', '--no-config', '--debug'],
                                     env=self.env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        stack.callback(stop_process, self.proc)
        wait_for(self.listening, 'headless control Weston did not accept a connection')
        # Exercise real capture before starting the core so a broken control
        # display cannot masquerade as a core regression.
        empty = self.capture()
        if empty.size != (1280, 900):
            raise RuntimeError('incorrect test parent output dimensions')
        sample = subprocess.Popen(['/usr/bin/weston-simple-shm'], env=self.env, stdin=subprocess.DEVNULL,
                                  stdout=log, stderr=log)
        try:
            wait_for(lambda: ImageChops.difference(empty, self.capture()).getbbox(),
                     'signed reference client produced no pixels on the headless parent')
        finally:
            stop_process(sample)

    def listening(self):
        if self.proc.poll() is not None:
            raise RuntimeError(self.log.read_text(errors='replace')[-1600:])
        with socket.socket(socket.AF_UNIX) as conn:
            try:
                conn.connect(str(self.socket))
                return True
            except (FileNotFoundError, ConnectionRefusedError):
                return False

    def capture(self):
        with tempfile.TemporaryDirectory(dir=self.output) as tmp:
            run = subprocess.run(['/usr/bin/weston-screenshooter', '--verbose'], cwd=tmp, env=self.env,
                                 capture_output=True, timeout=4, check=True)
            if b'Output capture error' in run.stderr + run.stdout:
                raise RuntimeError('headless parent denied fixture capture')
            names = list(Path(tmp).glob('*.png'))
            if len(names) != 1:
                raise RuntimeError('headless parent produced no unique frame')
            with self.image.open(names[0]) as shot:
                return shot.convert('RGB')


class Core:
    def __init__(self, stack, directory, env, wire):
        import grpc
        from google.protobuf.wrappers_pb2 import StringValue
        run = directory / 'core'
        run.mkdir(mode=0o700)
        identity = run / 'grpc'
        identity.mkdir(mode=0o700)
        (run / 'data').mkdir(mode=0o700)
        key, cert = identity / 'client.key', identity / 'client.crt'
        subprocess.run(['openssl', 'req', '-config', '/dev/null', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=private-wayland-test', '-addext', 'extendedKeyUsage=clientAuth',
                        '-keyout', str(key), '-out', str(cert)], env=env, capture_output=True, check=True)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            address = '127.0.0.1:' + str(sock.getsockname()[1])
        binary = str(Path(os.environ['HIDDIFY_WAYLAND_DRIVER']).resolve(strict=True))
        cmd = [binary]
        if os.environ.get('HIDDIFY_WAYLAND_APPIMAGE') == '1':
            cmd.append('HiddifyCli')
            env = dict(env, APPIMAGE_EXTRACT_AND_RUN='1')
        log = stack.enter_context((directory / 'core.log').open('wb'))
        self.proc = subprocess.Popen(cmd + ['core', '--mode', '1', '--listen', address, '--base-dir', str(run),
                                           '--working-dir', str(run), '--temp-dir', str(run),
                                           '--owner-pid', str(os.getpid())], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=log, cwd=run, env=env)
        stack.callback(self.close)
        ready = queue.Queue()

        def read():
            for line in self.proc.stdout:
                if line.startswith(b'HIDDIFY_CORE_READY '):
                    ready.put(base64.b64decode(line.split()[1], validate=True))
            ready.put(None)

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        server = ready.get(timeout=60)
        if not server:
            raise RuntimeError('core did not announce its mTLS certificate')
        creds = grpc.ssl_channel_credentials(server, key.read_bytes(), cert.read_bytes())
        channel = stack.enter_context(grpc.secure_channel(address, creds, options=[('grpc.enable_http_proxy', 0)]))
        hello = channel.unary_unary('/hello.Hello/SayHello', StringValue.SerializeToString, StringValue.FromString)
        if hello(StringValue(value='private-wayland'), timeout=10).value != 'Hello, private-wayland':
            raise RuntimeError('authenticated core readiness control failed')
        self.launch = channel.unary_stream('/hcore.Core/RunSandbox', wire.Request.SerializeToString, wire.Event.FromString)

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=18)
        except subprocess.TimeoutExpired:
            stop_process(self.proc)
            raise AssertionError('core failed to stop when its owner closed stdin')
        finally:
            self.reader.join(timeout=2)
            self.proc.stdout.close()


class Browser:
    def __init__(self, stack, core, request):
        self.stream = core.launch(request, timeout=100)
        stack.callback(self.stream.cancel)
        self.events = []
        self.failure = None

        def read():
            import grpc
            try:
                self.events.extend(self.stream)
            except grpc.RpcError as exc:
                self.failure = exc

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()

    def alive(self):
        if self.reader.is_alive():
            return
        stderr = b''.join(event.stderr for event in self.events)
        raise AssertionError(f'GUI session ended before presenting its page: {self.failure}; '
                             f'exits={[e.exit_code for e in self.events if e.state == 3]}; '
                             f'{stderr[-800:].decode(errors="replace")}')


@unittest.skipUnless(os.environ.get('HIDDIFY_WAYLAND_DRIVER'), 'explicit native core and private Weston fixtures required')
class WaylandFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from grpc_tools import protoc
        tmp = tempfile.TemporaryDirectory(prefix='hiddify-wayland-protocol-')
        cls.addClassCleanup(tmp.cleanup)
        schema = Path(__file__).resolve().parent / 'fixtures/private_wayland.proto'
        if protoc.main(['protoc', f'-I{schema.parent}', f'--python_out={tmp.name}', str(schema)]):
            raise RuntimeError('could not build the public client wire schema')
        spec = importlib.util.spec_from_file_location('private_wayland_pb2', Path(tmp.name)/'private_wayland_pb2.py')
        cls.wire = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.wire)

    def setUp(self):
        self.assertNotEqual(os.geteuid(), 0, 'the core acceptance fixture must run as an ordinary user')
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix='hiddify-gui-')))
        home = self.directory / 'home'
        home.mkdir(mode=0o700)
        self.env = {'HOME': str(home), 'TMPDIR': str(self.directory), 'PATH': '/usr/bin:/bin', 'LANG': 'C',
                    'HIDDIFY_CORE_SECRET': secrets.token_hex(32)}

    def browser_request(self, name, url):
        binary, root = BROWSERS[name]
        return self.wire.Request(command=[binary, *BASE_FLAGS, url], application_id='gui-' + name,
                                 executable_root=root, chromium_sandbox=True, private_wayland=True)

    def assert_rejected(self, core, request, codes):
        import grpc
        with self.assertRaises(grpc.RpcError) as failure:
            list(core.launch(request, timeout=20))
        self.assertIn(failure.exception.code(), codes, failure.exception)


class PrivateWayland(WaylandFixture):
    def test_mode_requires_browser_opt_in_and_application_id(self):
        import grpc
        core = Core(self.stack, self.directory, self.env, self.wire)
        legacy = list(core.launch(self.wire.Request(command=['/usr/bin/true']), timeout=15))
        self.assertEqual([e.exit_code for e in legacy if e.state == self.wire.Event.EXITED], [0])
        cases = [self.wire.Request(command=['/usr/bin/true'], application_id='not-a-browser', private_wayland=True),
                 self.wire.Request(command=[BROWSERS['brave'][0], '--version'], private_wayland=True,
                                   chromium_sandbox=True)]
        for request in cases:
            with self.subTest(command=list(request.command)):
                self.assert_rejected(core, request, (grpc.StatusCode.INVALID_ARGUMENT, grpc.StatusCode.FAILED_PRECONDITION))

    def test_unavailable_parent_fails_before_starting_the_browser(self):
        import grpc
        runtime = self.directory / 'empty-runtime'
        runtime.mkdir(mode=0o700)
        env = dict(self.env, XDG_RUNTIME_DIR=str(runtime), WAYLAND_DISPLAY='absent')
        core = Core(self.stack, self.directory, env, self.wire)
        request = self.browser_request('brave', 'about:blank')
        # --version makes a silent fallback observable even without a desktop.
        request.command[:] = [BROWSERS['brave'][0], '--version']
        self.assert_rejected(core, request, (grpc.StatusCode.FAILED_PRECONDITION,))

    def test_private_windows_render_independently_and_stay_offline(self):
        display = VirtualDisplay(self.stack, self.directory, self.env)
        trap = self.stack.enter_context(socket.socket(socket.AF_UNIX))
        dbus = display.runtime / 'bus'
        trap.bind(str(dbus))
        trap.listen()
        core = Core(self.stack, self.directory, dict(display.env, DBUS_SESSION_BUS_ADDRESS='unix:path='+str(dbus),
                                                      DISPLAY=':172'), self.wire)
        baseline_children = descendants(core.proc.pid)
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = self.stack.enter_context(ThreadingHTTPServer(('127.0.0.1', 0), Handler))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.stack.callback(server.shutdown)
        with contextlib.closing(HTTPConnection('127.0.0.1', server.server_port, timeout=3)) as control:
            control.request('GET', '/control')
            self.assertEqual(control.getresponse().status, 204)
        self.assertEqual(hits, ['/control'])
        sentinel = f'http://127.0.0.1:{server.server_port}/private-browser'
        sessions = []
        brokers = set()
        for name, color in [('chrome', (23, 177, 92)), ('brave', (188, 41, 96))]:
            css = '#%02x%02x%02x' % color
            # The page changes colour only after the network operation fails.
            # data: is self-contained and never needs a host file or web server.
            page = ('<body><script>const image=new Image();image.onerror=()=>{'
                    f'document.documentElement.style.backgroundColor="{css}"}};image.src="{sentinel}";</script></body>')
            req = self.browser_request(name, 'data:text/html,' + quote(page, safe=''))
            session = Browser(self.stack, core, req)
            self.wait_color(display, session, color)
            state = self.inspect_browser(core, BROWSERS[name][0], display, dbus)
            current = self.broker_pids(core)
            self.assertTrue(brokers.issubset(current), 'starting an application displaced a previous private Weston')
            self.assertEqual(len(current - brokers), 1, 'expected one new private Weston per browser')
            broker = (current - brokers).pop()
            state['broker_fd'] = os.pidfd_open(broker)
            self.stack.callback(os.close, state['broker_fd'])
            self.assertNotEqual(os.readlink(f'/proc/{broker}/ns/net'), os.readlink('/proc/self/ns/net'))
            brokers = current
            self.assertIn(self.wire.Event.OFFLINE, [e.state for e in session.events])
            self.assertNotIn(self.wire.Event.ONLINE, [e.state for e in session.events])
            sessions.append((session, color, state))
        first, second = sessions
        self.assertNotEqual(first[2]['display'], second[2]['display'], 'two sessions shared a Wayland listener')
        self.assertNotEqual(first[2]['net'], second[2]['net'], 'two browsers shared a network namespace')
        second[0].stream.cancel()
        wait_for(lambda: pidfd_exited(second[2]['pidfd']), 'cancelled browser is still alive')
        wait_for(lambda: pidfd_exited(second[2]['broker_fd']), 'cancelled browser retained its private compositor')
        self.wait_color(display, first[0], first[1])
        first[0].stream.cancel()
        wait_for(lambda: pidfd_exited(first[2]['pidfd']), 'last browser is still alive')
        wait_for(lambda: pidfd_exited(first[2]['broker_fd']), 'last private compositor is still alive')
        self.assertEqual(hits, ['/control'], 'an offline browser reached the host loopback server')
        wait_for(lambda: not (descendants(core.proc.pid) - baseline_children),
                 'core retained a GUI subprocess after cancelling both sessions')

    def wait_color(self, display, session, color):
        def presented():
            session.alive()
            frame = display.capture()
            return any(pixel == color and count > 10000
                       for count, pixel in frame.getcolors(frame.width * frame.height))
        wait_for(presented, f'no page pixels of colour {color} on the synthetic parent display', timeout=18)

    def inspect_browser(self, core, binary, display, dbus):
        for pid in descendants(core.proc.pid):
            proc = Path('/proc') / str(pid)
            try:
                args = (proc/'cmdline').read_bytes().replace(b'\0', b' ').split()
                if not args or args[0] != os.fsencode(binary) or any(a.startswith(b'--type=') for a in args):
                    continue
                env = dict(item.split(b'=', 1) for item in (proc/'environ').read_bytes().split(b'\0') if item)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            self.assertNotIn(b'--no-sandbox', args)
            self.assertFalse(any(arg.startswith(b'--headless') for arg in args))
            self.assertNotIn(b'DISPLAY', env)
            self.assertNotIn(b'DBUS_SESSION_BUS_ADDRESS', env)
            root = proc/'root'
            private = Path(os.fsdecode(env[b'XDG_RUNTIME_DIR'])) / os.fsdecode(env[b'WAYLAND_DISPLAY'])
            self.assertTrue(private.is_absolute())
            socket_info = (root / private.relative_to('/')).stat()
            self.assertTrue(stat.S_ISSOCK(socket_info.st_mode))
            self.assertFalse(os.path.samestat(socket_info, display.socket.stat()), 'browser received the parent socket')
            for host in (display.socket, dbus, Path('/tmp/.X11-unix/X172')):
                self.assertFalse((root / host.relative_to('/')).exists(), f'parent IPC visible at {host}')
            net = os.readlink(proc/'ns/net')
            self.assertNotEqual(net, os.readlink('/proc/self/ns/net'))
            fd = os.pidfd_open(pid)
            self.stack.callback(os.close, fd)
            return {'display': (socket_info.st_dev, socket_info.st_ino), 'net': net, 'pidfd': fd}
        self.fail(f'could not inspect the browser presenting the verified {binary} page')

    def broker_pids(self, core):
        found = set()
        for pid in descendants(core.proc.pid):
            try:
                if Path(os.readlink(f'/proc/{pid}/exe')).name == 'weston':
                    found.add(pid)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        return found


@unittest.skipUnless(os.environ.get('HIDDIFY_WAYLAND_TEST_PARENT_BIN'), 'requires a fixture without installed Weston')
class MissingCompositor(WaylandFixture):
    def test_missing_runtime_rejects_gui_while_the_parent_is_healthy(self):
        import grpc
        self.assertFalse(Path('/usr/bin/weston').exists())
        display = VirtualDisplay(self.stack, self.directory, self.env)
        core = Core(self.stack, self.directory, display.env, self.wire)
        request = self.browser_request('brave', 'about:blank')
        request.command[:] = [BROWSERS['brave'][0], '--version']
        self.assert_rejected(core, request, (grpc.StatusCode.FAILED_PRECONDITION,))


if __name__ == '__main__':
    unittest.main(verbosity=2)
