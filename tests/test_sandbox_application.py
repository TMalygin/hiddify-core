"""RunApplication acceptance with a native core, mTLS and disposable Wayland desktop.

Use the environment described by tests/fixtures/wayland_package_namespace.py.
Pass test_sandbox_application to that fixture to run this suite. The installed
image viewer, Python interpreter and caller-selected files all use real exec.
"""
import base64
import contextlib
import json
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
from types import SimpleNamespace

import test_sandbox_wayland as wayland


class CoreResources(contextlib.ExitStack):
    """Retain the authenticated channel created by the existing core fixture."""

    def enter_context(self, manager):
        import grpc
        value = super().enter_context(manager)
        if isinstance(value, grpc.Channel):
            self.channel = value
        return value


class GenericApplication(wayland.WaylandFixture):
    def start_core(self, env):
        resources = self.stack.enter_context(CoreResources())
        core = wayland.Core(resources, self.directory, env, self.wire)
        # Prove the native engine, mutual TLS and the original launcher are
        # healthy independently of the new endpoint.
        control = list(core.launch(self.wire.Request(command=['/usr/bin/true']), timeout=15))
        self.assertEqual(self.exit_codes(control), [0], 'original launcher control failed')
        return resources.channel.unary_stream('/hcore.Core/RunApplication',
                                              self.wire.Request.SerializeToString,
                                              self.wire.Event.FromString)

    def exit_codes(self, events):
        return [e.exit_code for e in events if e.state == self.wire.Event.EXITED]

    def completed(self, launch, request):
        import grpc
        try:
            events = list(launch(request, timeout=20))
        except grpc.RpcError as exc:
            self.fail(f'RunApplication failed with {exc.code().name}: {exc.details()}')
        stderr = b''.join(e.stderr for e in events)
        self.assertEqual(self.exit_codes(events), [0], stderr.decode(errors='replace'))
        states = [e.state for e in events]
        self.assertIn(self.wire.Event.OFFLINE, states)
        self.assertNotIn(self.wire.Event.ONLINE, states)
        return b''.join(e.stdout for e in events)

    def test_selected_elf_with_an_unregistered_name_preserves_argv(self):
        launch = self.start_core(self.env)
        program = self.directory / ('user selection ' + secrets.token_hex(8))
        shutil.copy('/usr/bin/printf', program)
        program.chmod(0o700)
        arguments = ['space separated', '--ordinary-option', '', 'literal *']
        request = self.wire.Request(command=[str(program), '<%s>\n', *arguments], application_id='selected-elf')
        self.assertEqual(self.completed(launch, request),
                         ''.join(f'<{s}>\n' for s in arguments).encode())

    def test_user_script_and_child_have_no_host_files_or_offline_connection(self):
        launch = self.start_core(self.env)
        origin = self.directory / 'my applications'
        origin.mkdir(mode=0o700)
        hidden = origin / 'sibling'
        hidden.write_text('belongs to the unshared host directory')
        program = origin / ('command ' + secrets.token_hex(8))
        program.write_text("""#!/usr/bin/python3
import json, os, socket, subprocess, sys
from pathlib import Path
host, port, sibling, *arguments = sys.argv[1:]
child = subprocess.run(['/usr/bin/python3', '-c',
    'import socket, sys; s=socket.socket(); s.settimeout(1); '
    'print(s.connect_ex((sys.argv[1], int(sys.argv[2]))) == 0)', host, port],
    check=True, capture_output=True, text=True)
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
print(json.dumps({'args': arguments, 'online': child.stdout.strip() == 'True',
    'sibling_visible': Path(sibling).exists() or Path(sys.argv[0]).with_name('sibling').exists(),
    'privileges': int(status['CapEff'].strip(), 16), 'no_new_privs': int(status['NoNewPrivs']),
    'seccomp': int(status['Seccomp']), 'display': os.environ.get('WAYLAND_DISPLAY')}))
""")
        program.chmod(0o700)
        listener = self.stack.enter_context(socket.socket())
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        host, port = listener.getsockname()
        with socket.create_connection((host, port), timeout=2), listener.accept()[0]:
            pass
        arguments = ['argument with spaces', '']
        request = self.wire.Request(command=[str(program), host, str(port), str(hidden), *arguments],
                                    application_id='selected-script')
        report = json.loads(self.completed(launch, request))
        self.assertEqual(report, {'args': arguments, 'online': False, 'sibling_visible': False,
                                  'privileges': 0, 'no_new_privs': 1, 'seccomp': 2, 'display': None})
        listener.settimeout(.2)
        with self.assertRaises(TimeoutError):
            listener.accept()

    def test_installed_image_viewer_renders_on_its_private_display(self):
        import grpc
        from PIL import Image
        display = wayland.VirtualDisplay(self.stack, self.directory, self.env)
        color = (37, 168, 92)
        path = self.directory / 'picture with spaces.png'
        Image.new('RGB', (320, 240), color).save(path)

        def visible():
            frame = display.capture()
            return any(n > 10000 and rgb == color for n, rgb in frame.getcolors(frame.width * frame.height))

        command = '/usr/bin/weston-image'
        # Confirm the distro-provided viewer can render these exact bytes on
        # the disposable parent and that its pixels disappear when it exits.
        viewer = subprocess.Popen([command, str(path)], env=display.env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            wayland.wait_for(visible, 'image viewer positive control failed')
        finally:
            wayland.stop_process(viewer)
        wayland.wait_for(lambda: not visible(), 'positive control pixels not cleared')
        launch = self.start_core(display.env)
        identity = 'generic-image-viewer'
        payload = base64.b64encode(path.read_bytes()).decode('ascii')
        prepare = "import base64,pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode(sys.argv[2]))"
        request = self.wire.Request(command=['/usr/bin/python3', '-c', prepare, path.name, payload],
                                    application_id=identity)
        self.completed(launch, request)

        # The real viewer accepts filenames in argv, so a Chromium-only flag
        # injected into this application would change its invocation.
        request = self.wire.Request(command=[command, path.name], application_id=identity, private_wayland=True)
        session = wayland.Browser(self.stack, SimpleNamespace(launch=launch), request)

        def presented():
            if session.failure is not None and isinstance(session.failure, grpc.RpcError):
                self.fail(f'viewer launch failed with {session.failure.code().name}: {session.failure.details()}')
            session.alive()
            return visible()
        wayland.wait_for(presented, 'viewer failed to present private-home PNG', timeout=15)
        self.assertIn(self.wire.Event.OFFLINE, [e.state for e in session.events])
        self.assertNotIn(self.wire.Event.ONLINE, [e.state for e in session.events])
        session.stream.cancel()
        wayland.wait_for(lambda: not visible(), 'cancelled viewer retained its window')

    def test_private_display_endpoint_is_distinct_from_parent(self):
        display = wayland.VirtualDisplay(self.stack, self.directory, self.env)
        launch = self.start_core(dict(display.env, DISPLAY=':77', DBUS_SESSION_BUS_ADDRESS='unix:path=/sentinel'))
        probe = """import json,os,pathlib,socket,sys
runtime=pathlib.Path(os.environ['XDG_RUNTIME_DIR'])
path=runtime / os.environ['WAYLAND_DISPLAY']
with socket.socket(socket.AF_UNIX) as s:
    s.connect(str(path))
st=path.stat()
print(json.dumps([st.st_dev, st.st_ino, pathlib.Path(sys.argv[1]).exists(),
                  'DISPLAY' in os.environ, 'DBUS_SESSION_BUS_ADDRESS' in os.environ]))"""
        request = self.wire.Request(command=['/usr/bin/python3', '-c', probe, str(display.socket)],
                                    private_wayland=True, application_id='generic-display')
        dev, inode, parent_visible, x11, bus = json.loads(self.completed(launch, request))
        host = display.socket.stat()
        self.assertNotEqual((dev, inode), (host.st_dev, host.st_ino))
        self.assertFalse(parent_visible or x11 or bus)

    def test_missing_parent_fails_before_exec_and_id_is_required(self):
        import grpc
        runtime = self.directory / 'no-display'
        runtime.mkdir(mode=0o700)
        launch = self.start_core(dict(self.env, XDG_RUNTIME_DIR=str(runtime), WAYLAND_DISPLAY='absent'))
        for request in [self.wire.Request(command=['/usr/bin/true'], private_wayland=True, application_id='gui'),
                        self.wire.Request(command=['/usr/bin/true'])]:
            with self.subTest(request=request):
                with self.assertRaises(grpc.RpcError) as exc:
                    list(launch(request, timeout=15))
                self.assertIn(exc.exception.code(),
                              (grpc.StatusCode.FAILED_PRECONDITION, grpc.StatusCode.INVALID_ARGUMENT))
