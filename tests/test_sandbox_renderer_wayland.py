"""Renderer private-display sizing against the real core and Wayland protocol.

HIDDIFY_RENDERER_TEST_DISPLAY=1 asserts that XDG_RUNTIME_DIR/WAYLAND_DISPLAY
refer to a disposable test compositor, never the user's actual desktop. Set
HIDDIFY_WAYLAND_DRIVER beside its core library and optionally APPIMAGE to
exercise the portable Weston capsule. No browser or application name is used.
"""
import json
import os
import textwrap
import unittest

from test_sandbox_application import CoreResources
from test_sandbox_wayland import Core, WaylandFixture


# Minimal xdg-shell client: declare an ordinary desktop minimum before the
# initial commit, then report the compositor's actual fullscreen configure.
CLIENT = textwrap.dedent(r'''
    import json, os, socket, struct
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(5)
    sock.connect(os.path.join(os.environ['XDG_RUNTIME_DIR'], os.environ['WAYLAND_DISPLAY']))
    def string(value):
        raw = value.encode() + b'\0'
        return struct.pack('I', len(raw)) + raw + b'\0' * (-len(raw) % 4)
    def send(obj, opcode, payload=b''):
        sock.sendall(struct.pack('II', obj, ((8+len(payload)) << 16) | opcode) + payload)
    def read(n):
        data = b''
        while len(data) < n:
            part = sock.recv(n-len(data))
            if not part: raise RuntimeError('compositor disconnected')
            data += part
        return data
    def event():
        obj, size_op = struct.unpack('II', read(8))
        return obj, size_op & 65535, read((size_op >> 16) - 8)
    send(1, 1, struct.pack('I', 2))  # registry
    send(1, 0, struct.pack('I', 3))  # sync
    globals = {}
    while True:
        obj, op, payload = event()
        if obj == 3: break
        if obj == 2 and op == 0:
            name, length = struct.unpack('II', payload[:8])
            interface = payload[8:8+length-1].decode()
            version, = struct.unpack('I', payload[8+((length+3)//4)*4:])
            globals[interface] = (name, version)
    for interface, identity, version in [('wl_compositor',4,4), ('xdg_wm_base',5,1)]:
        name, available = globals[interface]
        assert available >= version, (interface, available)
        send(2, 0, struct.pack('I',name) + string(interface) + struct.pack('II',version,identity))
    send(4, 0, struct.pack('I', 6))
    send(5, 2, struct.pack('II', 7, 6))
    send(7, 1, struct.pack('I', 8))
    send(8, 8, struct.pack('ii', 800, 600))
    send(6, 6)
    configured = None
    while True:
        obj, op, payload = event()
        if obj == 1 and op == 0: raise RuntimeError(repr(payload))
        if obj == 5 and op == 0: send(5, 3, payload)
        if obj == 8 and op == 0:
            width, height, length = struct.unpack('iiI', payload[:12])
            states = list(struct.unpack('I'*(length//4),payload[12:12+length]))
            configured = {'width':width, 'height':height, 'fullscreen':2 in states}
        if obj == 7 and op == 0 and configured is not None:
            send(7, 4, payload)
            print(json.dumps(configured), flush=True)
            break
''')


@unittest.skipUnless(os.environ.get('HIDDIFY_RENDERER_TEST_DISPLAY') == '1',
                     'explicit disposable parent display required')
class RendererMinimumWindow(WaylandFixture):
    def test_initial_configure_does_not_force_a_desktop_minimum_beyond_fullscreen(self):
        env = dict(self.env, XDG_RUNTIME_DIR=os.environ['XDG_RUNTIME_DIR'],
                   WAYLAND_DISPLAY=os.environ['WAYLAND_DISPLAY'])
        if os.environ.get('APPIMAGE'):
            env['APPIMAGE'] = os.environ['APPIMAGE']
        resources = self.stack.enter_context(CoreResources())
        core = Core(resources, self.directory, env, self.wire)
        control = list(core.launch(self.wire.Request(command=['/usr/bin/true']), timeout=15))
        self.assertEqual([e.exit_code for e in control if e.state == 3], [0])
        launch = resources.channel.unary_stream('/hcore.Core/RunRendererApplication',
                                                self.wire.Request.SerializeToString,
                                                self.wire.Event.FromString)
        events = list(launch(self.wire.Request(command=['/usr/bin/python3', '-c', CLIENT],
                                              application_id='minimum-desktop-window',
                                              private_wayland=True), timeout=25))
        stderr = b''.join(e.stderr for e in events).decode(errors='replace')
        self.assertEqual([e.exit_code for e in events if e.state == 3], [0], stderr)
        self.assertIn(self.wire.Event.OFFLINE, [e.state for e in events])
        self.assertNotIn(self.wire.Event.ONLINE, [e.state for e in events])
        geometry = json.loads(b''.join(e.stdout for e in events))
        # A normal toplevel can choose its own size. A fullscreen compositor
        # must fit this common minimum or real clients violate the protocol.
        if geometry['fullscreen']:
            self.assertGreaterEqual(geometry['width'], 800, geometry)
            self.assertGreaterEqual(geometry['height'], 600, geometry)


if __name__ == '__main__':
    unittest.main(verbosity=2)
