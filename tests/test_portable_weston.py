"""Native RunApplication checks for the private compositor shipped with AppImage.

Stage HiddifyCli, lib/hiddify-core.so and lib/hiddify-weston-runtime.tar.gz in
one directory. Set HIDDIFY_WAYLAND_DRIVER and the package inputs documented by
tests/fixtures/wayland_package_namespace.py. Run the positive case with
--without-weston and the refusal case with an installed test Weston.
"""
import io
import os
from pathlib import Path
import shutil
import tarfile
from types import SimpleNamespace
from unittest.mock import patch

import test_sandbox_application as generic
import test_sandbox_wayland as gui


CAPSULE = 'hiddify-weston-runtime.tar.gz'
GTK_PAGE = """import os
os.environ['GDK_BACKEND'] = 'wayland'
os.environ['GSK_RENDERER'] = 'cairo'
import gi
gi.require_version('Gtk', '4.0')
from gi.repository import GLib, Gtk
Gtk.init()
window = Gtk.Window()
window.set_default_size(420, 310)
area = Gtk.DrawingArea()
def paint(area, context, width, height):
    context.set_source_rgb(37/255, 168/255, 92/255)
    context.paint()
area.set_draw_func(paint)
window.set_child(area)
window.present()
GLib.MainLoop().run()
"""


def copy_with_changed_weston(source, target):
    """Keep a valid gzip/tar and runnable ELF while changing the program bytes."""
    changed = 0
    with tarfile.open(source, 'r:gz') as original, tarfile.open(target, 'w:gz') as altered:
        for entry in original:
            if not entry.isfile():
                altered.addfile(entry)
                continue
            with original.extractfile(entry) as content:
                if Path(entry.name).name == 'weston' and content.peek(4)[:4] == b'\x7fELF':
                    data = content.read() + b'\x00modified fixture'
                    entry.size = len(data)
                    altered.addfile(entry, io.BytesIO(data))
                    changed += 1
                else:
                    altered.addfile(entry, content)
    if changed != 1:
        raise RuntimeError(f'capsule fixture contains {changed} selected Weston ELF programs')


class PortableWeston(gui.WaylandFixture):
    def engine(self, display, name, mode):
        stage = self.directory / name
        stage.mkdir(mode=0o700)
        lib = stage / 'lib'
        lib.mkdir(mode=0o700)
        source = Path(os.environ['HIDDIFY_WAYLAND_DRIVER']).resolve(strict=True)
        cli = stage / 'HiddifyCli'
        shutil.copy(source, cli)
        (lib / 'hiddify-core.so').symlink_to(source.parent / 'lib/hiddify-core.so')
        archive = source.parent / 'lib' / CAPSULE
        if not archive.is_file():
            raise RuntimeError('stage the verified portable Weston archive next to the fixture CLI')
        if mode == 'valid':
            shutil.copyfile(archive, lib / CAPSULE)
        elif mode == 'changed':
            copy_with_changed_weston(archive, lib / CAPSULE)

        decoy = stage / 'path-search'
        decoy.mkdir(mode=0o700)
        marker = decoy / 'executed'
        dummy = decoy / 'weston'
        dummy.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 95\n')
        dummy.chmod(0o700)
        env = dict(display.env, PATH=str(decoy) + ':/usr/bin:/bin')
        if mode != 'native':
            # APPIMAGE selects the packaged policy. A decoy directory supplied
            # by the caller must not substitute for the real CLI's directory.
            decoy_dir = stage / 'caller-controlled-directory'
            (decoy_dir / 'lib').mkdir(parents=True)
            (decoy_dir / 'lib' / CAPSULE).symlink_to(archive)
            env.update(APPIMAGE=str(decoy_dir / 'renamed.AppImage'), APPDIR=str(decoy_dir))
        resources = self.stack.enter_context(generic.CoreResources())
        with patch.dict(os.environ, HIDDIFY_WAYLAND_DRIVER=str(cli)):
            core = gui.Core(resources, stage, env, self.wire)
        events = list(core.launch(self.wire.Request(command=['/usr/bin/true']), timeout=15))
        self.assertEqual([e.exit_code for e in events if e.state == self.wire.Event.EXITED], [0])
        launch = resources.channel.unary_stream('/hcore.Core/RunApplication', self.wire.Request.SerializeToString,
                                               self.wire.Event.FromString)
        return SimpleNamespace(launch=launch, decoy_marker=marker)

    def test_valid_local_archive_presents_an_ordinary_application_without_host_weston(self):
        self.assertFalse(Path('/usr/bin/weston').exists(), 'use the --without-weston configuration')
        display = gui.VirtualDisplay(self.stack, self.directory, self.env)
        engine = self.engine(display, 'packaged engine with spaces', 'valid')
        request = self.wire.Request(command=['/usr/bin/python3', '-c', GTK_PAGE], application_id='capsule-frame',
                                    private_wayland=True)
        session = gui.Browser(self.stack, engine, request)
        gui.PrivateWayland.wait_color(self, display, session, (37, 168, 92))
        self.assertIn(self.wire.Event.OFFLINE, [e.state for e in session.events])
        self.assertFalse(engine.decoy_marker.exists(), 'launcher ran Weston from the caller PATH')
        session.stream.cancel()

    def test_missing_and_modified_archives_cannot_fall_back_to_installed_weston(self):
        import grpc
        self.assertTrue(Path('/usr/bin/weston').is_file(), 'a working system Weston is the positive control')
        display = gui.VirtualDisplay(self.stack, self.directory, self.env)
        req = self.wire.Request(command=['/usr/bin/true'], application_id='capsule-errors', private_wayland=True)
        native = self.engine(display, 'native-control', 'native')
        events = list(native.launch(req, timeout=20))
        self.assertEqual([e.exit_code for e in events if e.state == self.wire.Event.EXITED], [0])
        for mode in ('missing', 'changed'):
            with self.subTest(mode=mode):
                engine = self.engine(display, mode, mode)
                with self.assertRaises(grpc.RpcError) as refusal:
                    list(engine.launch(req, timeout=20))
                self.assertEqual(refusal.exception.code(), grpc.StatusCode.FAILED_PRECONDITION)
                self.assertFalse(engine.decoy_marker.exists(), 'launcher ran Weston from the caller PATH')
