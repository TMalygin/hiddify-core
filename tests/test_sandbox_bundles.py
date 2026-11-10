"""Selected system bundle capability, tested in a private synthetic filesystem.

Use fixtures/sandbox_bundle_namespace.py. Its delegated namespace root creates
synthetic UID0 /opt trees; the production core runs as a nonzero UID with all
capabilities dropped. Nothing creates, changes or chmods the host's /opt.
"""
import contextlib
import ctypes
import errno
import json
import os
from pathlib import Path
import queue
import select
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from test_sandbox_storage import Driver as StorageDriver, INSPECT, pidfd_exited
from test_sandbox_profile_leases import profile
from test_sandbox_selection_recovery import IDENTIFIED_PROBE
from test_rootless_sandbox import Proxy


TEST_UID = int(os.environ.get('HIDDIFY_BUNDLE_TEST_UID', '-1'))
TEST_GID = int(os.environ.get('HIDDIFY_BUNDLE_TEST_GID', '-1'))
LIBC = ctypes.CDLL(None, use_errno=True)


def bind(source, target):
    if LIBC.mount(os.fsencode(source), os.fsencode(target), None, ctypes.c_ulong(4096), None):
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), str(target))


def unmount(target):
    if LIBC.umount2(os.fsencode(target), 2):
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), str(target))


class Driver(StorageDriver):
    def __init__(self, directory):
        self.events, self.output, self.errors = [], [], []
        self.pending = queue.Queue()
        self.sequence = 0
        self.buffers = {}
        self.proc = subprocess.Popen([os.environ['HIDDIFY_BUNDLE_DRIVER']], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     user=TEST_UID, group=TEST_GID, extra_groups=[],
                                     env={**os.environ, 'HIDDIFY_SANDBOX_TEST_DIR': str(directory),
                                          'HIDDIFY_ADMIN_BG_DATA': str(directory) + '/admin',
                                          'HIDDIFY_TUNNEL_DATA': str(directory) + '/tunnel',
                                          'HIDDIFY_CORE_SECRET': 'fixture-host-secret'})
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.error_reader = threading.Thread(target=lambda: self.errors.append(self.proc.stderr.read()), daemon=True)
        self.reader.start()
        self.error_reader.start()
        try:
            self.working = Path(self.wait(lambda event: event.get('kind') == 'ready')['working_dir'])
        except BaseException:
            self.close()
            raise

    def bundle_launch(self, root, command, application_id='bundle-app'):
        mark = self.mark()
        request = self.send('launch', executable_root=str(root), application_id=application_id, command=command)
        return request, mark


EXECUTED = "print('EXECUTED', flush=True)\n"
TRIVIAL = "import json; print('STORAGE '+json.dumps({'executed':True}), flush=True)\n"
INSPECT_BUNDLE = INSPECT.replace("print('STORAGE '", r'''
import errno
bundle = pathlib.Path(__file__).parent
result['resource'] = (bundle/'resource').read_text()
result['bundle'] = str(bundle)
result['readonly'] = bool(os.statvfs(bundle).f_flag & os.ST_RDONLY)
result['mount_options'] = next(line.split()[5].split(',') for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4] == str(bundle))
result['write_error'] = None
try: (bundle/'should-not-write').write_text('forbidden')
except OSError as error: result['write_error'] = error.errno
result['status'] = pathlib.Path('/proc/self/status').read_text()
result['parent_secret'] = (bundle.parent/'parent-secret').exists()
result['other_bundle'] = pathlib.Path('/opt/other-secret').exists()
print('STORAGE '
'''.strip() + ' ')


@unittest.skipUnless(os.environ.get('HIDDIFY_BUNDLE_NAMESPACE') == '1',
                     'run through the explicit delegated-UID namespace fixture')
class ApplicationBundles(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.getuid(), 0, 'fixture administrator must be namespace root')
        self.assertGreater(TEST_UID, 0, 'the tested core must remain unprivileged')
        self.assertEqual(Path('/').stat().st_uid, 0)
        self.assertFalse(Path('/.old-root').exists(), 'host root is still reachable')
        self.temp = tempfile.TemporaryDirectory(prefix='bundle-core-', dir='/work')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        os.chown(self.directory, TEST_UID, TEST_GID)
        self.vendor = Path('/opt') / ('bundle-test-' + uuid.uuid4().hex)
        self.vendor.mkdir(mode=0o755)
        self.addCleanup(shutil.rmtree, self.vendor)
        (self.vendor/'parent-secret').write_text('not part of the selected bundle')
        Path('/opt/other-secret').write_text('not part of any selected bundle')
        self.driver = Driver(self.directory)
        self.addCleanup(self.driver.close)

    def bundle(self, name='application', script=INSPECT_BUNDLE):
        root = self.vendor/name
        root.mkdir(mode=0o755)
        executable = root/'probe'
        executable.write_text('#!/usr/bin/python3\n' + script)
        executable.chmod(0o755)
        (root/'resource').write_text('selected-bundle-data')
        (root/'resource').chmod(0o644)
        return root, executable

    def one_shot(self, root, command, application_id='bundle-app'):
        request, mark = self.driver.bundle_launch(root, command, application_id)
        data = self.driver.storage(request, mark)
        self.driver.end(request, mark)
        terminal = [event for event in self.driver.events[mark:]
                    if event.get('id') == request and event.get('state') == 3]
        self.assertEqual(len(terminal), 1, 'missing native terminal completion')
        self.assertEqual(terminal[0].get('exit_code', 0), 0)
        return data

    def rejected(self, root, command, application_id='bundle-app'):
        request, mark = self.driver.bundle_launch(root, command, application_id)
        end = self.driver.end(request, mark)
        events = [event for event in self.driver.events[mark:] if event.get('id') == request]
        self.assertNotIn('EXECUTED', ''.join(event.get('stdout', '') for event in events))
        self.assertFalse(any(event.get('kind') == 'storage' for event in events), 'rejected bundle executed a probe')
        self.assertIn(end['code'], ('InvalidArgument', 'FailedPrecondition', 'PermissionDenied'), end)

    def test_namespace_fixture_runs_existing_unprivileged_console_mode(self):
        data = self.one_shot('', ['/usr/bin/python3', '-c', INSPECT])
        self.assertEqual(data['uid'], TEST_UID)
        self.assertEqual(data['home'], '/home/sandbox')
        self.assertLessEqual(set(data['fds']), {'0', '1', '2'})
        self.assertEqual(data['pid1_dangers'], [])

    def test_selected_bundle_resources_are_readonly_without_extra_fds_or_paths(self):
        root, executable = self.bundle()
        data = self.one_shot(root, [str(executable)])
        self.assertEqual(data['resource'], 'selected-bundle-data')
        self.assertEqual(data['bundle'], str(root))
        self.assertTrue(data['readonly'], 'bundle mount lacks ST_RDONLY')
        self.assertLessEqual({'ro', 'nosuid', 'nodev'}, set(data['mount_options']))
        self.assertEqual(data['write_error'], errno.EROFS)
        self.assertFalse((root/'should-not-write').exists())
        self.assertFalse(data['parent_secret'] or data['other_bundle'])
        self.assertEqual(data['uid'], TEST_UID)
        self.assertIn('CapEff:\t0000000000000000', data['status'])
        self.assertIn('NoNewPrivs:\t1', data['status'])
        self.assertLessEqual(set(data['fds']), {'0', '1', '2'})
        self.assertEqual(data['pid1_dangers'], [])

    def test_bundle_opt_in_requires_application_identity(self):
        root, executable = self.bundle(script=EXECUTED)
        self.rejected(root, [str(executable)], '')

    def test_root_must_be_canonical_below_opt_and_exact_selected_parent(self):
        root, executable = self.bundle(script=EXECUTED)
        invalid = ('/', '/opt', '/opt/', '/usr', '/home', '/run', '/proc',
                   'opt/application', str(root)+'/', str(root).replace('/opt/', '/opt//'),
                   str(root)+'/../application', str(root)+'/./', str(self.vendor))
        for value in invalid:
            with self.subTest(root=value):
                self.rejected(value, [str(executable)])
        self.rejected(root, ['/usr/bin/python3', '-c', EXECUTED])
        child = root/'nested'
        child.mkdir(mode=0o755)
        nested = child/'probe'
        nested.write_text('#!/usr/bin/python3\n'+EXECUTED)
        nested.chmod(0o755)
        self.rejected(root, [str(nested)])

    def test_selected_path_must_be_canonical_regular_executable(self):
        root, executable = self.bundle(script=EXECUTED)
        for path in (str(root)+'/./probe', str(root)+'//probe', str(root)+'/../application/probe', str(executable)+'/'):
            with self.subTest(path=path):
                self.rejected(root, [path])
        executable.chmod(0o644)
        self.rejected(root, [str(executable)])
        executable.unlink()
        executable.mkdir(mode=0o755)
        self.rejected(root, [str(executable)])
        executable.rmdir()
        self.rejected(root, [str(executable)])

    def test_ancestors_root_and_descendants_require_root_ownership(self):
        root, executable = self.bundle(script=EXECUTED)
        child = root/'directory'
        child.mkdir(mode=0o755)
        for path in (Path('/'), Path('/opt'), self.vendor, root, child, root/'resource', executable):
            with self.subTest(path=str(path)):
                original = path.stat()
                os.chown(path, TEST_UID, original.st_gid)
                try:
                    self.rejected(root, [str(executable)])
                    self.assertEqual(path.stat().st_uid, TEST_UID, 'launcher silently repaired ownership')
                finally:
                    os.chown(path, original.st_uid, original.st_gid)

    def test_ancestors_root_and_descendants_reject_group_or_world_write(self):
        root, executable = self.bundle(script=EXECUTED)
        child = root/'directory'
        child.mkdir(mode=0o755)
        for path in (Path('/'), Path('/opt'), self.vendor, root, child, root/'resource', executable):
            for bit in (0o020, 0o002):
                with self.subTest(path=str(path), bit=oct(bit)):
                    original = stat.S_IMODE(path.stat().st_mode)
                    path.chmod(original | bit)
                    try:
                        self.rejected(root, [str(executable)])
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), original | bit)
                    finally:
                        path.chmod(original)

    def test_symlinks_in_root_ancestors_selected_file_or_tree_are_rejected(self):
        root, executable = self.bundle(script=EXECUTED)
        alias = self.vendor/'alias'
        alias.symlink_to(root)
        self.rejected(alias, [str(alias/'probe')])
        alias.unlink()
        vendor_alias = Path(str(self.vendor)+'-alias')
        vendor_alias.symlink_to(self.vendor)
        try:
            self.rejected(vendor_alias/root.name, [str(vendor_alias/root.name/'probe')])
        finally:
            vendor_alias.unlink()
        selected = root/'selected-link'
        selected.symlink_to('probe')
        self.rejected(root, [str(selected)])
        selected.unlink()
        for target in ('resource', '/etc/passwd', str(self.directory)):
            alias.symlink_to(target)
            # The hostile link must be inside the selected tree.
            alias.rename(root/'link')
            try:
                self.rejected(root, [str(executable)])
            finally:
                (root/'link').unlink()

    def test_hardlinked_selected_executable_or_resource_is_rejected(self):
        root, executable = self.bundle(script=EXECUTED)
        for path in (executable, root/'resource'):
            with self.subTest(path=path.name):
                os.link(path, root/'hardlink')
                try:
                    self.assertEqual(path.stat().st_nlink, 2)
                    self.rejected(root, [str(executable)])
                finally:
                    (root/'hardlink').unlink()

    def test_fifo_socket_and_device_nodes_cannot_be_exposed_as_resources(self):
        root, executable = self.bundle(script=EXECUTED)
        special = root/'special'
        os.mkfifo(special, 0o644)
        try:
            self.rejected(root, [str(executable)])
        finally:
            special.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(special))
        listener.listen()
        listener.settimeout(.15)
        try:
            self.rejected(root, [str(executable)])
            with self.assertRaises(socket.timeout):
                listener.accept()
        finally:
            listener.close()
            special.unlink()
        # Binding an existing device avoids mknod privileges on the host.
        special.touch()
        bind('/dev/null', special)
        try:
            self.assertTrue(stat.S_ISCHR(special.stat().st_mode))
            self.rejected(root, [str(executable)])
        finally:
            unmount(special)
            special.unlink()

    def test_nested_mounts_are_rejected_even_on_the_same_filesystem(self):
        root, executable = self.bundle(script=EXECUTED)
        source = self.vendor/'mount-source'
        source.mkdir(mode=0o755)
        (source/'resource').write_text('must not be mounted through the bundle')
        target = root/'nested'
        target.mkdir(mode=0o755)
        self.assertEqual(source.stat().st_dev, target.stat().st_dev)
        bind(source, target)
        try:
            self.rejected(root, [str(executable)])
        finally:
            unmount(target)
        target = root/'resource'
        bind(source/'resource', target)
        try:
            self.rejected(root, [str(executable)])
        finally:
            unmount(target)

    def test_file_capabilities_are_rejected_on_selected_and_other_files(self):
        root, executable = self.bundle(script=EXECUTED)
        for path in (executable, root/'resource'):
            with self.subTest(path=path.name):
                subprocess.run(['/usr/bin/setcap', 'cap_net_bind_service=ep', str(path)], check=True)
                try:
                    self.assertGreater(len(os.getxattr(path, 'security.capability')), 0)
                    self.rejected(root, [str(executable)])
                finally:
                    os.removexattr(path, 'security.capability')

    def test_selected_setid_is_rejected_and_inert_helper_cannot_gain_privileges(self):
        script = "import json,os,pathlib,subprocess\np=pathlib.Path(__file__).parent\nprint('STORAGE '+json.dumps({'uid':os.getuid(),'helper_uid':subprocess.check_output([str(p/'inert-helper'),'-u'],text=True).strip(),'readonly':bool(os.statvfs(p).f_flag & os.ST_RDONLY),'status':pathlib.Path('/proc/self/status').read_text(),'mount_options':next(line.split()[5].split(',') for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines() if line.split()[4]==str(p))}),flush=True)\n"
        root, executable = self.bundle(script=script)
        for mode in (0o4755, 0o2755):
            executable.chmod(mode)
            try:
                self.rejected(root, [str(executable)])
            finally:
                executable.chmod(0o755)
        shutil.copyfile('/usr/bin/id', root/'inert-helper')
        (root/'inert-helper').chmod(0o4755)
        data = self.one_shot(root, [str(executable)])
        self.assertEqual(data['uid'], TEST_UID)
        self.assertEqual(data['helper_uid'], str(TEST_UID))
        self.assertTrue(data['readonly'])
        self.assertLessEqual({'ro', 'nosuid', 'nodev'}, set(data['mount_options']))
        self.assertIn('NoNewPrivs:\t1', data['status'])

    def test_tree_entry_limit_counts_all_descendants(self):
        root, executable = self.bundle(script=TRIVIAL)
        for number in range(16382):
            (root/('entry-%05d' % number)).touch(mode=0o644)
        self.assertEqual(len(list(root.iterdir())), 16384)
        self.assertTrue(self.one_shot(root, [str(executable)])['executed'])
        (root/'one-too-many').touch(mode=0o644)
        self.rejected(root, [str(executable)])

    def test_tree_depth_limit_includes_regular_files(self):
        root, executable = self.bundle(script=TRIVIAL)
        deepest = root
        for _ in range(31):
            deepest = deepest/'d'
            deepest.mkdir(mode=0o755)
        (deepest/'resource-at-depth-32').touch(mode=0o644)
        deepest = deepest/'empty-directory-at-depth-32'
        deepest.mkdir(mode=0o755)
        self.assertTrue(self.one_shot(root, [str(executable)])['executed'])
        (deepest/'resource-at-depth-33').touch(mode=0o644)
        self.rejected(root, [str(executable)])

    def test_replacing_root_or_ancestor_does_not_redirect_a_live_mount(self):
        script = "import json,pathlib,time\np=pathlib.Path(__file__).parent\nfor seq in range(1000):\n print('STORAGE '+json.dumps({'seq':seq,'resource':(p/'resource').read_text()}),flush=True)\n time.sleep(.04)\n"
        for component in ('root', 'ancestor'):
            with self.subTest(component=component):
                root, executable = self.bundle(component, script)
                request, mark = self.driver.bundle_launch(root, [str(executable)], component)
                first = self.driver.storage(request, mark)
                self.assertEqual(first['resource'], 'selected-bundle-data')
                lease = json.loads((self.driver.working/'sandbox-apps'/component/'.lease.json').read_text())
                lifetime = os.pidfd_open(lease['pid'])
                try:
                    foreign = self.directory/('foreign-'+component)
                    foreign.mkdir(mode=0o755)
                    (foreign/'resource').write_text('foreign-data')
                    if component == 'ancestor':
                        (foreign/root.name).mkdir(mode=0o755)
                        (foreign/root.name/'resource').write_text('foreign-data')
                    original = root if component == 'root' else self.vendor
                    saved = Path(str(original)+'-pinned')
                    original.rename(saved)
                    original.symlink_to(foreign)
                    try:
                        sequence = first['seq']
                        since = self.driver.mark()
                        for _ in range(3):
                            event = self.driver.wait(lambda event: event.get('kind') == 'storage'
                                                     and event.get('id') == request and event['seq'] > sequence, since)
                            sequence = event['seq']
                            self.assertEqual(event['resource'], 'selected-bundle-data')
                        self.driver.cancel(request)
                        self.driver.end(request, mark)
                        self.assertTrue(pidfd_exited(lifetime, 5000))
                        self.rejected(root, [str(executable)], component)
                    finally:
                        original.unlink()
                        saved.rename(original)
                finally:
                    os.close(lifetime)

    @staticmethod
    def network_probe():
        return IDENTIFIED_PROBE.replace("print('PROBE '", "print('STORAGE '").replace(
            "'profile-flow-%d' % seq", "'bundle50-' + instance + '-' + str(seq)")

    def test_namespace_fixture_keeps_existing_proxy_network(self):
        self.network_contract('', ['/usr/bin/python3', '-c', self.network_probe()])

    def test_bundle_keeps_proxy_only_network_and_persistent_home(self):
        root, executable = self.bundle(script=self.network_probe())
        self.network_contract(root, [str(executable)])

    def network_contract(self, root, command):
        proxy = Proxy()
        self.addCleanup(proxy.close)
        request, mark = self.driver.bundle_launch(root, command)
        first = self.driver.storage(request, mark)
        self.assertFalse(first['tcp'] or first['udp'])
        identity = first['pid'], first['netns'], first['instance']
        since = self.driver.mark()
        start = self.driver.send('start', profile=profile(proxy))
        reply = self.driver.wait(lambda event: event.get('kind') == 'reply' and event.get('id') == start, since)
        self.assertEqual(reply['error'], '<nil>')
        online = self.driver.wait(lambda event: event.get('kind') == 'storage' and event.get('id') == request
                                  and event['seq'] > first['seq'] and event['tcp'] and event['udp'], since)
        self.assertEqual((online['pid'], online['netns'], online['instance']), identity)
        prefix = ('bundle50-' + first['instance'] + '-').encode()
        self.assertTrue(any(event[0] == 'tcp' and event[3].startswith(prefix) for event in proxy.events))
        self.assertTrue(any(event[0] == 'udp' and event[3].startswith(prefix) for event in proxy.events))
        since = self.driver.mark()
        stop = self.driver.send('stop')
        reply = self.driver.wait(lambda event: event.get('kind') == 'reply' and event.get('id') == stop, since)
        self.assertEqual(reply['error'], '<nil>')
        offline = self.driver.wait(lambda event: event.get('kind') == 'storage' and event.get('id') == request
                                   and event['seq'] > online['seq'] and not event['tcp'] and not event['udp'], since)
        self.assertEqual((offline['pid'], offline['netns'], offline['instance']), identity)
        for _ in range(2):
            sequence = offline['seq']
            offline = self.driver.wait(lambda event: event.get('kind') == 'storage' and event.get('id') == request
                                       and event['seq'] > sequence, since)
            self.assertFalse(offline['tcp'] or offline['udp'])
        self.driver.cancel(request)
        self.driver.end(request, mark)
        self.assertTrue((self.driver.working/'sandbox-apps/bundle-app/home').is_dir())


if __name__ == '__main__':
    unittest.main(verbosity=2)
