"""Persistent application storage, namespace lifetime and crash-fence contract.

Runs only with an explicitly supplied native storage RPC fixture. All files,
identifiers and process targets are disposable test resources. No network is
needed. Existing sandbox tests and their fixtures are not modified.
"""
import contextlib
import json
import os
import pathlib
import queue
import select
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from test_sandbox_profile_leases import Proxy, profile
from test_sandbox_selection_recovery import IDENTIFIED_PROBE


CHILD_IMPORTS = "import json, os, pathlib, stat, time\nhome = pathlib.Path.home()\n"

INSPECT = CHILD_IMPORTS + r'''
result = {'home': str(home), 'uid': os.getuid(), 'env': dict(os.environ), 'fds': {}}
for fd in os.listdir('/proc/self/fd'):
    try: result['fds'][fd] = os.readlink('/proc/self/fd/' + fd)
    except FileNotFoundError: pass
result['dirs'] = {}
for name in ('HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME', 'XDG_RUNTIME_DIR'):
    path = os.environ.get(name)
    if path and pathlib.Path(path).is_dir():
        info = pathlib.Path(path).stat()
        result['dirs'][name] = {'path': path, 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid}
    else:
        result['dirs'][name] = None
result['metadata_visible'] = any((home / name).exists() or (home.parent / name).exists()
                                 for name in ('.lock', '.lease.json'))
result['pid1_fds'] = {}
result['pid1_dangers'] = []
try: pid1_entries = os.listdir('/proc/1/fd')
except PermissionError: pid1_entries = []
for name in pid1_entries:
    entry = '/proc/1/fd/' + name
    try: target = os.readlink(entry)
    except (FileNotFoundError, PermissionError): continue
    result['pid1_fds'][name] = target
    try: descriptor = os.open(entry, os.O_RDONLY | os.O_NONBLOCK)
    except OSError: continue
    try:
        if any(marker in target for marker in ('.lock', '.lease.json', 'sandbox-apps', 'socket:', 'net:[', 'user:[', 'mnt:[', 'pid:[')):
            result['pid1_dangers'].append(target)
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            result['pid1_dangers'].append(target + ' (openable directory)')
            for candidate in ('.lock', '.lease.json', '../.lock', '../.lease.json'):
                try:
                    os.stat(candidate, dir_fd=descriptor)
                    result['pid1_dangers'].append(target + '/' + candidate)
                except OSError: pass
    finally: os.close(descriptor)
print('STORAGE ' + json.dumps(result), flush=True)
'''

HOLD = CHILD_IMPORTS + "print('STORAGE ' + json.dumps({'ready': True, 'pid': os.getpid()}), flush=True)\ntime.sleep(90)\n"
EXECUTED = CHILD_IMPORTS + "print('EXECUTED', flush=True)\n"


class Driver:
    def __init__(self, directory, relative=False, host_home=None):
        self.events = []
        self.pending = queue.Queue()
        self.output = []
        self.errors = []
        self.sequence = 0
        self.buffers = {}
        self.proc = subprocess.Popen([os.environ['HIDDIFY_STORAGE_DRIVER']], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     env={**os.environ, 'HIDDIFY_SANDBOX_TEST_DIR': str(directory),
                                          'HIDDIFY_ADMIN_BG_DATA': str(directory) + '/admin',
                                          'HIDDIFY_TUNNEL_DATA': str(directory) + '/tunnel',
                                          'HIDDIFY_STORAGE_RELATIVE_WORKDIR': '1' if relative else '0',
                                          'HIDDIFY_CORE_SECRET': 'fixture-host-secret',
                                          **({'HOME': str(host_home)} if host_home else {})})
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.error_reader = threading.Thread(target=lambda: self.errors.append(self.proc.stderr.read()), daemon=True)
        self.reader.start()
        self.error_reader.start()
        try:
            self.working = pathlib.Path(self.wait(lambda event: event.get('kind') == 'ready')['working_dir'])
        except BaseException:
            self.close()
            raise

    def read(self):
        for line in self.proc.stdout:
            if not line.startswith('EVENT '):
                self.output.append(line)
                continue
            event = json.loads(line[6:])
            self.pending.put(event)
            if event.get('stdout'):
                session = event['id']
                data = self.buffers.get(session, '') + event['stdout']
                while '\n' in data:
                    line, data = data.split('\n', 1)
                    if line.startswith('STORAGE '):
                        self.pending.put({'kind': 'storage', 'id': session, **json.loads(line[8:])})
                self.buffers[session] = data
        self.pending.put({'kind': 'driver_exit', 'code': self.proc.poll()})

    def mark(self):
        while True:
            try:
                self.events.append(self.pending.get_nowait())
            except queue.Empty:
                return len(self.events)

    def wait(self, predicate, since=0, timeout=15):
        index = since
        deadline = time.monotonic() + timeout
        while True:
            while index < len(self.events):
                event = self.events[index]
                index += 1
                if predicate(event):
                    return event
                if event.get('kind') == 'driver_exit':
                    raise AssertionError(f'driver exited: {event}; errors={self.errors}; events={self.events[-8:]}')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f'event deadline; events={self.events[-8:]}; stderr={self.errors}')
            try:
                self.events.append(self.pending.get(timeout=remaining))
            except queue.Empty:
                raise AssertionError(f'event deadline; events={self.events[-8:]}') from None

    def send(self, action, **kwargs):
        self.sequence += 1
        self.proc.stdin.write(json.dumps(dict(action=action, id=self.sequence, **kwargs)) + '\n')
        self.proc.stdin.flush()
        return self.sequence

    def launch(self, application_id, script=INSPECT):
        mark = self.mark()
        request = self.send('launch', application_id=application_id, command=['/usr/bin/python3', '-c', script])
        return request, mark

    def storage(self, request, mark):
        event = self.wait(lambda event: event.get('id') == request and event.get('kind') in ('storage', 'stream_end'), mark)
        if event['kind'] != 'storage':
            raise AssertionError(f'launch did not emit storage result: {event}; events={self.events[-8:]}')
        return event

    def end(self, request, mark):
        return self.wait(lambda event: event.get('id') == request and event.get('kind') == 'stream_end', mark)

    def cancel(self, session):
        request = self.send('cancel', session=session)
        return self.wait(lambda event: event.get('kind') == 'reply' and event.get('id') == request)

    def close(self):
        if not self.proc.stdin.closed:
            with contextlib.suppress(BrokenPipeError):
                self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)
        self.reader.join(1)
        self.error_reader.join(1)
        self.proc.stdout.close()
        self.proc.stderr.close()


def process_start(pid):
    # comm can contain spaces and parentheses; fields after the last ')' start
    # at field 3, making starttime (field 22) index 19 in this suffix.
    return pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]


def pidfd_exited(fd, timeout=0):
    poll = select.poll()
    poll.register(fd, select.POLLIN)
    return bool(poll.poll(timeout))


def descendants(pid):
    pending, seen = [pid], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        for file in pathlib.Path(f'/proc/{current}/task').glob('*/children'):
            with contextlib.suppress(FileNotFoundError):
                pending.extend(int(value) for value in file.read_text().split())
    return seen - {pid}


@unittest.skipUnless(os.environ.get('HIDDIFY_STORAGE_DRIVER'), 'explicit native Linux storage RPC driver required')
class ApplicationStorage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hiddify-storage-')
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.host_home = self.directory / 'host-home'
        self.host_home.mkdir(mode=0o700)
        (self.host_home / 'HOST_SECRET_SENTINEL').write_text('not for sandbox')
        self.driver = Driver(self.directory, host_home=self.host_home)
        self.addCleanup(self.driver.close)
        self.root = self.driver.working / 'sandbox-apps'
        self.boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()

    def one_shot(self, application_id, script=INSPECT, driver=None):
        driver = driver or self.driver
        request, mark = driver.launch(application_id, script)
        data = driver.storage(request, mark)
        driver.end(request, mark)
        terminal = [event for event in driver.events[mark:] if event.get('id') == request and event.get('state') == 3]
        self.assertEqual(len(terminal), 1, 'missing terminal completion')
        self.assertEqual(terminal[0]['exit_code'], 0)
        return data

    def rejected(self, application_id, driver=None):
        driver = driver or self.driver
        request, mark = driver.launch(application_id, EXECUTED)
        terminal = driver.end(request, mark)
        output = ''.join(event.get('stdout', '') for event in driver.events[mark:] if event.get('id') == request)
        self.assertNotIn('EXECUTED', output, 'rejected application storage still executed the command')
        self.assertIn(terminal['code'], ('InvalidArgument', 'FailedPrecondition', 'AlreadyExists', 'ResourceExhausted'), terminal)

    def prepare(self, application_id='alpha'):
        directory = self.root / application_id
        for path in (self.root, directory, directory / 'home'):
            path.mkdir(mode=0o700, exist_ok=True)
        return directory

    def lease(self, application_id='alpha'):
        path = self.root / application_id / '.lease.json'
        self.assertTrue(path.is_file(), 'persistent lifetime lease was not created')
        return json.loads(path.read_text())

    def write_lease(self, value, application_id='alpha'):
        directory = self.prepare(application_id)
        path = directory / '.lease.json'
        if isinstance(value, dict):
            value = {'version': 1, **value}
        path.write_text(json.dumps(value) if not isinstance(value, str) else value)
        path.chmod(0o600)

    def sleeper(self):
        proc = subprocess.Popen(['/usr/bin/sleep', '60'])
        def close():
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
        self.addCleanup(close)
        return proc

    def test_empty_application_id_preserves_legacy_console_launch(self):
        data = self.one_shot('')
        self.assertEqual(data['home'], '/home/sandbox')
        self.assertNotEqual(data['uid'], 0)
        self.assertNotIn('HIDDIFY_CORE_SECRET', data['env'])
        self.assertLessEqual(set(data['fds']), {'0', '1', '2'})
        self.assertFalse(self.root.exists(), 'legacy session unexpectedly created persistent storage')

    def test_home_survives_relaunch_and_core_restart(self):
        write = CHILD_IMPORTS + "(home/'sentinel').write_text('alpha-data')\nprint('STORAGE ' + json.dumps({'written': True}), flush=True)\n"
        read = CHILD_IMPORTS + "print('STORAGE ' + json.dumps({'value': (home/'sentinel').read_text() if (home/'sentinel').exists() else None}), flush=True)\n"
        self.one_shot('alpha', write)
        self.assertEqual(self.one_shot('alpha', read)['value'], 'alpha-data')
        self.driver.close()
        restarted = Driver(self.directory, host_home=self.host_home)
        self.addCleanup(restarted.close)
        self.assertEqual(self.one_shot('alpha', read, restarted)['value'], 'alpha-data')

    def test_application_ids_have_separate_homes(self):
        write = CHILD_IMPORTS + "(home/'sentinel').write_text('alpha-data')\nprint('STORAGE ' + json.dumps({'written': True}), flush=True)\n"
        read = CHILD_IMPORTS + "print('STORAGE ' + json.dumps({'value': (home/'sentinel').read_text() if (home/'sentinel').exists() else None}), flush=True)\n"
        self.one_shot('alpha', write)
        self.assertIsNone(self.one_shot('beta', read)['value'])
        self.assertEqual(self.one_shot('alpha', read)['value'], 'alpha-data')

    def test_private_xdg_directories_no_host_home_or_control_descriptors(self):
        # The app owns creation of its XDG directories. The launcher provides
        # private paths, without traversing these app-controlled paths on host.
        prepare_xdg = "for name in ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'XDG_STATE_HOME'):\n    if name in os.environ: pathlib.Path(os.environ[name]).mkdir(parents=True, exist_ok=True, mode=0o700)\n"
        script = INSPECT.replace(CHILD_IMPORTS, CHILD_IMPORTS + prepare_xdg).replace("print('STORAGE '", "result['host_visible'] = pathlib.Path(" + repr(str(self.host_home / 'HOST_SECRET_SENTINEL')) + ").exists()\nprint('STORAGE '")
        data = self.one_shot('alpha', script)
        paths = {'HOME': '/home/sandbox', 'XDG_CONFIG_HOME': '/home/sandbox/.config',
                 'XDG_DATA_HOME': '/home/sandbox/.local/share', 'XDG_CACHE_HOME': '/home/sandbox/.cache',
                 'XDG_STATE_HOME': '/home/sandbox/.local/state', 'XDG_RUNTIME_DIR': '/run/sandbox'}
        for key, path in paths.items():
            self.assertEqual(data['env'].get(key), path, key)
            self.assertEqual(data['dirs'][key], {'path': path, 'mode': 0o700, 'uid': os.getuid()}, key)
        self.assertFalse(data['host_visible'])
        self.assertFalse(data['metadata_visible'])
        self.assertEqual(data['pid1_dangers'], [], 'namespace PID1 exposed host metadata/control descriptors')
        self.assertNotIn('HIDDIFY_CORE_SECRET', data['env'])
        self.assertLessEqual(set(data['fds']), {'0', '1', '2'})
        for path in (self.root, self.root/'alpha', self.root/'alpha/home'):
            info = path.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            self.assertEqual(info.st_uid, os.getuid())
        self.assertTrue((self.root/'alpha/.lock').is_file())
        self.assertTrue((self.root/'alpha/.lease.json').is_file())
        for path in (self.root/'alpha/.lock', self.root/'alpha/.lease.json'):
            info = path.stat()
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink), (0o600, os.getuid(), 1))

    def test_runtime_directory_is_fresh_between_sessions(self):
        script = CHILD_IMPORTS + r'''
runtime = os.environ.get('XDG_RUNTIME_DIR')
path = pathlib.Path(runtime) / 'temporary-marker' if runtime else None
existed = path.exists() if path else None
if path: path.write_text('ephemeral')
print('STORAGE ' + json.dumps({'existed': existed}), flush=True)
'''
        self.assertIs(self.one_shot('alpha', script)['existed'], False)
        self.assertIs(self.one_shot('alpha', script)['existed'], False)

    def test_invalid_application_ids_never_execute(self):
        for name in ('.', '..', '../alpha', '/alpha', 'alpha/beta', 'Alpha', '-alpha', '_alpha',
                     'alpha beta', 'alpha\x00beta', 'аlpha', 'a'*65):
            with self.subTest(application_id=repr(name)):
                self.rejected(name)

    def test_valid_application_id_boundaries(self):
        for name in ('a', '0', 'alpha-1_test', 'a'*64):
            with self.subTest(application_id=name):
                self.one_shot(name)
                self.assertTrue((self.root/name/'home').is_dir())

    def test_symlink_storage_components_never_execute(self):
        foreign = self.directory / 'foreign'
        foreign.mkdir(mode=0o700)
        sentinel = foreign / 'sentinel'
        sentinel.write_text('unchanged')
        for component in ('root', 'id', 'home', '.lock', '.lease.json'):
            with self.subTest(component=component):
                case = self.directory / ('case-' + component.replace('.', ''))
                case.mkdir(mode=0o700)
                driver = Driver(case)
                self.addCleanup(driver.close)
                root = driver.working / 'sandbox-apps'
                target = root
                if component != 'root':
                    root.mkdir(mode=0o700)
                    target = root/'alpha'
                if component not in ('root', 'id'):
                    target.mkdir(mode=0o700)
                    target = target/component
                target.symlink_to(sentinel if component in ('.lock', '.lease.json') else foreign)
                self.rejected('alpha', driver)
                self.assertEqual(sentinel.read_text(), 'unchanged')

    def test_unsafe_modes_and_hardlinked_metadata_never_execute(self):
        for component in ('root', 'id', 'home', '.lock', '.lease.json', 'hardlink-lock', 'hardlink-lease',
                          'fifo-lock', 'fifo-lease', 'socket-lock', 'socket-lease'):
            with self.subTest(component=component):
                case = self.directory / ('unsafe-' + component.replace('.', ''))
                case.mkdir(mode=0o700)
                driver = Driver(case)
                self.addCleanup(driver.close)
                root = driver.working / 'sandbox-apps'
                application = root/'alpha'
                home = application/'home'
                for path in (root, application, home):
                    path.mkdir(mode=0o700)
                if component in ('root', 'id', 'home'):
                    target = {'root': root, 'id': application, 'home': home}[component]
                    target.chmod(0o755)
                else:
                    name = '.lock' if component.endswith('lock') else '.lease.json'
                    target = application/name
                    value = json.dumps({'version': 1, 'phase': 'preparing', 'boot_id': str(uuid.uuid4()), 'pid': 0})
                    if component.startswith('hardlink-'):
                        foreign = case/'foreign-metadata'
                        foreign.write_text(value)
                        foreign.chmod(0o600)
                        os.link(foreign, target)
                    elif component.startswith('fifo-'):
                        os.mkfifo(target, mode=0o600)
                    elif component.startswith('socket-'):
                        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        self.addCleanup(control.close)
                        control.bind(str(target))
                        target.chmod(0o600)
                    else:
                        target.write_text(value)
                        target.chmod(0o644)
                original_mode = stat.S_IMODE(target.stat().st_mode)
                before = time.monotonic()
                self.rejected('alpha', driver)
                self.assertLess(time.monotonic()-before, 5, 'rejecting non-regular metadata blocked the launch')
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), original_mode,
                                 'unsafe storage was silently chmodded')

    def test_replacing_storage_path_cannot_redirect_live_home(self):
        observe = CHILD_IMPORTS + r'''
for seq in range(1000):
    value = (home/'sentinel').read_text() if (home/'sentinel').exists() else None
    (home/'writer').write_text('inside-write')
    print('STORAGE ' + json.dumps({'seq': seq, 'value': value}), flush=True)
    time.sleep(.08)
'''
        for component in ('home', 'id'):
            with self.subTest(component=component):
                name = 'replace-' + component
                directory = self.prepare(name)
                (directory/'home/sentinel').write_text('inside')
                foreign = self.directory/('outside-' + component)
                foreign.mkdir(mode=0o700)
                (foreign/'sentinel').write_text('outside')
                (foreign/'writer').write_text('unchanged')
                first, mark = self.driver.launch(name, observe)
                initial = self.driver.storage(first, mark)
                self.assertEqual(initial['value'], 'inside', 'initial app home did not mount its own persistent data')
                lease = self.lease(name)
                fd = os.pidfd_open(lease['pid'])
                self.addCleanup(os.close, fd)
                path = directory/'home' if component == 'home' else directory
                pinned = path.with_name(path.name + '-pinned')
                path.rename(pinned)
                path.symlink_to(foreign)
                cursor = self.driver.mark()
                sequence = initial['seq']
                for _ in range(4):
                    event = self.driver.wait(lambda event: event.get('id') == first and event.get('kind') == 'storage'
                                             and event['seq'] > sequence, cursor)
                    sequence = event['seq']
                    self.assertEqual(event['value'], 'inside', 'live mount followed replaced host pathname')
                self.assertEqual((foreign/'writer').read_text(), 'unchanged', 'live app wrote through replacement symlink')
                self.driver.cancel(first)
                self.driver.end(first, mark)
                self.assertTrue(pidfd_exited(fd, 5000))
                self.rejected(name)

    def test_concurrent_same_id_is_refused_other_id_can_run(self):
        first, mark = self.driver.launch('alpha', HOLD)
        self.assertTrue(self.driver.storage(first, mark)['ready'])
        self.rejected('alpha')
        self.one_shot('beta')
        self.driver.cancel(first)
        self.driver.end(first, mark)

    def test_clean_cancel_releases_id_only_after_namespace_exit(self):
        first, mark = self.driver.launch('alpha', HOLD)
        self.driver.storage(first, mark)
        lease = self.lease()
        self.assertEqual(lease['version'], 1)
        self.assertEqual(lease['phase'], 'running')
        self.assertEqual(lease['boot_id'], self.boot)
        self.assertEqual(lease['start_time'], process_start(lease['pid']))
        status = pathlib.Path(f"/proc/{lease['pid']}/status").read_text()
        namespace_pids = next(line.split()[1:] for line in status.splitlines() if line.startswith('NSpid:'))
        self.assertEqual(namespace_pids[-1], '1', 'lease must fence namespace PID1, not a short-lived wrapper')
        fd = os.pidfd_open(lease['pid'])
        self.addCleanup(os.close, fd)
        self.driver.cancel(first)
        self.driver.end(first, mark)
        self.assertTrue(pidfd_exited(fd, 5000), 'cancelled namespace remains alive')
        self.one_shot('alpha')

    def test_preparing_and_malformed_persistent_leases_fail_closed(self):
        preparing = {'version': 1, 'phase': 'preparing', 'boot_id': self.boot, 'pid': 0}
        for index, lease in enumerate((preparing, '{broken json', '', {'phase': 'unknown', 'boot_id': self.boot},
                                       {'version': 2, 'phase': 'preparing', 'boot_id': self.boot},
                                       json.dumps({'phase': 'preparing', 'boot_id': self.boot}),
                                       json.dumps(preparing) + '{}',
                                       json.dumps(preparing)[:-1] + ',"version":1}',
                                       {**preparing, 'unknown': True}, ' ' * 4097,
                                       {'phase': 'running', 'boot_id': 'invalid-boot', 'pid': 100, 'start_time': '100'},
                                       {'phase': 'running', 'boot_id': self.boot, 'pid': 1, 'start_time': '100'},
                                       {'phase': 'running', 'boot_id': self.boot, 'pid': 100, 'start_time': 'notdecimal'})):
            name = 'blocked-' + str(index)
            with self.subTest(lease=lease):
                self.write_lease(lease, name)
                self.rejected(name)

    def test_stored_application_keeps_proxy_only_network_lifecycle(self):
        proxy = Proxy()
        self.addCleanup(proxy.close)
        code = IDENTIFIED_PROBE.replace("print('PROBE '", "print('STORAGE '").replace(
            "'profile-flow-%d' % seq", "'storage49-' + instance + '-' + str(seq)")
        request, mark = self.driver.launch('alpha', code)
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
        prefix = ('storage49-' + first['instance'] + '-').encode()
        self.assertTrue(any(event[0] == 'tcp' and event[3].startswith(prefix) for event in proxy.events))
        self.assertTrue(any(event[0] == 'udp' and event[3].startswith(prefix) for event in proxy.events))
        since = self.driver.mark()
        stop = self.driver.send('stop')
        reply = self.driver.wait(lambda event: event.get('kind') == 'reply' and event.get('id') == stop, since)
        self.assertEqual(reply['error'], '<nil>')
        offline = self.driver.wait(lambda event: event.get('kind') == 'storage' and event.get('id') == request
                                   and event['seq'] > online['seq'] and not event['tcp'] and not event['udp'], since)
        self.assertEqual((offline['pid'], offline['netns'], offline['instance']), identity)
        # Require later observations to remain offline, without counting the
        # ordinary core's independent URL health checks as application traffic.
        for _ in range(2):
            sequence = offline['seq']
            offline = self.driver.wait(lambda event: event.get('kind') == 'storage' and event.get('id') == request
                                       and event['seq'] > sequence, since)
            self.assertFalse(offline['tcp'] or offline['udp'])
            self.assertEqual((offline['pid'], offline['netns'], offline['instance']), identity)
        self.driver.cancel(request)
        self.driver.end(request, mark)

    def test_live_matching_lease_refuses_reuse_without_signalling_process(self):
        other = self.sleeper()
        self.write_lease({'phase': 'running', 'boot_id': self.boot, 'pid': other.pid,
                          'start_time': process_start(other.pid)})
        self.rejected('alpha')
        self.assertIsNone(other.poll(), 'storage recovery signalled a recorded host process')
        other.terminate()
        other.wait(timeout=5)
        self.one_shot('alpha')

    def test_stale_identity_or_old_boot_allows_reuse_without_signalling_pid(self):
        other = self.sleeper()
        for name, boot, start in (('mismatch', self.boot, str(int(process_start(other.pid))+1)),
                                  ('oldboot', str(uuid.uuid4()), process_start(other.pid))):
            with self.subTest(case=name):
                self.write_lease({'phase': 'running', 'boot_id': boot, 'pid': other.pid, 'start_time': start}, name)
                write = CHILD_IMPORTS + "(home/'stored').write_text('owned-data')\nprint('STORAGE ' + json.dumps({'written': True}), flush=True)\n"
                self.one_shot(name, write)
                self.assertIsNone(other.poll(), 'stale lease recovery signalled an unrelated process')
                self.assertTrue((self.root/name/'home/stored').is_file(), 'accepted launch did not use persistent home')
                self.assertEqual((self.root/name/'home/stored').read_text(), 'owned-data')

    def test_guardian_death_cannot_overlap_old_descendants_and_replacement(self):
        hold = CHILD_IMPORTS + r'''
import fcntl
file = (home/'exclusive').open('a+')
fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
pid = os.fork()
if pid == 0:
    os.setsid()
    time.sleep(90)
    os._exit(0)
print('STORAGE ' + json.dumps({'ready': True, 'descendant': pid}), flush=True)
time.sleep(90)
'''
        first, mark = self.driver.launch('alpha', hold)
        self.driver.storage(first, mark)
        lease = self.lease()
        fd = os.pidfd_open(lease['pid'])
        self.addCleanup(os.close, fd)
        guardians = []
        for pid in descendants(self.driver.proc.pid):
            with contextlib.suppress(FileNotFoundError):
                argv = pathlib.Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
                if b'__session' in argv or b'__stored_session' in argv:
                    guardians.append(pid)
        self.assertEqual(len(guardians), 1)
        os.kill(guardians[0], signal.SIGKILL)
        claim = CHILD_IMPORTS + r'''
import fcntl
with (home/'exclusive').open('a+') as file:
    try:
        fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        overlap = False
    except BlockingIOError:
        overlap = True
    print('STORAGE ' + json.dumps({'overlap': overlap}), flush=True)
'''
        request, since = self.driver.launch('alpha', claim)
        outcome = self.driver.wait(lambda event: event.get('id') == request and event.get('kind') in ('storage', 'stream_end'), since)
        if outcome['kind'] == 'storage':
            self.assertFalse(outcome['overlap'], 'replacement overlaps a descendant with access to the same home')
            self.assertTrue(pidfd_exited(fd), 'replacement started before old PID namespace exited')
            self.driver.end(request, since)
        else:
            self.assertIn(outcome['code'], ('FailedPrecondition', 'AlreadyExists', 'ResourceExhausted'))
            self.assertTrue(pidfd_exited(fd, 5000), 'guardian death did not retire its child namespace')
            self.assertFalse(self.one_shot('alpha', claim)['overlap'])

    def test_relative_working_directory_is_captured_before_core_chdir(self):
        directory = self.directory/'relative-case'
        directory.mkdir(mode=0o700)
        driver = Driver(directory, relative=True)
        self.addCleanup(driver.close)
        self.one_shot('alpha', driver=driver)
        expected = directory/'relative-working/sandbox-apps/alpha/home'
        self.assertTrue(expected.is_dir(), 'storage root did not resolve against the original setup working directory')
        self.assertFalse((directory/'relative-working/relative-working/sandbox-apps').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
