"""Regression contract for ordered sandbox output and normal completion.

The native gRPC driver is opt-in. Each probe pauses only its disposable driver
after OFFLINE, lets the isolated command finish, then resumes the driver with
stdout, stderr and the terminal status all pending. No real profile is loaded.
"""
import collections
import contextlib
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


class CompletionDriver:
    def __init__(self, directory):
        self.errors = tempfile.TemporaryFile(mode='w+t')
        self.proc = subprocess.Popen(
            [os.environ['HIDDIFY_SANDBOX_DRIVER']], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.errors, text=True,
            env={**os.environ, 'HIDDIFY_SANDBOX_TEST_DIR': directory,
                 'HIDDIFY_ADMIN_BG_DATA': directory + '/admin',
                 'HIDDIFY_TUNNEL_DATA': directory + '/tunnel'})
        self.events = queue.Queue()
        self.other_output = collections.deque(maxlen=8)
        self.sequence = 0
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            for line in self.proc.stdout:
                if line.startswith('EVENT '):
                    self.events.put(json.loads(line[6:]))
                else:
                    self.other_output.append(line.rstrip())
        except Exception as error:
            self.events.put({'kind': 'reader_error', 'error': repr(error)})
        finally:
            self.events.put({'kind': 'driver_exit'})

    def next_event(self, deadline):
        try:
            event = self.events.get(timeout=max(.01, deadline - time.monotonic()))
        except queue.Empty as error:
            raise AssertionError(f'event deadline; output={list(self.other_output)}') from error
        if event.get('kind') in ('reader_error', 'driver_exit'):
            raise AssertionError(f'unexpected driver termination: {event}')
        return event

    def ready(self):
        deadline = time.monotonic() + 15
        event = self.next_event(deadline)
        if event.get('kind') != 'ready':
            raise AssertionError(f'expected ready, got {event}')

    def launch(self, exit_code, marker):
        self.sequence += 1
        # Give the controller time to receive the initial OFFLINE event and
        # suspend the core; the zombie barrier below establishes completion.
        command = ('import sys,time; time.sleep(.25); '
                   f'sys.stdout.write({marker + "-stdout"!r}); sys.stdout.flush(); '
                   f'sys.stderr.write({marker + "-stderr"!r}); sys.stderr.flush(); '
                   f'sys.exit({exit_code})')
        request = {'action': 'launch', 'id': self.sequence,
                   'command': ['/usr/bin/python3', '-c', command]}
        self.proc.stdin.write(json.dumps(request) + '\n')
        self.proc.stdin.flush()
        return self.sequence

    def hold_until_guardian_exit(self):
        # Linux records children per OS thread. The Go launcher is allowed to
        # create the guardian from any thread, not just the thread-group leader.
        os.kill(self.proc.pid, signal.SIGSTOP)
        try:
            children = set()
            for task in pathlib.Path(f'/proc/{self.proc.pid}/task').iterdir():
                with contextlib.suppress(FileNotFoundError):
                    children.update(int(pid) for pid in (task / 'children').read_text().split())
            if len(children) != 1:
                raise AssertionError(f'expected one live sandbox guardian, found {children}')
            guardian = children.pop()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                status = pathlib.Path(f'/proc/{guardian}/status').read_text()
                if any(line.startswith('State:') and line.split()[1] == 'Z'
                       for line in status.splitlines()):
                    return
                time.sleep(.01)
            raise AssertionError('isolated command did not finish while its core was paused')
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.kill(self.proc.pid, signal.SIGCONT)

    def collect_completion(self, request):
        deadline = time.monotonic() + 15
        events = []
        paused = False
        while time.monotonic() < deadline:
            event = self.next_event(deadline)
            if event.get('id') != request:
                raise AssertionError(f'cross-session event: {event}')
            events.append(event)
            if not paused and event.get('kind') == 'sandbox' and event.get('state') == 0:
                self.hold_until_guardian_exit()
                paused = True
            if event.get('kind') == 'stream_end':
                if not paused:
                    raise AssertionError(f'session ended before scheduler pause: {events}')
                return events
        raise AssertionError(f'completion deadline: {events}')

    def close(self):
        with contextlib.suppress(ProcessLookupError):
            os.kill(self.proc.pid, signal.SIGCONT)
        with contextlib.suppress(BrokenPipeError):
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self.reader.join(timeout=2)
        self.proc.stdout.close()
        self.errors.close()


@unittest.skipUnless(os.environ.get('HIDDIFY_SANDBOX_DRIVER'),
                     'explicit Linux host integration driver required')
class SandboxCompletion(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hiddify-completion-')
        self.addCleanup(self.temp.cleanup)
        self.driver = CompletionDriver(self.temp.name)
        self.addCleanup(self.driver.close)
        self.driver.ready()

    def check_completion(self, exit_code):
        # Every repetition is required to pass. This is a controlled scheduling
        # probe, not a retry accepting an eventual successful completion.
        for iteration in range(6):
            with self.subTest(exit_code=exit_code, iteration=iteration):
                marker = f'completion-{exit_code}-{iteration}'
                request = self.driver.launch(exit_code, marker)
                events = self.driver.collect_completion(request)
                stdout = ''.join(event.get('stdout', '') for event in events)
                stderr = ''.join(event.get('stderr', '') for event in events)
                exits = [(index, event) for index, event in enumerate(events)
                         if event.get('state') == 3]
                self.assertEqual(stdout, marker + '-stdout', events)
                self.assertEqual(stderr, marker + '-stderr', events)
                self.assertEqual(len(exits), 1, events)
                index, terminal = exits[0]
                self.assertEqual(terminal.get('exit_code', 0), exit_code, events)
                self.assertTrue(all(not event.get('stdout') and not event.get('stderr')
                                    for event in events[index + 1:]), events)
                self.assertFalse(any(event.get('state') == 2 for event in events), events)
                self.assertEqual(events[-1].get('error'), 'EOF', events)
                self.assertNotEqual(events[-1].get('code'), 'Unavailable', events)

    def test_success_delivers_all_output_before_exit(self):
        self.check_completion(0)

    def test_nonzero_exit_delivers_all_output_and_original_status(self):
        self.check_completion(7)


if __name__ == '__main__':
    unittest.main(verbosity=2)
