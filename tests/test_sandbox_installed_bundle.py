"""Opt-in installed Chrome bundle smoke; no GUI, network or real profiles.

Run with the new bundle RPC fixture. --version exits before browser startup;
the core and both application HOME directories are disposable test storage.
This checks executable/resource exposure, not browser GUI or renderer sandbox
compatibility. Existing storage helpers and tests remain unchanged.
"""
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from test_sandbox_storage import Driver


CHROME_ROOT = pathlib.Path('/opt/google/chrome')
CHROME_COMMANDS = ('chrome', 'google-chrome')


@unittest.skipUnless(
    os.environ.get('HIDDIFY_BUNDLE_DRIVER')
    and all((CHROME_ROOT / command).is_file() for command in CHROME_COMMANDS),
    'explicit native bundle RPC driver and installed /opt/google/chrome required',
)
class InstalledChromeBundle(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hiddify-installed-bundle-')
        self.addCleanup(self.temp.cleanup)
        directory = pathlib.Path(self.temp.name)
        host_home = directory / 'host-home'
        host_home.mkdir(mode=0o700)
        # Redirect only the new fixture selection; imported frozen helpers are
        # unchanged. Even the driver's own optional HOME is disposable.
        with mock.patch.dict(os.environ, {'HIDDIFY_STORAGE_DRIVER': os.environ['HIDDIFY_BUNDLE_DRIVER']}):
            self.driver = Driver(directory, host_home=host_home)
        self.addCleanup(self.driver.close)

    def test_installed_chrome_elf_and_wrapper_report_version(self):
        for index, command in enumerate(CHROME_COMMANDS):
            with self.subTest(command=command):
                mark = self.driver.mark()
                request = self.driver.send(
                    'launch',
                    application_id=f'installed-chrome-{index}',
                    executable_root=str(CHROME_ROOT),
                    command=[str(CHROME_ROOT / command), '--version'],
                )
                end = self.driver.end(request, mark)
                events = [event for event in self.driver.events[mark:] if event.get('id') == request]
                stdout = ''.join(event.get('stdout', '') for event in events)
                stderr = ''.join(event.get('stderr', '') for event in events)
                self.assertLessEqual(len(stdout.encode()) + len(stderr.encode()), 4096,
                                     'version smoke produced unexpected output volume')
                # The raw-wire fixture reports normal gRPC EOF as error="EOF";
                # status.Code(io.EOF) itself is Unknown, not a session failure.
                self.assertEqual(end.get('error'), 'EOF', end)
                self.assertFalse(any(event.get('state') == 2 for event in events), events)
                terminal = [event for event in events if event.get('state') == 3]
                self.assertEqual(len(terminal), 1, 'missing or duplicate command completion')
                self.assertEqual(terminal[0]['exit_code'], 0, f'{command}: {stderr}')
                self.assertRegex(stdout, r'\AGoogle Chrome \d+(?:\.\d+){3}\s*\Z')


if __name__ == '__main__':
    unittest.main(verbosity=2)
