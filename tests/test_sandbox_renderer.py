"""Generic renderer RPC regressions. Set HIDDIFY_RENDERER_DRIVER to the native fixture.

The selected programs and shell arguments stay unchanged. Browser observations
use real process namespaces and additional renderer seccomp filters, with only
synthetic proxy traffic and disposable homes.
"""
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_sandbox_chromium as chromium
from test_sandbox_storage import Driver


RENDERER_DRIVER = os.environ.get('HIDDIFY_RENDERER_DRIVER') or os.environ.get('HIDDIFY_WAYLAND_DRIVER')


@unittest.skipUnless(RENDERER_DRIVER, 'native renderer RPC fixture required')
class RendererApplication(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='hiddify-renderer-')
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        host_home = self.directory / 'host-home'
        host_home.mkdir(mode=0o700)
        with mock.patch.dict(os.environ, {'HIDDIFY_STORAGE_DRIVER': RENDERER_DRIVER}):
            self.driver = Driver(self.directory, host_home=host_home)
        self.addCleanup(self.driver.close)

    def launch(self, command, root='', identity='renderer-test', opted_in=True):
        mark = self.driver.mark()
        request = self.driver.send('launch', command=command, executable_root=root,
                                   application_id=identity, renderer_sandbox=opted_in)
        return request, mark

    result = chromium.ChromiumSandbox.result
    service = chromium.ChromiumSandbox.service
    observe = chromium.ChromiumSandbox.observe
    check_attestation = chromium.ChromiumSandbox.check_attestation

    def test_new_endpoint_accepts_a_system_command_without_browser_identity(self):
        end, exits, stdout, stderr = self.result(*self.launch(['/usr/bin/printf', '<%s>', 'literal *', 'two words', '']))
        self.assertEqual(exits, [0], (end, stderr))
        self.assertEqual(stdout, '<literal *><two words><>')
        self.assertEqual(end['error'], 'EOF')

    def test_selected_script_and_shell_have_the_same_opt_in(self):
        probe = ('import ctypes,json; c=ctypes.CDLL(None,use_errno=True);'
                 'r=c.unshare(0x10000000);print(json.dumps([r,ctypes.get_errno() if r else 0]))')
        selected = self.directory / 'arbitrary user filename'
        selected.write_text('#!/usr/bin/python3\n' + probe + '\n')
        selected.chmod(0o700)
        for command in ([str(selected)], ['/bin/sh', '-c', '--', "python3 -c '" + probe + "'"]):
            with self.subTest(command=command[0]):
                end, exits, stdout, stderr = self.result(*self.launch(command))
                self.assertEqual(exits, [0], (end, stderr))
                self.assertEqual(json.loads(stdout), [0, 0])

    def test_default_endpoint_retains_ordinary_namespace_restriction(self):
        code = 'import ctypes; c=ctypes.CDLL(None,use_errno=True); print(c.unshare(0x10000000), ctypes.get_errno())'
        end, exits, stdout, stderr = self.result(*self.launch(['/usr/bin/python3', '-c', code], opted_in=False))
        self.assertEqual(exits, [0], (end, stderr))
        self.assertEqual(stdout.strip(), f'-1 {errno.EPERM}')

    def test_missing_identity_and_invalid_bundle_are_rejected_before_exec(self):
        for command, root, identity in [
            (['/usr/bin/printf', 'EXECUTED'], '', ''),
            (['/usr/bin/printf', 'EXECUTED'], '/opt/google/chrome', 'wrong-bundle'),
        ]:
            with self.subTest(root=root, identity=identity):
                end, exits, stdout, _ = self.result(*self.launch(command, root, identity))
                self.assertEqual(end['code'], 'FailedPrecondition', end)
                self.assertEqual((exits, stdout), ([], ''))

    test_chrome_renders_javascript_in_nested_renderer = chromium.ChromiumSandbox.test_chrome_renders_javascript_in_a_separately_sandboxed_process
    test_brave_renders_javascript_in_nested_renderer = chromium.ChromiumSandbox.test_brave_renders_javascript_in_a_separately_sandboxed_process
    test_offline_browser_cannot_reach_parent_loopback = chromium.ChromiumSandbox.test_offline_browser_cannot_load_an_actual_host_loopback_http_server
    test_proxy_profile_revokes_live_browser_connection = chromium.ChromiumSandbox.test_profile_serves_http_only_through_proxy_then_revokes_the_live_flow
