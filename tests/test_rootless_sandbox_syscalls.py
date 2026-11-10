"""Additional x86_64 application-side syscall contract, frozen before filtering."""
import errno
import os
import platform
import unittest

from test_rootless_sandbox import Run


@unittest.skipUnless(os.environ.get("HIDDIFY_SANDBOX_BINARY") and platform.machine() == "x86_64",
                     "explicit Linux x86_64 sandbox binary required")
class SandboxSyscalls(unittest.TestCase):
    def probe(self, expression):
        code = """
import ctypes, json, os
libc = ctypes.CDLL(None, use_errno=True)
def call(number, *args):
    ctypes.set_errno(0)
    result = libc.syscall(number, *args)
    error = ctypes.get_errno()
    if result >= 0: os.close(result)
    return error
""" + "\nprint('RESULT ' + json.dumps(" + expression + "), flush=True)\n"
        run = Run(os.environ["HIDDIFY_SANDBOX_BINARY"], code)
        self.addCleanup(run.close)
        result = run.event()
        self.assertEqual(run.wait(), 0)
        return result

    def test_non_ip_socket_channels_are_denied(self):
        # socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC), AF_PACKET and AF_VSOCK.
        # Only create/close descriptors: no packets or host actions are sent.
        result = self.probe("[call(41, 16, 3, 16), call(41, 17, 3, 0), call(41, 40, 1, 0)]")
        self.assertEqual(result, [errno.EPERM] * 3)

    def test_uring_keyring_and_cross_process_channels_are_denied(self):
        # Invalid/empty arguments are deliberate: without a filter these return
        # EFAULT/EINVAL/ESRCH, and cannot create a key, ring or process operation.
        result = self.probe("[call(425, 1, 0), call(248, 0, 0, 0, 0, 0), call(310, -1, 0, 0, 0, 0, 0)]")
        self.assertEqual(result, [errno.EPERM] * 3)

    def test_clone3_fails_with_enosys_for_libc_fallback(self):
        self.assertEqual(self.probe("call(435, 0, 0)"), errno.ENOSYS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
