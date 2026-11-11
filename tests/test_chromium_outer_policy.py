"""Check the application-side policy independently of a trusted browser process.

Run in sandbox_bundle_namespace.py with the Chromium RPC driver. The fixture
installs a small ELF in its *private* /opt. Invalid syscall arguments measure
seccomp errno without mounting filesystems, opening other processes or sending
traffic. The only namespace it creates is its own empty user namespace.
"""
import errno
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_sandbox_bundles import Driver, TEST_GID, TEST_UID


PROBE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <linux/nsfs.h>
#include <linux/pidfd.h>

int main(void) {
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return 1;
    char line[512];
    while (fgets(line, sizeof(line), status)) {
        if (!strncmp(line, "CapEff:", 7) || !strncmp(line, "NoNewPrivs:", 11) ||
            !strncmp(line, "Seccomp:", 8)) fputs(line, stdout);
    }
    fclose(status);
    struct statvfs mount;
    const char *paths[] = {"/proc/sys", "/proc/irq", "/proc/bus", "/proc/sysrq-trigger"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        // A missing interface is also safe on kernels built without it.
        int result = statvfs(paths[i], &mount);
        printf("%s: %d\n", paths[i], result == 0 ? !!(mount.f_flag & ST_RDONLY) : errno == ENOENT);
    }
    // Bad descriptors, empty path and invalid flags cannot create a mount or
    // retrieve a namespace. EPERM is the outer filter's decision.
    printf("mount_api: %d\n", syscall(SYS_open_tree_attr, -1, "", ~0U, NULL, 0) < 0 ? errno : 0);
    printf("join: %d\n", setns(-1, 0) < 0 ? errno : 0);
    printf("pidfd_ns: %d\n", ioctl(-1, PIDFD_GET_NET_NAMESPACE) < 0 ? errno : 0);
    printf("parent_ns: %d\n", ioctl(-1, NS_GET_PARENT) < 0 ? errno : 0);
    printf("wrong_socket_type: %d\n", socket(AF_INET, SOCK_SEQPACKET, 255) < 0 ? errno : 0);
    printf("own_userns: %d\n", unshare(CLONE_NEWUSER) < 0 ? errno : 0);
    return 0;
}
'''


@unittest.skipUnless(os.environ.get('HIDDIFY_BUNDLE_NAMESPACE') == '1',
                     'requires the private delegated namespace fixture')
class ChromiumOuterPolicy(unittest.TestCase):
    def test_browser_and_default_run_with_distinct_namespace_permissions(self):
        # Fail closed before touching /opt unless the test-only filesystem and
        # subordinate mapping are both present. Never run this against host /opt.
        self.assertEqual(os.getuid(), 0)
        self.assertGreater(TEST_UID, 0)
        self.assertFalse(any(line.split()[:2] == ['0', '0']
                             for line in Path('/proc/self/uid_map').read_text().splitlines()))
        root_mount = next(line for line in Path('/proc/self/mountinfo').read_text().splitlines()
                          if line.split()[4] == '/')
        self.assertIn(' - tmpfs ', root_mount)
        root = Path('/opt/google/chrome')
        root.mkdir(parents=True)
        executable = root / 'chrome'
        subprocess.run(['cc', '-x', 'c', '-O2', '-o', executable, '-'], input=PROBE, text=True, check=True)
        with tempfile.TemporaryDirectory(dir='/work') as directory:
            os.chown(directory, TEST_UID, TEST_GID)
            driver = Driver(Path(directory))
            self.addCleanup(driver.close)
            for chromium in (False, True):
                with self.subTest(chromium=chromium):
                    mark = driver.mark()
                    request = driver.send('launch', application_id='policy-' + str(chromium).lower(),
                                          executable_root=str(root), command=[str(executable)],
                                          chromium_sandbox=chromium)
                    end = driver.end(request, mark)
                    events = [event for event in driver.events[mark:] if event.get('id') == request]
                    self.assertEqual(end.get('error'), 'EOF', events)
                    self.assertEqual([e.get('exit_code') for e in events if e.get('state') == 3], [0], events)
                    stdout = ''.join(e.get('stdout', '') for e in events)
                    values = dict(line.split(':', 1) for line in stdout.splitlines())
                    self.assertEqual(int(values['CapEff'], 16), 0)
                    self.assertEqual(int(values['NoNewPrivs']), 1)
                    self.assertEqual(int(values['Seccomp']), 2)
                    self.assertEqual(int(values['join']), errno.EPERM)
                    with self.subTest(operation='own_userns'):
                        self.assertEqual(int(values['own_userns']), 0 if chromium else errno.EPERM)
                    if chromium:
                        for path in ('/proc/sys', '/proc/irq', '/proc/bus', '/proc/sysrq-trigger'):
                            with self.subTest(path=path):
                                self.assertEqual(int(values[path]), 1)
                        for key in ('mount_api', 'pidfd_ns', 'parent_ns', 'wrong_socket_type'):
                            with self.subTest(operation=key):
                                self.assertEqual(int(values[key]), errno.EPERM)
