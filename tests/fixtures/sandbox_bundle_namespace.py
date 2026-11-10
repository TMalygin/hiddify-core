"""Run bundle tests in a disposable root-owned filesystem without host root.

The installed newuidmap/newgidmap helpers grant only the invoking user's
configured subordinate IDs. This fixture's namespace root creates /opt data;
the real core always runs as the original nonzero UID with no capabilities.
No production code uses these helpers or this fixture setup.
"""
import ctypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


MS_RDONLY, MS_NOSUID, MS_NODEV = 1, 2, 4
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 32, 4096, 16384, 262144
LIBC = ctypes.CDLL(None, use_errno=True)


def mount(source, target, kind=None, flags=0, data=None):
    encoded = [value.encode() if isinstance(value, str) else value
               for value in (source, target, kind, data)]
    if LIBC.mount(encoded[0], encoded[1], encoded[2], ctypes.c_ulong(flags), encoded[3]):
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), target)


def inside(root, configuration):
    if os.getuid() != 0 or os.getgid() != 0:
        raise RuntimeError('fixture setup requires namespace root, never host root')
    mapping = Path('/proc/self/uid_map').read_text()
    if any(line.split()[:2] == ['0', '0'] for line in mapping.splitlines()):
        raise RuntimeError('refusing a fixture mapped to host UID 0')
    mount(None, '/', flags=MS_REC | MS_PRIVATE)
    mount('tmpfs', root, 'tmpfs', MS_NOSUID | MS_NODEV, 'size=384m,mode=0755')
    base = Path(root)
    for name in ('usr', 'proc', 'dev', 'dev/net', 'dev/shm', 'work', 'tmp', 'opt', 'etc', 'tests'):
        (base / name).mkdir(mode=0o755, exist_ok=True)
    (base / 'tmp').chmod(0o1777)
    mount('/usr', str(base / 'usr'), flags=MS_BIND | MS_REC)
    class MountAttributes(ctypes.Structure):
        _fields_ = [('set', ctypes.c_uint64), ('clear', ctypes.c_uint64),
                    ('propagation', ctypes.c_uint64), ('userns_fd', ctypes.c_uint64)]
    attributes = MountAttributes(1 | 2 | 4, 0, 0, 0)
    # mount_setattr(AT_RECURSIVE) also restricts any inherited /usr submounts.
    if LIBC.syscall(442, -100, str(base / 'usr').encode(), 0x8000,
                    ctypes.byref(attributes), ctypes.sizeof(attributes)):
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), '/usr recursive read-only bind')
    # Nested user namespaces write their own UID/GID maps through proc. Keep
    # proc recursive (locked host submounts) and writable for that purpose.
    mount('/proc', str(base / 'proc'), flags=MS_BIND | MS_REC)
    for name in ('null', 'zero', 'full', 'random', 'urandom', 'tty', 'net/tun'):
        path = base / 'dev' / name
        path.touch()
        mount('/dev/' + name, str(path), flags=MS_BIND)
    for name, target in (('bin', 'usr/bin'), ('sbin', 'usr/bin'), ('lib', 'usr/lib'),
                         ('lib64', 'usr/lib'), ('dev/fd', '/proc/self/fd')):
        (base / name).symlink_to(target)
    for entry in configuration['files']:
        target = base / entry['target']
        with os.fdopen(entry['fd'], 'rb') as source, target.open('wb') as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
        target.chmod(entry['mode'])
    os.close(configuration['script_fd'])
    # chroot alone forbids CLONE_NEWUSER. pivot_root changes this mount
    # namespace's actual root, then detaches every path back to the host root.
    (base / '.old-root').mkdir()
    os.chdir(root)
    if LIBC.syscall(155, b'.', b'.old-root'):
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    os.chdir('/')
    if LIBC.umount2(b'/.old-root', 2):
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    os.rmdir('/.old-root')
    os.environ['HIDDIFY_BUNDLE_NAMESPACE'] = '1'
    os.environ['HIDDIFY_BUNDLE_DRIVER'] = '/driver'
    os.environ['HIDDIFY_BUNDLE_TEST_UID'] = str(configuration['uid'])
    os.environ['HIDDIFY_BUNDLE_TEST_GID'] = str(configuration['gid'])
    os.environ['HOME'] = '/work/fixture-home'
    os.environ['TMPDIR'] = '/tmp'
    os.environ['PYTHONPATH'] = '/tests'
    os.environ.pop('HIDDIFY_BUNDLE_HOST_SMOKE', None)
    os.environ.pop('LD_LIBRARY_PATH', None)
    os.environ.pop('LD_PRELOAD', None)
    command = [sys.executable, '-m', 'unittest', *configuration['tests'], '-v']
    os.execv(sys.executable, command)


def run():
    if os.getuid() == 0:
        raise RuntimeError('invoke the namespace fixture as an ordinary user')
    if os.uname().machine != 'x86_64':
        raise RuntimeError('this native sandbox fixture currently requires x86_64')
    driver = os.environ.get('HIDDIFY_BUNDLE_DRIVER')
    if not driver:
        raise RuntimeError('HIDDIFY_BUNDLE_DRIVER must identify the built native fixture')
    source = Path(__file__).resolve().parents[1]
    opened = []
    try:
        files = []
        for path, target, mode in [(Path(driver), 'driver', 0o755)] + [
            (path, 'tests/' + path.name, 0o644) for path in sorted(source.glob('test_*.py'))
        ]:
            fd = os.open(path, os.O_RDONLY)
            opened.append(fd)
            files.append({'fd': fd, 'target': target, 'mode': mode})
        script_fd = os.open(__file__, os.O_RDONLY)
        opened.append(script_fd)
        configuration = {'uid': os.getuid(), 'gid': os.getgid(), 'files': files,
                         'script_fd': script_fd, 'tests': sys.argv[1:] or ['test_sandbox_bundles.ApplicationBundles']}
        with tempfile.TemporaryDirectory(prefix='hiddify-bundle-namespace-', dir='/tmp') as root:
            os.chmod(root, 0o755)
            command = ['unshare', '-U', '-m', '--map-auto', '--map-user=' + str(os.getuid()),
                       '--map-group=' + str(os.getgid()), '--setuid=0', '--setgid=0',
                       sys.executable, '/proc/self/fd/' + str(script_fd), '--inside', root,
                       json.dumps(configuration)]
            return subprocess.run(command, pass_fds=opened, check=False).returncode
    finally:
        for fd in opened:
            os.close(fd)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--inside':
        inside(sys.argv[2], json.loads(sys.argv[3]))
    else:
        sys.exit(run())
