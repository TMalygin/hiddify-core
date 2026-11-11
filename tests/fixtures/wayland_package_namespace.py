"""Run native Wayland tests with the signed Manjaro Weston package, without installation.

Set HIDDIFY_WESTON_PACKAGE and HIDDIFY_WESTON_SIGNATURE to downloaded files,
HIDDIFY_WAYLAND_DRIVER to the built HiddifyCli beside lib/hiddify-core.so, and
PYTHONPATH to any extra test site-packages. Pass test_sandbox_wayland to run
both configurations, or pass unittest names and optional --without-weston.
Requires x86_64 Manjaro, Chrome and Brave, subordinate IDs and rootless userns.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile


PACKAGE_SHA256 = '92fe0bfe2cf1ae02105b0e6573f6695c6bbd4637c9a6b20299a6fea8c3d23b4d'
BUNDLES = ('/opt/google/chrome', '/usr/lib/brave-browser')


def trusted_browser_tree(name):
    # These files become root-owned in the test namespace. Check their original
    # host owners before mapping UID 0 to an unprivileged subordinate ID.
    path = Path(name)
    for entry in [*path.parents, path, *path.rglob('*')]:
        info = entry.lstat()
        if (info.st_uid != 0 or info.st_mode & 0o022 or
                not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))):
            raise ValueError(f'unsafe installed browser entry: {entry}')


def inside(config):
    sys.path.insert(0, '/proc/self/fd/' + str(config['fixture_dir_fd']))
    from sandbox_bundle_namespace import LIBC, mount, MS_BIND, MS_REC, MS_NODEV, MS_NOSUID, MS_PRIVATE

    if os.getuid() != 0 or any(line.split()[:2] == ['0', '0']
                               for line in Path('/proc/self/uid_map').read_text().splitlines()):
        raise RuntimeError('setup must run as subordinate namespace root')
    mount(None, '/', flags=MS_REC | MS_PRIVATE)
    root = Path(config['root'])
    mount('tmpfs', str(root), 'tmpfs', MS_NODEV | MS_NOSUID, 'size=2g,mode=0755')
    for directory in ('usr', 'usr/.system', 'opt/google', 'proc', 'dev/net', 'dev/shm',
                      'tmp', 'home/test', 'run', 'etc/fonts', 'cli', 'repo/tests',
                      'repo/v2/hcore', 'repo/v2/hcommon'):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root/'tmp').chmod(0o1777)
    (root/'dev/shm').chmod(0o1777)
    os.chown(root/'home/test', config['uid'], config['gid'])

    def readonly_bind(source, target):
        mount(str(source), str(target), flags=MS_BIND | MS_REC)
        # Recursively set only the new restrictions, retaining original flags.
        attrs = (ctypes.c_uint64 * 4)(1 | 2 | 4, 0, 0, 0)
        if LIBC.syscall(442, -100, os.fsencode(target), 0x8000, attrs, ctypes.sizeof(attrs)):
            raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()), str(target))

    readonly_bind('/usr', root/'usr/.system')
    for source, destination in config['binds']:
        target = root / destination
        target.mkdir(parents=True, exist_ok=True)
        # A bind source must be on this mount namespace's copy of the tree.
        # Resolve the invoking user's input while holding their filesystem UID.
        LIBC.setfsuid(config['uid'])
        try:
            fd = os.open(source, os.O_PATH | os.O_DIRECTORY)
        finally:
            LIBC.setfsuid(0)
        try:
            readonly_bind('/proc/self/fd/' + str(fd), target)
        finally:
            os.close(fd)
    readonly_bind('/etc/fonts', root/'etc/fonts')
    mount('/proc', str(root/'proc'), flags=MS_BIND | MS_REC)
    for device in ('null', 'zero', 'full', 'random', 'urandom', 'tty', 'net/tun'):
        target = root/'dev'/device
        target.touch()
        mount('/dev/' + device, str(target), flags=MS_BIND)
    for name, dest in [('bin', 'usr/bin'), ('sbin', 'usr/bin'), ('lib', 'usr/lib'),
                       ('lib64', 'usr/lib'), ('dev/fd', '/proc/self/fd')]:
        (root/name).symlink_to(dest)

    # Extract first. Preserve packaged Weston helpers/modules at their exact
    # system paths. Only the test root is writable; no host packages are changed.
    subprocess.run(['bsdtar', '-xf', '/proc/self/fd/' + str(config['package_fd']),
                    '-C', str(root), 'usr'], check=True, pass_fds=[config['package_fd']])
    for bundle in BUNDLES:
        shutil.copytree(bundle, root / bundle.lstrip('/'), symlinks=True)
    # Fill gaps from the same host userspace. Keep /usr/bin and /usr/lib as
    # real directories owned by namespace root for the production trust checks.
    for relative in ('bin', 'lib', 'share', ''):
        original = Path('/usr') / relative
        dest = root/'usr'/relative
        for path in original.iterdir():
            target = dest/path.name
            if not os.path.lexists(target):
                target.symlink_to('/usr/.system/' + str(path.relative_to('/usr')))
    if config['without_weston']:
        (root/'usr/bin/weston').rename(root/'usr/bin/wayland-fixture-parent')

    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    (root/'.old-root').mkdir()
    os.chdir(root)
    if LIBC.syscall(155, b'.', b'.old-root'):
        raise OSError(ctypes.get_errno(), 'pivot_root')
    os.chdir('/')
    if LIBC.umount2(b'/.old-root', 2):
        raise OSError(ctypes.get_errno(), 'detach old root')
    os.rmdir('/.old-root')
    for fd in set(config['opened']):
        os.close(fd)
    os.setgroups([])
    os.setgid(config['gid'])
    os.setuid(config['uid'])
    os.chdir('/repo/tests')
    # Supply neither the real user's display nor their IPC addresses.
    environment = {'PATH': '/usr/bin', 'HOME': '/home/test', 'TMPDIR': '/tmp', 'LANG': 'C.UTF-8',
                   'HIDDIFY_WAYLAND_DRIVER': '/cli/' + config['driver_name'],
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': ':'.join(['/repo/tests', *config['python']])}
    if config['without_weston']:
        environment['HIDDIFY_WAYLAND_TEST_PARENT_BIN'] = '/usr/bin/wayland-fixture-parent'
    os.execve('/usr/bin/python3', ['python3', '-m', 'unittest', '-v', *config['tests']], environment)


def run(tests, without_weston=False):
    uid, gid = os.getuid(), os.getgid()
    if uid == 0 or os.uname().machine != 'x86_64' or not tests:
        raise RuntimeError('run as an ordinary x86_64 user and supply unittest names')
    driver = Path(os.environ['HIDDIFY_WAYLAND_DRIVER']).resolve(strict=True)
    for path in BUNDLES:
        trusted_browser_tree(path)
    with tempfile.TemporaryDirectory(prefix='hiddify-wayland-package-', dir='/tmp') as directory:
        temporary = Path(directory)
        # Verify stable, private copies before handing the same package inode
        # to the helper. The distro keyring performs the signature trust check.
        package = temporary/'weston.pkg'
        signature = temporary/'weston.sig'
        shutil.copyfile(os.environ['HIDDIFY_WESTON_PACKAGE'], package)
        shutil.copyfile(os.environ['HIDDIFY_WESTON_SIGNATURE'], signature)
        with package.open('rb') as f:
            if hashlib.file_digest(f, 'sha256').hexdigest() != PACKAGE_SHA256:
                raise ValueError('wrong SHA-256 for Manjaro weston 15.0.1-3 x86_64')
        subprocess.run(['pacman-key', '--verify', str(signature), str(package)], check=True)
        root = temporary/'root'
        root.mkdir(mode=0o755)
        # The subordinate setup UID needs to reach this empty mountpoint.
        temporary.chmod(0o711)
        opened = []
        def pin(path, flags):
            fd = os.open(path, flags | os.O_CLOEXEC)
            opened.append(fd)
            return fd
        try:
            repo = Path(__file__).resolve().parents[2]
            sources = [(driver.parent, 'cli'), (repo/'tests', 'repo/tests'),
                       (repo/'v2/hcore', 'repo/v2/hcore'), (repo/'v2/hcommon', 'repo/v2/hcommon')]
            python = []
            for path in os.environ.get('PYTHONPATH', '').split(os.pathsep):
                if path and Path(path).resolve() != (repo/'tests') and Path(path).is_dir():
                    dest = 'python/' + str(len(python))
                    python.append('/' + dest)
                    sources.append((Path(path), dest))
            binds = [(str(path.resolve()), dest) for path, dest in sources]
            script_fd = pin(__file__, os.O_RDONLY)
            config = {'uid': uid, 'gid': gid, 'tests': tests, 'root': str(root), 'python': python,
                      'without_weston': without_weston,
                      'driver_name': driver.name, 'binds': binds, 'opened': opened,
                      'fixture_dir_fd': pin(repo/'tests/fixtures', os.O_PATH | os.O_DIRECTORY),
                      'package_fd': pin(package, os.O_RDONLY)}
            cmd = ['unshare', '--user', '--mount', '--net', '--map-auto', '--map-user=' + str(uid),
                   '--map-group=' + str(gid), '--setuid=0', '--setgid=0', '/usr/bin/python3', '-B',
                   '/proc/self/fd/' + str(script_fd), '--inside', json.dumps(config)]
            return subprocess.run(cmd, pass_fds=opened).returncode
        finally:
            for fd in opened:
                os.close(fd)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--inside']:
        inside(json.loads(sys.argv[2]))
    elif sys.argv[1:] == ['test_sandbox_wayland']:
        normal = run(['test_sandbox_wayland.PrivateWayland'])
        missing = run(['test_sandbox_wayland.MissingCompositor'], without_weston=True)
        sys.exit(normal or missing)
    elif sys.argv[1:2] == ['--without-weston']:
        sys.exit(run(sys.argv[2:], without_weston=True))
    else:
        sys.exit(run(sys.argv[1:]))
