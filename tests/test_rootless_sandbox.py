"""Black-box Linux security contract. Run explicitly with HIDDIFY_SANDBOX_BINARY.

Only local listeners are used. The fake SOCKS server records destinations and
answers them itself; it NEVER dials a requested destination. All remote-looking
addresses and names below are documentation/test destinations.
"""
import contextlib
import ipaddress
import json
import os
import pathlib
import queue
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest


def exact(conn, length):
    value = b""
    while len(value) < length:
        part = conn.recv(length - len(value))
        if not part:
            raise EOFError()
        value += part
    return value


def address(read):
    kind = read(1)[0]
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, read(4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, read(16))
    elif kind == 3:
        host = read(read(1)[0]).decode("ascii")
    else:
        raise ValueError(kind)
    return host, struct.unpack("!H", read(2))[0]


def dns_answer(data):
    end = 12
    while data[end]:
        end += data[end] + 1
    end += 1
    kind = struct.unpack("!H", data[end:end + 2])[0]
    question = data[12:end + 4]
    ip = "2001:db8::44" if kind == 28 else "198.51.100.44"
    packed = ipaddress.ip_address(ip).packed
    answer = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(packed)) + packed
    return data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer


class Proxy:
    def __init__(self):
        self.events = []
        self.stopped = threading.Event()
        self.connections = []
        self.tcp = socket.socket()
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen()
        self.tcp.settimeout(.1)
        self.port = self.tcp.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp.settimeout(.1)
        self.udp_port = self.udp.getsockname()[1]
        threading.Thread(target=self.accept, daemon=True).start()
        threading.Thread(target=self.datagrams, daemon=True).start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.tcp.accept()
                conn.settimeout(3)
                self.connections.append(conn)
                threading.Thread(target=self.serve, args=(conn,), daemon=True).start()
            except (TimeoutError, OSError):
                continue

    def serve(self, conn):
        try:
            version, count = exact(conn, 2)
            if version != 5 or 0 not in exact(conn, count):
                return
            conn.sendall(b"\x05\x00")
            version, command, _ = exact(conn, 3)
            host, port = address(lambda n: exact(conn, n))
            if version != 5 or command not in (1, 3):
                return
            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", self.udp_port))
            if command == 3:
                while not self.stopped.is_set() and conn.recv(1):
                    pass
                return
            self.events.append(("connect", host, port, b""))
            while not self.stopped.is_set():
                if port == 53:
                    data = exact(conn, struct.unpack("!H", exact(conn, 2))[0])
                    response = dns_answer(data)
                    conn.sendall(struct.pack("!H", len(response)) + response)
                else:
                    data = conn.recv(65536)
                    if not data:
                        return
                    conn.sendall(data)
                self.events.append(("tcp", host, port, data))
        except (OSError, EOFError, ValueError, IndexError):
            pass
        finally:
            conn.close()

    def datagrams(self):
        while not self.stopped.is_set():
            try:
                data, peer = self.udp.recvfrom(65536)
                if data[:3] != b"\0\0\0":
                    continue
                offset = 3

                def read(n):
                    nonlocal offset
                    result = data[offset:offset + n]
                    offset += n
                    return result

                host, port = address(read)
                payload = data[offset:]
                response = dns_answer(payload) if port == 53 else payload
                self.events.append(("udp", host, port, payload))
                self.udp.sendto(data[:offset] + response, peer)
            except (OSError, ValueError, IndexError, struct.error):
                continue

    def close(self):
        self.stopped.set()
        self.tcp.close()
        self.udp.close()
        for conn in self.connections:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
            conn.close()


class Run:
    def __init__(self, binary, script, proxy_file=None, env=None, pass_fds=()):
        args = [binary, "experimental-sandbox"]
        if proxy_file is not None:
            args += ["--proxy-file", str(proxy_file)]
        args += ["--", "/usr/bin/python3", "-c", script]
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, env=env, pass_fds=pass_fds)
        self.lines = queue.Queue()
        self.output = []
        self.errors = []
        self.out_thread = threading.Thread(target=self.read, daemon=True)
        self.err_thread = threading.Thread(target=lambda: self.errors.append(self.proc.stderr.read()), daemon=True)
        self.out_thread.start()
        self.err_thread.start()

    def read(self):
        for line in self.proc.stdout:
            self.output.append(line)
            self.lines.put(line)
        self.lines.put(None)

    def event(self, prefix="RESULT ", timeout=20):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            try:
                line = self.lines.get(timeout=max(.01, until - time.monotonic()))
            except queue.Empty:
                break
            if line is None:
                break
            if line.startswith(prefix):
                return json.loads(line[len(prefix):])
        self.err_thread.join(.2)
        raise AssertionError(f"child did not emit {prefix!r}; exit={self.proc.poll()}; "
                             f"stdout={''.join(self.output)[-2000:]}; stderr={''.join(self.errors)[-3000:]}")

    def wait(self):
        code = self.proc.wait(timeout=10)
        self.out_thread.join(2)
        self.err_thread.join(2)
        return code

    def close(self):
        if self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=2)
        self.out_thread.join(2)
        self.err_thread.join(2)
        self.proc.stdout.close()
        self.proc.stderr.close()


PROBE = r'''
import json, os, pathlib, socket, subprocess
results = {}
def exchange(host, port, udp=False):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((host, port))
            s.sendall(b'sandbox-probe')
            return s.recv(64) == b'sandbox-probe'
    except OSError:
        return False
for host in ('198.51.100.44', '2001:db8::44'):
    for udp in (False, True):
        results[host + ('/udp' if udp else '/tcp')] = exchange(host, 443, udp)
try:
    results['dns'] = sorted({x[4][0] for x in socket.getaddrinfo('sandbox.invalid', 443)})
except OSError:
    results['dns'] = []
results['descendant'] = subprocess.check_output(['/usr/bin/python3', '-c',
    "import os; print(os.readlink('/proc/self/ns/net'))"], text=True).strip()
results['netns'] = os.readlink('/proc/self/ns/net')
results['status'] = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
results['env'] = dict(os.environ)
results['fds'] = {}
for fd in os.listdir('/proc/self/fd'):
    try: results['fds'][fd] = os.readlink('/proc/self/fd/' + fd)
    except FileNotFoundError: pass
results['host_home_visible'] = os.path.exists(HOST_HOME)
results['host_socket_visible'] = os.path.exists(HOST_SOCKET)
results['run_user_visible'] = os.path.exists('/run/user')
results['host_process_visible'] = os.path.exists('/proc/' + str(HOST_PID))
results['nested_userns'] = subprocess.run(['/usr/bin/unshare', '-Ur', '/usr/bin/true'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
results['host_canary'] = exchange(HOST_ADDRESS, HOST_PORT)
results['host_loopback'] = exchange('127.0.0.1', HOST_PORT)
try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(.2)
    s.connect(ABSTRACT_SOCKET)
    results['abstract_socket'] = True
except OSError:
    results['abstract_socket'] = False
finally:
    s.close()
print('RESULT ' + json.dumps(results), flush=True)
'''

FLOW = r'''
import json, os, socket, time
if os.fork() == 0:
    os.setsid()
    s = socket.create_connection(('198.51.100.44', 443), timeout=2)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(2)
    u.connect(('198.51.100.44', 443))
    for n in range(200):
        data = ('flow-%d' % n).encode()
        s.sendall(data)
        assert s.recv(64) == data
        u.send(data)
        assert u.recv(64) == data
        if n == 0: print('FLOW ' + json.dumps({'ready': True}), flush=True)
        time.sleep(.05)
    os._exit(0)
os.wait()
'''


@unittest.skipUnless(os.environ.get("HIDDIFY_SANDBOX_BINARY"), "explicit Linux host sandbox binary required")
class RootlessSandbox(unittest.TestCase):
    def setUp(self):
        self.binary = os.environ["HIDDIFY_SANDBOX_BINARY"]
        self.assertNotEqual(os.geteuid(), 0, "this contract must run without root")
        self.temp = tempfile.TemporaryDirectory(prefix="hiddify-sandbox-test-")
        self.addCleanup(self.temp.cleanup)
        self.proxy = Proxy()
        self.addCleanup(self.proxy.close)
        self.profile = pathlib.Path(self.temp.name, "proxy.json")
        self.valid = dict(type="socks", version="5", server="127.0.0.1", server_port=self.proxy.port,
                          dns_server="203.0.113.53")
        self.profile.write_text(json.dumps(self.valid))
        self.host_socket = pathlib.Path(self.temp.name, "control.sock")
        self.unix_socket = socket.socket(socket.AF_UNIX)
        self.unix_socket.bind(str(self.host_socket))
        self.unix_socket.listen()
        self.addCleanup(self.unix_socket.close)
        self.abstract_name = "\0hiddify-test-" + str(os.getpid()) + self.temp.name
        self.abstract = socket.socket(socket.AF_UNIX)
        self.abstract.bind(self.abstract_name)
        self.abstract.listen()
        self.addCleanup(self.abstract.close)
        self.canary = socket.socket()
        self.canary.bind(("0.0.0.0", 0))
        self.canary.listen()
        self.canary.settimeout(.1)
        self.addCleanup(self.canary.close)
        self.host_address = json.loads(subprocess.check_output(
            ["ip", "-j", "route", "get", "192.0.2.1"], text=True))[0]["prefsrc"]
        self.routes = self.host_routes()
        self.addCleanup(lambda: self.assertEqual(self.routes, self.host_routes(), "host routing changed"))

    def host_routes(self):
        return [subprocess.check_output(["ip", "-j", family, "route", "show", "table", "main"], text=True)
                for family in ("-4", "-6")]

    def start(self, script, profile=None, **kwargs):
        run = Run(self.binary, script, profile, **kwargs)
        self.addCleanup(run.close)
        return run

    def probe(self, online):
        constants = dict(HOST_HOME=str(pathlib.Path.home()), HOST_SOCKET=str(self.host_socket),
                         HOST_PID=os.getpid(), HOST_ADDRESS=self.host_address,
                         HOST_PORT=self.canary.getsockname()[1], ABSTRACT_SOCKET=self.abstract_name)
        script = "\n".join(f"{key} = {value!r}" for key, value in constants.items()) + "\n" + PROBE
        env = dict(os.environ, HIDDIFY_CORE_SECRET="must-not-reach-child", HTTP_PROXY="http://127.0.0.1:9",
                   DBUS_SESSION_BUS_ADDRESS="unix:path=" + str(self.host_socket), DISPLAY=":99")
        run = self.start(script, self.profile if online else None, env=env, pass_fds=(self.canary.fileno(),))
        result = run.event()
        self.assertEqual(run.wait(), 0, "isolated command did not finish successfully")
        return result

    def assert_isolation(self, result):
        self.assertNotEqual(result["netns"], os.readlink("/proc/self/ns/net"))
        self.assertEqual(result["netns"], result["descendant"])
        for key in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd"):
            self.assertEqual(int(result["status"][key], 16), 0, key)
        self.assertEqual(result["status"]["NoNewPrivs"].strip(), "1")
        for key in ("host_home_visible", "host_socket_visible", "run_user_visible", "host_process_visible",
                    "host_loopback", "abstract_socket"):
            self.assertFalse(result[key], key)
        for key in ("HIDDIFY_CORE_SECRET", "HTTP_PROXY", "DBUS_SESSION_BUS_ADDRESS", "DISPLAY"):
            self.assertNotIn(key, result["env"], key)
        self.assertNotEqual(result["nested_userns"], 0)
        self.assertLessEqual(set(result["fds"]), {"0", "1", "2"})
        self.assertFalse(any(value.startswith("socket:") for value in result["fds"].values()))
        with self.assertRaises(TimeoutError, msg="direct host TCP connection reached the canary"):
            connection, _ = self.canary.accept()
            connection.close()

    def test_offline_child_and_descendants_have_no_network_or_host_ipc(self):
        result = self.probe(False)
        self.assert_isolation(result)
        for key in ("198.51.100.44/tcp", "198.51.100.44/udp", "2001:db8::44/tcp", "2001:db8::44/udp", "host_canary"):
            self.assertFalse(result[key], key)
        self.assertEqual(result["dns"], [])
        self.assertEqual(self.proxy.events, [])

    def test_tcp_udp_ipv4_ipv6_and_dns_use_only_the_proxy(self):
        result = self.probe(True)
        self.assert_isolation(result)
        for key in ("198.51.100.44/tcp", "198.51.100.44/udp", "2001:db8::44/tcp", "2001:db8::44/udp", "host_canary"):
            self.assertTrue(result[key], key)
        self.assertEqual(result["dns"], ["198.51.100.44", "2001:db8::44"])
        reached = {(protocol, host, port) for protocol, host, port, _ in self.proxy.events}
        for host in ("198.51.100.44", "2001:db8::44"):
            for protocol in ("tcp", "udp"):
                self.assertIn((protocol, host, 443), reached)
        self.assertIn(("udp", "203.0.113.53", 53), reached)
        self.assertIn(("tcp", self.host_address, self.canary.getsockname()[1]), reached)

    def test_unreachable_proxy_never_falls_back_to_direct(self):
        self.proxy.close()
        result = self.probe(True)
        self.assert_isolation(result)
        self.assertFalse(result["host_canary"])
        self.assertFalse(result["198.51.100.44/tcp"])
        self.assertFalse(result["198.51.100.44/udp"])
        self.assertFalse(result["2001:db8::44/tcp"])
        self.assertFalse(result["2001:db8::44/udp"])
        self.assertEqual(result["dns"], [])

    def test_direct_routing_unknown_fields_and_hostname_bootstrap_are_rejected(self):
        bad = [dict(self.valid, type="direct"), dict(self.valid, detour="direct"),
               dict(self.valid, route={"final": "direct"}), dict(self.valid, server="proxy.invalid"),
               dict(self.valid, version="4"), dict(self.valid, server_port=0),
               dict(self.valid, dns_server="resolver.invalid"), dict(self.valid, username="x" * 256)]
        encoded = [json.dumps(value) for value in bad]
        encoded += [json.dumps(self.valid) + " {}", '{"type":"direct",' + json.dumps(self.valid)[1:]]
        for value in encoded:
            with self.subTest(value=value):
                self.profile.write_text(value)
                run = self.start("print('UNRESTRICTED', flush=True)", self.profile)
                self.assertNotEqual(run.wait(), 0)
                self.assertNotIn("UNRESTRICTED", "".join(run.output))
        self.assertEqual(self.proxy.events, [])

    def test_child_exit_status_is_preserved(self):
        run = self.start("raise SystemExit(37)")
        self.assertEqual(run.wait(), 37)

    def stop_flows(self, reason):
        run = self.start(FLOW, self.profile)
        self.assertEqual(run.event("FLOW "), {"ready": True})
        if reason == "lease":
            run.proc.stdin.close()
        elif reason == "launcher":
            run.proc.kill()
        else:
            # The supervisor must have a separate worker; kill it as an OS failure,
            # without invoking any cooperative cleanup in the worker.
            child_file = pathlib.Path(f"/proc/{run.proc.pid}/task/{run.proc.pid}/children")
            children = [int(value) for value in child_file.read_text().split()]
            self.assertTrue(children, "a separate worker process is required")
            for child in children:
                os.kill(child, signal.SIGKILL)
        run.wait()
        time.sleep(.25)  # drain packets already queued before revocation
        count = len(self.proxy.events)
        time.sleep(.35)
        self.assertEqual(len(self.proxy.events), count, "descendant traffic continued after revocation")

    def test_lease_eof_stops_established_tcp_udp_and_daemon_descendant(self):
        self.stop_flows("lease")

    def test_worker_crash_stops_established_tcp_udp_and_daemon_descendant(self):
        self.stop_flows("worker")

    def test_launcher_crash_stops_established_tcp_udp_and_daemon_descendant(self):
        self.stop_flows("launcher")


if __name__ == "__main__":
    unittest.main(verbosity=2)
