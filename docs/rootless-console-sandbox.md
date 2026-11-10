# Experimental rootless console sandbox

Tracking: [hiddify-app issue 46](https://github.com/TMalygin/hiddify-app/issues/46).
This is the native feasibility prototype, not a completed AppImage feature.
It does not read the active app profile, modify the existing VPN service, or
offer a GUI launcher. Its CLI is hidden from normal help.

## Contract

`HiddifyCli experimental-sandbox [--proxy-file FILE] -- /absolute/command args...`

The caller keeps stdin open as a supervisor lease. EOF, any input byte, SIGINT,
SIGTERM or SIGHUP revokes the launch. Application stdin is `/dev/null`; stdout
and stderr are copied through pipes. A normal child exit preserves its status;
revocation returns 125. The CLI is not an interactive terminal wrapper.

Without `--proxy-file`, the command runs in an isolated network namespace with
no TUN and no external route. With a policy, a dedicated sing-box TUN worker
forwards TCP and UDP through one SOCKS5 outbound. DNS packets, including IPv6
queries, use that path. Engine DNS also explicitly uses the proxy. There is no
DIRECT outbound, imported route, host resolver or fallback on proxy failure.
ICMP and other unsupported traffic cannot fall back to host networking.

The policy is deliberately smaller than a profile:

```json
{
  "type": "socks",
  "version": "5",
  "server": "192.0.2.10",
  "server_port": 1080,
  "dns_server": "203.0.113.53"
}
```

These example IPs are documentation addresses, not working services. Optional
`username` and `password` fields have the SOCKS5 255-byte limit. IP literals are
required, so bootstrap cannot use host DNS. Unknown/duplicate fields, multiple
JSON objects, unsupported types and oversized policies are rejected before the
application starts. A validated snapshot is sent to the worker in a sealed
anonymous file; it is never reloaded from a mutable path or exposed to the app.

The SOCKS server and its nominated UDP relay are trusted tunnel endpoints.
SOCKS5 itself does not encrypt traffic. Do not point this prototype at Hiddify's
ordinary mixed port: that server can apply DIRECT rules. Production integration
must construct a validated proxy graph from the active profile instead.

## Isolation and prerequisites

Linux x86_64, unprivileged user namespaces, `/dev/net/tun`, seccomp, memfd seals
and a system `/usr/bin/bwrap` with `--disable-userns` and
`--assert-userns-disabled` support are required. The launcher refuses root,
effective/permitted host capabilities, setuid/setgid bwrap and file capabilities.
An unsupported environment fails the launch; it never executes unrestricted.
Other architectures currently return an explicit unsupported error.

The worker receives only capabilities inside a newly created user namespace.
Its host network namespace is retained solely for proxy transport; the child
gets a separate network namespace. sing-box's existing TUN namespace support
installs routes there. No host route, firewall or sysctl is changed.

Before application exec, bubblewrap creates nested user, PID, mount, IPC and UTS
namespaces, drops all capability sets, enforces `no_new_privs`, disables further
user namespaces and creates a new session. The application sees read-only
system executables/libraries, private `/proc`, `/dev`, temporary home and `/tmp`,
and a generated resolver file. Host home, `/run`, display and D-Bus sockets,
profile files, host process handles and inherited socket descriptors are absent.
No writable host directories are exported. The environment is cleared.

An application-side seccomp filter permits IP/Unix sockets and route netlink,
blocks other socket families (including VSOCK), io_uring, keyrings, cross-process
access, namespace/mount manipulation and terminal input injection. Alternate
32-bit/x32 syscall ABIs are refused; clone3 returns ENOSYS for libc's clone
fallback. Ordinary fork/thread creation remains available.

The worker and child holder use parent-death signals. Bubblewrap's parent-death
handling and PID namespace teardown contain daemon descendants. Revocation
kills the worker, closing TUN and existing TCP/UDP transport sockets; child
death cannot restore a host route. Kernel, bubblewrap, core and the host system
installation remain trusted. This is not protection against host compromise,
kernel vulnerabilities or resource-exhaustion attacks; no resource quotas are
implemented. Untrusted terminal output is still passed to the caller.

## Verification

Build tags come from `make -s print-CLI_TAGS` for a standalone CLI or the normal
`make linux-amd64` target for the shared-library CLI used by AppImage. Run the
contract as an ordinary user on a host that meets the prerequisites:

```sh
HIDDIFY_SANDBOX_BINARY=/absolute/path/HiddifyCli \
  python3 -m unittest discover -s tests -p 'test_rootless_sandbox*.py' -v
```

No test uses a real profile or dials an external server. A local SOCKS fixture
records destinations and answers them itself; separate host listeners detect
direct access. The suite checks IPv4/IPv6 TCP/UDP, DNS, unavailable/absent proxy,
unknown/DIRECT configuration, caps/FD/environment/IPC isolation, descendants,
host routing, exit codes, lease EOF and SIGKILL of worker/launcher. Additional
raw-syscall tests verify socket-family, io_uring, keyring and process restrictions.
Without the explicit binary environment variable these host tests are skipped.

## Work required before app integration

- Tie readiness and revocation to an exact active-profile revision in native
  lifecycle code. Block and close old flows before switching; a selected DB row
  or UI connection state is not sufficient. No hot policy switching exists here.
- Validate supported proxy graphs and their bootstrap/relay transport; reject
  DIRECT and bypass rules. Only one SOCKS5 transport is tested here.
- Package and verify the helper/dependencies for AppImage; add supported GUI
  isolation and persistent storage. Shared host X11/D-Bus and browser
  single-instance forwarding must not become escape paths.
- Add adversarial protocol/GUI tests, explicit QUIC/DoH/DoT application fixtures,
  platform coverage and performance/resource-limit measurements. Generic UDP
  and TCP tests are not measurements of those applications or protocols.

No Android behavior is added. The implementation and CLI registration are
excluded from Android builds.
