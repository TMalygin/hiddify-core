# Experimental rootless console sandbox

Tracking: [hiddify-app issue 46](https://github.com/TMalygin/hiddify-app/issues/46).
This is a native console prototype, not a completed AppImage feature. The CLI
uses a supplied policy; the experimental RPC below follows native active-profile
revisions. Neither offers a GUI launcher. The CLI is hidden from normal help.

## Contract

`HiddifyCli experimental-sandbox [--proxy-file FILE] -- /absolute/command args...`

The caller keeps stdin open as a supervisor lease. EOF, any input byte, SIGINT,
SIGTERM or SIGHUP revokes the launch. Application stdin is `/dev/null`; stdout
and stderr are copied through pipes. A normal child exit preserves its status;
revocation returns 125. The CLI is not an interactive terminal wrapper.

Without `--proxy-file`, the command runs in an isolated network namespace with
no TUN and no external route. With a policy, a dedicated sing-box TUN worker
forwards TCP and UDP through one SOCKS5 or VLESS/Reality outbound. DNS packets, including IPv6
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
ordinary mixed port: that server can apply DIRECT rules.

### VLESS/Reality policy

Tracking: [hiddify-app issue 48](https://github.com/TMalygin/hiddify-app/issues/48).
The alternative sealed policy has `type: "vless"`, the same numeric `server`,
`server_port` and `dns_server`, plus `uuid`, `flow`, `server_name`, `public_key`,
`short_id`, `fingerprint`, `packet_encoding` and `key_share`. No SOCKS fields or
nested arbitrary engine options are accepted. Credentials are supplied at
runtime; never put a real profile or private key in test fixtures.

- UUID must be canonical and nonzero. Flow is empty or `xtls-rprx-vision`.
- TLS, Reality and uTLS are always enabled. SNI must be an explicit ASCII DNS
  name. The raw URL-base64 Reality public key must encode 32 bytes and cannot
  be a low-order X25519 point. Short ID is empty or even-length hexadecimal,
  at most 16 digits.
- Fixed fingerprints: `chrome`, `firefox`, `edge`, `safari`, `ios`, `android`.
  Empty fingerprint uses the engine's Chrome default explicitly.
- `packet_encoding` is `xudp`. In managed profiles, an absent packet encoding
  means XUDP; explicitly empty/native UDP and `packetaddr` are rejected.
- `key_share` is `hybrid`; an empty value is normalized to that default.
  Adaptive `auto` and explicit `classical` are not supported by this policy.

Managed extraction accepts only this subset, including no extra VLESS
encryption (`""` or `"none"`). It rejects custom dialers, detours, transport,
multiplexing and all other TLS options rather than silently removing them.
Proxy/DNS hostname bootstrap, custom DNS transports and other protocol settings
remain unsupported. Failed Reality authentication cannot forward application
payloads or select DIRECT. Worker readiness means its isolated forwarding
instance started; it is not a successful remote-handshake or connectivity test.

## Experimental managed RPC

Tracking: [hiddify-app issue 47](https://github.com/TMalygin/hiddify-app/issues/47).
`Core.RunSandbox(SandboxRunRequest)` is a server stream accepting an absolute
command and arguments. It requires verified mutual TLS and an ordinary Linux
x86_64 user. Plaintext clients are refused even if another API permits them.
Cancelling the stream closes the application session. Profile disconnect does
not cancel the stream: it keeps the application and its network namespace alive
offline. Output is bounded; a stalled consumer terminates its session. There are
at most 16 concurrent sessions, without CPU, memory or per-application quotas.

Before start, restart, hot reload, stop or manual selection, the native broker
revokes network permission and waits for each previous proxy worker to exit.
That closes its TUN and transport sockets. Only a successfully loaded profile
from the current operation generation may grant a new worker. A failed reload
keeps sandbox applications offline even if the ordinary core retains its old
config. Late completion of a cancelled operation cannot grant permission.
Worker failure leaves the application offline; there is no automatic retry.
Core/guardian death terminates the child session through parent-death handling.
An invalid selection revokes permission but retains the accepted config for a
later valid selection. Failed config replacement still invalidates that snapshot.

The application sees a fixed resolver address. An explicit DNS route action
uses the profile's numeric remote resolver over proxied TCP. IPv4/IPv6 default
routes exist only inside the child namespace and disappear with the TUN link,
including after SIGKILL. Reconnecting replaces the worker, not the application.
The stream reports offline/online/error/exit/output events and permission
revisions. Application output is untrusted and must be escaped by a GUI client.
All output is drained before the terminal exit event. Ordinary nonzero command
exit codes are preserved; a guardian failure is reported as an error instead.

This stage supports numeric SOCKS5 leaves and the VLESS/Reality subset above,
selected directly or through explicit selectors. DIRECT, automatic groups, detours, custom dialers,
UDP-over-TCP and domain-based DNS/proxy endpoints remain offline. Unused DIRECT
outbounds in an ordinary profile are not copied into the worker. Profiles with
an external Clash controller are ineligible because it bypasses the native
selection barrier. Automatic keep-top reload revokes existing permission until
a successful explicit restart or reload. Neither transport adds a GUI launcher.

The ordinary core may run its own health checks independently. The managed
contract restricts launched applications, not all network activity of Hiddify.
No profile secrets, host control sockets or namespace descriptors reach the
application. The worker gets a sealed immutable policy containing credentials.
Regenerate client stubs from the additive protobuf API before app integration;
non-Linux platforms return `Unimplemented` for this RPC.

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

- Validate the managed RPC lifecycle across production clients and resolve all
  outstanding test failures before integration. A selected DB row or UI
  connection state is not sufficient to grant network permission.
- Validate supported proxy graphs and their bootstrap/relay transport; reject
  DIRECT and bypass rules. Support is restricted to the SOCKS5 and VLESS/Reality
  subsets above; other transports and hostname bootstrap need separate work.
- Package and verify the helper/dependencies for AppImage; add supported GUI
  isolation and persistent storage. Shared host X11/D-Bus and browser
  single-instance forwarding must not become escape paths.
- Add adversarial protocol/GUI tests, explicit QUIC/DoH/DoT application fixtures,
  platform coverage and performance/resource-limit measurements. Generic UDP
  and TCP tests are not measurements of those applications or protocols.

No Android behavior is added. The implementation and CLI registration are
excluded from Android builds.
