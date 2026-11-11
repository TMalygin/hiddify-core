//go:build linux && !android

package sandbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The guardian owns namespace for the lifetime of the isolated application.
type browserConnections struct {
	namespace *os.File
	diag      *netlink.Conn
}

func openBrowserConnections(namespace *os.File) (*browserConnections, error) {
	diag, err := openBrowserDiag(namespace)
	if err != nil {
		return nil, err
	}
	return &browserConnections{namespace: namespace, diag: diag}, nil
}

func openBrowserDiag(namespace *os.File) (*netlink.Conn, error) {
	target, err := namespace.Stat()
	if err != nil {
		return nil, err
	}
	guardianNet, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	if os.SameFile(target, guardianNet) {
		return nil, errors.New("application shares the guardian network namespace")
	}
	fd := int(namespace.Fd())
	namespaceType, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil {
		return nil, err
	}
	if namespaceType != unix.CLONE_NEWNET {
		return nil, errors.New("expected an application network namespace")
	}
	ownerFD, err := unix.IoctlRetInt(fd, unix.NS_GET_USERNS)
	if err != nil {
		return nil, err
	}
	owner := os.NewFile(uintptr(ownerFD), "application-network-owner")
	defer owner.Close()
	ownerInfo, err := owner.Stat()
	if err != nil {
		return nil, err
	}
	guardianUser, err := os.Stat("/proc/self/ns/user")
	if err != nil {
		return nil, err
	}
	if !os.SameFile(ownerInfo, guardianUser) {
		return nil, errors.New("guardian does not own the application network namespace")
	}

	// The rootless guardian cannot re-enter the host network namespace.
	// Create the socket on a disposable thread; exiting without unlocking
	// lets the Go runtime retire that thread in the private namespace.
	var diag *netlink.Conn
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
			done <- err
			return
		}
		current, err := os.Stat("/proc/thread-self/ns/net")
		if err != nil {
			done <- err
			return
		}
		if !os.SameFile(current, target) {
			done <- errors.New("thread did not enter the application network namespace")
			return
		}
		diag, err = netlink.Dial(unix.NETLINK_SOCK_DIAG, nil)
		done <- err
	}()
	err = <-done
	runtime.KeepAlive(namespace)
	if err != nil {
		return nil, fmt.Errorf("open application socket diagnostics: %w", err)
	}
	return diag, nil
}

func (c *browserConnections) close() {
	if c.diag != nil {
		c.diag.Close()
		c.diag = nil
	}
}

// The request and response layouts are defined by linux/inet_diag.h. Socket
// IDs include both endpoints, the interface and the kernel's 64-bit cookie.
type browserSocketID [48]byte

func browserSocketAddress(family byte, address []byte) netip.Addr {
	if family == unix.AF_INET {
		return netip.AddrFrom4([4]byte(address))
	}
	return netip.AddrFrom16([16]byte(address)).Unmap()
}

const browserTCPStates = 1<<unix.BPF_TCP_ESTABLISHED | 1<<unix.BPF_TCP_SYN_SENT |
	1<<unix.BPF_TCP_FIN_WAIT1 | 1<<unix.BPF_TCP_FIN_WAIT2 | 1<<unix.BPF_TCP_CLOSE_WAIT |
	1<<unix.BPF_TCP_LAST_ACK | 1<<unix.BPF_TCP_CLOSING

func (c *browserConnections) revoke() error {
	deadline := time.Now().Add(3 * time.Second)
	// One descriptor per revocation. An interrupted dump or late acknowledgement
	// on this socket can never satisfy a request from a later revision.
	if c.diag == nil {
		diag, err := openBrowserDiag(c.namespace)
		if err != nil {
			return err
		}
		c.diag = diag
	}
	defer c.close()
	if err := c.diag.SetDeadline(deadline); err != nil {
		return err
	}
	for _, family := range []byte{unix.AF_INET, unix.AF_INET6} {
		request := make([]byte, 8+len(browserSocketID{})) // inet_diag_req_v2
		request[0], request[1] = family, unix.IPPROTO_TCP
		binary.NativeEndian.PutUint32(request[4:8], browserTCPStates)
		ids, err := c.tunnelSocketIDs(request, deadline)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if !time.Now().Before(deadline) {
				return os.ErrDeadlineExceeded
			}
			copy(request[8:], id[:])
			_, err := c.diag.Execute(netlink.Message{
				Header: netlink.Header{Type: unix.SOCK_DESTROY, Flags: netlink.Request | netlink.Acknowledge},
				Data:   request,
			})
			if err != nil && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("close application TCP connection: %w", err)
			}
		}
	}
	return nil
}

func (c *browserConnections) tunnelSocketIDs(request []byte, deadline time.Time) ([]browserSocketID, error) {
	raw, err := c.diag.SyscallConn()
	if err != nil {
		return nil, err
	}
	query, err := c.diag.Send(netlink.Message{
		Header: netlink.Header{Type: unix.SOCK_DIAG_BY_FAMILY, Flags: netlink.Request | netlink.Dump},
		Data:   request,
	})
	if err != nil {
		return nil, err
	}
	var ids []browserSocketID
	buffer := make([]byte, 64*1024)
	// netlink.Conn.ReceiveIter consumes NLMSG_DONE before exposing its flags
	// or sequence. Read each datagram, including the dump's terminal status.
	for {
		if !time.Now().Before(deadline) {
			return nil, os.ErrDeadlineExceeded
		}
		n, err := receiveBrowserDiag(raw, buffer)
		if err != nil {
			return nil, err
		}
		for datagram := buffer[:n]; len(datagram) > 0; {
			var reply netlink.Message
			if err := reply.UnmarshalBinary(datagram); err != nil {
				return nil, err
			}
			// Each message starts on NLMSG_ALIGNTO; UnmarshalBinary checks
			// the buffer alignment and the declared message length.
			aligned := (int(reply.Header.Length) + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1)
			datagram = datagram[aligned:]
			if reply.Header.Sequence != query.Header.Sequence || reply.Header.PID != query.Header.PID {
				return nil, errors.New("unmatched application socket dump response")
			}
			if reply.Header.Flags&netlink.DumpInterrupted != 0 {
				return nil, errors.New("application TCP socket dump interrupted")
			}
			if reply.Header.Type == netlink.Error || reply.Header.Type == netlink.Done {
				if len(reply.Data) < 4 {
					return nil, errors.New("missing application TCP socket dump status")
				}
				status := int32(binary.NativeEndian.Uint32(reply.Data[:4]))
				if status < 0 {
					return nil, fmt.Errorf("application TCP socket dump: %w", unix.Errno(-int64(status)))
				}
				if status != 0 || reply.Header.Type != netlink.Done || reply.Header.Flags&netlink.Multi == 0 || len(datagram) != 0 {
					return nil, errors.New("invalid application TCP socket dump completion")
				}
				return ids, nil
			}
			if reply.Header.Type != unix.SOCK_DIAG_BY_FAMILY || reply.Header.Flags&netlink.Multi == 0 {
				return nil, errors.New("unexpected application TCP socket dump message")
			}
			id, include, err := browserTunnelSocket(request[0], reply.Data)
			if err != nil {
				return nil, err
			}
			if include {
				if len(ids) == 16384 {
					return nil, errors.New("too many application TCP connections to revoke in one operation")
				}
				ids = append(ids, id)
			}
		}
	}
}

// RawConn.Read uses the socket's poller and the deadline set by revoke.
func receiveBrowserDiag(raw syscall.RawConn, buffer []byte) (int, error) {
	var n, flags int
	var from unix.Sockaddr
	var readErr error
	if err := raw.Read(func(fd uintptr) bool {
		for {
			n, _, flags, from, readErr = unix.Recvmsg(int(fd), buffer, nil, unix.MSG_DONTWAIT)
			if !errors.Is(readErr, unix.EINTR) {
				return !errors.Is(readErr, unix.EAGAIN)
			}
		}
	}); err != nil {
		return 0, err
	}
	if readErr != nil {
		return 0, readErr
	}
	sender, ok := from.(*unix.SockaddrNetlink)
	if !ok || sender.Pid != 0 || sender.Groups != 0 {
		return 0, errors.New("application socket diagnostic reply did not come from the kernel")
	}
	if n == 0 || flags&unix.MSG_TRUNC != 0 {
		return 0, errors.New("empty or truncated application socket diagnostic datagram")
	}
	return n, nil
}

func browserTunnelSocket(family byte, data []byte) (browserSocketID, bool, error) {
	// inet_diag_msg starts with four header bytes, followed by the ID.
	if len(data) < 72 || data[0] != family {
		return browserSocketID{}, false, errors.New("invalid application TCP socket diagnostic response")
	}
	if data[1] >= 32 || browserTCPStates&(1<<data[1]) == 0 {
		return browserSocketID{}, false, nil
	}
	id := browserSocketID(data[4:52])
	source := browserSocketAddress(family, id[4:20])
	if source != sandboxTunIPv4.Addr() && source != sandboxTunIPv6.Addr() {
		return browserSocketID{}, false, nil
	}
	destination := browserSocketAddress(family, id[20:36])
	// The other end of the TUN subnet can be a worker-owned DNS endpoint.
	if destination.IsLoopback() || destination == sandboxTunIPv4.Addr() || destination == sandboxTunIPv6.Addr() {
		return browserSocketID{}, false, nil
	}
	if binary.NativeEndian.Uint64(id[40:48]) == ^uint64(0) {
		return browserSocketID{}, false, errors.New("application TCP socket lacks an exact cookie")
	}
	return id, true, nil
}
