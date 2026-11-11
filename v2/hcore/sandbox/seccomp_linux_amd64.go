//go:build linux && amd64 && !android

package sandbox

import (
	"bytes"
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

const (
	filterAllow = unix.SECCOMP_RET_ALLOW
	filterDeny  = uint32(unix.SECCOMP_RET_ERRNO | unix.EPERM)
)

// Absolute offsets into Linux's seccomp_data, whose six syscall arguments are
// 64-bit slots even for arguments the kernel consumes as ints.
const (
	argument0 = 16
	argument1 = 24
	argument2 = 32
)

type applicationBPF []unix.SockFilter

func (p *applicationBPF) load(offset uint32) {
	*p = append(*p, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offset})
}

func (p *applicationBPF) mask(bits uint32) {
	*p = append(*p, unix.SockFilter{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: bits})
}

func (p *applicationBPF) ret(action uint32) {
	*p = append(*p, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: action})
}

func (p *applicationBPF) jump(op uint16, value uint32, yes, no uint8) {
	*p = append(*p, unix.SockFilter{Code: unix.BPF_JMP | op | unix.BPF_K, K: value, Jt: yes, Jf: no})
}

func (p *applicationBPF) returnIf(value, action uint32) {
	p.jump(unix.BPF_JEQ, value, 0, 1)
	p.ret(action)
}

// Every matching body ends with a return. Use a 32-bit forward JA to skip
// the whole body on mismatch, avoiding a truncated 8-bit conditional offset.
func (p *applicationBPF) when(value uint32, body func()) {
	p.jump(unix.BPF_JEQ, value, 1, 0)
	i := len(*p)
	*p = append(*p, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JA})
	body()
	(*p)[i].K = uint32(len(*p) - i - 1)
}

func (p *applicationBPF) flags32(offset uint32) {
	p.load(offset + 4)
	p.jump(unix.BPF_JEQ, 0, 1, 0)
	p.ret(filterDeny)
	p.load(offset)
}

func (p *applicationBPF) clone(chromium bool) {
	const chromiumNamespaces = unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET
	forbidden := uint32(unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC | unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_PARENT)
	if chromium {
		p.flags32(argument0)
	} else {
		p.load(argument0)
		forbidden |= chromiumNamespaces
	}
	p.jump(unix.BPF_JSET, forbidden, 0, 1)
	p.ret(filterDeny)
	if chromium {
		// Chromium probes a user namespace, starts its zygote in fresh
		// user, PID and network namespaces, then forks in nested PID namespaces.
		// Ordinary threads and forks require none of these namespace bits.
		p.mask(chromiumNamespaces)
		for _, namespaces := range []uint32{0, unix.CLONE_NEWUSER, chromiumNamespaces, unix.CLONE_NEWPID} {
			p.returnIf(namespaces, filterAllow)
		}
		p.ret(filterDeny)
		return
	}
	p.ret(filterAllow)
}

func (p *applicationBPF) socket(chromium bool) {
	p.load(argument0)
	p.returnIf(unix.AF_UNIX, filterAllow)
	p.when(unix.AF_NETLINK, func() {
		p.load(argument2)
		p.returnIf(unix.NETLINK_ROUTE, filterAllow)
		p.ret(filterDeny)
	})
	p.jump(unix.BPF_JEQ, unix.AF_INET, 2, 0)
	p.jump(unix.BPF_JEQ, unix.AF_INET6, 1, 0)
	p.ret(filterDeny)
	if chromium {
		// A new user namespace can have CAP_NET_RAW in a newly created
		// network namespace. Browsers only need ordinary TCP/UDP sockets.
		p.load(argument1)
		p.mask(^uint32(unix.SOCK_CLOEXEC | unix.SOCK_NONBLOCK))
		for _, pair := range []struct{ kind, protocol uint32 }{
			{unix.SOCK_STREAM, unix.IPPROTO_TCP}, {unix.SOCK_DGRAM, unix.IPPROTO_UDP},
		} {
			p.when(pair.kind, func() {
				p.load(argument2)
				p.returnIf(0, filterAllow)
				p.returnIf(pair.protocol, filterAllow)
				p.ret(filterDeny)
			})
		}
		p.ret(filterDeny)
		return
	}
	p.ret(filterAllow)
}

func (p *applicationBPF) ioctl(chromium bool) {
	p.load(argument1)
	p.returnIf(unix.TIOCSTI, filterDeny)
	p.returnIf(unix.TIOCLINUX, filterDeny)
	if chromium {
		for _, request := range []uint32{
			unix.SIOCGSKNS, unix.TUNGETDEVNETNS,
			unix.PIDFD_GET_CGROUP_NAMESPACE, unix.PIDFD_GET_IPC_NAMESPACE, unix.PIDFD_GET_MNT_NAMESPACE,
			unix.PIDFD_GET_NET_NAMESPACE, unix.PIDFD_GET_PID_NAMESPACE, unix.PIDFD_GET_PID_FOR_CHILDREN_NAMESPACE,
			unix.PIDFD_GET_TIME_NAMESPACE, unix.PIDFD_GET_TIME_FOR_CHILDREN_NAMESPACE,
			unix.PIDFD_GET_USER_NAMESPACE, unix.PIDFD_GET_UTS_NAMESPACE,
		} {
			p.returnIf(request, filterDeny)
		}
		// NSFS ioctls include operations that return another namespace FD.
		// Filter the request type, including size-dependent mount namespace
		// enumeration requests. Normal pidfd poll/wait is unaffected.
		const ioctlTypeMask = 0xff00
		p.mask(ioctlTypeMask)
		p.returnIf(unix.NS_GET_USERNS&ioctlTypeMask, filterDeny)
	}
	p.ret(filterAllow)
}

// applicationFilter is applied by bwrap after namespace/mount setup, before
// application exec. Net namespaces alone do not isolate AF_VSOCK, keyrings or
// every kernel IPC interface. io_uring must not bypass the socket filter.
func applicationFilter(chromium bool) (*os.File, error) {
	var p applicationBPF
	p.load(4) // seccomp_data.arch
	p.jump(unix.BPF_JEQ, unix.AUDIT_ARCH_X86_64, 1, 0)
	p.ret(unix.SECCOMP_RET_KILL_PROCESS)
	p.load(0) // seccomp_data.nr
	p.jump(unix.BPF_JSET, 0x40000000, 0, 1)
	p.ret(unix.SECCOMP_RET_KILL_PROCESS) // refuse the x32 alternate syscall ABI
	for _, number := range []uint32{
		unix.SYS_SETNS, unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT,
		unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_MOVE_MOUNT,
		unix.SYS_OPEN_TREE, unix.SYS_MOUNT_SETATTR, unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_USERFAULTFD, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_KCMP, unix.SYS_PIDFD_GETFD,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_REBOOT, unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	} {
		p.returnIf(number, filterDeny)
	}
	if chromium {
		for _, number := range []uint32{
			unix.SYS_OPEN_TREE_ATTR, unix.SYS_FSPICK, unix.SYS_NAME_TO_HANDLE_AT,
			unix.SYS_FANOTIFY_INIT, unix.SYS_FANOTIFY_MARK, unix.SYS_LISTNS,
			unix.SYS_PROCESS_MADVISE, unix.SYS_PROCESS_MRELEASE,
		} {
			p.returnIf(number, filterDeny)
		}
		p.when(unix.SYS_UNSHARE, func() {
			p.flags32(argument0)
			p.returnIf(unix.CLONE_NEWUSER, filterAllow)
			p.ret(filterDeny)
		})
		// Chromium uses chroot to discard its own filesystem access.
		// All host/guardian directory FDs must already be gone at exec.
		devices := func(offset uint32) {
			p.load(offset)
			p.mask(unix.S_IFMT)
			p.returnIf(unix.S_IFCHR, filterDeny)
			p.returnIf(unix.S_IFBLK, filterDeny)
			p.ret(filterAllow)
		}
		p.when(unix.SYS_MKNOD, func() { devices(argument1) })
		p.when(unix.SYS_MKNODAT, func() { devices(argument2) })
	} else {
		p.returnIf(unix.SYS_UNSHARE, filterDeny)
		p.returnIf(unix.SYS_CHROOT, filterDeny)
	}
	p.returnIf(unix.SYS_CLONE3, uint32(unix.SECCOMP_RET_ERRNO|unix.ENOSYS)) // libc clone fallback
	p.when(unix.SYS_SOCKET, func() { p.socket(chromium) })
	p.when(unix.SYS_SOCKETPAIR, func() {
		p.load(argument0)
		p.returnIf(unix.AF_UNIX, filterAllow)
		p.ret(filterDeny)
	})
	p.when(unix.SYS_CLONE, func() { p.clone(chromium) })
	p.when(unix.SYS_IOCTL, func() { p.ioctl(chromium) })
	p.ret(filterAllow)
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, p); err != nil {
		return nil, err
	}
	return anonymousFile(encoded.Bytes())
}
