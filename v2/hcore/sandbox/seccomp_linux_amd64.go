//go:build linux && amd64 && !android

package sandbox

import (
	"bytes"
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

// applicationFilter is applied by bwrap after namespace/mount setup, before
// application exec. Net namespaces alone do not isolate AF_VSOCK, keyrings or
// every kernel IPC interface. io_uring must not bypass the socket filter.
func applicationFilter() (*os.File, error) {
	var code []unix.SockFilter
	load := func(offset uint32) {
		code = append(code, unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: offset})
	}
	ret := func(action uint32) { code = append(code, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: action}) }
	equal := func(value uint32, yes, no uint8) {
		code = append(code, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: value, Jt: yes, Jf: no})
	}
	deny := uint32(unix.SECCOMP_RET_ERRNO | unix.EPERM)
	load(4) // seccomp_data.arch
	equal(unix.AUDIT_ARCH_X86_64, 1, 0)
	ret(unix.SECCOMP_RET_KILL_PROCESS)
	load(0) // seccomp_data.nr
	code = append(code, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1})
	ret(unix.SECCOMP_RET_KILL_PROCESS) // refuse the x32 alternate syscall ABI
	for _, number := range []uint32{
		unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT,
		unix.SYS_CHROOT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_MOVE_MOUNT,
		unix.SYS_OPEN_TREE, unix.SYS_MOUNT_SETATTR, unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_USERFAULTFD, unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_KCMP, unix.SYS_PIDFD_GETFD,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_REBOOT, unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	} {
		equal(number, 0, 1)
		ret(deny)
	}
	equal(unix.SYS_CLONE3, 0, 1)
	ret(uint32(unix.SECCOMP_RET_ERRNO | unix.ENOSYS)) // libc may safely fall back to clone
	socketJump := len(code)
	equal(unix.SYS_SOCKET, 0, 0)
	pairJump := len(code)
	equal(unix.SYS_SOCKETPAIR, 0, 0)
	cloneJump := len(code)
	equal(unix.SYS_CLONE, 0, 0)
	ioctlJump := len(code)
	equal(unix.SYS_IOCTL, 0, 0)
	ret(unix.SECCOMP_RET_ALLOW)

	code[socketJump].Jt = uint8(len(code) - socketJump - 1)
	load(16) // args[0]: socket family
	for _, family := range []uint32{unix.AF_UNIX, unix.AF_INET, unix.AF_INET6} {
		equal(family, 0, 1)
		ret(unix.SECCOMP_RET_ALLOW)
	}
	equal(unix.AF_NETLINK, 1, 0)
	ret(deny)
	load(32) // args[2]: only namespace-scoped route netlink
	equal(unix.NETLINK_ROUTE, 0, 1)
	ret(unix.SECCOMP_RET_ALLOW)
	ret(deny)

	code[pairJump].Jt = uint8(len(code) - pairJump - 1)
	load(16)
	equal(unix.AF_UNIX, 0, 1)
	ret(unix.SECCOMP_RET_ALLOW)
	ret(deny)

	code[cloneJump].Jt = uint8(len(code) - cloneJump - 1)
	load(16)
	code = append(code, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K,
		K: unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC | unix.CLONE_NEWNET | unix.CLONE_NEWNS |
			unix.CLONE_NEWPID | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS | unix.CLONE_PARENT, Jf: 1})
	ret(deny)
	ret(unix.SECCOMP_RET_ALLOW)

	code[ioctlJump].Jt = uint8(len(code) - ioctlJump - 1)
	load(24) // args[1]: request
	for _, request := range []uint32{unix.TIOCSTI, unix.TIOCLINUX} {
		equal(request, 0, 1)
		ret(deny)
	}
	ret(unix.SECCOMP_RET_ALLOW)
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.LittleEndian, code); err != nil {
		return nil, err
	}
	return anonymousFile(encoded.Bytes())
}
