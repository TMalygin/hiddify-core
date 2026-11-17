//go:build linux && amd64 && !android

package sandbox

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The package test executable follows the same worker/guardian/child reexec
// entry point as HiddifyCli. Ordinary test execution remains unchanged.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == commandName {
		os.Exit(Run(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func rendererOptions(enabled bool) ApplicationOptions {
	options := ApplicationOptions{ID: "renderer-policy", SelectedApplication: true}
	// Keep the regression compilable before the new opt-in exists. On that
	// revision the actual ordinary child runs and fails the namespace assertion.
	if field := reflect.ValueOf(&options).Elem().FieldByName("RendererSandbox"); field.IsValid() {
		field.SetBool(enabled)
	}
	return options
}

func rendererRun(t *testing.T, command []string, options ApplicationOptions) ([]byte, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := StartManagedWithOptions(ctx, command, t.TempDir(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var stdout, stderr []byte
	offline := false
	for {
		select {
		case event, ok := <-session.Events():
			if !ok {
				t.Fatalf("closed before exit: %s", stderr)
			}
			stdout = append(stdout, event.Stdout...)
			stderr = append(stderr, event.Stderr...)
			switch event.State {
			case "offline":
				offline = true
			case "online", "error":
				t.Fatalf("unexpected state %q: %s", event.State, event.Error)
			case "exited":
				if !offline || event.ExitCode != 0 {
					t.Fatalf("offline=%v exit=%d stderr=%s stdout=%s", offline, event.ExitCode, stderr, stdout)
				}
				return stdout, stderr
			}
		case <-ctx.Done():
			t.Fatalf("child timeout: %s", stderr)
		}
	}
}

const rendererProbe = `import ctypes, errno, json, os, pathlib, socket
libc=ctypes.CDLL(None,use_errno=True)
libc.syscall.restype=ctypes.c_long
def result(number,*args):
    ctypes.set_errno(0)
    value=libc.syscall(ctypes.c_long(number),*args)
    return ctypes.get_errno() if value<0 else 0
status=dict(line.split(":",1) for line in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)
report={"caps":int(status["CapEff"],16),"nnp":int(status["NoNewPrivs"]),"seccomp":int(status["Seccomp"]),"path":os.environ["PATH"],"home":os.environ["HOME"]}
# Invalid descriptors/pointers cannot mutate another process or mount state.
report["join"]=result(308,-1,0)
report["mount"]=result(165,0,0,0,0,0)
report["pidfd_getfd"]=result(438,-1,-1,0)
report["ptrace"]=result(101,-1,-1,0,0)
report["io_uring"]=result(425,0,0)
report["new_mount"]=result(272,0x20000)
report["new_net"]=result(272,0x40000000)
report["own_userns"]=result(272,0x10000000)
report["post_userns_mount"]=result(165,0,0,0,0,0)
report["post_userns_join"]=result(308,-1,0)
print(json.dumps(report))
`

func TestRendererOwnNamespaceAndInheritedOuterPolicy(t *testing.T) {
	if os.Getenv("HIDDIFY_RENDERER_NATIVE_TESTS") != "1" {
		t.Skip("requires explicit rootless native namespace test")
	}
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("renderer=%v", enabled), func(t *testing.T) {
			stdout, _ := rendererRun(t, []string{"/usr/bin/python3", "-c", rendererProbe}, rendererOptions(enabled))
			var values map[string]any
			if err := json.Unmarshal(stdout, &values); err != nil {
				t.Fatal(err)
			}
			for name, expected := range map[string]float64{
				"caps": 0, "nnp": 1, "seccomp": 2, "join": 1, "mount": 1,
				"pidfd_getfd": 1, "ptrace": 1, "io_uring": 1, "new_mount": 1,
				"new_net": 1, "post_userns_mount": 1, "post_userns_join": 1,
			} {
				if values[name] != expected {
					t.Errorf("%s = %v, want %v", name, values[name], expected)
				}
			}
			wantNamespace := float64(unix.EPERM)
			if enabled {
				wantNamespace = 0
			}
			if values["own_userns"] != wantNamespace {
				t.Errorf("own user namespace = %v, want %v", values["own_userns"], wantNamespace)
			}
			if values["path"] != "/usr/bin:/bin" || values["home"] != "/home/sandbox" {
				t.Errorf("unexpected environment: %v", values)
			}
		})
	}
}

func TestRendererAcceptsUnregisteredSelectedScriptAndShell(t *testing.T) {
	if os.Getenv("HIDDIFY_RENDERER_NATIVE_TESTS") != "1" {
		t.Skip("requires explicit rootless native namespace test")
	}
	selected := filepath.Join(t.TempDir(), "selected renderer with spaces")
	if err := os.WriteFile(selected, []byte("#!/usr/bin/python3\n"+rendererProbe), 0700); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{selected},
		{"/bin/sh", "-c", "--", "exec python3 -c '$PROBE'"},
	} {
		// Quote only inside the controlled fixture. The public argv must not be
		// rewritten by the renderer capability, including shell source.
		if command[0] == "/bin/sh" {
			command[3] = "exec python3 -c '" + strings.ReplaceAll(rendererProbe, "'", "'\\''") + "'"
		}
		stdout, _ := rendererRun(t, command, rendererOptions(true))
		var values map[string]any
		if err := json.Unmarshal(stdout, &values); err != nil {
			t.Fatal(err)
		}
		if values["own_userns"] != float64(0) {
			t.Errorf("%s did not receive renderer namespace permission: %v", command[0], values)
		}
	}
}

func TestRendererCapabilityRequiresGenericSessionAndIdentity(t *testing.T) {
	if os.Getenv("HIDDIFY_RENDERER_NATIVE_TESTS") != "1" {
		t.Skip("requires explicit rootless native namespace test")
	}
	options := rendererOptions(true)
	options.SelectedApplication = false
	session, err := StartManagedWithOptions(context.Background(), []string{"/usr/bin/true"}, t.TempDir(), options)
	if session != nil {
		session.Close()
	}
	if err == nil {
		t.Error("renderer capability outside RunRendererApplication was accepted")
	}
	options = rendererOptions(true)
	options.ID = ""
	session, err = StartManagedWithOptions(context.Background(), []string{"/usr/bin/true"}, t.TempDir(), options)
	if session != nil {
		session.Close()
	}
	if err == nil {
		t.Error("renderer session without private home identity was accepted")
	}
}

// Execute the generated classic BPF in memory. This covers unsafe syscall flag
// combinations without ever issuing those syscalls to the host kernel.
func evaluateRendererFilter(t *testing.T, number uint32, arguments [6]uint64) uint32 {
	t.Helper()
	file, err := applicationFilter(true)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	words := make([]byte, 64)
	binary.LittleEndian.PutUint32(words, number)
	binary.LittleEndian.PutUint32(words[4:], unix.AUDIT_ARCH_X86_64)
	for i, value := range arguments {
		binary.LittleEndian.PutUint64(words[16+i*8:], value)
	}
	var accumulator uint32
	for pc := 0; pc < len(data)/8; pc++ {
		instruction := data[pc*8:]
		code := binary.LittleEndian.Uint16(instruction)
		k := binary.LittleEndian.Uint32(instruction[4:])
		switch code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			accumulator = binary.LittleEndian.Uint32(words[k:])
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			accumulator &= k
		case unix.BPF_RET | unix.BPF_K:
			return k
		case unix.BPF_JMP | unix.BPF_JA:
			pc += int(k)
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			yes := accumulator == k
			if code == unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K {
				yes = accumulator&k != 0
			}
			if yes {
				pc += int(instruction[2])
			} else {
				pc += int(instruction[3])
			}
		default:
			t.Fatalf("unimplemented fixture BPF opcode %x", code)
		}
	}
	t.Fatal("filter fell through without a decision")
	return 0
}

func TestRendererFilterKeepsExistingNamespaceAndKernelBoundaries(t *testing.T) {
	namespaceFlags := []uint64{
		unix.CLONE_NEWUSER, unix.CLONE_NEWNET, unix.CLONE_NEWPID,
		unix.CLONE_NEWNS, unix.CLONE_NEWIPC, unix.CLONE_NEWUTS, unix.CLONE_NEWCGROUP,
	}
	for mask := 0; mask < 1<<len(namespaceFlags); mask++ {
		var flags uint64
		for i, bit := range namespaceFlags {
			if mask&(1<<i) != 0 {
				flags |= bit
			}
		}
		expected := uint32(filterDeny)
		switch flags {
		case 0, unix.CLONE_NEWUSER, unix.CLONE_NEWPID, unix.CLONE_NEWUSER | unix.CLONE_NEWNET | unix.CLONE_NEWPID:
			expected = filterAllow
		}
		if got := evaluateRendererFilter(t, unix.SYS_CLONE, [6]uint64{flags | uint64(unix.SIGCHLD)}); got != expected {
			t.Errorf("clone %#x = %#x, want %#x", flags, got, expected)
		}
	}
	for _, flags := range []uint64{unix.CLONE_PARENT, uint64(1) << 32, unix.CLONE_NEWUSER | uint64(1)<<32} {
		if got := evaluateRendererFilter(t, unix.SYS_CLONE, [6]uint64{flags}); got != filterDeny {
			t.Errorf("clone forbidden flags %#x = %#x", flags, got)
		}
	}
	for _, number := range []uint32{
		unix.SYS_SETNS, unix.SYS_MOUNT, unix.SYS_PIVOT_ROOT, unix.SYS_OPEN_TREE,
		unix.SYS_OPEN_TREE_ATTR, unix.SYS_FSPICK, unix.SYS_NAME_TO_HANDLE_AT,
		unix.SYS_PIDFD_GETFD, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_KEYCTL, unix.SYS_BPF, unix.SYS_FANOTIFY_INIT,
	} {
		if got := evaluateRendererFilter(t, number, [6]uint64{}); got != filterDeny {
			t.Errorf("syscall %d = %#x, want EPERM", number, got)
		}
	}
	for _, args := range [][6]uint64{
		{unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP},
		{unix.AF_INET6, unix.SOCK_RAW, 0}, {unix.AF_PACKET, unix.SOCK_RAW, 0},
		{unix.AF_VSOCK, unix.SOCK_STREAM, 0}, {unix.AF_INET, unix.SOCK_SEQPACKET, 255},
	} {
		if got := evaluateRendererFilter(t, unix.SYS_SOCKET, args); got != filterDeny {
			t.Errorf("socket %v = %#x, want EPERM", args, got)
		}
	}
	for _, request := range []uint64{unix.SIOCGSKNS, unix.TUNGETDEVNETNS, unix.PIDFD_GET_NET_NAMESPACE, unix.NS_GET_PARENT} {
		if got := evaluateRendererFilter(t, unix.SYS_IOCTL, [6]uint64{0, request}); got != filterDeny {
			t.Errorf("namespace ioctl %#x = %#x, want EPERM", request, got)
		}
	}
}
