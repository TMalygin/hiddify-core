//go:build linux && !android

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"golang.org/x/sys/unix"
)

const commandName = "experimental-sandbox"

var cleanEnvironment = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}

// Run is deliberately separate from the privileged core service. Its stdin is
// a supervisor lease, NOT application input. Any byte or EOF revokes the lease.
func Run(args []string) int {
	runtime.LockOSThread() // Pdeathsig is tied to the thread that starts the child.
	defer runtime.UnlockOSThread()
	var code int
	var err error
	var mode string
	if len(args) > 0 {
		mode = args[0]
	}
	switch mode {
	case "__wayland_runtime":
		code, err = manageWaylandRuntime(args[1:])
	case "__worker":
		code, err = worker(args[1:])
	case "__child", "__stored_child":
		code, err = child(args[1:], sessionLayout{persistent: mode == "__stored_child"})
	case "__session", "__stored_session":
		code, err = managedSession(args[1:], sessionLayout{persistent: mode == "__stored_session"})
	case "__bundled_child", "__bundled_session", "__chromium_child", "__chromium_session", "__wayland_child", "__wayland_session":
		if len(args) < 3 {
			err = errors.New("missing bundle argument or application")
			break
		}
		wayland := strings.HasPrefix(mode, "__wayland_")
		layout := sessionLayout{persistent: true, bundleRoot: args[1], chromium: wayland || strings.HasPrefix(mode, "__chromium_"), wayland: wayland}
		if strings.HasSuffix(mode, "_child") {
			code, err = child(args[2:], layout)
		} else {
			code, err = managedSession(args[2:], layout)
		}
	case "__tunnel":
		code, err = managedTunnel()
	default:
		code, err = launch(args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func checkRootless() error {
	if runtime.GOARCH != "amd64" {
		return errors.New("prototype currently supports Linux x86_64 only")
	}
	if os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return errors.New("run the prototype as an ordinary unprivileged user")
	}
	var header = unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capget(&header, &caps[0]); err != nil {
		return err
	}
	for _, value := range caps {
		if value.Effective != 0 || value.Permitted != 0 {
			return errors.New("launcher must not carry capabilities")
		}
	}
	// Desktop sessions can carry an inert inheritable capability (for example
	// CAP_WAKE_ALARM) without any permitted/effective capabilities. Discard it;
	// never pass it to a helper. This does not require a host privilege.
	caps = [2]unix.CapUserData{}
	if err := unix.Capset(&header, &caps[0]); err != nil {
		return fmt.Errorf("clear inherited capabilities: %w", err)
	}
	return nil
}

func launch(args []string) (int, error) {
	if err := checkRootless(); err != nil {
		return 1, err
	}
	flags := flag.NewFlagSet(commandName, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	proxyFile := flags.String("proxy-file", "", "immutable restricted SOCKS5 policy")
	if flags.Parse(args) != nil {
		return 1, errors.New("usage: experimental-sandbox [--proxy-file FILE] -- COMMAND [ARGS...]")
	}
	command := flags.Args()
	if len(command) == 0 || !filepath.IsAbs(command[0]) {
		return 1, errors.New("an absolute application executable path is required")
	}
	var policy *proxyPolicy
	if *proxyFile != "" {
		file, err := os.Open(*proxyFile)
		if err != nil {
			return 1, errors.New("cannot open proxy policy")
		}
		policy, err = readPolicy(file)
		file.Close()
		if err != nil {
			return 1, err
		}
	}
	// Only the system bwrap is accepted. Never search an inherited PATH or use a
	// setuid/file-capability helper to compensate for disabled user namespaces.
	if err := checkBubblewrap(); err != nil {
		return 1, err
	}
	config, err := json.Marshal(policy)
	if err != nil {
		return 1, err
	}
	configFD, err := anonymousFile(config)
	if err != nil {
		return 1, err
	}
	defer configFD.Close()
	process := selfCommand("__worker", command...)
	process.ExtraFiles = []*os.File{configFD}
	process.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Geteuid(), HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Getegid(), HostID: os.Getegid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		AmbientCaps:                []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN},
		Pdeathsig:                  syscall.SIGKILL,
	}
	return supervise(process)
}

func selfCommand(mode string, args ...string) *exec.Cmd {
	process := exec.Command("/proc/self/exe", append([]string{commandName, mode}, args...)...)
	process.Env = cleanEnvironment
	process.Dir = "/"
	return process
}

// supervise copies output through pipes, never passing the caller's sockets or
// terminal descriptors to the worker/application. Revocation kills the worker;
// its TUN fd and all connections close, while bwrap kills the child PID namespace.
func supervise(process *exec.Cmd) (int, error) {
	lease, err := process.StdinPipe()
	if err != nil {
		return 1, err
	}
	defer lease.Close()
	process.Stdout = struct{ io.Writer }{os.Stdout}
	process.Stderr = struct{ io.Writer }{os.Stderr}
	if err := process.Start(); err != nil {
		return 1, fmt.Errorf("cannot create rootless sandbox (user namespaces required): %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	revoked := make(chan struct{}, 1)
	go func() {
		var buffer [1]byte
		os.Stdin.Read(buffer[:])
		revoked <- struct{}{}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	select {
	case err := <-done:
		return exitCode(err), nil
	case <-revoked:
	case <-signals:
	}
	process.Process.Kill()
	<-done
	return 125, errors.New("supervisor lease revoked")
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) && exited.ExitCode() >= 0 {
		return exited.ExitCode()
	}
	return 1
}

func worker(args []string) (code int, resultErr error) {
	if len(args) == 0 {
		return 1, errors.New("missing child command")
	}
	config := os.NewFile(3, "proxy-policy")
	content, err := io.ReadAll(io.LimitReader(config, maxPolicyBytes+1))
	config.Close()
	if err != nil {
		return 1, errors.New("cannot read sealed proxy policy")
	}
	var policy *proxyPolicy
	if !bytes.Equal(content, []byte("null")) {
		policy, err = readPolicy(bytes.NewReader(content))
		if err != nil {
			return 1, err
		}
	}
	resolver, err := anonymousFile([]byte(resolverContent(policy)))
	if err != nil {
		return 1, err
	}
	defer resolver.Close()
	filter, err := applicationFilter(false)
	if err != nil {
		return 1, err
	}
	defer filter.Close()
	process := selfCommand("__child", args...)
	process.ExtraFiles = []*os.File{resolver, filter}
	process.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	// Gate application exec until the worker has installed its TUN in this new
	// namespace. Without a policy the namespace has only a down loopback device.
	gate, err := process.StdinPipe()
	if err != nil {
		return 1, err
	}
	defer gate.Close()
	process.Stdout, process.Stderr = os.Stdout, os.Stderr
	if err := process.Start(); err != nil {
		return 1, fmt.Errorf("create isolated network namespace: %w", err)
	}
	defer process.Process.Kill()
	var instance *box.Box
	if policy != nil {
		// The child can exit before engine cleanup. Keep its namespace alive by
		// fd instead of using a /proc/<pid> path that disappears on exit. This
		// handle is opened after child exec and is never inherited by the app.
		namespace, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", process.Process.Pid))
		if err != nil {
			process.Process.Kill()
			process.Wait()
			return 1, fmt.Errorf("open child network namespace: %w", err)
		}
		defer namespace.Close()
		instance, err = box.New(box.Options{
			Context: include.Context(context.Background()),
			Options: workerOptions(policy, fmt.Sprintf("/proc/self/fd/%d", namespace.Fd())),
		})
		if err == nil {
			err = instance.Start()
		}
		if err != nil {
			process.Process.Kill()
			process.Wait()
			if instance != nil {
				err = errors.Join(err, instance.Close())
			}
			return 1, fmt.Errorf("start isolated proxy worker: %w", err)
		}
		defer func() {
			if err := instance.Close(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("close isolated proxy worker: %w", err))
				if code == 0 {
					code = 1
				}
			}
		}()
	}
	if _, err := gate.Write([]byte{1}); err != nil {
		process.Process.Kill()
		process.Wait()
		return 1, errors.New("sandbox failed before application exec")
	}
	gate.Close()
	return exitCode(process.Wait()), nil
}

func checkBubblewrap() error {
	info, err := os.Stat("/usr/bin/bwrap")
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("a non-setuid /usr/bin/bwrap with --disable-userns support is required")
	}
	size, err := unix.Getxattr("/usr/bin/bwrap", "security.capability", nil)
	if size > 0 || (err != nil && err != unix.ENODATA && err != unix.ENOTSUP) {
		return errors.New("bubblewrap file capabilities are not allowed")
	}
	return nil
}

func anonymousFile(content []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("hiddify-sandbox", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "sandbox-data")
	if _, err = file.Write(content); err == nil {
		_, err = file.Seek(0, 0)
	}
	if err == nil {
		_, err = unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_WRITE)
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func child(command []string, layout sessionLayout) (int, error) {
	var ready [1]byte
	if _, err := io.ReadFull(os.Stdin, ready[:]); err != nil || ready[0] != 1 {
		return 1, errors.New("proxy worker did not authorize sandbox exec")
	}
	// The worker needed capabilities in its own user namespace to create this
	// network namespace. The application side needs none, including before
	// bwrap creates its nested user/mount/PID namespaces.
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	caps := [2]unix.CapUserData{}
	if err := unix.Capset(&header, &caps[0]); err != nil {
		return 1, err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 1, err
	}
	// Do not expose the worker's gate or any caller's input channel to the app.
	input, err := os.Open("/dev/null")
	if err != nil {
		return 1, err
	}
	if err := unix.Dup2(int(input.Fd()), 0); err != nil {
		input.Close()
		return 1, err
	}
	input.Close()
	args := []string{"bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--cap-drop", "ALL", "--new-session", "--die-with-parent",
		"--seccomp", "4",
		"--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8",
		"--setenv", "HOME", "/home/sandbox", "--ro-bind", "/usr", "/usr",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/home/sandbox",
		"--dir", "/etc", "--ro-bind-data", "3", "/etc/resolv.conf", "--chdir", "/home/sandbox"}
	if layout.chromium {
		// Keep PID-local uid_map/gid_map available to the zygote. The browser
		// does not need any host kernel or network tuning interfaces.
		for _, subtree := range []string{"/proc/sys", "/proc/irq", "/proc/bus"} {
			args = append(args, "--tmpfs", subtree, "--remount-ro", subtree)
		}
		if _, err := os.Stat("/proc/sysrq-trigger"); err == nil {
			args = append(args, "--ro-bind", "/dev/null", "/proc/sysrq-trigger")
		} else if !os.IsNotExist(err) {
			return 1, err
		}
	} else {
		args = append(args, "--disable-userns", "--assert-userns-disabled")
	}
	firstPrivateFD := uint(5)
	if layout.persistent {
		args = append(args,
			"--bind-fd", "5", "/home/sandbox", "--info-fd", "6", "--block-fd", "7",
			"--setenv", "XDG_CONFIG_HOME", "/home/sandbox/.config",
			"--setenv", "XDG_DATA_HOME", "/home/sandbox/.local/share",
			"--setenv", "XDG_CACHE_HOME", "/home/sandbox/.cache",
			"--setenv", "XDG_STATE_HOME", "/home/sandbox/.local/state",
			"--tmpfs", "/run", "--perms", "0700", "--dir", "/run/sandbox",
			"--setenv", "XDG_RUNTIME_DIR", "/run/sandbox")
		firstPrivateFD = 8
	}
	if layout.bundleRoot != "" {
		// No pathname source is reopened: bwrap consumes this pinned directory
		// FD and applies recursive read-only, nosuid and nodev mount flags.
		args = append(args, "--ro-bind-fd", "8", layout.bundleRoot)
		firstPrivateFD = 9
	}
	if layout.wayland {
		args = append(args, "--ro-bind-fd", fmt.Sprint(firstPrivateFD), "/run/sandbox/"+privateWaylandSocket,
			"--setenv", "WAYLAND_DISPLAY", privateWaylandSocket)
		firstPrivateFD++
		command = append([]string{command[0], "--ozone-platform=wayland"}, command[1:]...)
	}
	args, err = appendSystemLibraryMounts(args)
	if err != nil {
		return 1, err
	}
	args = append(args, "--")
	args = append(args, command...)
	// bwrap consumes the explicitly passed descriptors before application exec.
	if err := unix.CloseRange(firstPrivateFD, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
		return 1, err
	}
	return 1, syscall.Exec("/usr/bin/bwrap", args, cleanEnvironment)
}

func appendSystemLibraryMounts(args []string) ([]string, error) {
	// Support both merged-/usr and separate system library directories without
	// binding the host root, /etc, /home, /run, /tmp or any session sockets.
	for _, path := range []string{"/bin", "/sbin", "/lib", "/lib64"} {
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return nil, err
			}
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil || !strings.HasPrefix(resolved, "/usr/") {
				return nil, errors.New("system directory symlink must resolve inside /usr")
			}
			args = append(args, "--symlink", target, path)
		} else {
			args = append(args, "--ro-bind", path, path)
		}
	}
	return args, nil
}
