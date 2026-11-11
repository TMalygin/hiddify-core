//go:build linux && !android

package sandbox

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const privateWaylandSocket = "wayland-0"

type privateDisplay struct {
	socket   *os.File
	done     chan struct{}
	command  *exec.Cmd
	owner    *waylandRuntime
	waitErr  error // read only after done closes
	stopOnce sync.Once
}

func (d *privateDisplay) close() {
	if d == nil {
		return
	}
	d.stopOnce.Do(func() {
		if d.command != nil {
			if d.command.Process != nil {
				d.command.Process.Kill()
			}
			<-d.done
		}
		if d.socket != nil {
			d.socket.Close()
		}
		if d.owner != nil {
			d.owner.close()
		}
	})
}

func openDesktopRuntime() (*os.File, error) {
	path := os.Getenv("XDG_RUNTIME_DIR")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("private Wayland requires an absolute XDG_RUNTIME_DIR")
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := openStorageAt(root, strings.TrimPrefix(path, "/"), unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open Wayland desktop runtime: %w", err)
	}
	if err := validateStorageDirectory(dir, true); err != nil {
		dir.Close()
		return nil, fmt.Errorf("unsafe Wayland desktop runtime: %w", err)
	}
	return dir, nil
}

func openWaylandSocket(dir *os.File, name string) (*os.File, error) {
	socket, err := openStorageAt(dir, name, unix.O_PATH, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(socket.Fd()), &st); err != nil {
		socket.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != uint32(os.Geteuid()) {
		socket.Close()
		return nil, errors.New("Wayland endpoint must be a socket owned by the current user")
	}
	return socket, nil
}

func openSystemWeston(ctx context.Context) (_ *os.File, resultErr error) {
	dir, err := openSystemDirectory(ctx, "/usr/bin")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	f, err := openExecutableBundleAt(dir, "weston", unix.O_PATH, false)
	if err != nil {
		return nil, fmt.Errorf("private Wayland requires system /usr/bin/weston: %w", err)
	}
	defer func() {
		if resultErr != nil {
			f.Close()
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return nil, err
	}
	if err := validateExecutableBundleOwner(&st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("system Weston must be a regular file")
	}
	readable, err := openRegularBundleFile(f, &st, true)
	if err != nil {
		return nil, err
	}
	if err := readable.Close(); err != nil {
		return nil, err
	}
	return f, nil // bwrap mounts the validated O_PATH descriptor
}

func startPrivateDisplay(ctx context.Context) (_ *privateDisplay, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	runtimeDir, err := openDesktopRuntime()
	if err != nil {
		return nil, err
	}
	defer runtimeDir.Close()
	d := &privateDisplay{done: make(chan struct{})}
	defer func() {
		if resultErr != nil {
			d.close()
		}
	}()
	parentName := os.Getenv("WAYLAND_DISPLAY")
	if parentName == "" {
		parentName = "wayland-0"
	}
	if filepath.IsAbs(parentName) && filepath.Clean(parentName) == parentName && filepath.Dir(parentName) == os.Getenv("XDG_RUNTIME_DIR") {
		parentName = filepath.Base(parentName)
	}
	if parentName == "." || parentName == ".." || filepath.Base(parentName) != parentName {
		return nil, errors.New("WAYLAND_DISPLAY must name a socket inside XDG_RUNTIME_DIR")
	}
	parent, err := openWaylandSocket(runtimeDir, parentName)
	if err != nil {
		return nil, fmt.Errorf("open parent Wayland display: %w", err)
	}
	defer parent.Close()
	d.owner, err = startWaylandRuntime(ctx, runtimeDir)
	if err != nil {
		return nil, err
	}

	filter, err := applicationFilter(false)
	if err != nil {
		return nil, err
	}
	defer filter.Close()
	files := []*os.File{parent, filter, d.owner.dir, d.owner.lease}
	// The four session descriptors above have their own owners. Release
	// all runtime contents here, including a partially prepared archive.
	ownsPortableSlot := false
	releaseRuntime := sync.OnceFunc(func() {
		for _, file := range files[4:] {
			file.Close()
		}
		if ownsPortableSlot {
			<-portableWestonStartup
		}
	})
	defer releaseRuntime()
	args := []string{"--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--disable-userns", "--assert-userns-disabled", "--cap-drop", "ALL", "--new-session", "--die-with-parent",
		"--clearenv", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "LANG", "C.UTF-8",
		"--setenv", "HOME", "/home/display", "--setenv", "XDG_RUNTIME_DIR", "/run/display",
		"--seccomp", "4", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--dir", "/etc", "--dir", "/home/display", "--chdir", "/home/display", "--tmpfs", "/run",
		"--dir", "/run/parent", "--ro-bind-fd", "3", "/run/parent/display",
		"--bind-fd", "5", "/run/display", "--sync-fd", "6"}
	if os.Getenv("APPIMAGE") != "" {
		select {
		case portableWestonStartup <- struct{}{}:
			ownsPortableSlot = true
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		args, err = mountPortableWeston(ctx, args, &files)
		if err != nil {
			return nil, err
		}
	} else {
		weston, err := openSystemWeston(ctx)
		if err != nil {
			return nil, err
		}
		files = append(files, weston)
		args = append(args, "--ro-bind", "/usr", "/usr", "--ro-bind-fd", "7", "/usr/bin/weston")
		args, err = appendSystemLibraryMounts(args)
		if err != nil {
			return nil, err
		}
		if err := checkPrivateWestonVersion(ctx, args, files); err != nil {
			return nil, err
		}
		if _, err := filter.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
	}
	cmd := exec.Command("/usr/bin/bwrap", append(args, "--", "/usr/bin/weston", "--backend=wayland", "--display=/run/parent/display",
		"--width=640", "--height=480", "--renderer=pixman", "--shell=kiosk", "--socket="+privateWaylandSocket,
		"--idle-time=0", "--no-config")...)
	cmd.Dir, cmd.Env, cmd.ExtraFiles = "/", cleanEnvironment, files
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	d.command = cmd
	started := make(chan error, 1)
	go func() {
		// Linux ties Pdeathsig to the creating OS thread. Keep it alive
		// until the bwrap supervisor and the nested Weston have exited.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		started <- err
		if err == nil {
			err = cmd.Wait()
		}
		d.waitErr = err
		close(d.done)
	}()
	err = <-started
	releaseRuntime()
	if err != nil {
		return nil, err
	}
	go func() {
		select {
		case <-d.owner.done:
			cmd.Process.Kill()
		case <-d.done:
		}
	}()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		socket, err := openWaylandSocket(d.owner.dir, privateWaylandSocket)
		if err == nil {
			err = syncPrivateWayland(ctx, socket)
			if err == nil {
				select {
				case <-d.done:
					socket.Close()
					return nil, errors.New("private Weston exited during startup")
				default:
					d.socket = socket
					return d, nil
				}
			}
			socket.Close()
		}
		// A freshly bound filesystem socket may precede listen(2).
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ECONNREFUSED) {
			return nil, fmt.Errorf("private Wayland readiness: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.done:
			return nil, fmt.Errorf("private Weston exited before display readiness (%v)", d.waitErr)
		case <-ticker.C:
		}
	}
}

func checkPrivateWestonVersion(ctx context.Context, args []string, files []*os.File) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", append(args, "--", "/usr/bin/weston", "--version")...)
	cmd.Dir, cmd.Env, cmd.ExtraFiles = "/", cleanEnvironment, files
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	output, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) != 0 {
			return fmt.Errorf("check private Weston version: %w: %.512s", err, strings.TrimSpace(string(exit.Stderr)))
		}
		return fmt.Errorf("check private Weston version: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) != 2 || fields[0] != "weston" {
		return errors.New("unexpected system Weston version output")
	}
	major, _, _ := strings.Cut(fields[1], ".")
	version, err := strconv.Atoi(major)
	if err != nil || version < 15 {
		return errors.New("private Wayland requires Weston 15 or newer")
	}
	return nil
}

// wl_display.sync creates callback 2. Its done event proves the compositor
// is servicing the exact inode we will mount for the application. No registry
// extensions, buffer descriptors or desktop data are requested.
func syncPrivateWayland(ctx context.Context, socket *os.File) error {
	path := fmt.Sprintf("/proc/self/fd/%d", socket.Fd())
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	var message [12]byte
	binary.NativeEndian.PutUint32(message[:4], 1)
	binary.NativeEndian.PutUint32(message[4:8], 12<<16)
	binary.NativeEndian.PutUint32(message[8:], 2)
	if _, err := conn.Write(message[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, message[:]); err != nil {
		return err
	}
	if binary.NativeEndian.Uint32(message[:4]) != 2 || binary.NativeEndian.Uint32(message[4:8]) != 12<<16 {
		return errors.New("private compositor returned an invalid wl_callback.done")
	}
	return ctx.Err()
}
