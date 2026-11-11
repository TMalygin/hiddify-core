//go:build linux && !android

package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The runtime owner survives a core crash. Only the core and bwrap's PID 1
// hold the write end of the lease. EOF means neither can still create an
// entry in the directory. The browser never receives the directory or lease.
type waylandRuntime struct {
	parent  *os.File
	dir     *os.File
	lease   *os.File
	command *exec.Cmd
	done    chan struct{}
	name    string
}

type runtimeIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

func startWaylandRuntime(ctx context.Context, parent *os.File) (_ *waylandRuntime, resultErr error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(token)
	// Retain the verified parent for bounded fallback cleanup if the owner
	// itself fails after reporting readiness.
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	r := &waylandRuntime{parent: os.NewFile(uintptr(fd), "display-runtime-parent"), name: "hiddify-wayland-" + id, done: make(chan struct{})}
	defer func() {
		if resultErr != nil {
			r.close()
		}
	}()
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	r.lease = writer
	ready, report, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer ready.Close()
	defer report.Close()
	cmd := selfCommand("__wayland_runtime", id)
	cmd.ExtraFiles = []*os.File{parent}
	cmd.Stdin, cmd.Stdout = reader, report
	// Deliberately no Pdeathsig: EOF is the cleanup signal if the core dies.
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	r.command = cmd
	go func() {
		cmd.Wait()
		close(r.done)
	}()
	report.Close()
	stop := context.AfterFunc(ctx, func() { ready.Close() })
	defer stop()
	data, err := io.ReadAll(io.LimitReader(ready, 257))
	if err != nil {
		return nil, err
	}
	var expected runtimeIdentity
	if len(data) > 256 || json.Unmarshal(data, &expected) != nil || expected.Inode == 0 {
		return nil, errors.New("private Wayland runtime owner did not report its directory")
	}
	dir, err := openStorageAt(parent, r.name, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		dir.Close()
		return nil, err
	}
	if uint64(st.Dev) != expected.Device || st.Ino != expected.Inode {
		dir.Close()
		return nil, errors.New("private Wayland runtime was replaced")
	}
	r.dir = dir
	if err := validateStorageDirectory(dir, true); err != nil {
		return nil, err
	}
	select {
	case <-r.done:
		return nil, errors.New("private Wayland runtime owner exited early")
	default:
		return r, nil
	}
}

func (r *waylandRuntime) close() {
	if r.lease != nil {
		r.lease.Close()
	}
	if r.command != nil {
		select {
		case <-r.done:
		case <-time.After(2 * time.Second):
			r.command.Process.Kill()
			select {
			case <-r.done:
			case <-time.After(time.Second):
			}
		}
	}
	if r.dir != nil {
		removeWaylandRuntime(r.parent, r.dir, r.name)
		r.dir.Close()
	}
	r.parent.Close()
}

func manageWaylandRuntime(args []string) (int, error) {
	if len(args) != 1 || len(args[0]) != 32 {
		return 1, errors.New("invalid private Wayland runtime identity")
	}
	token, err := hex.DecodeString(args[0])
	if err != nil || hex.EncodeToString(token) != args[0] {
		return 1, errors.New("invalid private Wayland runtime identity")
	}
	if err := checkRootless(); err != nil {
		return 1, err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 1, err
	}
	parent := os.NewFile(3, "display-runtime-parent")
	defer parent.Close()
	if err := validateStorageDirectory(parent, true); err != nil {
		return 1, err
	}
	name := "hiddify-wayland-" + args[0]
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return 1, err
	}
	dir, err := openStorageAt(parent, name, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return 1, err
	}
	defer dir.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return 1, err
	}
	if err := validateStorageDirectory(dir, true); err != nil {
		return 1, err
	}
	// A closed stdout normally terminates a Go process with SIGPIPE. If
	// the core dies before receiving this report, still clean the directory.
	signal.Ignore(syscall.SIGPIPE)
	if err := json.NewEncoder(os.Stdout).Encode(runtimeIdentity{Device: uint64(st.Dev), Inode: st.Ino}); err != nil {
		removeWaylandRuntime(parent, dir, name)
		return 1, err
	}
	os.Stdout.Close()
	// No commands or paths are accepted on the lease. Even an unexpected
	// octet must not trigger cleanup while a supervisor still holds the pipe.
	_, readErr := io.Copy(io.Discard, os.Stdin)
	if err := errors.Join(readErr, removeWaylandRuntime(parent, dir, name)); err != nil {
		return 1, err
	}
	return 0, nil
}

func removeWaylandRuntime(parent, dir *os.File, name string) error {
	var pinned, entry unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &pinned); err != nil {
		return err
	}
	err := unix.Fstatat(int(parent.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if pinned.Dev != entry.Dev || pinned.Ino != entry.Ino {
		return errors.New("refusing to remove a replaced Wayland runtime")
	}
	for _, file := range []string{privateWaylandSocket, privateWaylandSocket + ".lock"} {
		if err := unix.Unlinkat(int(dir.Fd()), file, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	// Never recursively remove application files or follow socket-name links.
	return unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
}
