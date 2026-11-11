//go:build linux && !android

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maxSelectedExecutableSize = 256 << 20

// openSelectedExecutable imports one user-selected file into a sealed memfd.
// The child receives only the bytes. Its containing directory, source path and
// source inode never enter the child mount namespace.
func openSelectedExecutable(ctx context.Context, path string) (_ *os.File, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || path != filepath.Clean(path) || path == "/" || strings.IndexByte(path, 0) >= 0 {
		return nil, errors.New("selected executable requires a canonical absolute path")
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// openStorageAt rejects symlinks (including procfs magic links) throughout
	// the selected path. O_PATH lets us reject devices and FIFOs without opening them.
	pinned, err := openStorageAt(root, path[1:], unix.O_PATH, 0)
	if err != nil {
		return nil, fmt.Errorf("open selected executable: %w", err)
	}
	defer pinned.Close()
	var before unix.Stat_t
	if err := unix.Fstat(int(pinned.Fd()), &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Mode&06000 != 0 {
		return nil, errors.New("selected executable must be a regular file owned by the current user without setuid or setgid")
	}
	if before.Size < 2 || before.Size > maxSelectedExecutableSize {
		return nil, errors.New("selected executable must contain 2 bytes to 256 MiB")
	}
	// Check X_OK on the actual host mount before moving the bytes. This also
	// honors ACLs and a host noexec mount even if the file has executable bits.
	if err := unix.Faccessat2(int(pinned.Fd()), "", unix.X_OK, unix.AT_EMPTY_PATH|unix.AT_EACCESS); err != nil {
		return nil, fmt.Errorf("selected file cannot be executed on the host: %w", err)
	}
	// Only this internally constructed procfs link is followed, after classifying
	// its pinned target as an ordinary file. Never reopen the selected path.
	source, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", pinned.Fd()))
	if err != nil {
		return nil, err
	}
	defer source.Close()
	_, err = unix.Fgetxattr(int(source.Fd()), "security.capability", nil)
	if err == nil {
		return nil, errors.New("selected executable has file capabilities")
	}
	if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
		return nil, fmt.Errorf("check selected executable capabilities: %w", err)
	}
	fd, err := unix.MemfdCreate("hiddify-selected-application", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	snapshot := os.NewFile(uintptr(fd), "selected-application")
	defer func() {
		if resultErr != nil {
			snapshot.Close()
		}
	}()
	buf := make([]byte, min(before.Size, 64<<10))
	for remaining := before.Size; remaining > 0; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk := buf[:min(remaining, int64(len(buf)))]
		if _, err := io.ReadFull(source, chunk); err != nil {
			return nil, fmt.Errorf("read selected executable: %w", err)
		}
		if remaining == before.Size && !bytes.HasPrefix(chunk, []byte("\x7fELF")) && !bytes.HasPrefix(chunk, []byte("#!")) {
			return nil, errors.New("selected file must be an ELF executable or a script with an interpreter line")
		}
		if _, err := snapshot.Write(chunk); err != nil {
			return nil, err
		}
		remaining -= int64(len(chunk))
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(source.Fd()), &after); err != nil {
		return nil, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errors.New("selected executable changed while it was being imported")
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(snapshot.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return snapshot, nil
}
