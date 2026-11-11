//go:build linux && !android

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxExecutableBundleEntries = 16384
	maxExecutableBundleDepth   = 32
)

// Validation runs in the ordinary host core, before entering a user namespace.
// The helpers receive only this pinned directory and its validated destination;
// they must not reinterpret namespace-mapped owner IDs as host ownership.
type executableBundle struct {
	directory *os.File
	path      string
}

func openExecutableBundle(ctx context.Context, rootPath string, command []string) (*executableBundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(rootPath, "/opt/") || rootPath != filepath.Clean(rootPath) || strings.IndexByte(rootPath, 0) >= 0 {
		return nil, errors.New("executable_root must be a canonical absolute directory below /opt")
	}
	if len(command) == 0 || !filepath.IsAbs(command[0]) || command[0] != filepath.Clean(command[0]) ||
		strings.IndexByte(command[0], 0) >= 0 || filepath.Dir(command[0]) != rootPath {
		return nil, errors.New("selected executable must be a canonical path directly inside executable_root")
	}
	directory, err := openSystemDirectory(ctx, rootPath)
	if err != nil {
		return nil, err
	}
	bundle := &executableBundle{directory: directory, path: rootPath}
	if err := validateBundleTree(ctx, directory, filepath.Base(command[0])); err != nil {
		bundle.close()
		return nil, err
	}
	return bundle, nil
}

func validateBundleTree(ctx context.Context, directory *os.File, selected string) error {
	entries := 0
	selectedFound := false
	if err := walkExecutableBundle(ctx, directory, "", 0, selected, &entries, &selectedFound); err != nil {
		return err
	}
	if !selectedFound {
		return errors.New("selected executable is missing from executable_root")
	}
	return ctx.Err()
}

// Both callers supply a canonical absolute path. Check every ancestor before
// passing a system package directory to the scanner or the ELF reader.
func openSystemDirectory(ctx context.Context, rootPath string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open executable bundle ancestors: %w", err)
	}
	current := os.NewFile(uintptr(fd), "/")
	defer func() {
		if current != nil {
			current.Close()
		}
	}()
	if err := validateExecutableBundleDirectory(current); err != nil {
		return nil, fmt.Errorf("unsafe executable bundle ancestor /: %w", err)
	}
	parts := strings.Split(strings.TrimPrefix(rootPath, "/"), "/")
	for index, part := range parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		flags := unix.O_PATH | unix.O_DIRECTORY
		if index == len(parts)-1 {
			flags = unix.O_RDONLY | unix.O_DIRECTORY
		}
		// A separate filesystem at /opt or at the selected bundle is allowed.
		// Every ancestor is nevertheless pinned and checked without symlinks.
		next, err := openExecutableBundleAt(current, part, flags, false)
		if err != nil {
			return nil, fmt.Errorf("open executable bundle ancestor %q: %w", part, err)
		}
		if err := validateExecutableBundleDirectory(next); err != nil {
			next.Close()
			return nil, fmt.Errorf("unsafe executable bundle ancestor %q: %w", part, err)
		}
		current.Close()
		current = next
	}
	directory := current
	current = nil
	return directory, nil
}

func openExecutableBundleAt(parent *os.File, name string, flags int, noMounts bool) (*os.File, error) {
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	if noMounts {
		resolve |= unix.RESOLVE_NO_XDEV // st_dev alone does not detect bind mounts
	}
	fd, err := unix.Openat2(int(parent.Fd()), name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Resolve: resolve,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func validateExecutableBundleOwner(stat *unix.Stat_t) error {
	if stat.Uid != 0 || stat.Mode&0022 != 0 {
		return errors.New("bundle entries must be root-owned and not writable by group or others")
	}
	return nil
}

func validateExecutableBundleDirectory(directory *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("bundle ancestor is not a directory")
	}
	return validateExecutableBundleOwner(&stat)
}

func walkExecutableBundle(ctx context.Context, directory *os.File, prefix string, depth int, selected string, total *int, selectedFound *bool) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			*total++
			if *total > maxExecutableBundleEntries {
				return errors.New("executable bundle exceeds 16384 entries")
			}
			if depth+1 > maxExecutableBundleDepth {
				return errors.New("executable bundle exceeds depth 32")
			}
			isSelected := depth == 0 && entry.Name() == selected
			relative := filepath.Join(prefix, entry.Name())
			if err := validateExecutableBundleEntry(ctx, directory, entry.Name(), relative, depth+1, isSelected, total); err != nil {
				return fmt.Errorf("unsafe executable bundle entry %q: %w", relative, err)
			}
			if isSelected {
				*selectedFound = true
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read executable bundle directory %q: %w", prefix, readErr)
		}
	}
}

func validateExecutableBundleEntry(ctx context.Context, parent *os.File, name, relative string, depth int, selected bool, total *int) error {
	// O_PATH classifies the pinned inode without opening a FIFO or device.
	file, err := openExecutableBundleAt(parent, name, unix.O_PATH, true)
	if err != nil {
		return err
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if err := validateExecutableBundleOwner(&stat); err != nil {
		return err
	}
	kind := stat.Mode & unix.S_IFMT
	if selected && kind != unix.S_IFREG {
		return errors.New("selected executable must be a regular file")
	}
	switch kind {
	case unix.S_IFDIR:
		directory, err := openExecutableBundleAt(file, ".", unix.O_RDONLY|unix.O_DIRECTORY, true)
		if err != nil {
			return err
		}
		defer directory.Close()
		unusedSelected := false
		return walkExecutableBundle(ctx, directory, relative, depth, "", total, &unusedSelected)
	case unix.S_IFREG:
		readable, err := openRegularBundleFile(file, &stat, selected)
		if err != nil {
			return err
		}
		return readable.Close()
	default:
		return errors.New("bundle may contain only directories and regular files; symlinks and special nodes are not allowed")
	}
}

// The caller has pinned and classified this inode as a regular file.
func openRegularBundleFile(file *os.File, stat *unix.Stat_t, selected bool) (*os.File, error) {
	if stat.Nlink != 1 {
		return nil, errors.New("bundle files must have exactly one hard link")
	}
	if selected && (stat.Mode&0111 == 0 || stat.Mode&06000 != 0) {
		return nil, errors.New("selected executable must be executable without setuid or setgid")
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", file.Fd()), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open readable bundle file: %w", err)
	}
	_, err = unix.Fgetxattr(fd, "security.capability", nil)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return os.NewFile(uintptr(fd), file.Name()), nil
	}
	unix.Close(fd)
	if err == nil {
		return nil, errors.New("bundle file capabilities are not allowed")
	}
	return nil, fmt.Errorf("check bundle file capabilities: %w", err)
}

func (bundle *executableBundle) close() {
	if bundle != nil && bundle.directory != nil {
		bundle.directory.Close()
		bundle.directory = nil
	}
}
