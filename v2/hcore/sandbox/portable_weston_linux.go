//go:build linux && !android

package sandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The AppImage packager reproduces this normalized USTAR from pinned distribution
// packages. Hash the decompressed bytes so a different gzip implementation
// cannot change the runtime identity.
const westonTarSHA256 = "40cafb2edb7d162bcccdbeb62a74c0e2634b482d0a32d36ae1171bcbb9be511c"
const westonTarSize = 30187520

// Only preparation through cmd.Start shares the core's descriptor budget.
// Once inherited by bwrap, simultaneous running windows are independent.
var portableWestonStartup = make(chan struct{}, 1)

func readPortableWeston() ([]byte, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	name := filepath.Join(filepath.Dir(executable), "lib", "hiddify-weston-runtime.tar.gz")
	fd, err := unix.Open(name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	pinned := os.NewFile(uintptr(fd), name)
	defer pinned.Close()
	info, err := pinned.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<20 {
		return nil, errors.New("invalid private Weston archive")
	}
	file, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader, err := gzip.NewReader(io.LimitReader(file, 64<<20))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	contents := make([]byte, westonTarSize)
	if _, err := io.ReadFull(reader, contents); err != nil {
		return nil, fmt.Errorf("incomplete private Weston archive: %w", err)
	}
	var end [1]byte
	if n, err := reader.Read(end[:]); n != 0 || err != io.EOF {
		return nil, errors.New("invalid length or checksum in private Weston archive")
	}
	digest := sha256.Sum256(contents)
	if hex.EncodeToString(digest[:]) != westonTarSHA256 {
		return nil, errors.New("private Weston archive does not match this core build")
	}
	return contents, nil
}

// Append files from the verified buffer to bwrap's private tmpfs mounts.
// bwrap consumes and closes each sealed descriptor before Weston starts.
// The caller owns every descriptor appended to files, also on error.
func mountPortableWeston(ctx context.Context, args []string, files *[]*os.File) ([]string, error) {
	contents, err := readPortableWeston()
	if err != nil {
		return nil, fmt.Errorf("load AppImage private Weston: %w", err)
	}
	// A glibc-linked x86_64 binary requests its loader at an absolute /lib64
	// path, including when its other libraries use Debian multiarch paths.
	roots := []string{"/usr", "/lib", "/lib64", "/etc"}
	for _, root := range roots {
		args = append(args, "--tmpfs", root)
	}
	archive := tar.NewReader(bytes.NewReader(contents))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name {
			return nil, errors.New("invalid path in private Weston archive")
		}
		top, _, _ := strings.Cut(name, "/")
		if !slices.Contains(roots, "/"+top) {
			// The source archive includes empty runtime mountpoints. bwrap
			// sets up /dev, /proc, /run, /home and /tmp separately.
			if header.Typeflag == tar.TypeDir {
				continue
			}
			return nil, errors.New("file outside private Weston runtime roots")
		}
		destination := "/" + name
		switch header.Typeflag {
		case tar.TypeDir:
			if name != top {
				args = append(args, "--dir", destination)
			}
		case tar.TypeReg:
			if header.Mode != 0444 && header.Mode != 0555 {
				return nil, errors.New("invalid permissions in private Weston archive")
			}
			data, err := io.ReadAll(archive)
			if err != nil {
				return nil, err
			}
			file, err := anonymousFile(data)
			if err != nil {
				return nil, fmt.Errorf("prepare private Weston file %s: %w", name, err)
			}
			slot := 3 + len(*files)
			*files = append(*files, file)
			args = append(args, "--perms", strconv.FormatInt(header.Mode, 8), "--file", strconv.Itoa(slot), destination)
		default:
			return nil, errors.New("unsupported entry in private Weston archive")
		}
	}
	for _, root := range roots {
		args = append(args, "--remount-ro", root)
	}
	return args, nil
}
