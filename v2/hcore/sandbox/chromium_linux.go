//go:build linux && !android

package sandbox

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const chromeBundle = "/opt/google/chrome"

func validateChromiumRequest(command []string, options ApplicationOptions) error {
	if !validApplicationID(options.ID) {
		return errors.New("chromium_sandbox requires a valid application_id")
	}
	switch command[0] {
	case chromeBundle + "/chrome":
		if options.ExecutableRoot != chromeBundle {
			return errors.New("Chrome requires the /opt/google/chrome executable_root")
		}
	case "/usr/lib/brave-browser/brave":
		if options.ExecutableRoot != "" {
			return errors.New("Brave under /usr requires an empty executable_root")
		}
	default:
		return errors.New("chromium_sandbox requires a supported installed Chrome or Brave executable")
	}
	for _, arg := range command[1:] {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("invalid Chromium launch argument")
		}
		if options.PrivateWayland && (arg == "--headless" || arg == "--headless=new" || arg == "--dump-dom") {
			return errors.New("headless Chromium arguments are incompatible with private_wayland")
		}
		switch arg {
		case "--headless", "--headless=new", "--dump-dom", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--version", "about:blank":
			continue
		}
		if strings.HasPrefix(arg, "data:text/html,") {
			continue
		}
		u, err := url.Parse(arg)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			// URLs may contain credentials. Avoid echoing launch arguments.
			return errors.New("unsupported Chromium launch argument")
		}
	}
	return nil
}

func validateChromiumExecutable(ctx context.Context, path string, bundle *executableBundle) error {
	executable := filepath.Base(path)
	var directory *os.File
	if bundle != nil {
		directory = bundle.directory
	} else {
		var err error
		directory, err = openSystemDirectory(ctx, filepath.Dir(path))
		if err != nil {
			return err
		}
		defer directory.Close()
		if err := validateBundleTree(ctx, directory, executable); err != nil {
			return err
		}
	}
	file, err := openExecutableBundleAt(directory, executable, unix.O_PATH, true)
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
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("Chromium must be a regular executable")
	}
	readable, err := openRegularBundleFile(file, &stat, true)
	if err != nil {
		return err
	}
	defer readable.Close()
	var header [20]byte
	if _, err := io.ReadFull(readable, header[:]); err != nil {
		return err
	}
	kind := elf.Type(binary.LittleEndian.Uint16(header[16:18]))
	if (kind != elf.ET_EXEC && kind != elf.ET_DYN) || string(header[:4]) != elf.ELFMAG || header[elf.EI_CLASS] != byte(elf.ELFCLASS64) ||
		header[elf.EI_DATA] != byte(elf.ELFDATA2LSB) || elf.Machine(binary.LittleEndian.Uint16(header[18:])) != elf.EM_X86_64 {
		return errors.New("Chromium must be an installed Linux x86_64 ELF executable")
	}
	return nil
}
