//go:build linux && !android

package sandbox

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const applicationLeaseLimit = 4096

// Only home is passed to the sandbox. The directory, lock and lease stay in the
// core: even a descriptor retained by bubblewrap PID 1 is visible via /proc/1/fd.
type applicationStorage struct {
	home      *os.File
	lock      *os.File
	directory *os.File
	bootID    string
	prepared  bool
}

type applicationLease struct {
	Version   int    `json:"version"`
	Phase     string `json:"phase"`
	BootID    string `json:"boot_id"`
	PID       int    `json:"pid,omitempty"`
	StartTime string `json:"start_time,omitempty"`
}

func openApplicationStorage(workingDirectory, id string) (_ *applicationStorage, resultErr error) {
	if !validApplicationID(id) {
		return nil, errors.New("application_id must contain 1-64 lowercase ASCII letters, digits, underscores or hyphens and start with a letter or digit")
	}
	if !filepath.IsAbs(workingDirectory) {
		return nil, errors.New("application storage requires an absolute trusted working directory")
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	defer root.Close()
	path := strings.TrimPrefix(filepath.Clean(workingDirectory), "/")
	if path == "" {
		path = "."
	}
	base, err := openStorageAt(root, path, unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open trusted working directory without symlinks: %w", err)
	}
	defer base.Close()
	if err := validateStorageDirectory(base, false); err != nil {
		return nil, fmt.Errorf("unsafe working directory: %w", err)
	}
	store, err := openPrivateStorageDirectory(base, "sandbox-apps", false)
	if err != nil {
		return nil, fmt.Errorf("open application storage root: %w", err)
	}
	defer store.Close()
	directory, err := openPrivateStorageDirectory(store, id, false)
	if err != nil {
		return nil, fmt.Errorf("open application storage directory: %w", err)
	}
	storage := &applicationStorage{directory: directory}
	defer func() {
		if resultErr != nil {
			storage.close()
		}
	}()
	storage.home, err = openPrivateStorageDirectory(directory, "home", true)
	if err != nil {
		return nil, fmt.Errorf("open application home: %w", err)
	}
	storage.lock, err = openStorageAt(directory, ".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("open application storage lock: %w", err)
	}
	if err := validateStorageMetadata(storage.lock); err != nil {
		return nil, fmt.Errorf("unsafe application storage lock: %w", err)
	}
	if err := unix.Flock(int(storage.lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, fmt.Errorf("application data is already in use or cannot be locked: %w", err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, fmt.Errorf("read boot identity: %w", err)
	}
	storage.bootID = strings.TrimSpace(string(boot))
	if !validStorageBootID(storage.bootID) {
		return nil, errors.New("invalid kernel boot identity")
	}
	if err := storage.checkPreviousLease(); err != nil {
		return nil, err
	}
	return storage, nil
}

func validApplicationID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for i := range id {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-') {
			continue
		}
		return false
	}
	return true
}

// The caller supplies a pinned directory, never an application-provided path.
// No fallback to pathname-only opening is safe when openat2 is unavailable.
func openStorageAt(parent *os.File, path string, flags int, mode uint32) (*os.File, error) {
	fd, err := unix.Openat2(int(parent.Fd()), path, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openPrivateStorageDirectory(parent *os.File, name string, pathOnly bool) (*os.File, error) {
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY
	if pathOnly {
		flags = unix.O_PATH | unix.O_DIRECTORY
	}
	directory, err := openStorageAt(parent, name, flags, 0)
	if err != nil {
		return nil, err
	}
	if err := validateStorageDirectory(directory, true); err != nil {
		directory.Close()
		return nil, err
	}
	return directory, nil
}

func validateStorageDirectory(file *os.File, private bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("directory must be owned by the current user")
	}
	if private && stat.Mode&07777 != 0700 {
		return errors.New("application directories must have mode 0700")
	}
	if !private && stat.Mode&0022 != 0 {
		return errors.New("working directory must not be writable by group or others")
	}
	return nil
}

func validateStorageMetadata(file *os.File) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&07777 != 0600 || stat.Nlink != 1 {
		return errors.New("metadata must be a current-user regular file with mode 0600 and exactly one link")
	}
	return nil
}

func (s *applicationStorage) checkPreviousLease() error {
	file, err := openStorageAt(s.directory, ".lease.json", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open application lease: %w", err)
	}
	defer file.Close()
	if err := validateStorageMetadata(file); err != nil {
		return fmt.Errorf("unsafe application lease: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, applicationLeaseLimit+1))
	if err != nil {
		return fmt.Errorf("read application lease: %w", err)
	}
	lease, err := parseApplicationLease(data)
	if err != nil {
		return err
	}
	if lease.BootID != s.bootID {
		return nil // No process from a previous boot can still hold the home.
	}
	if lease.Phase == "preparing" {
		return errors.New("application storage has an interrupted launch with unknown lifetime; recovery requires a new boot")
	}
	pidfd, err := unix.PidfdOpen(lease.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check previous application lifetime: %w", err)
	}
	defer unix.Close(pidfd)
	start, err := storageProcessStartTime(lease.PID)
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check previous application identity: %w", err)
	}
	if start != lease.StartTime {
		return nil // PID reuse: never signal the unrelated replacement process.
	}
	exited, err := storageProcessExited(pidfd)
	if err != nil {
		return err
	}
	if !exited {
		return errors.New("application data is still in use by its previous process namespace")
	}
	return nil
}

func parseApplicationLease(data []byte) (*applicationLease, error) {
	invalid := errors.New("invalid application lifetime lease")
	if len(data) == 0 || len(data) > applicationLeaseLimit {
		return nil, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, invalid
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, invalid
		}
		key, ok := token.(string)
		if !ok {
			return nil, invalid
		}
		switch key {
		case "version", "phase", "boot_id", "pid", "start_time":
		default:
			return nil, invalid
		}
		if _, exists := fields[key]; exists {
			return nil, invalid
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, invalid
		}
		fields[key] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid
	}
	var lease applicationLease
	if err := json.Unmarshal(data, &lease); err != nil || lease.Version != 1 || !validStorageBootID(lease.BootID) {
		return nil, invalid
	}
	switch lease.Phase {
	case "preparing":
		if lease.PID != 0 || lease.StartTime != "" {
			return nil, invalid
		}
	case "running":
		if lease.PID <= 1 || lease.PID > 1<<31-1 || !validStorageStartTime(lease.StartTime) {
			return nil, invalid
		}
	default:
		return nil, invalid
	}
	return &lease, nil
}

func validStorageBootID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if id[i] != '-' {
				return false
			}
		} else if !(id[i] >= '0' && id[i] <= '9' || id[i] >= 'a' && id[i] <= 'f') {
			return false
		}
	}
	return true
}

func validStorageStartTime(value string) bool {
	parsed, err := strconv.ParseUint(value, 10, 64)
	return err == nil && parsed != 0 && strconv.FormatUint(parsed, 10) == value
}

func storageProcessStartTime(pid int) (string, error) {
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, applicationLeaseLimit+1))
	if err != nil {
		return "", err
	}
	end := bytes.LastIndex(data, []byte(") "))
	if end < 0 || len(data) > applicationLeaseLimit {
		return "", errors.New("invalid process identity record")
	}
	fields := strings.Fields(string(data[end+2:]))
	// The suffix starts at field 3 (state); starttime is field 22.
	if len(fields) <= 19 || !validStorageStartTime(fields[19]) {
		return "", errors.New("invalid process start time")
	}
	return fields[19], nil
}

func storageProcessExited(pidfd int) (bool, error) {
	ready := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	if _, err := unix.Poll(ready, 0); err != nil {
		return false, fmt.Errorf("check process namespace completion: %w", err)
	}
	if ready[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
		return false, errors.New("invalid process namespace lifetime descriptor")
	}
	return ready[0].Revents&unix.POLLIN != 0, nil
}

// A persistent preparing record precedes process creation. If the core crashes
// before it records PID 1, the next launch refuses to guess whether HOME is free.
func (s *applicationStorage) prepare() error {
	if s.prepared {
		return errors.New("application storage launch was already prepared")
	}
	if err := s.writeLease(applicationLease{Version: 1, Phase: "preparing", BootID: s.bootID}); err != nil {
		return err
	}
	s.prepared = true
	return nil
}

// The caller keeps bubblewrap blocked until this succeeds. PID 1's pidfd, unlike
// its flock lifetime, only reports exit after its namespace descendants exit.
func (s *applicationStorage) recordRunning(pid int) error {
	if !s.prepared || pid <= 1 || pid > 1<<31-1 {
		return errors.New("invalid prepared application process identity")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("open application namespace lifetime: %w", err)
	}
	defer unix.Close(pidfd)
	start, err := storageProcessStartTime(pid)
	if err != nil {
		return fmt.Errorf("read application namespace identity: %w", err)
	}
	exited, err := storageProcessExited(pidfd)
	if err != nil {
		return err
	}
	if exited {
		return errors.New("application process namespace exited during storage setup")
	}
	return s.writeLease(applicationLease{Version: 1, Phase: "running", BootID: s.bootID, PID: pid, StartTime: start})
}

func (s *applicationStorage) writeLease(lease applicationLease) error {
	if s.directory == nil || s.lock == nil {
		return errors.New("application storage is closed")
	}
	data, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Errorf("create application lease name: %w", err)
	}
	name := ".lease-" + hex.EncodeToString(random[:]) + ".tmp"
	file, err := openStorageAt(s.directory, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create application lease: %w", err)
	}
	defer file.Close()
	defer unix.Unlinkat(int(s.directory.Fd()), name, 0)
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write application lease: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("persist application lease: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close application lease: %w", err)
	}
	if err := unix.Renameat(int(s.directory.Fd()), name, int(s.directory.Fd()), ".lease.json"); err != nil {
		return fmt.Errorf("replace application lease: %w", err)
	}
	if err := s.directory.Sync(); err != nil {
		return fmt.Errorf("persist application lease directory: %w", err)
	}
	return nil
}

func (s *applicationStorage) close() {
	if s == nil {
		return
	}
	for _, file := range []*os.File{s.home, s.lock, s.directory} {
		if file != nil {
			file.Close()
		}
	}
	s.home, s.lock, s.directory = nil, nil, nil
}
