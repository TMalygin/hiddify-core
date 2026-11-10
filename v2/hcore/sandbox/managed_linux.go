//go:build linux && !android

package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// Policy is an immutable, validated proxy snapshot. It contains no ordinary
// profile routes, inbounds, DIRECT outbound or bootstrap resolver.
type Policy = proxyPolicy

func ParsePolicy(reader io.Reader) (*Policy, error) { return readPolicy(reader) }

type ManagedEvent struct {
	Revision uint64 `json:"revision"`
	State    string `json:"state"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Stdout   []byte `json:"-"`
	Stderr   []byte `json:"-"`
}

type managedUpdate struct {
	Revision uint64  `json:"revision"`
	Policy   *Policy `json:"policy"`
}

// Managed owns an isolated application's guardian. Update(nil) closes only its
// proxy worker. Close ends the application session; the ordinary profile Stop
// path must use Update(nil), not Close.
type Managed struct {
	process   *exec.Cmd
	input     io.WriteCloser
	writeMu   sync.Mutex
	mu        sync.Mutex
	pending   map[uint64]chan ManagedEvent
	ready     chan error
	done      chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	events    chan ManagedEvent
}

func StartManaged(ctx context.Context, command []string) (*Managed, error) {
	if err := checkRootless(); err != nil {
		return nil, err
	}
	if err := checkBubblewrap(); err != nil {
		return nil, err
	}
	if len(command) == 0 || len(command) > 1024 || len(command[0]) == 0 || command[0][0] != '/' {
		return nil, errors.New("an absolute command with at most 1024 arguments is required")
	}
	size := 0
	for _, arg := range command {
		size += len(arg) + 1
	}
	if size > 64*1024 {
		return nil, errors.New("sandbox command exceeds 64 KiB")
	}
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	process := selfCommand("__session", command...)
	process.ExtraFiles = []*os.File{statusWrite}
	process.SysProcAttr = rootlessAttributes()
	input, err := process.StdinPipe()
	if err != nil {
		statusRead.Close()
		statusWrite.Close()
		return nil, err
	}
	m := &Managed{process: process, input: input, pending: make(map[uint64]chan ManagedEvent), ready: make(chan error, 1), done: make(chan struct{}), closed: make(chan struct{}), events: make(chan ManagedEvent, 64)}
	process.Stdout = managedOutput{m, false}
	process.Stderr = managedOutput{m, true}
	started := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := process.Start()
		statusWrite.Close()
		started <- err
		if err == nil {
			process.Wait()
		}
		close(m.done)
	}()
	if err := <-started; err != nil {
		input.Close()
		statusRead.Close()
		return nil, fmt.Errorf("create rootless guardian: %w", err)
	}
	go m.readStatus(statusRead)
	select {
	case err := <-m.ready:
		if err != nil {
			m.Close()
			return nil, err
		}
	case <-ctx.Done():
		m.Close()
		return nil, ctx.Err()
	}
	return m, nil
}

func rootlessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Geteuid(), HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Getegid(), HostID: os.Getegid(), Size: 1}},
		GidMappingsEnableSetgroups: false, AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN}, Pdeathsig: syscall.SIGKILL}
}

func (m *Managed) Events() <-chan ManagedEvent { return m.events }
func (m *Managed) Done() <-chan struct{}       { return m.done }

func (m *Managed) emit(event ManagedEvent) {
	select {
	case m.events <- event:
	case <-m.closed:
	default:
		// A stalled consumer must not prevent network revocation or accumulate
		// unbounded application output. End this session, never bypass isolation.
		go m.Close()
	}
}

type managedOutput struct {
	session *Managed
	stderr  bool
}

func (w managedOutput) Write(data []byte) (int, error) {
	event := ManagedEvent{State: "output"}
	copy := append([]byte(nil), data...)
	if w.stderr {
		event.Stderr = copy
	} else {
		event.Stdout = copy
	}
	w.session.emit(event)
	return len(data), nil
}

func (m *Managed) readStatus(reader *os.File) {
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	first := true
	var highestRevision uint64
	for {
		var event ManagedEvent
		if err := decoder.Decode(&event); err != nil {
			if first {
				m.ready <- fmt.Errorf("sandbox guardian did not become ready: %w", err)
			}
			m.emit(ManagedEvent{State: "error", Error: "sandbox guardian control channel closed"})
			return
		}
		if first {
			first = false
			m.ready <- nil
		}
		m.mu.Lock()
		reply := m.pending[event.Revision]
		delete(m.pending, event.Revision)
		m.mu.Unlock()
		if reply != nil {
			reply <- event
		}
		// An older request can arrive after a newer revocation. Deliver its
		// acknowledgement to its waiter, but never regress the public state.
		if event.Revision >= highestRevision {
			highestRevision = event.Revision
			m.emit(event)
		}
	}
}

// Concurrent updates are intentional: a new revocation can interrupt a worker
// still starting for an older revision. The guardian rejects stale revisions.
func (m *Managed) Update(ctx context.Context, revision uint64, policy *Policy) error {
	reply := make(chan ManagedEvent, 1)
	m.mu.Lock()
	if _, exists := m.pending[revision]; exists {
		m.mu.Unlock()
		return errors.New("duplicate sandbox revision")
	}
	m.pending[revision] = reply
	m.mu.Unlock()
	defer func() { m.mu.Lock(); delete(m.pending, revision); m.mu.Unlock() }()
	m.writeMu.Lock()
	err := json.NewEncoder(m.input).Encode(managedUpdate{Revision: revision, Policy: policy})
	m.writeMu.Unlock()
	if err != nil {
		m.Close()
		return fmt.Errorf("write sandbox policy: %w", err)
	}
	select {
	case result := <-reply:
		if result.Error != "" {
			return errors.New(result.Error)
		}
		return nil
	case <-m.done:
		return errors.New("sandbox guardian exited")
	case <-ctx.Done():
		m.Close()
		return ctx.Err()
	}
}

func (m *Managed) Close() {
	m.closeOnce.Do(func() { close(m.closed); m.input.Close(); m.process.Process.Kill() })
	<-m.done
}
