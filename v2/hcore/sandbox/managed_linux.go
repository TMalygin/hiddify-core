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

type managedCompletion struct {
	terminal *ManagedEvent
	err      error
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
	return StartManagedWithApplication(ctx, command, "", "")
}

// StartManagedWithApplication optionally mounts a private persistent HOME.
// workingDirectory comes from trusted core Setup, never the launch request.
// An empty applicationID preserves the original temporary console sandbox.
func StartManagedWithApplication(ctx context.Context, command []string, workingDirectory, applicationID string) (*Managed, error) {
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
	var storage *applicationStorage
	var infoRead, infoWrite, blockRead, blockWrite *os.File
	if applicationID != "" {
		var err error
		storage, err = openApplicationStorage(workingDirectory, applicationID)
		if err != nil {
			return nil, err
		}
		// The startup lock never enters the sandbox. A durable PID1 lease
		// fences later launches after this core-only descriptor is closed.
		defer storage.close()
		infoRead, infoWrite, err = os.Pipe()
		if err != nil {
			return nil, err
		}
		defer infoRead.Close()
		defer infoWrite.Close()
		blockRead, blockWrite, err = os.Pipe()
		if err != nil {
			return nil, err
		}
		defer blockRead.Close()
		defer blockWrite.Close()
	}
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	process := selfCommand("__session", command...)
	process.ExtraFiles = []*os.File{statusWrite}
	if storage != nil {
		process = selfCommand("__stored_session", command...)
		process.ExtraFiles = []*os.File{statusWrite, storage.home, infoWrite, blockRead}
	}
	process.SysProcAttr = rootlessAttributes()
	input, err := process.StdinPipe()
	if err != nil {
		statusRead.Close()
		statusWrite.Close()
		return nil, err
	}
	if err = ctx.Err(); err == nil && storage != nil {
		err = storage.prepare()
	}
	if err != nil {
		input.Close()
		statusRead.Close()
		statusWrite.Close()
		return nil, err
	}
	m := &Managed{process: process, input: input, pending: make(map[uint64]chan ManagedEvent), ready: make(chan error, 1), done: make(chan struct{}), closed: make(chan struct{}), events: make(chan ManagedEvent, 64)}
	process.Stdout = managedOutput{m, false}
	process.Stderr = managedOutput{m, true}
	started := make(chan error, 1)
	completion := make(chan managedCompletion, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := process.Start()
		statusWrite.Close()
		started <- err
		if err == nil {
			// Wait joins the stdout/stderr copy goroutines. The status reader
			// independently reaches EOF and retains EXITED rather than exposing
			// it early. Both producers must finish before terminal delivery.
			waitErr := process.Wait()
			result := <-completion
			var final ManagedEvent
			if result.err != nil {
				final = ManagedEvent{State: "error", Error: result.err.Error()}
			} else if err := guardianExitError(waitErr, result.terminal.ExitCode); err != nil {
				final = ManagedEvent{Revision: result.terminal.Revision, State: "error", Error: err.Error()}
			} else {
				final = *result.terminal
			}
			// Report a broken channel even if readStatus already revoked the
			// session. With a full output buffer, closure itself reports failure
			// to the RPC consumer; never wait for it to permit cleanup.
			select {
			case m.events <- final:
			default:
			}
		}
		close(m.events)
		close(m.done)
	}()
	err = <-started
	if storage != nil {
		infoWrite.Close()
		blockRead.Close()
	}
	if err != nil {
		input.Close()
		statusRead.Close()
		return nil, fmt.Errorf("create rootless guardian: %w", err)
	}
	go func() { completion <- m.readStatus(statusRead) }()
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
	if storage != nil {
		if err = authorizeStoredApplication(ctx, m, storage, infoRead, blockWrite); err != nil {
			// bwrap's block-fd also unblocks on EOF. Kill the guardian and
			// join it BEFORE the deferred writer close on every error path.
			m.Close()
			return nil, err
		}
	}
	return m, nil
}

func authorizeStoredApplication(ctx context.Context, managed *Managed, storage *applicationStorage, infoRead, blockWrite *os.File) error {
	type result struct {
		pid int
		err error
	}
	ready := make(chan result, 1)
	go func() {
		// bubblewrap closes its info FD before waiting on block-fd. Requiring
		// EOF prevents a partial frame from authorizing an application.
		data, err := io.ReadAll(io.LimitReader(infoRead, 4097))
		var info struct {
			PID int `json:"child-pid"`
		}
		if err == nil && len(data) > 4096 {
			err = errors.New("bubblewrap information exceeds limit")
		}
		if err == nil {
			err = json.Unmarshal(data, &info)
		}
		if err == nil && info.PID <= 1 {
			err = errors.New("bubblewrap did not identify its PID namespace init")
		}
		ready <- result{info.PID, err}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-managed.Done():
		return errors.New("sandbox guardian exited before storage authorization")
	case info := <-ready:
		if info.err != nil {
			return fmt.Errorf("read sandbox namespace identity: %w", info.err)
		}
		if err := storage.recordRunning(info.pid); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The running fence is durable before the first application instruction.
	_, err := blockWrite.Write([]byte{1})
	return err
}

func rootlessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Geteuid(), HostID: os.Geteuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: os.Getegid(), HostID: os.Getegid(), Size: 1}},
		GidMappingsEnableSetgroups: false, AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN}, Pdeathsig: syscall.SIGKILL}
}

func (m *Managed) Events() <-chan ManagedEvent { return m.events }
func (m *Managed) Done() <-chan struct{}       { return m.done }

// A nonzero application exit is a successful protocol completion, but an
// unexpected guardian failure must not be hidden by its earlier status frame.
func guardianExitError(waitErr error, reportedCode int) error {
	if waitErr == nil && reportedCode == 0 {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) && exitErr.ExitCode() == reportedCode && reportedCode >= 0 {
		return nil
	}
	if waitErr != nil {
		return fmt.Errorf("sandbox guardian failed after reporting exit %d: %w", reportedCode, waitErr)
	}
	return fmt.Errorf("sandbox guardian reported exit %d but exited successfully", reportedCode)
}

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

func (m *Managed) readStatus(reader *os.File) managedCompletion {
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	first := true
	var highestRevision uint64
	var terminal *ManagedEvent
	for {
		var event ManagedEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF && terminal != nil {
				return managedCompletion{terminal: terminal}
			}
			if first {
				m.ready <- fmt.Errorf("sandbox guardian did not become ready: %w", err)
			}
			// Stop without waiting: the completion coordinator itself joins
			// this reader. A broken control channel must revoke permission.
			m.stop()
			return managedCompletion{err: fmt.Errorf("sandbox guardian control channel closed without valid completion: %w", err)}
		}
		if terminal != nil {
			m.stop()
			return managedCompletion{err: errors.New("sandbox guardian sent status after its terminal event")}
		}
		if first {
			first = false
			m.ready <- nil
		}
		if event.State == "exited" {
			terminal = &event
			continue
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
	m.stop()
	<-m.done
}

func (m *Managed) stop() {
	m.closeOnce.Do(func() { close(m.closed); m.input.Close(); m.process.Process.Kill() })
}
