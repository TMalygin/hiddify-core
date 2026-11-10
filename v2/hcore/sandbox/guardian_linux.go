//go:build linux && !android

package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"

	"github.com/sagernet/netlink"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/vishvananda/netns"
)

type tunnelProcess struct {
	command      *exec.Cmd
	revision     uint64
	done         chan struct{}
	err          error
	acknowledged bool
}

func (p *tunnelProcess) stop() {
	if p == nil {
		return
	}
	p.command.Process.Kill()
	<-p.done // barrier: the old TUN and all TCP/UDP descriptors are closed
}

type tunnelReady struct {
	process *tunnelProcess
	err     error
}

func managedSession(args []string) (int, error) {
	if len(args) == 0 {
		return 1, errors.New("missing isolated application")
	}
	statusFile := os.NewFile(3, "sandbox-status")
	defer statusFile.Close()
	status := json.NewEncoder(statusFile)
	send := func(event ManagedEvent) error { return status.Encode(event) }
	// This resolver address stays stable while workers are replaced. Only the
	// dedicated TUN can answer it; worker DNS goes through that profile's proxy.
	resolver, err := anonymousFile([]byte("nameserver 172.31.255.2\noptions timeout:1 attempts:1\n"))
	if err != nil {
		return 1, err
	}
	defer resolver.Close()
	filter, err := applicationFilter()
	if err != nil {
		return 1, err
	}
	defer filter.Close()
	application := selfCommand("__child", args...)
	application.ExtraFiles = []*os.File{resolver, filter}
	application.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET, Pdeathsig: syscall.SIGKILL}
	application.Stdout, application.Stderr = os.Stdout, os.Stderr
	gate, err := application.StdinPipe()
	if err != nil {
		return 1, err
	}
	defer gate.Close()
	if err = application.Start(); err != nil {
		return 1, fmt.Errorf("create application namespace: %w", err)
	}
	appDone := make(chan error, 1)
	go func() { appDone <- application.Wait() }()
	defer application.Process.Kill()
	namespace, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", application.Process.Pid))
	if err != nil {
		return 1, err
	}
	defer namespace.Close()
	if err = send(ManagedEvent{State: "offline"}); err != nil {
		return 1, err
	}
	if _, err = gate.Write([]byte{1}); err != nil {
		return 1, err
	}
	gate.Close()
	updates := make(chan managedUpdate)
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		decoder := json.NewDecoder(os.Stdin)
		for {
			var update managedUpdate
			if decoder.Decode(&update) != nil {
				return
			}
			updates <- update
		}
	}()
	ready := make(chan tunnelReady, 8)
	var active *tunnelProcess
	var revision uint64
	defer func() { active.stop() }()
	for {
		var tunnelDone <-chan struct{}
		if active != nil {
			tunnelDone = active.done
		}
		select {
		case update := <-updates:
			if update.Revision <= revision {
				if err = send(ManagedEvent{Revision: update.Revision, State: "offline", Error: "stale sandbox revision"}); err != nil {
					return 1, err
				}
				continue
			}
			if active != nil {
				active.stop()
				if !active.acknowledged {
					if err = send(ManagedEvent{Revision: active.revision, State: "offline", Error: "sandbox revision superseded"}); err != nil {
						return 1, err
					}
				}
				active = nil
			}
			revision = update.Revision
			if update.Policy == nil {
				if err = send(ManagedEvent{Revision: revision, State: "offline"}); err != nil {
					return 1, err
				}
				continue
			}
			active, err = startTunnel(update, namespace, ready)
			if err != nil {
				if err = send(ManagedEvent{Revision: revision, State: "offline", Error: err.Error()}); err != nil {
					return 1, err
				}
			}
		case result := <-ready:
			if result.process != active {
				continue
			}
			active.acknowledged = true
			if result.err != nil {
				active.stop()
				active = nil
				err = send(ManagedEvent{Revision: revision, State: "offline", Error: result.err.Error()})
			} else {
				err = send(ManagedEvent{Revision: revision, State: "online"})
			}
			if err != nil {
				return 1, err
			}
		case <-tunnelDone:
			active = nil
			if err = send(ManagedEvent{Revision: revision, State: "offline", Error: "proxy worker exited; network permission revoked"}); err != nil {
				return 1, err
			}
		case err := <-appDone:
			active.stop()
			active = nil
			code := exitCode(err)
			if err = send(ManagedEvent{Revision: revision, State: "exited", ExitCode: code}); err != nil {
				return 1, err
			}
			return code, nil
		case <-controlDone:
			active.stop()
			active = nil
			application.Process.Kill()
			<-appDone
			return 0, nil
		}
	}
}

func startTunnel(update managedUpdate, namespace *os.File, ready chan<- tunnelReady) (*tunnelProcess, error) {
	content, err := json.Marshal(update.Policy)
	if err != nil {
		return nil, err
	}
	// Validate again at the capability boundary. A malformed control frame must
	// never gain a generic config parser, DIRECT outbound or local DNS fallback.
	if _, err = readPolicy(bytes.NewReader(content)); err != nil {
		return nil, err
	}
	config, err := anonymousFile(content)
	if err != nil {
		return nil, err
	}
	defer config.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	command := selfCommand("__tunnel")
	command.ExtraFiles = []*os.File{namespace, config, writer}
	command.Stderr = os.Stderr
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	process := &tunnelProcess{command: command, revision: update.Revision, done: make(chan struct{})}
	if err = command.Start(); err != nil {
		reader.Close()
		writer.Close()
		return nil, err
	}
	writer.Close()
	go func() { process.err = command.Wait(); close(process.done) }()
	go func() {
		defer reader.Close()
		var response ManagedEvent
		err := json.NewDecoder(reader).Decode(&response)
		if err == nil && response.Error != "" {
			err = errors.New(response.Error)
		}
		if err == nil && response.State != "online" {
			err = errors.New("proxy worker was not ready")
		}
		ready <- tunnelReady{process, err}
	}()
	return process, nil
}

func managedTunnel() (code int, resultErr error) {
	namespace := os.NewFile(3, "application-network-namespace")
	defer namespace.Close()
	config := os.NewFile(4, "proxy-policy")
	policy, err := readPolicy(config)
	config.Close()
	status := os.NewFile(5, "worker-ready")
	defer status.Close()
	report := func(err error) {
		message := ""
		if err != nil {
			message = err.Error()
		}
		json.NewEncoder(status).Encode(ManagedEvent{State: "online", Error: message})
	}
	if err != nil {
		report(err)
		return 1, err
	}
	options := workerOptions(policy, fmt.Sprintf("/proc/self/fd/%d", namespace.Fd()))
	tun := options.Inbounds[0].Options.(*option.TunInboundOptions)
	tun.DNSMode = "hijack"
	// A namespace with just lo + TUN needs no policy-routing rules. Link-scoped
	// default routes disappear with the TUN even after SIGKILL, so a replacement
	// worker cannot inherit stale policy rules from an unclean predecessor.
	tun.AutoRoute = false
	tun.StrictRoute = false
	tun.DNSAddress = badoption.Listable[netip.Addr]{netip.MustParseAddr("172.31.255.2"), netip.MustParseAddr("fd7a:115c:a1e0::2")}
	// Explicit dns_address requires an explicit hijack-dns route rule. Match
	// resolver requests by port so apps using a different DNS address still use
	// the selected profile's resolver, with no native or host resolver fallback.
	options.Route.Rules = []option.Rule{{Type: "default", DefaultOptions: option.DefaultRule{
		RawDefaultRule: option.RawDefaultRule{Port: badoption.Listable[uint16]{53}},
		RuleAction:     option.RuleAction{Action: "hijack-dns"},
	}}}
	instance, err := box.New(box.Options{Context: include.Context(context.Background()), Options: options})
	if err != nil {
		report(err)
		return 1, err
	}
	defer func() {
		if err := instance.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
			if code == 0 {
				code = 1
			}
		}
	}()
	if err = instance.Start(); err != nil {
		report(err)
		return 1, err
	}
	if err = namespaceRoutes(namespace, tun.InterfaceName); err != nil {
		report(err)
		return 1, err
	}
	report(nil)
	// Network permission ends by killing this process, which closes every
	// transport fd before the guardian acknowledges revocation. No retry.
	select {}
}

var _ io.Writer = managedOutput{}

func namespaceRoutes(namespace *os.File, name string) error {
	handle, err := netlink.NewHandleAt(netns.NsHandle(namespace.Fd()))
	if err != nil {
		return err
	}
	defer handle.Close()
	link, err := handle.LinkByName(name)
	if err != nil {
		return err
	}
	for _, network := range []*net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, {IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}} {
		if err = handle.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: network, Scope: netlink.SCOPE_LINK}); err != nil {
			return fmt.Errorf("add isolated default route: %w", err)
		}
	}
	return nil
}
