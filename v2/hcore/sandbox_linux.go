//go:build linux && !android

package hcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/hiddify/hiddify-core/v2/hcore/sandbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Snapshots only contain supported leaf policies and explicit selector tags.
// Ordinary profile rules, DIRECT, inbounds, remote rule sets, and bootstrap DNS
// are never passed to the isolated worker. Unsupported selections stay offline.
type sandboxProfile struct {
	final     string
	leaves    map[string]*sandbox.Policy
	selectors map[string]bool
	errors    map[string]error
	blocked   error
}

var sandboxLeases = struct {
	sync.Mutex
	generation uint64
	revision   uint64
	profile    *sandboxProfile
	policy     *sandbox.Policy
	sessions   map[*sandbox.Managed]struct{}
	reserved   int
}{sessions: make(map[*sandbox.Managed]struct{})}

type sandboxGenerationKey struct{}

func sandboxBegin(ctx context.Context) context.Context {
	sandboxLeases.Lock()
	return sandboxBeginLocked(ctx)
}

// Takes ownership of the broker lock and releases it before waiting on helpers.
func sandboxBeginLocked(ctx context.Context) context.Context {
	// A config replacement or stop invalidates the accepted snapshot as well
	// as permission. A failed replacement must not be undone by selecting a
	// proxy in the ordinary core's still-running old config.
	sandboxLeases.profile = nil
	return sandboxRevokeLocked(ctx)
}

// Revoke permission independently of the accepted config. Selection attempts
// keep that config available for a later explicit, successful selection, but
// no existing or new application may use it while policy is nil.
func sandboxRevokeLocked(ctx context.Context) context.Context {
	sandboxLeases.generation++
	generation := sandboxLeases.generation
	sandboxLeases.revision++
	revision := sandboxLeases.revision
	sandboxLeases.policy = nil
	sessions := sandboxSessionsLocked()
	sandboxLeases.Unlock()
	sandboxUpdate(sessions, revision, nil)
	return context.WithValue(ctx, sandboxGenerationKey{}, generation)
}

func sandboxSessionsLocked() []*sandbox.Managed {
	sessions := make([]*sandbox.Managed, 0, len(sandboxLeases.sessions))
	for session := range sandboxLeases.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

func sandboxUpdate(sessions []*sandbox.Managed, revision uint64, policy *sandbox.Policy) {
	// Do not hold either broker lock while a helper starts. A newer Stop must be
	// able to revoke an older worker that is still starting. Each helper rejects
	// stale revisions and acknowledges revocation after the worker has exited.
	var wait sync.WaitGroup
	for _, session := range sessions {
		wait.Add(1)
		go func(session *sandbox.Managed) {
			defer wait.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := session.Update(ctx, revision, policy); err != nil {
				Log(LogLevel_WARNING, LogType_CORE, "sandbox permission update: ", err.Error())
			}
		}(session)
	}
	wait.Wait()
}

// Called only after the engine has accepted a config, with static.lock held.
func sandboxPublish(ctx context.Context, options *option.Options) {
	profile := &sandboxProfile{leaves: make(map[string]*sandbox.Policy), selectors: make(map[string]bool), errors: make(map[string]error)}
	if options.Experimental != nil && options.Experimental.ClashAPI != nil && options.Experimental.ClashAPI.ExternalController != "" {
		// External controllers can change a selector without our revocation
		// barrier. Such profiles are not eligible for a managed sandbox lease.
		profile.blocked = errors.New("sandbox requires profile selection through the native core API; external Clash control is unsupported")
	}
	if options.Route != nil {
		profile.final = options.Route.Final
	}
	if profile.final == "" && len(options.Outbounds) > 0 {
		profile.final = options.Outbounds[0].Tag
	}
	for _, outbound := range options.Outbounds {
		if outbound.Type == "selector" {
			profile.selectors[outbound.Tag] = true
			continue
		}
		policy, err := sandboxLeaf(outbound)
		if err != nil {
			profile.errors[outbound.Tag] = err
		} else {
			profile.leaves[outbound.Tag] = policy
		}
	}
	sandboxPublishProfile(ctx, profile)
}

func sandboxLeaf(outbound option.Outbound) (*sandbox.Policy, error) {
	if static.HiddifyOptions == nil {
		return nil, errors.New("sandbox DNS settings are unavailable")
	}
	if outbound.Type == "vless" {
		return sandboxRealityLeaf(outbound)
	}
	socks, ok := outbound.Options.(*option.SOCKSOutboundOptions)
	if outbound.Type != "socks" || !ok || socks == nil {
		return nil, errors.New("sandbox requires an explicit SOCKS5 or VLESS/Reality proxy; DIRECT and automatic groups are forbidden")
	}
	if !reflect.DeepEqual(socks.DialerOptions, option.DialerOptions{}) || socks.Network != "" || socks.UDPOverTCP != nil {
		return nil, errors.New("sandbox does not support proxy detours, custom dialers or UDP-over-TCP")
	}
	version := socks.Version
	if version == "" {
		version = "5"
	}
	content, err := json.Marshal(sandbox.Policy{Type: "socks", Version: version, Server: socks.Server, ServerPort: socks.ServerPort,
		DNSServer: static.HiddifyOptions.RemoteDnsAddress, Username: socks.Username, Password: socks.Password})
	if err != nil {
		return nil, err
	}
	return sandbox.ParsePolicy(bytes.NewReader(content))
}

func sandboxRealityLeaf(outbound option.Outbound) (*sandbox.Policy, error) {
	vless, ok := outbound.Options.(*option.VLESSOutboundOptions)
	if !ok || vless == nil || vless.TLS == nil || vless.TLS.UTLS == nil || vless.TLS.Reality == nil {
		return nil, errors.New("sandbox VLESS requires explicit Reality and uTLS settings")
	}
	if vless.Encryption != "" && vless.Encryption != "none" {
		return nil, errors.New("sandbox VLESS does not support additional encryption settings")
	}
	if vless.PacketEncoding != nil && *vless.PacketEncoding != "xudp" {
		// nil is the engine's XUDP default; an explicitly empty string is native
		// UDP, which is a different protocol and must not be silently replaced.
		return nil, errors.New("sandbox VLESS supports XUDP only")
	}
	tls := vless.TLS
	allowedTLS := &option.OutboundTLSOptions{
		Enabled: true, ServerName: tls.ServerName,
		UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: tls.UTLS.Fingerprint},
		Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: tls.Reality.PublicKey,
			ShortID: tls.Reality.ShortID, KeyShare: tls.Reality.KeyShare},
	}
	// Compare against a constructed allow-list, including nested TLS options.
	// This also rejects newly added engine options until explicitly reviewed;
	// do not silently discard detours, ECH, certificate paths, fragmentation,
	// platform TLS engines, custom dialers or other profile behavior.
	allowed := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: vless.Server, ServerPort: vless.ServerPort},
		UUID:          vless.UUID, Flow: vless.Flow, Encryption: vless.Encryption,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: allowedTLS},
		PacketEncoding:              vless.PacketEncoding,
	}
	if !reflect.DeepEqual(*vless, allowed) {
		return nil, errors.New("sandbox VLESS profile contains unsupported TLS, dialer or transport settings")
	}
	content, err := json.Marshal(sandbox.Policy{
		Type: "vless", Server: vless.Server, ServerPort: vless.ServerPort,
		DNSServer: static.HiddifyOptions.RemoteDnsAddress, UUID: vless.UUID, Flow: vless.Flow,
		ServerName: tls.ServerName, PublicKey: tls.Reality.PublicKey, ShortID: tls.Reality.ShortID,
		Fingerprint: tls.UTLS.Fingerprint, PacketEncoding: "xudp", KeyShare: tls.Reality.KeyShare,
	})
	if err != nil {
		return nil, err
	}
	return sandbox.ParsePolicy(bytes.NewReader(content))
}

// Resolve only explicit selectors against the live engine, never its global
// STARTED flag (which may mean an unselected proxy answered a health check).
func (p *sandboxProfile) selected() (*sandbox.Policy, error) {
	if p.blocked != nil {
		return nil, p.blocked
	}
	tag := p.final
	seen := make(map[string]bool)
	for p.selectors[tag] {
		if seen[tag] {
			return nil, errors.New("sandbox selector cycle")
		}
		seen[tag] = true
		box := static.Box()
		if box == nil {
			return nil, errors.New("core is not running")
		}
		outbound, ok := box.Outbound().Outbound(tag)
		if !ok {
			return nil, errors.New("sandbox selector is unavailable")
		}
		selector, ok := outbound.(*group.Selector)
		if !ok {
			return nil, errors.New("sandbox selection is not explicit")
		}
		selected := selector.Selected("tcp")
		if selected == nil {
			return nil, errors.New("sandbox selector has no proxy")
		}
		tag = selected.Tag()
	}
	if policy := p.leaves[tag]; policy != nil {
		return policy, nil
	}
	if err := p.errors[tag]; err != nil {
		return nil, err
	}
	return nil, errors.New("sandbox has no supported selected proxy")
}

func sandboxPublishProfile(ctx context.Context, profile *sandboxProfile) {
	generation, _ := ctx.Value(sandboxGenerationKey{}).(uint64)
	policy, err := profile.selected()
	sandboxLeases.Lock()
	if generation != sandboxLeases.generation || contextErr(ctx) != nil {
		sandboxLeases.Unlock()
		return
	}
	sandboxLeases.profile = profile
	sandboxLeases.policy = policy
	sandboxLeases.revision++
	revision := sandboxLeases.revision
	sessions := sandboxSessionsLocked()
	sandboxLeases.Unlock()
	if err != nil {
		Log(LogLevel_INFO, LogType_CORE, "sandbox remains offline: ", err.Error())
	}
	sandboxUpdate(sessions, revision, policy)
}

// Changing a selection first revokes its worker, even when selection fails.
// The saved snapshot is eligible only until another lifecycle operation begins.
func sandboxSelection() func(bool) {
	sandboxLeases.Lock()
	profile := sandboxLeases.profile
	ctx := sandboxRevokeLocked(context.Background())
	return func(success bool) {
		if success && profile != nil {
			sandboxPublishProfile(ctx, profile)
		}
	}
}

// Service failure/close can arrive outside the normal queue. Do not invalidate
// an already-offline newer start when the previous service finishes closing.
func sandboxEmergencyRevoke() {
	sandboxLeases.Lock()
	if sandboxLeases.profile == nil {
		sandboxLeases.Unlock()
		return
	}
	sandboxLeases.generation++
	sandboxLeases.revision++
	revision := sandboxLeases.revision
	sandboxLeases.profile = nil
	sandboxLeases.policy = nil
	sessions := sandboxSessionsLocked()
	sandboxLeases.Unlock()
	sandboxUpdate(sessions, revision, nil)
}

func (s *CoreService) RunSandbox(request *SandboxRunRequest, stream grpc.ServerStreamingServer[SandboxEvent]) error {
	remote, ok := peer.FromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "sandbox requires mutual TLS")
	}
	tls, ok := remote.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tls.State.VerifiedChains) == 0 {
		return status.Error(codes.Unauthenticated, "sandbox requires a verified client certificate")
	}
	sandboxLeases.Lock()
	if sandboxLeases.reserved >= 16 {
		sandboxLeases.Unlock()
		return status.Error(codes.ResourceExhausted, "at most 16 sandbox sessions are supported")
	}
	sandboxLeases.reserved++
	sandboxLeases.Unlock()
	defer func() { sandboxLeases.Lock(); sandboxLeases.reserved--; sandboxLeases.Unlock() }()
	ctx, cancel := context.WithTimeout(stream.Context(), 10*time.Second)
	mu.Lock()
	workingDirectory := sSandboxWorkingPath
	mu.Unlock()
	session, err := sandbox.StartManagedWithOptions(ctx, request.Command, workingDirectory, sandbox.ApplicationOptions{
		ID: request.ApplicationId, ExecutableRoot: request.ExecutableRoot,
		ChromiumSandbox: request.ChromiumSandbox, PrivateWayland: request.PrivateWayland,
	})
	cancel()
	if err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	defer session.Close()
	sandboxLeases.Lock()
	sandboxLeases.sessions[session] = struct{}{}
	revision, policy := sandboxLeases.revision, sandboxLeases.policy
	sandboxLeases.Unlock()
	defer func() { sandboxLeases.Lock(); delete(sandboxLeases.sessions, session); sandboxLeases.Unlock() }()
	if revision > 0 {
		go sandboxUpdate([]*sandbox.Managed{session}, revision, policy)
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case event, open := <-session.Events():
			if !open {
				return status.Error(codes.Unavailable, "sandbox guardian exited without completing the session")
			}
			state := SandboxState_SANDBOX_OFFLINE
			switch event.State {
			case "online":
				state = SandboxState_SANDBOX_ONLINE
			case "error":
				state = SandboxState_SANDBOX_ERROR
			case "exited":
				state = SandboxState_SANDBOX_EXITED
			case "output":
				state = SandboxState_SANDBOX_OUTPUT
			}
			if err := stream.Send(&SandboxEvent{State: state, Revision: event.Revision, Stdout: event.Stdout, Stderr: event.Stderr, ExitCode: int32(event.ExitCode), Message: event.Error}); err != nil {
				return err
			}
			if event.State == "exited" {
				return nil
			}
		}
	}
}
