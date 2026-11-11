//go:build linux && !android

package hcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"weak"

	"github.com/hiddify/hiddify-core/v2/hcore/sandbox"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Snapshots contain proxy definitions and explicit selector tags. A Reality
// hostname remains a template until the selected outbound authenticates a peer.
// Ordinary profile rules, DIRECT, inbounds, remote rule sets, and bootstrap DNS
// are never passed to the isolated worker. Unsupported selections stay offline.
type sandboxProfile struct {
	final              string
	leaves             map[string]*sandbox.Policy
	selectors          map[string]string // sole configured member, or "" for a mutable group
	errors             map[string]error
	blocked            error
	externalController bool
}

var sandboxLeases = struct {
	sync.Mutex
	generation    uint64
	revision      uint64
	profile       *sandboxProfile
	policy        *sandbox.Policy
	offlineReason string
	sessions      map[*sandbox.Managed]struct{}
	reserved      int
	lastEngine    weak.Pointer[box.Box]
	watch         *sandboxPeerWatch
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
	sandboxLeases.offlineReason = ""
	sessions := sandboxSessionsLocked()
	watch := sandboxLeases.watch
	sandboxLeases.watch = nil
	sandboxLeases.Unlock()
	if watch != nil {
		watch.unsubscribe()
	}
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
	profile := &sandboxProfile{leaves: make(map[string]*sandbox.Policy), selectors: make(map[string]string), errors: make(map[string]error)}
	profile.externalController = options.Experimental != nil && options.Experimental.ClashAPI != nil && options.Experimental.ClashAPI.ExternalController != ""
	if options.Route != nil {
		profile.final = options.Route.Final
	}
	// Reload can retain the running default when route.final is omitted.
	if box := static.Box(); profile.final == "" && box != nil {
		if current := box.Outbound().Default(); current != nil {
			profile.final = current.Tag()
		}
	}
	defined := make(map[string]bool)
	for i, endpoint := range options.Endpoints {
		defined[sandboxRuntimeTag(endpoint.Tag, i)] = true
	}
	for i, outbound := range options.Outbounds {
		tag := sandboxRuntimeTag(outbound.Tag, i)
		if defined[tag] {
			profile.blocked = errors.New("duplicate route tags prevent verification of the selected proxy")
			break
		}
		defined[tag] = true
		if outbound.Type == "selector" {
			member := ""
			if group, ok := outbound.Options.(*option.SelectorOutboundOptions); ok && group != nil && len(group.Outbounds) == 1 {
				member = group.Outbounds[0]
			}
			profile.selectors[tag] = member
			continue
		}
		policy, err := sandboxProfileLeaf(outbound)
		if err != nil {
			profile.errors[tag] = err
		} else {
			profile.leaves[tag] = policy
		}
	}
	sandboxPublishProfile(ctx, profile)
}

// The engine installs unnamed outbounds and endpoints under their decimal
// index in the respective list. Empty strings are never runtime identities.
func sandboxRuntimeTag(tag string, index int) string {
	if tag == "" {
		return strconv.Itoa(index)
	}
	return tag
}

func sandboxLeaf(outbound option.Outbound) (*sandbox.Policy, error) {
	if static.HiddifyOptions == nil {
		return nil, errors.New("sandbox DNS settings are unavailable")
	}
	if outbound.Type == "vless" {
		policy, err := sandboxRealityDefinition(outbound)
		if err != nil {
			return nil, err
		}
		return sandboxWorkerPolicy(*policy)
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
	return sandboxWorkerPolicy(sandbox.Policy{Type: "socks", Version: version, Server: socks.Server, ServerPort: socks.ServerPort,
		DNSServer: static.HiddifyOptions.RemoteDnsAddress, Username: socks.Username, Password: socks.Password})
}

func sandboxWorkerPolicy(policy sandbox.Policy) (*sandbox.Policy, error) {
	content, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	return sandbox.ParsePolicy(bytes.NewReader(content))
}

func sandboxRealityDefinition(outbound option.Outbound) (*sandbox.Policy, error) {
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
	dnsAddress, err := sandboxRealityDNS(static.HiddifyOptions.RemoteDnsAddress)
	if err != nil {
		return nil, err
	}
	return &sandbox.Policy{
		Type: "vless", Server: vless.Server, ServerPort: vless.ServerPort,
		DNSServer: dnsAddress, UUID: vless.UUID, Flow: vless.Flow,
		ServerName: tls.ServerName, PublicKey: tls.Reality.PublicKey, ShortID: tls.Reality.ShortID,
		Fingerprint: tls.UTLS.Fingerprint, PacketEncoding: "xudp", KeyShare: tls.Reality.KeyShare,
	}, nil
}

// The worker's resolver uses TCP/53 through its only outbound. Accept that
// exact Hiddify DNS transport without changing the main engine's DNS settings.
func sandboxRealityDNS(configured string) (string, error) {
	authority, tcp := strings.CutPrefix(configured, "tcp://")
	if !tcp {
		return configured, nil // ParsePolicy validates bare numeric addresses.
	}
	if addr, err := netip.ParseAddr(authority); err == nil && addr.Is4() {
		return addr.String(), nil
	}
	if strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]") {
		if addr, err := netip.ParseAddr(authority[1 : len(authority)-1]); err == nil && addr.Is6() && addr.Zone() == "" {
			return addr.String(), nil
		}
	}
	if endpoint, err := netip.ParseAddrPort(authority); err == nil && endpoint.Port() == 53 && endpoint.Addr().Zone() == "" {
		return endpoint.Addr().String(), nil
	}
	return "", errors.New("sandbox TCP DNS requires a numeric resolver address on port 53")
}

// Resolve only explicit selectors against the live engine, never its global
// STARTED flag (which may mean an unselected proxy answered a health check).
func (p *sandboxProfile) selectedTag() (string, error) {
	if p.blocked != nil {
		return "", p.blocked
	}
	tag := p.final
	seen := make(map[string]bool)
	for {
		member, isSelector := p.selectors[tag]
		if !isSelector {
			break
		}
		// Clash can change a selector without entering sandboxSelection. Only
		// singleton selectors cannot change the authorized route in this way.
		if p.externalController && member == "" {
			return "", errors.New("external Clash control requires a single VLESS/Reality exit at every selector")
		}
		if seen[tag] {
			return "", errors.New("sandbox selector cycle")
		}
		seen[tag] = true
		box := static.Box()
		if box == nil {
			return "", errors.New("core is not running")
		}
		outbound, ok := box.Outbound().Outbound(tag)
		if !ok {
			return "", errors.New("sandbox selector is unavailable")
		}
		selector, ok := outbound.(*group.Selector)
		if !ok {
			return "", errors.New("sandbox selection is not explicit")
		}
		selected := selector.Selected("tcp")
		if selected == nil {
			return "", errors.New("sandbox selector has no proxy")
		}
		tag = selected.Tag()
		if p.externalController && tag != member {
			return "", errors.New("the selected proxy does not match the sole configured exit")
		}
	}
	return tag, nil
}

func (p *sandboxProfile) selected() (*sandbox.Policy, verifiedRealityPeers, error) {
	tag, err := p.selectedTag()
	if err != nil {
		return nil, nil, err
	}
	policy := p.leaves[tag]
	if policy == nil {
		if err := p.errors[tag]; err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("sandbox has no supported selected proxy")
	}
	domain := policy.Type == "vless" && sandbox.IsRealityDomain(policy.Server)
	if !p.externalController && !domain {
		return policy, nil, nil
	}
	if policy.Type != "vless" {
		return nil, nil, errors.New("external Clash control requires a single VLESS/Reality exit")
	}
	box := static.Box()
	if box == nil {
		return nil, nil, errors.New("core is not running")
	}
	live, ok := box.Outbound().Outbound(tag)
	if !ok || live.Type() != policy.Type {
		return nil, nil, errors.New("the selected proxy does not match the running Reality exit")
	}
	if domain {
		source, ok := live.(verifiedRealityPeers)
		if !ok {
			return nil, nil, errors.New("the selected Reality exit cannot report a verified peer")
		}
		return policy, source, nil
	}
	return policy, nil, nil
}

func sandboxPublishProfile(ctx context.Context, profile *sandboxProfile) {
	generation, _ := ctx.Value(sandboxGenerationKey{}).(uint64)
	policy, source, err := profile.selected()
	engine := weak.Make(static.Box())
	sandboxLeases.Lock()
	if generation != sandboxLeases.generation || contextErr(ctx) != nil {
		sandboxLeases.Unlock()
		return
	}
	// Only the first publication of a new engine may replay a connection
	// authenticated during startup. Reloads and selections on the same engine
	// require a fresh connection, even when they return to the same outbound.
	replay := engine != sandboxLeases.lastEngine
	sandboxLeases.lastEngine = engine
	previousWatch := sandboxLeases.watch
	var watch *sandboxPeerWatch
	if source != nil {
		updates, unwatch := source.WatchVerifiedRealityPeer(replay)
		watch = &sandboxPeerWatch{generation: generation, template: *policy, updates: updates, unsubscribe: unwatch}
		policy = nil
		err = errors.New(sandboxWaitingForPeer)
	}
	sandboxLeases.watch = watch
	sandboxLeases.profile = profile
	sandboxLeases.policy = policy
	sandboxLeases.offlineReason = ""
	if err != nil {
		// selected() and the leaf validators use fixed diagnostics which can be
		// sent to users without disclosing tags, credentials or endpoint values.
		sandboxLeases.offlineReason = err.Error()
	}
	sandboxLeases.revision++
	revision := sandboxLeases.revision
	sessions := sandboxSessionsLocked()
	sandboxLeases.Unlock()
	if previousWatch != nil {
		previousWatch.unsubscribe()
	}
	if watch != nil {
		go watch.run()
	}
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
	sandboxBeginLocked(context.Background())
}

func (s *CoreService) RunSandbox(request *SandboxRunRequest, stream grpc.ServerStreamingServer[SandboxEvent]) error {
	return s.runIsolated(request, stream, false)
}

func (s *CoreService) RunApplication(request *SandboxRunRequest, stream grpc.ServerStreamingServer[SandboxEvent]) error {
	return s.runIsolated(request, stream, true)
}

func (s *CoreService) runIsolated(request *SandboxRunRequest, stream grpc.ServerStreamingServer[SandboxEvent], selectedApplication bool) error {
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
		ChromiumSandbox: request.ChromiumSandbox, PrivateWayland: request.PrivateWayland, SelectedApplication: selectedApplication,
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
			if state == SandboxState_SANDBOX_OFFLINE && event.Error == "" {
				sandboxLeases.Lock()
				if event.Revision == sandboxLeases.revision {
					event.Error = sandboxLeases.offlineReason
				}
				sandboxLeases.Unlock()
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
