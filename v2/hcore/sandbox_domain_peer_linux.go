//go:build linux && !android

package hcore

import (
	"net/netip"

	"github.com/hiddify/hiddify-core/v2/hcore/sandbox"
	"github.com/sagernet/sing-box/option"
)

const sandboxWaitingForPeer = "waiting for the selected Reality exit to authenticate"

// The actual selected outbound owns the feed. Registration only subscribes to
// ordinary foreground traffic and must never resolve or dial the profile.
type verifiedRealityPeers interface {
	WatchVerifiedRealityPeer(replay bool) (<-chan netip.AddrPort, func())
}

// A domain describes the foreground exit. Only a numeric policy from its
// authenticated peer may cross the boundary into the worker.
func sandboxProfileLeaf(outbound option.Outbound) (*sandbox.Policy, error) {
	vless, ok := outbound.Options.(*option.VLESSOutboundOptions)
	if static.HiddifyOptions != nil && outbound.Type == "vless" && ok && vless != nil && sandbox.IsRealityDomain(vless.Server) {
		return sandboxRealityDefinition(outbound)
	}
	return sandboxLeaf(outbound)
}

type sandboxPeerWatch struct {
	generation  uint64
	template    sandbox.Policy
	updates     <-chan netip.AddrPort
	unsubscribe func()
}

func (w *sandboxPeerWatch) run() {
	var previous netip.AddrPort
	for peer := range w.updates {
		// A busy foreground exit can confirm the same endpoint on every
		// connection. Revalidate the immutable Reality policy only on change.
		if peer.IsValid() && peer == previous {
			continue
		}
		previous = peer
		addr := peer.Addr().Unmap()
		if peer.Port() != w.template.ServerPort || peer.Addr().Zone() != "" || !(addr.IsGlobalUnicast() || addr.IsLoopback()) {
			w.publish(nil, "the authenticated Reality peer has an unusable address or port")
			continue
		}
		candidate := w.template
		candidate.Server = addr.String()
		policy, err := sandboxWorkerPolicy(candidate)
		if err != nil {
			w.publish(nil, err.Error())
			continue
		}
		w.publish(policy, "")
	}
	w.publish(nil, sandboxWaitingForPeer)
}

func (w *sandboxPeerWatch) publish(policy *sandbox.Policy, reason string) {
	sandboxLeases.Lock()
	if sandboxLeases.generation != w.generation || sandboxLeases.watch != w {
		sandboxLeases.Unlock()
		return
	}
	// Repeated ordinary connections to the same peer grant no new permission.
	// In particular, they must not restart a worker which failed in this lease.
	previous := sandboxLeases.policy
	if (policy == nil && previous == nil && sandboxLeases.offlineReason == reason) ||
		(policy != nil && previous != nil && previous.Server == policy.Server) {
		sandboxLeases.Unlock()
		return
	}
	sandboxLeases.policy = policy
	sandboxLeases.offlineReason = reason
	sandboxLeases.revision++
	revision := sandboxLeases.revision
	sessions := sandboxSessionsLocked()
	sandboxLeases.Unlock()
	sandboxUpdate(sessions, revision, policy)
}
