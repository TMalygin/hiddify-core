//go:build linux && !android

package hcore

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestSandboxDomainPeerMatchesInstalledConfiguration(t *testing.T) {
	sandboxRealitySettings(t)
	installed := sandboxRealityOptions(t)
	installed.Server = "installed.invalid"
	const tag = "same-tag"
	profile := func(vless *option.VLESSOutboundOptions) option.Options {
		return option.Options{
			Route:     &option.RouteOptions{Final: tag},
			Outbounds: []option.Outbound{{Type: "vless", Tag: tag, Options: vless}},
		}
	}
	// Installation goes through the production outbound manager. The test
	// controls only the chosen connection's verified physical peer feed.
	source := domainPeerEngine(t, profile(installed))[tag]
	require.NotNil(t, source)
	peer := netip.MustParseAddrPort("192.0.2.31:443")
	granted := func() bool {
		sandboxLeases.Lock()
		defer sandboxLeases.Unlock()
		return sandboxLeases.policy != nil
	}
	alternateKey := sandboxRealityOptions(t).TLS.Reality.PublicKey
	changes := []struct {
		name   string
		change func(*option.VLESSOutboundOptions)
	}{
		{"endpoint name", func(o *option.VLESSOutboundOptions) { o.Server = "replacement.invalid" }},
		{"port", func(o *option.VLESSOutboundOptions) { o.ServerPort = 1443 }},
		{"SNI", func(o *option.VLESSOutboundOptions) { o.TLS.ServerName = "other-sni.example" }},
		{"public key", func(o *option.VLESSOutboundOptions) { o.TLS.Reality.PublicKey = alternateKey }},
		{"UUID", func(o *option.VLESSOutboundOptions) { o.UUID = "62cfe2ec-f862-487d-9de6-0c86a13f5b9d" }},
		{"short ID", func(o *option.VLESSOutboundOptions) { o.TLS.Reality.ShortID = "aa" }},
		{"flow", func(o *option.VLESSOutboundOptions) { o.Flow = "" }},
		{"fingerprint", func(o *option.VLESSOutboundOptions) { o.TLS.UTLS.Fingerprint = "firefox" }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			candidate := *installed
			tls, utls, reality := *installed.TLS, *installed.TLS.UTLS, *installed.TLS.Reality
			candidate.TLS = &tls
			tls.UTLS, tls.Reality = &utls, &reality
			test.change(&candidate)
			options := profile(&candidate)
			sandboxPublish(sandboxBegin(context.Background()), &options)
			source.record(peer) // authentication by the installed configuration
			require.Never(t, granted, 45*time.Millisecond, 2*time.Millisecond,
				"a physical peer for the installed exit must not authorize another profile's parameters")
			require.False(t, source.subscribed(), "only a matching live exit should receive a subscription")
		})
	}
	// This matches by content despite allocating fresh option structures.
	copy := *installed
	tls, utls, reality := *installed.TLS, *installed.TLS.UTLS, *installed.TLS.Reality
	copy.TLS = &tls
	tls.UTLS, tls.Reality = &utls, &reality
	matched := profile(&copy)
	sandboxPublish(sandboxBegin(context.Background()), &matched)
	require.False(t, granted(), "an exact match still requires authentication after a replacement")
	source.record(peer)
	require.Eventually(t, granted, time.Second, 2*time.Millisecond, "the actual configured exit remains usable")
}
