//go:build linux && !android

package hcore

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestSandboxDefaultRemoteDNS(t *testing.T) {
	sandboxRealitySettings(t)
	vless := option.Outbound{Tag: "reality", Type: "vless", Options: sandboxRealityOptions(t)}
	for _, tc := range []struct{ input, address string }{
		{"8.8.8.8", "8.8.8.8"}, {"tcp://8.8.8.8", "8.8.8.8"},
		{"tcp://192.0.2.53:53", "192.0.2.53"}, {"tcp://[2001:db8::53]", "2001:db8::53"},
		{"tcp://[2001:db8::53]:53", "2001:db8::53"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			static.HiddifyOptions.RemoteDnsAddress = tc.input
			policy, err := sandboxLeaf(vless)
			require.NoError(t, err, "managed DNS must accept this explicit TCP resolver")
			require.NotNil(t, policy)
			require.Equal(t, tc.address, policy.DNSServer)
			require.Equal(t, tc.input, static.HiddifyOptions.RemoteDnsAddress, "keep the ordinary profile settings")
		})
	}
	for _, address := range []string{
		"tcp://resolver.invalid", "tcp://192.0.2.1:54", "tcp://192.0.2.1:", "tcp://192.0.2.1/path",
		"tcp://192.0.2.1?x", "tcp://192.0.2.1#", "tcp://192.0.2.1?", "tcp://a@192.0.2.1",
		"tcp://[fe80::1%25lo]", "tcp://0.0.0.0", "tcp://224.0.0.1", "tcp://169.254.1.1",
		"udp://192.0.2.53", "tls://192.0.2.53", "https://192.0.2.53/dns-query", "local",
	} {
		t.Run(address, func(t *testing.T) {
			static.HiddifyOptions.RemoteDnsAddress = address
			policy, err := sandboxLeaf(vless)
			require.Error(t, err)
			require.Nil(t, policy)
		})
	}
}

func TestSandboxDefaultClashProfilePermission(t *testing.T) {
	sandboxRealitySettings(t)
	leaf := func(tag string) option.Outbound {
		o := sandboxRealityOptions(t)
		o.Server = "127.0.0.1"
		return option.Outbound{Type: "vless", Tag: tag, Options: o}
	}
	selector := func(tag string, members ...string) option.Outbound {
		return option.Outbound{Type: "selector", Tag: tag, Options: &option.SelectorOutboundOptions{Outbounds: members}}
	}
	opts := option.Options{
		Experimental: &option.ExperimentalOptions{ClashAPI: &option.ClashAPIOptions{ExternalController: "127.0.0.1:0"}},
		Route:        &option.RouteOptions{Final: "root"},
		Outbounds: []option.Outbound{
			leaf("a"), leaf("b"), {Type: "direct", Tag: "direct", Options: &option.DirectOutboundOptions{}},
			selector("root", "inner"), selector("inner", "a"), selector("mutable", "a", "b"),
			selector("mixed", "a", "direct"), selector("nested-mixed", "mixed"),
		},
	}
	// Use actual engine selectors and the ordinary external controller. This
	// fixture has no external inbounds, and both proxy endpoints are loopback.
	server, err := NewService(libbox.BaseContext(nil), opts, nil)
	require.NoError(t, err)
	prev := static.StartedService
	static.StartedService = server
	t.Cleanup(func() {
		sandboxBegin(context.Background())
		static.StartedService = prev
		require.NoError(t, closeService(server))
	})
	check := func(t *testing.T, opts option.Options, allowed bool) {
		t.Helper()
		ctx := sandboxBegin(context.Background())
		sandboxPublish(ctx, &opts)
		sandboxLeases.Lock()
		policy := sandboxLeases.policy
		sandboxLeases.Unlock()
		if allowed {
			require.NotNil(t, policy, "an unambiguous accepted Reality profile must authorize the managed app")
			require.Equal(t, "vless", policy.Type)
			require.Equal(t, "127.0.0.1", policy.Server)
			require.Equal(t, "203.0.113.53", policy.DNSServer)
		} else {
			require.Nil(t, policy, "an unguarded external selector must not grant a stale or direct route")
		}
	}
	for _, tc := range []struct {
		final   string
		allowed bool
	}{
		{"root", true}, {"inner", true}, {"a", true}, {"mutable", false}, {"mixed", false},
		{"nested-mixed", false}, {"direct", false}, {"missing", false},
	} {
		t.Run(tc.final, func(t *testing.T) {
			selected := opts
			selected.Route = &option.RouteOptions{Final: tc.final}
			check(t, selected, tc.allowed)
		})
	}
	// Feed malformed snapshots to the publication boundary as well: neither
	// duplicate definitions nor cycles can establish a unique authorized leaf.
	for name, extra := range map[string][]option.Outbound{
		"ambiguous-tag": {leaf("a")},
		"cycle":         {selector("loop", "loop")},
		"unknown-type":  {{Type: "direct", Tag: "a", Options: &option.DirectOutboundOptions{}}},
	} {
		t.Run(name, func(t *testing.T) {
			malformed := opts
			malformed.Outbounds = append(append([]option.Outbound{}, opts.Outbounds...), extra...)
			if name == "cycle" {
				malformed.Route = &option.RouteOptions{Final: "loop"}
			}
			check(t, malformed, false)
		})
	}
	t.Run("disconnect invalidates old permission", func(t *testing.T) {
		check(t, opts, true)
		completeOldSelection := sandboxSelection()
		sandboxBegin(context.Background())
		completeOldSelection(true)
		sandboxLeases.Lock()
		defer sandboxLeases.Unlock()
		require.Nil(t, sandboxLeases.profile)
		require.Nil(t, sandboxLeases.policy)
	})
	t.Run("switch between profiles with one Reality exit each", func(t *testing.T) {
		first, second := opts, opts
		first.Route = &option.RouteOptions{Final: "a"}
		second.Route = &option.RouteOptions{Final: "b"}
		first.Outbounds = opts.Outbounds[:1]
		second.Outbounds = opts.Outbounds[1:2]
		check(t, first, true)
		completeFirst := sandboxSelection()
		check(t, second, true)
		completeFirst(true)
		sandboxLeases.Lock()
		defer sandboxLeases.Unlock()
		require.NotNil(t, sandboxLeases.policy)
		require.Equal(t, second.Outbounds[0].Options.(*option.VLESSOutboundOptions).TLS.Reality.PublicKey, sandboxLeases.policy.PublicKey)
	})
}
