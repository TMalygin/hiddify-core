//go:build linux && !android

package hcore

import (
	"context"
	"os"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service/filemanager"
	"github.com/stretchr/testify/require"
)

func TestManagedImplicitRouteMatchesRunningEngine(t *testing.T) {
	sandboxRealitySettings(t)
	direct := option.Outbound{Type: "direct", Options: &option.DirectOutboundOptions{}}
	reality := sandboxRealityOptions(t)
	reality.Server = "127.0.0.1"
	proxy := option.Outbound{Type: "vless", Options: reality}
	controller := &option.ExperimentalOptions{ClashAPI: &option.ClashAPIOptions{ExternalController: "127.0.0.1:0"}}
	live := func(t *testing.T, outbounds ...option.Outbound) option.Options {
		t.Helper()
		options := option.Options{Outbounds: outbounds, Experimental: controller}
		dir := t.TempDir()
		ctx := filemanager.WithDefault(libbox.BaseContext(nil), dir, dir, os.Getuid(), os.Getgid())
		instance, err := NewService(ctx, options, nil)
		require.NoError(t, err)
		old := static.StartedService
		static.StartedService = instance
		t.Cleanup(func() {
			sandboxBegin(context.Background())
			static.StartedService = old
			require.NoError(t, closeService(instance))
		})
		return options
	}
	requirePolicy := func(t *testing.T, options option.Options, allowed bool) {
		t.Helper()
		sandboxPublish(sandboxBegin(context.Background()), &options)
		sandboxLeases.Lock()
		defer sandboxLeases.Unlock()
		if allowed {
			require.NotNil(t, sandboxLeases.policy)
			require.Equal(t, reality.TLS.Reality.PublicKey, sandboxLeases.policy.PublicKey)
		} else {
			require.Nil(t, sandboxLeases.policy, "only the identified running Reality exit may supply a lease")
		}
	}
	t.Run("anonymous direct is the actual default", func(t *testing.T) {
		options := live(t, direct, proxy)
		main := static.Box().Outbound().Default()
		require.Equal(t, "0", main.Tag())
		require.Equal(t, "direct", main.Type())
		requirePolicy(t, options, false)
	})
	t.Run("anonymous Reality is the actual default", func(t *testing.T) {
		options := live(t, proxy, direct)
		require.Equal(t, "vless", static.Box().Outbound().Default().Type())
		requirePolicy(t, options, true)
		// The engine accepts numeric references to the tag it assigned to an
		// anonymous outbound. Tag 1 belongs to the DIRECT outbound in this box.
		options.Route = &option.RouteOptions{Final: "1"}
		requirePolicy(t, options, false)
	})
	t.Run("an omitted final can retain an earlier engine default after reload", func(t *testing.T) {
		p, d := proxy, direct
		p.Tag, d.Tag = "reality", "ordinary"
		options := live(t, p, d)
		manager := static.Box().Outbound().(interface{ SetDefaultTag(string) error })
		require.NoError(t, manager.SetDefaultTag(d.Tag))
		require.NoError(t, manager.SetDefaultTag(""))
		require.Equal(t, d.Tag, static.Box().Outbound().Default().Tag())
		requirePolicy(t, options, false)
	})
	t.Run("a colliding endpoint cannot supply a verified outlet identity", func(t *testing.T) {
		p := proxy
		p.Tag = "reality"
		options := live(t, p)
		options.Endpoints = []option.Endpoint{{Type: "wireguard", Tag: p.Tag}}
		requirePolicy(t, options, false)
	})
	t.Run("a numeric tag colliding with an implicit outbound is ambiguous", func(t *testing.T) {
		options := live(t, direct, proxy)
		p := proxy
		p.Tag = "0"
		options.Outbounds = append(options.Outbounds, p)
		options.Route = &option.RouteOptions{Final: "0"}
		requirePolicy(t, options, false)
	})
}
