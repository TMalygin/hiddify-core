package config

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// A single local proxy is enough to exercise inbound construction without
// depending on a subscription or contacting a remote server.
const oneProxyProfile = `{"outbounds":[{"type":"socks","tag":"proxy-a","server":"127.0.0.1","server_port":1080}]}`

// Shared helpers from chain_test.go, removed in 2ed0bb5 while callers remained.
func chainTestOptions(t *testing.T, settings string) *HiddifyOptions {
	t.Helper()
	opts := DefaultHiddifyOptions()
	if err := json.Unmarshal([]byte(settings), opts); err != nil {
		t.Fatalf("settings: %v", err)
	}
	return opts
}

func selectorItems(options *option.Options) []string {
	for _, out := range options.Outbounds {
		if out.Tag == OutboundSelectTag {
			return out.Options.(*option.SelectorOutboundOptions).Outbounds
		}
	}
	return nil
}
