//go:build linux && !android

package sandbox

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func realityPolicyFixture(t *testing.T) map[string]any {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"type": "vless", "server": "192.0.2.48", "server_port": 443,
		"dns_server": "203.0.113.53", "uuid": "00000000-0000-4000-8000-000000000048",
		"flow": "xtls-rprx-vision", "server_name": "reality.test",
		"public_key": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		"short_id":   "0123456789abcdef", "fingerprint": "chrome",
		"packet_encoding": "xudp", "key_share": "hybrid",
	}
}

func realityPolicyJSON(t *testing.T, value map[string]any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRealityPolicyCreatesOnlyPinnedProxyAndProxiedDNS(t *testing.T) {
	for _, flow := range []string{"", "xtls-rprx-vision"} {
		for _, fingerprint := range []string{"chrome", "firefox", "edge", "safari", "ios", "android"} {
			t.Run(flow+"/"+fingerprint, func(t *testing.T) {
				input := realityPolicyFixture(t)
				input["flow"], input["fingerprint"] = flow, fingerprint
				policy, err := readPolicy(strings.NewReader(realityPolicyJSON(t, input)))
				if err != nil {
					t.Fatalf("supported VLESS/Reality policy rejected: %v", err)
				}
				options := workerOptions(policy, "/proc/self/fd/123")
				if len(options.Outbounds) != 1 || options.Outbounds[0].Type != "vless" || options.Outbounds[0].Tag != "proxy" {
					t.Fatalf("worker must contain exactly one VLESS proxy, got %#v", options.Outbounds)
				}
				proxy, ok := options.Outbounds[0].Options.(*option.VLESSOutboundOptions)
				if !ok {
					t.Fatal("worker outbound is not VLESS")
				}
				if proxy.Server != input["server"] || proxy.ServerPort != 443 || proxy.UUID != input["uuid"] || proxy.Flow != flow || proxy.PacketEncoding == nil || *proxy.PacketEncoding != "xudp" {
					t.Fatal("worker changed VLESS endpoint, identity, flow or UDP encoding")
				}
				expectedTLS := &option.OutboundTLSOptions{
					Enabled: true, ServerName: "reality.test",
					UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
					Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: input["public_key"].(string), ShortID: "0123456789abcdef", KeyShare: "hybrid"},
				}
				if !reflect.DeepEqual(proxy.TLS, expectedTLS) {
					t.Fatal("worker changed or weakened the validated TLS/Reality settings")
				}
				if !reflect.DeepEqual(proxy.DialerOptions, option.DialerOptions{}) || proxy.Network != "" || proxy.Transport != nil || proxy.Multiplex != nil || proxy.Encryption != "" {
					t.Fatal("worker contains an unapproved dialer, transport, mux, encryption or network override")
				}
				if options.Route == nil || options.Route.Final != "proxy" || len(options.Route.Rules) != 0 {
					t.Fatal("worker permits a route outside the proxy")
				}
				if options.DNS == nil || options.DNS.Final != "proxy-dns" || len(options.DNS.Servers) != 1 {
					t.Fatal("worker DNS has a fallback")
				}
				dns := options.DNS.Servers[0]
				remote, ok := dns.Options.(*option.RemoteDNSServerOptions)
				if !ok || dns.Type != "tcp" || remote.Server != input["dns_server"] || remote.ServerPort != 53 || remote.Detour != "proxy" {
					t.Fatal("worker DNS escapes proxy")
				}
				if len(options.Inbounds) != 1 || options.Inbounds[0].Type != "tun" {
					t.Fatal("worker exposes an extra inbound")
				}
				tun := options.Inbounds[0].Options.(*option.TunInboundOptions)
				if tun.NetNs != "/proc/self/fd/123" || !tun.AutoRoute || !tun.StrictRoute {
					t.Fatal("worker routes outside the requested namespace")
				}
			})
		}
	}
}

func TestRealityPolicyRejectsUnsupportedOrAmbiguousInputs(t *testing.T) {
	cases := []struct {
		name, field string
		value       any
	}{
		{"direct", "type", "direct"}, {"hostname", "server", "proxy.test"},
		{"dns_hostname", "dns_server", "dns.test"}, {"missing_port", "server_port", 0},
		{"invalid_uuid", "uuid", "do-not-derive-a-uuid-from-this-secret"},
		{"empty_uuid", "uuid", ""}, {"nil_uuid", "uuid", "00000000-0000-0000-0000-000000000000"},
		{"unknown_flow", "flow", "unsupported-flow"}, {"native_udp", "packet_encoding", ""},
		{"packetaddr", "packet_encoding", "packetaddr"}, {"missing_sni", "server_name", ""},
		{"sni_url", "server_name", "https://reality.test"}, {"sni_control", "server_name", "reality.test\n"},
		{"missing_key", "public_key", ""}, {"short_key", "public_key", "AAAA"},
		{"invalid_key", "public_key", "not-a-valid-public-key"},
		{"zero_key", "public_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"odd_short_id", "short_id", "abc"}, {"invalid_short_id", "short_id", "gg"},
		{"long_short_id", "short_id", "0123456789abcdef00"},
		{"unsafe_utls", "fingerprint", "unsafe"}, {"random_utls", "fingerprint", "random"},
		{"unknown_utls", "fingerprint", "typo"}, {"automatic_key_share", "key_share", "auto"},
		{"classical_key_share", "key_share", "classical"},
		{"socks_version", "version", "5"}, {"socks_username", "username", "secret-user"},
		{"empty_socks_password", "password", ""}, {"tls_override", "tls", map[string]any{"insecure": true}},
		{"detour", "detour", "direct"}, {"unknown", "unrecognized", true}, {"null", "flow", nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input := realityPolicyFixture(t)
			input[test.field] = test.value
			policy, err := readPolicy(strings.NewReader(realityPolicyJSON(t, input)))
			if err == nil || policy != nil {
				t.Fatal("unsupported or invalid policy was accepted")
			}
			for _, secret := range []string{input["uuid"].(string), input["public_key"].(string), "secret-user"} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Fatal("validation error disclosed credentials")
				}
			}
		})
	}
	valid := realityPolicyJSON(t, realityPolicyFixture(t))
	for name, raw := range map[string]string{
		"duplicate": strings.TrimSuffix(valid, "}") + `,"flow":""}`,
		"trailing":  valid + ` {}`, "oversized": strings.Repeat(" ", maxPolicyBytes) + valid,
	} {
		t.Run(name, func(t *testing.T) {
			if policy, err := readPolicy(strings.NewReader(raw)); err == nil || policy != nil {
				t.Fatal("ambiguous or oversized policy accepted")
			}
		})
	}
}

func TestRealityPolicyAllowsIPv6AndEmptyShortID(t *testing.T) {
	input := realityPolicyFixture(t)
	input["server"], input["dns_server"], input["short_id"] = "2001:db8::48", "2001:db8::53", ""
	if _, err := readPolicy(strings.NewReader(realityPolicyJSON(t, input))); err != nil {
		t.Fatalf("valid IPv6 policy rejected: %v", err)
	}
}

func TestSocksPolicyRejectsRealityFieldsWithoutChangingLegacyBehavior(t *testing.T) {
	input := map[string]any{"type": "socks", "version": "5", "server": "192.0.2.48", "server_port": 1080, "dns_server": "203.0.113.53"}
	if _, err := readPolicy(strings.NewReader(realityPolicyJSON(t, input))); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"uuid", "flow", "server_name", "public_key", "short_id", "fingerprint", "packet_encoding", "key_share"} {
		t.Run(field, func(t *testing.T) {
			input[field] = ""
			defer delete(input, field)
			if policy, err := readPolicy(strings.NewReader(realityPolicyJSON(t, input))); err == nil || policy != nil {
				t.Fatal("cross-protocol field accepted")
			}
		})
	}
}
