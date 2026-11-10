//go:build linux && !android

package hcore

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/hcore/sandbox"
	"github.com/sagernet/sing-box/option"
)

// These tests never start a core or dial a server. All credentials are synthetic;
// X25519 key material is generated in memory and is never written to a fixture.
// No test is parallel: sandboxLeaf reads the process-wide HiddifyOptions snapshot.
func sandboxRealitySettings(t *testing.T) {
	t.Helper()
	previous := static.HiddifyOptions
	static.HiddifyOptions = &config.HiddifyOptions{
		DNSOptions: config.DNSOptions{RemoteDnsAddress: "203.0.113.53"},
	}
	t.Cleanup(func() { static.HiddifyOptions = previous })
}

func sandboxRealityOptions(t *testing.T) *option.VLESSOutboundOptions {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "192.0.2.48", ServerPort: 443},
		UUID:          "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:          "xtls-rprx-vision",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled: true, ServerName: "sandbox-reality.example",
				UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
				Reality: &option.OutboundRealityOptions{
					Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
					ShortID: "0123456789abcdef",
				},
			},
		},
	}
}

func sandboxRealityExtract(t *testing.T, options *option.VLESSOutboundOptions) (*sandbox.Policy, map[string]any) {
	t.Helper()
	policy, err := sandboxLeaf(option.Outbound{Type: "vless", Tag: "fixture", Options: options})
	if err != nil {
		t.Fatalf("a supported VLESS/Reality leaf must be accepted: %v", err)
	}
	if policy == nil {
		t.Fatal("accepted VLESS/Reality leaf has no sealed policy")
	}
	content, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(content, &fields); err != nil {
		t.Fatal(err)
	}
	// The capability-boundary parser must accept the extracted snapshot too.
	roundtrip, err := sandbox.ParsePolicy(bytes.NewReader(content))
	if err != nil {
		t.Fatalf("extracted policy fails capability-boundary validation: %v", err)
	}
	if !reflect.DeepEqual(policy, roundtrip) {
		t.Fatal("policy changed after its sealed JSON round trip")
	}
	return policy, fields
}

func TestSandboxRealityLeafPreservesSupportedPolicy(t *testing.T) {
	sandboxRealitySettings(t)
	for _, flow := range []string{"", "xtls-rprx-vision"} {
		t.Run("flow="+flow, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			options.Flow = flow
			_, fields := sandboxRealityExtract(t, options)
			want := map[string]any{
				"type": "vless", "server": options.Server, "server_port": float64(options.ServerPort),
				"dns_server": "203.0.113.53", "uuid": options.UUID,
				"server_name": options.TLS.ServerName, "public_key": options.TLS.Reality.PublicKey,
				"short_id": options.TLS.Reality.ShortID, "fingerprint": "chrome",
				"packet_encoding": "xudp", "key_share": "hybrid",
			}
			if flow != "" {
				want["flow"] = flow
			}
			for key, value := range want {
				if !reflect.DeepEqual(fields[key], value) {
					t.Errorf("supported policy field %q was lost or changed", key)
				}
			}
			if value, exists := fields["flow"]; flow == "" && exists && value != "" {
				t.Error("empty VLESS flow was changed")
			}
			for _, key := range []string{"version", "username", "password"} {
				if value, exists := fields[key]; exists && value != "" {
					t.Errorf("VLESS snapshot contains SOCKS field %q", key)
				}
			}
		})
	}
}

func TestSandboxRealityLeafAcceptsExplicitSupportedSettings(t *testing.T) {
	sandboxRealitySettings(t)
	for _, fingerprint := range []string{"", "chrome", "firefox", "edge", "safari", "ios", "android"} {
		t.Run("fingerprint="+fingerprint, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			options.TLS.UTLS.Fingerprint = fingerprint
			options.TLS.Reality.KeyShare = "hybrid"
			packet := "xudp"
			options.PacketEncoding = &packet
			_, fields := sandboxRealityExtract(t, options)
			want := fingerprint
			if want == "" {
				want = "chrome"
			}
			if fields["fingerprint"] != want || fields["packet_encoding"] != "xudp" || fields["key_share"] != "hybrid" {
				t.Fatal("explicit fingerprint/XUDP/hybrid policy was changed")
			}
		})
	}
	t.Run("explicit no extra encryption", func(t *testing.T) {
		options := sandboxRealityOptions(t)
		options.Encryption = "none"
		_, fields := sandboxRealityExtract(t, options)
		if value, exists := fields["encryption"]; exists && value != "" && value != "none" {
			t.Fatal("explicit no-extra-encryption profile changed its security mode")
		}
	})
	t.Run("IPv6 endpoints and empty short ID", func(t *testing.T) {
		options := sandboxRealityOptions(t)
		options.Server = "2001:db8::48"
		options.TLS.Reality.ShortID = ""
		static.HiddifyOptions.RemoteDnsAddress = "2001:db8::53"
		_, fields := sandboxRealityExtract(t, options)
		if fields["server"] != options.Server || fields["dns_server"] != "2001:db8::53" {
			t.Fatal("IPv6 endpoints were not preserved")
		}
	})
}

func sandboxRealityReject(t *testing.T, options *option.VLESSOutboundOptions) {
	t.Helper()
	policy, err := sandboxLeaf(option.Outbound{Type: "vless", Tag: "fixture", Options: options})
	if err == nil || policy != nil {
		t.Fatal("unsupported VLESS/Reality settings must return an error and no policy")
	}
	secrets := []string{options.UUID, "rejected-secret-sentinel"}
	if options.TLS != nil {
		secrets = append(secrets, options.TLS.ServerName)
		if options.TLS.Reality != nil {
			secrets = append(secrets, options.TLS.Reality.PublicKey, options.TLS.Reality.ShortID)
		}
	}
	for _, secret := range secrets {
		if len(secret) >= 8 && strings.Contains(err.Error(), secret) {
			t.Fatal("rejected profile error discloses a credential or profile value")
		}
	}
}

func TestSandboxRealityLeafRejectsUnsupportedCombinations(t *testing.T) {
	sandboxRealitySettings(t)
	cases := map[string]func(*option.VLESSOutboundOptions){
		"TLS absent":             func(o *option.VLESSOutboundOptions) { o.TLS = nil },
		"TLS disabled":           func(o *option.VLESSOutboundOptions) { o.TLS.Enabled = false },
		"Reality absent":         func(o *option.VLESSOutboundOptions) { o.TLS.Reality = nil },
		"Reality disabled":       func(o *option.VLESSOutboundOptions) { o.TLS.Reality.Enabled = false },
		"uTLS absent":            func(o *option.VLESSOutboundOptions) { o.TLS.UTLS = nil },
		"uTLS disabled":          func(o *option.VLESSOutboundOptions) { o.TLS.UTLS.Enabled = false },
		"unsafe fingerprint":     func(o *option.VLESSOutboundOptions) { o.TLS.UTLS.Fingerprint = "unsafe" },
		"unknown fingerprint":    func(o *option.VLESSOutboundOptions) { o.TLS.UTLS.Fingerprint = "rejected-secret-sentinel" },
		"random fingerprint":     func(o *option.VLESSOutboundOptions) { o.TLS.UTLS.Fingerprint = "random" },
		"randomized fingerprint": func(o *option.VLESSOutboundOptions) { o.TLS.UTLS.Fingerprint = "randomized" },
		"automatic key share":    func(o *option.VLESSOutboundOptions) { o.TLS.Reality.KeyShare = "auto" },
		"classical key share":    func(o *option.VLESSOutboundOptions) { o.TLS.Reality.KeyShare = "classical" },
		"unknown flow":           func(o *option.VLESSOutboundOptions) { o.Flow = "rejected-secret-sentinel" },
		"extra encryption":       func(o *option.VLESSOutboundOptions) { o.Encryption = "rejected-secret-sentinel" },
		"mux object":             func(o *option.VLESSOutboundOptions) { o.Multiplex = &option.OutboundMultiplexOptions{} },
		"mux enabled":            func(o *option.VLESSOutboundOptions) { o.Multiplex = &option.OutboundMultiplexOptions{Enabled: true} },
		"transport object":       func(o *option.VLESSOutboundOptions) { o.Transport = &option.V2RayTransportOptions{} },
		"TCP-only network":       func(o *option.VLESSOutboundOptions) { o.Network = "tcp" },
		"UDP-only network":       func(o *option.VLESSOutboundOptions) { o.Network = "udp" },
		"native UDP":             func(o *option.VLESSOutboundOptions) { value := ""; o.PacketEncoding = &value },
		"packetaddr UDP":         func(o *option.VLESSOutboundOptions) { value := "packetaddr"; o.PacketEncoding = &value },
		"unknown encoding":       func(o *option.VLESSOutboundOptions) { value := "rejected-secret-sentinel"; o.PacketEncoding = &value },
		"zero port":              func(o *option.VLESSOutboundOptions) { o.ServerPort = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			mutate(options)
			sandboxRealityReject(t, options)
		})
	}
	for _, value := range []string{"", "rejected-secret-sentinel", "00000000-0000-0000-0000-000000000000", "B831381D-6324-4D53-AD4F-8CDA48B30811", "b831381d63244d53ad4f8cda48b30811"} {
		t.Run("invalid UUID="+value, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			options.UUID = value
			sandboxRealityReject(t, options)
		})
	}
	for index, value := range []string{"", "rejected-secret-sentinel", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), base64.RawURLEncoding.EncodeToString(make([]byte, 32)), base64.RawURLEncoding.EncodeToString(make([]byte, 33))} {
		t.Run("invalid public key="+strconv.Itoa(index), func(t *testing.T) {
			options := sandboxRealityOptions(t)
			options.TLS.Reality.PublicKey = value
			sandboxRealityReject(t, options)
		})
	}
	t.Run("padded public key", func(t *testing.T) {
		options := sandboxRealityOptions(t)
		options.TLS.Reality.PublicKey += "="
		sandboxRealityReject(t, options)
	})
	for _, value := range []string{"0", "gg", "0123456789abcdef00", "rejected-secret-sentinel"} {
		t.Run("invalid short ID="+value, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			options.TLS.Reality.ShortID = value
			sandboxRealityReject(t, options)
		})
	}
	for _, value := range []string{"", "127.0.0.1", "[::1]", "https://example.com", "example.com:443", "bad name.example", "bad\nname.example", "-bad.example", "bad-.example", "bad..example"} {
		t.Run("invalid SNI="+value, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			options.TLS.ServerName = value
			sandboxRealityReject(t, options)
		})
	}
}

func TestSandboxRealityLeafRejectsNonNumericAndUnsafeEndpoints(t *testing.T) {
	sandboxRealitySettings(t)
	for _, value := range []string{"", "bootstrap.example", "https://resolver.example/dns-query", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "169.254.1.2", "fe80::1", "fe80::1%eth0"} {
		t.Run("server="+value, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			options.Server = value
			sandboxRealityReject(t, options)
		})
		t.Run("DNS="+value, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			previous := static.HiddifyOptions.RemoteDnsAddress
			static.HiddifyOptions.RemoteDnsAddress = value
			defer func() { static.HiddifyOptions.RemoteDnsAddress = previous }()
			sandboxRealityReject(t, options)
		})
	}
}

// Set only one unsupported field at a time so accepting any new configuration
// surface requires an explicit extension of the reviewed whitelist. Pointer and
// slice presence is itself nonzero; their contents need not be meaningful.
func sandboxRealityNonzero(t *testing.T, value reflect.Value) {
	t.Helper()
	switch value.Kind() {
	case reflect.Bool:
		value.SetBool(true)
	case reflect.String:
		value.SetString("rejected-secret-sentinel")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value.SetUint(1)
	case reflect.Pointer:
		value.Set(reflect.New(value.Type().Elem()))
	case reflect.Slice:
		value.Set(reflect.MakeSlice(value.Type(), 1, 1))
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if value.Field(index).CanSet() {
				sandboxRealityNonzero(t, value.Field(index))
				return
			}
		}
		t.Fatalf("cannot populate unsupported struct %s", value.Type())
	default:
		t.Fatalf("add explicit whitelist test data for %s", value.Type())
	}
	if value.IsZero() {
		t.Fatalf("unsupported-field fixture remained zero for %s", value.Type())
	}
}

func TestSandboxRealityLeafRejectsEveryOtherTLSField(t *testing.T) {
	sandboxRealitySettings(t)
	allowed := map[string]bool{"Enabled": true, "ServerName": true, "UTLS": true, "Reality": true}
	typ := reflect.TypeOf(option.OutboundTLSOptions{})
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if allowed[field.Name] {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			options := sandboxRealityOptions(t)
			sandboxRealityNonzero(t, reflect.ValueOf(options.TLS).Elem().Field(index))
			sandboxRealityReject(t, options)
		})
	}
}

func TestSandboxRealityLeafRejectsEveryCustomDialerField(t *testing.T) {
	sandboxRealitySettings(t)
	var walk func(reflect.Type, []int, string)
	walk = func(typ reflect.Type, prefix []int, label string) {
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			path := append(append([]int{}, prefix...), index)
			if field.Anonymous && field.Type.Kind() == reflect.Struct {
				walk(field.Type, path, label+field.Name+"/")
				continue
			}
			t.Run(label+field.Name, func(t *testing.T) {
				options := sandboxRealityOptions(t)
				sandboxRealityNonzero(t, reflect.ValueOf(&options.DialerOptions).Elem().FieldByIndex(path))
				sandboxRealityReject(t, options)
			})
		}
	}
	walk(reflect.TypeOf(option.DialerOptions{}), nil, "")
}

func TestSandboxRealityLeafRequiresSettingsAndMatchingOptionType(t *testing.T) {
	sandboxRealitySettings(t)
	t.Run("missing settings", func(t *testing.T) {
		previous := static.HiddifyOptions
		static.HiddifyOptions = nil
		defer func() { static.HiddifyOptions = previous }()
		sandboxRealityReject(t, sandboxRealityOptions(t))
	})
	for _, outbound := range []option.Outbound{
		{Type: "vless", Options: nil},
		{Type: "vless", Options: (*option.VLESSOutboundOptions)(nil)},
		{Type: "vless", Options: &option.SOCKSOutboundOptions{}},
		{Type: "direct", Options: sandboxRealityOptions(t)},
		{Type: "socks", Options: sandboxRealityOptions(t)},
	} {
		t.Run(outbound.Type, func(t *testing.T) {
			policy, err := sandboxLeaf(outbound)
			if err == nil || policy != nil {
				t.Fatal("outbound type/options mismatch must not grant a policy")
			}
		})
	}
}

func TestSandboxRealityLeafSnapshotDoesNotFollowSourceMutations(t *testing.T) {
	sandboxRealitySettings(t)
	options := sandboxRealityOptions(t)
	policy, _ := sandboxRealityExtract(t, options)
	before, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	options.Server = "198.51.100.49"
	options.UUID = "b831381d-6324-4d53-ad4f-8cda48b30812"
	options.Flow = ""
	options.TLS.ServerName = "different.example"
	options.TLS.UTLS.Fingerprint = "firefox"
	options.TLS.Reality.PublicKey = "rejected-secret-sentinel"
	options.TLS.Reality.ShortID = ""
	options.TLS.Reality.KeyShare = "auto"
	static.HiddifyOptions.RemoteDnsAddress = "203.0.113.54"
	after, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("accepted policy changed through a mutable profile/settings alias")
	}
}
