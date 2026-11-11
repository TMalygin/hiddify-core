//go:build linux && !android

// Package sandbox implements an experimental console-only launcher. It does not
// consume ordinary profiles or the app's mixed port: both may permit DIRECT.
package sandbox

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

const maxPolicyBytes = 16 * 1024

type proxyPolicy struct {
	Type           string `json:"type"`
	Version        string `json:"version,omitempty"`
	Server         string `json:"server"`
	ServerPort     uint16 `json:"server_port"`
	DNSServer      string `json:"dns_server"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	UUID           string `json:"uuid,omitempty"`
	Flow           string `json:"flow,omitempty"`
	ServerName     string `json:"server_name,omitempty"`
	PublicKey      string `json:"public_key,omitempty"`
	ShortID        string `json:"short_id,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	PacketEncoding string `json:"packet_encoding,omitempty"`
	KeyShare       string `json:"key_share,omitempty"`
}

func readPolicy(reader io.Reader) (*proxyPolicy, error) {
	content, err := io.ReadAll(io.LimitReader(reader, maxPolicyBytes+1))
	if err != nil {
		return nil, errors.New("cannot read proxy policy")
	}
	if len(content) > maxPolicyBytes || !utf8.Valid(content) {
		return nil, errors.New("proxy policy must be UTF-8 and at most 16 KiB")
	}
	// Reject duplicate keys as well as unknown fields. Do not echo field values:
	// the input may contain credentials, including in malformed JSON.
	decoder := json.NewDecoder(bytes.NewReader(content))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("proxy policy must be one JSON object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return nil, errors.New("invalid proxy policy")
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return nil, errors.New("duplicate or invalid proxy policy field")
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return nil, errors.New("invalid proxy policy value")
		}
	}
	var policy proxyPolicy
	decoder = json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil {
		return nil, errors.New("invalid or unsupported proxy policy fields")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("proxy policy must contain exactly one object")
	}
	// Even an empty field for a different protocol is ambiguous. Validate field
	// presence separately from decoded zero values before creating a worker.
	allowed := map[string]bool{"type": true, "server": true, "server_port": true, "dns_server": true}
	var protocolFields []string
	switch policy.Type {
	case "socks":
		protocolFields = []string{"version", "username", "password"}
	case "vless":
		protocolFields = []string{"uuid", "flow", "server_name", "public_key", "short_id", "fingerprint", "packet_encoding", "key_share"}
	default:
		return nil, errors.New("sandbox policy requires SOCKS5 or VLESS/Reality")
	}
	for _, field := range protocolFields {
		allowed[field] = true
	}
	for field := range seen {
		if !allowed[field] {
			return nil, errors.New("proxy policy contains fields for a different protocol")
		}
	}
	if policy.ServerPort == 0 {
		return nil, errors.New("proxy policy requires a nonzero server_port")
	}
	for _, value := range []string{policy.Server, policy.DNSServer} {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
			return nil, errors.New("server and dns_server must be unicast IP literals without a zone")
		}
	}
	if policy.Type == "socks" {
		if policy.Version != "5" {
			return nil, errors.New("sandbox SOCKS policy requires version 5")
		}
		if len(policy.Username) > 255 || len(policy.Password) > 255 {
			return nil, errors.New("SOCKS credentials exceed 255 bytes")
		}
	} else if err := validateRealityPolicy(&policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func validateRealityPolicy(policy *proxyPolicy) error {
	identity, err := uuid.Parse(policy.UUID)
	if err != nil || identity == uuid.Nil || identity.String() != policy.UUID {
		// The engine accepts arbitrary strings by deriving another UUID; do not
		// silently turn a malformed credential into a different credential.
		return errors.New("VLESS requires a canonical nonzero UUID")
	}
	if (policy.Flow != "" && policy.Flow != "xtls-rprx-vision") || policy.PacketEncoding != "xudp" {
		return errors.New("sandbox VLESS supports empty or Vision flow with XUDP only")
	}
	if !validRealityServerName(policy.ServerName) {
		return errors.New("Reality requires an explicit ASCII DNS server name")
	}
	keyBytes, err := base64.RawURLEncoding.Strict().DecodeString(policy.PublicKey)
	if err != nil || len(keyBytes) != 32 || base64.RawURLEncoding.EncodeToString(keyBytes) != policy.PublicKey {
		return errors.New("Reality requires a 32-byte raw URL-base64 public key")
	}
	publicKey, err := ecdh.X25519().NewPublicKey(keyBytes)
	if err != nil {
		return errors.New("invalid Reality public key")
	}
	// A fixed scalar is used only to reject low-order public points. It is not a
	// protocol credential, and the resulting shared value is never used.
	var scalar [32]byte
	scalar[0] = 1
	probeKey, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		return errors.New("cannot validate Reality public key")
	}
	if _, err = probeKey.ECDH(publicKey); err != nil {
		return errors.New("invalid low-order Reality public key")
	}
	if len(policy.ShortID) > 16 {
		return errors.New("Reality short ID must contain at most 16 hexadecimal digits")
	}
	if _, err := hex.DecodeString(policy.ShortID); err != nil {
		return errors.New("Reality short ID must contain an even number of hexadecimal digits")
	}
	if policy.Fingerprint == "" {
		policy.Fingerprint = "chrome"
	}
	switch policy.Fingerprint {
	case "chrome", "firefox", "edge", "safari", "ios", "android":
	default:
		return errors.New("sandbox Reality requires a supported fixed uTLS fingerprint")
	}
	if policy.KeyShare != "" && policy.KeyShare != "hybrid" {
		return errors.New("sandbox Reality requires hybrid key shares without adaptive fallback")
	}
	policy.KeyShare = "hybrid"
	return nil
}

func validRealityServerName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func workerOutbound(policy *proxyPolicy) option.Outbound {
	if policy.Type == "vless" {
		encoding := policy.PacketEncoding
		return option.Outbound{Type: "vless", Tag: "proxy", Options: &option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: policy.Server, ServerPort: policy.ServerPort},
			UUID:          policy.UUID, Flow: policy.Flow, PacketEncoding: &encoding,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
				Enabled: true, ServerName: policy.ServerName,
				UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: policy.Fingerprint},
				Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: policy.PublicKey,
					ShortID: policy.ShortID, KeyShare: policy.KeyShare},
			}},
		}}
	}
	return option.Outbound{Type: "socks", Tag: "proxy", Options: &option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: policy.Server, ServerPort: policy.ServerPort},
		Version:       "5", Username: policy.Username, Password: policy.Password,
	}}
}

var (
	sandboxTunIPv4 = netip.MustParsePrefix("172.31.255.1/30")
	sandboxTunIPv6 = netip.MustParsePrefix("fd7a:115c:a1e0::1/126")
)

func workerOptions(policy *proxyPolicy, namespace string) option.Options {
	return option.Options{
		Log: &option.LogOptions{Level: "error", DisableColor: true},
		// Avoid even an unused implicit host DNS fallback in the engine.
		DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
			Final: "proxy-dns",
			Servers: []option.DNSServerOptions{{Type: "tcp", Tag: "proxy-dns", Options: &option.RemoteDNSServerOptions{
				RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{DialerOptions: option.DialerOptions{Detour: "proxy"}},
				DNSServerAddressOptions:  option.DNSServerAddressOptions{Server: policy.DNSServer, ServerPort: 53},
			}}},
		}},
		Inbounds: []option.Inbound{{Type: "tun", Tag: "sandbox", Options: &option.TunInboundOptions{
			InterfaceName: "hiddify_sbox",
			NetNs:         namespace,
			Address: badoption.Listable[netip.Prefix]{
				sandboxTunIPv4, sandboxTunIPv6,
			},
			MTU: 1500, AutoRoute: true, StrictRoute: true,
			// DNS packets are ordinary proxied UDP/TCP. No local resolver or DNS
			// hijacker is used, and the proxy endpoint never requires DNS.
			DNSMode: "disabled", Stack: "gvisor",
		}}},
		Outbounds: []option.Outbound{workerOutbound(policy)},
		Route:     &option.RouteOptions{Final: "proxy"},
	}
}

func resolverContent(policy *proxyPolicy) string {
	// With no proxy there is no TUN or route; this documentation address cannot
	// leave the isolated namespace. An explicit resolver is required online.
	resolver := "203.0.113.53"
	if policy != nil {
		resolver = policy.DNSServer
	}
	return fmt.Sprintf("nameserver %s\noptions timeout:1 attempts:1\n", resolver)
}
