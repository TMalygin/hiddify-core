//go:build linux && !android

// Package sandbox implements an experimental console-only launcher. It does not
// consume ordinary profiles or the app's mixed port: both may permit DIRECT.
package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"unicode/utf8"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

const maxPolicyBytes = 16 * 1024

type proxyPolicy struct {
	Type       string `json:"type"`
	Version    string `json:"version"`
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
	DNSServer  string `json:"dns_server"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
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
	if policy.Type != "socks" || policy.Version != "5" || policy.ServerPort == 0 {
		return nil, errors.New("prototype requires SOCKS5 and a nonzero server_port")
	}
	for _, value := range []string{policy.Server, policy.DNSServer} {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
			return nil, errors.New("server and dns_server must be unicast IP literals without a zone")
		}
	}
	if len(policy.Username) > 255 || len(policy.Password) > 255 {
		return nil, errors.New("SOCKS credentials exceed 255 bytes")
	}
	return &policy, nil
}

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
				netip.MustParsePrefix("172.31.255.1/30"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/126"),
			},
			MTU: 1500, AutoRoute: true, StrictRoute: true,
			// DNS packets are ordinary proxied UDP/TCP. No local resolver or DNS
			// hijacker is used, and the proxy endpoint never requires DNS.
			DNSMode: "disabled", Stack: "gvisor",
		}}},
		Outbounds: []option.Outbound{{Type: "socks", Tag: "proxy", Options: &option.SOCKSOutboundOptions{
			ServerOptions: option.ServerOptions{Server: policy.Server, ServerPort: policy.ServerPort},
			Version:       "5", Username: policy.Username, Password: policy.Password,
		}}},
		Route: &option.RouteOptions{Final: "proxy"},
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
