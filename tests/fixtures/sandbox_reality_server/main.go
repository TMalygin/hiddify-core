// Local-only VLESS/Reality fixture. Requested destinations are never dialled:
// TCP/UDP are echoed and DNS questions receive documentation addresses.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const serverName = "reality-fixture.invalid"

var output sync.Mutex

func emit(value any) {
	output.Lock()
	defer output.Unlock()
	data, _ := json.Marshal(value)
	fmt.Println(string(data))
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func dnsAnswer(data []byte) ([]byte, error) {
	request := new(dns.Msg)
	if err := request.Unpack(data); err != nil {
		return nil, err
	}
	response := new(dns.Msg)
	response.SetReply(request)
	for _, question := range request.Question {
		header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 1}
		switch question.Qtype {
		case dns.TypeA:
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: net.ParseIP("198.51.100.44")})
		case dns.TypeAAAA:
			response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::44")})
		}
	}
	return response.Pack()
}

type echoHandler struct{ innerTLS *stdtls.Config }

func record(network string, destination M.Socksaddr, data []byte) {
	length := len(data)
	digest := sha256.Sum256(data)
	if len(data) > 512 {
		data = data[:512]
	}
	emit(map[string]any{"kind": "traffic", "network": network, "destination": destination.String(),
		"payload": data, "payload_size": length, "payload_sha256": hex.EncodeToString(digest[:])})
}

func (h echoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		if onClose != nil {
			defer onClose(nil)
		}
		if destination.Port == 8443 {
			inner := stdtls.Server(conn, h.innerTLS)
			_ = inner.SetDeadline(time.Now().Add(10 * time.Second))
			if inner.Handshake() != nil {
				return
			}
			conn = inner
		}
		data := make([]byte, 65536)
		for {
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			// Both fixture echoes and DNS use a uint16 length prefix, so the
			// observer does not confuse TCP fragmentation with distinct probes.
			var length uint16
			if binary.Read(conn, binary.BigEndian, &length) != nil {
				return
			}
			n, err := io.ReadFull(conn, data[:length])
			if err != nil {
				return
			}
			record("tcp", destination, data[:n])
			response := data[:n]
			if destination.Port == 53 {
				response, err = dnsAnswer(response)
				if err != nil {
					return
				}
			}
			if binary.Write(conn, binary.BigEndian, uint16(len(response))) != nil {
				return
			}
			if _, err = conn.Write(response); err != nil {
				return
			}
		}
	}()
}

func (echoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		if onClose != nil {
			defer onClose(nil)
		}
		for {
			packet := buf.NewPacket()
			destination, err := conn.ReadPacket(packet)
			if err != nil {
				packet.Release()
				return
			}
			record("udp", destination, packet.Bytes())
			if destination.Port == 53 {
				answer, err := dnsAnswer(packet.Bytes())
				packet.Release()
				if err != nil {
					return
				}
				packet = buf.As(answer)
			}
			if _, err := bufio.WritePacketBuffer(conn, packet, destination); err != nil {
				return
			}
		}
	}()
}

func fixtureTLSConfig(name string) *stdtls.Config {
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der := must(x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key))
	return &stdtls.Config{
		Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   stdtls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"},
	}
}

func startHandshakeTarget() net.Listener {
	listener := must(stdtls.Listen("tcp", "127.0.0.1:0", fixtureTLSConfig(serverName)))
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if conn.(*stdtls.Conn).Handshake() == nil {
					_, _ = io.Copy(io.Discard, conn)
				}
			}()
		}
	}()
	return listener
}

func selfCheck(address string, tlsConfig boxtls.Config, user, flow string) {
	client := must(vless.NewClient(user, flow, logger.NOP()))
	connect := func() net.Conn {
		raw := must(net.DialTimeout("tcp", address, 5*time.Second))
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		return must(boxtls.ClientHandshake(context.Background(), raw, tlsConfig))
	}
	for _, target := range []string{"198.51.100.44:443", "[2001:db8::44]:443"} {
		destination := M.ParseSocksaddr(target)
		tcp := must(client.DialConn(connect(), destination))
		message := []byte("issue48-fixture-self-check")
		if err := binary.Write(tcp, binary.BigEndian, uint16(len(message))); err != nil {
			panic(err)
		}
		must(tcp.Write(message))
		data := make([]byte, len(message))
		var length uint16
		if err := binary.Read(tcp, binary.BigEndian, &length); err != nil || int(length) != len(message) {
			panic("TCP fixture frame mismatch")
		}
		must(io.ReadFull(tcp, data))
		if !bytes.Equal(data, message) {
			panic("TCP fixture echo mismatch")
		}
		tcp.Close()
		udp := must(client.DialEarlyXUDPPacketConn(connect(), destination))
		must(udp.WriteTo(message, destination.UDPAddr()))
		packet := make([]byte, 65536)
		n, _, err := udp.ReadFrom(packet)
		if err != nil || !bytes.Equal(packet[:n], message) {
			panic(fmt.Sprintf("XUDP fixture echo mismatch: %v", err))
		}
		udp.Close()
	}
	dnsConn := must(client.DialConn(connect(), M.ParseSocksaddr("203.0.113.53:53")))
	defer dnsConn.Close()
	question := new(dns.Msg)
	question.SetQuestion("sandbox.invalid.", dns.TypeAAAA)
	query := must(question.Pack())
	if err := binary.Write(dnsConn, binary.BigEndian, uint16(len(query))); err != nil {
		panic(err)
	}
	must(dnsConn.Write(query))
	var size uint16
	if err := binary.Read(dnsConn, binary.BigEndian, &size); err != nil {
		panic(err)
	}
	response := make([]byte, size)
	must(io.ReadFull(dnsConn, response))
	answer := new(dns.Msg)
	if answer.Unpack(response) != nil || len(answer.Answer) != 1 || answer.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::44" {
		panic("DNS fixture self-check failed")
	}
	// Real TLS inside Vision exercises its padding/direct-copy transition; a
	// short plaintext echo alone cannot validate that path.
	inner := stdtls.Client(must(client.DialConn(connect(), M.ParseSocksaddr("198.51.100.44:8443"))),
		&stdtls.Config{ServerName: "inner-fixture.invalid", InsecureSkipVerify: true, MinVersion: stdtls.VersionTLS13}) // synthetic fixture certificate only
	defer inner.Close()
	if err := inner.Handshake(); err != nil {
		panic(err)
	}
	for index := 0; index < 3; index++ {
		message := bytes.Repeat([]byte("issue48-inner-tls-"), 2000)
		if err := binary.Write(inner, binary.BigEndian, uint16(len(message))); err != nil {
			panic(err)
		}
		must(inner.Write(message))
		var length uint16
		if err := binary.Read(inner, binary.BigEndian, &length); err != nil || int(length) != len(message) {
			panic("inner TLS fixture frame mismatch")
		}
		data := make([]byte, length)
		must(io.ReadFull(inner, data))
		if !bytes.Equal(data, message) {
			panic("inner TLS fixture echo mismatch")
		}
	}
}

func main() {
	flow := flag.String("flow", "", "VLESS flow for this local fixture")
	fingerprint := flag.String("fingerprint", "chrome", "uTLS client fingerprint for self-check")
	check := flag.Bool("self-check", false, "check real VLESS/Reality TCP/XUDP/DNS without a sandbox")
	flag.Parse()
	if *flow != "" && *flow != vless.FlowVision {
		panic("unsupported fixture flow")
	}
	ctx := context.Background()
	camouflage := startHandshakeTarget()
	defer camouflage.Close()
	private := must(ecdh.X25519().GenerateKey(rand.Reader))
	public := base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
	shortBytes := make([]byte, 8)
	must(rand.Read(shortBytes))
	shortID := hex.EncodeToString(shortBytes)
	user := uuid.NewString()
	serverTLS := must(boxtls.NewRealityServer(ctx, log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		Enabled: true, ServerName: serverName,
		Reality: &option.InboundRealityOptions{Enabled: true,
			Handshake:  option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(camouflage.Addr().(*net.TCPAddr).Port)}},
			PrivateKey: base64.RawURLEncoding.EncodeToString(private.Bytes()), ShortID: []string{shortID},
		},
	}))
	defer serverTLS.Close()
	service := vless.NewService[int](logger.NOP(), echoHandler{innerTLS: fixtureTLSConfig("inner-fixture.invalid")})
	service.UpdateUsers([]int{0}, []string{user}, []string{*flow})
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	defer listener.Close()
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
				conn, err := boxtls.ServerHandshake(ctx, raw, serverTLS)
				if err == nil {
					_ = conn.SetDeadline(time.Time{})
					err = service.NewConnection(ctx, conn, M.SocksaddrFromNet(raw.RemoteAddr()), func(error) { raw.Close() })
				}
				if err != nil {
					raw.Close()
				}
			}()
		}
	}()
	tlsOptions := option.OutboundTLSOptions{
		Enabled: true, ServerName: serverName, UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: *fingerprint},
		Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: public, ShortID: shortID},
	}
	if *check {
		clientTLS := must(boxtls.NewRealityClient(ctx, logger.NOP(), "127.0.0.1", tlsOptions))
		selfCheck(listener.Addr().String(), clientTLS, user, *flow)
		emit(map[string]any{"kind": "self-check", "flow": *flow, "fingerprint": *fingerprint, "ok": true})
		return
	}
	emit(map[string]any{"kind": "ready", "outbound": map[string]any{
		"type": "vless", "tag": "proxy", "server": "127.0.0.1", "server_port": listener.Addr().(*net.TCPAddr).Port,
		"uuid": user, "flow": *flow, "packet_encoding": "xudp", "tls": tlsOptions,
	}})
	_, _ = io.Copy(io.Discard, os.Stdin)
}
