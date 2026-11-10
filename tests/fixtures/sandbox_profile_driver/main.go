// Linux host integration driver. Only synthetic profiles and local listeners
// are provided by the Python tests. It compiles against the pre-feature core.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hiddify/hiddify-core/cmd"
	"github.com/hiddify/hiddify-core/v2/hcore"
	"github.com/sagernet/sing-box/experimental/libbox"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

var outputMu sync.Mutex

func emit(value any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	data, _ := json.Marshal(value)
	fmt.Println("EVENT " + string(data))
}

type frame []byte
type codec struct{}

func (codec) Name() string                      { return "proto" }
func (codec) Marshal(value any) ([]byte, error) { return []byte(*value.(*frame)), nil }
func (codec) Unmarshal(data []byte, value any) error {
	*value.(*frame) = append((*value.(*frame))[:0], data...)
	return nil
}

type request struct {
	ID              int      `json:"id"`
	Action          string   `json:"action"`
	Profile         string   `json:"profile"`
	Command         []string `json:"command"`
	Group           string   `json:"group"`
	Outbound        string   `json:"outbound"`
	Unauthenticated bool     `json:"unauthenticated"`
}

func launch(ctx context.Context, conn *grpc.ClientConn, request request) {
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/hcore.Core/RunSandbox", grpc.ForceCodec(codec{}))
	if err == nil {
		var input frame
		for _, arg := range request.Command {
			input = protowire.AppendTag(input, 1, protowire.BytesType)
			input = protowire.AppendString(input, arg)
		}
		err = stream.SendMsg(&input)
		if err == nil {
			err = stream.CloseSend()
		}
	}
	for err == nil {
		var data frame
		err = stream.RecvMsg(&data)
		if err != nil {
			break
		}
		event := map[string]any{"kind": "sandbox", "id": request.ID, "state": uint64(0), "revision": uint64(0)}
		for len(data) > 0 {
			number, wire, n := protowire.ConsumeTag(data)
			if n < 0 {
				panic("invalid sandbox event tag")
			}
			data = data[n:]
			switch wire {
			case protowire.VarintType:
				value, n := protowire.ConsumeVarint(data)
				if n < 0 {
					panic("invalid event varint")
				}
				data = data[n:]
				if number == 1 {
					event["state"] = value
				}
				if number == 2 {
					event["revision"] = value
				}
				if number == 5 {
					event["exit_code"] = int32(value)
				}
			case protowire.BytesType:
				value, n := protowire.ConsumeBytes(data)
				if n < 0 {
					panic("invalid event bytes")
				}
				data = data[n:]
				if number == 3 {
					event["stdout"] = string(value)
				}
				if number == 4 {
					event["stderr"] = string(value)
				}
				if number == 6 {
					event["message"] = string(value)
				}
			default:
				n := protowire.ConsumeFieldValue(number, wire, data)
				if n < 0 {
					panic("invalid event field")
				}
				data = data[n:]
			}
		}
		emit(event)
	}
	emit(map[string]any{"kind": "stream_end", "id": request.ID, "code": status.Code(err).String(), "error": fmt.Sprint(err)})
}

func main() {
	// Native sandbox reexecs use the same executable as the core, including in
	// this fixture. This delegates to the real production CLI implementation.
	if len(os.Args) > 1 && os.Args[1] == "experimental-sandbox" {
		cmd.ParseCli(os.Args[1:])
		return
	}
	if os.Geteuid() == 0 {
		panic("test must not run as root")
	}
	dir := os.Getenv("HIDDIFY_SANDBOX_TEST_DIR")
	if dir == "" {
		panic("missing disposable test directory")
	}
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0700); err != nil {
		panic(err)
	}
	if err := hcore.Setup(&hcore.SetupRequest{BasePath: dir, WorkingDir: dir, TempDir: dir, Mode: hcore.SetupMode_OLD}, nil); err != nil {
		panic(err)
	}
	defer hcore.Close(hcore.SetupMode_OLD)
	_, err := hcore.ChangeHiddifySettings(&hcore.ChangeHiddifySettingsRequest{HiddifySettingsJson: `{"enable-tun":false,"set-system-proxy":false,"remote-dns-address":"203.0.113.53","log-level":"error"}`}, false)
	if err != nil {
		panic(err)
	}
	ctx := libbox.BaseContext(nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sandbox-test.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12})))
	hcore.RegisterCoreServer(server, &hcore.CoreService{})
	go server.Serve(listener)
	defer server.Stop()
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{certificate}, RootCAs: pool, MinVersion: tls.VersionTLS12})))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	plainListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	plain := grpc.NewServer()
	hcore.RegisterCoreServer(plain, &hcore.CoreService{})
	go plain.Serve(plainListener)
	defer plain.Stop()
	plainConn, err := grpc.NewClient(plainListener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	defer plainConn.Close()
	emit(map[string]any{"kind": "ready"})
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	var cancelLaunch context.CancelFunc
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			panic(err)
		}
		if req.Action == "launch" {
			var launchCtx context.Context
			launchCtx, cancelLaunch = context.WithCancel(context.Background())
			client := conn
			if req.Unauthenticated {
				client = plainConn
			}
			go launch(launchCtx, client, req)
			continue
		}
		if req.Action == "cancel" {
			if cancelLaunch != nil {
				cancelLaunch()
			}
			emit(map[string]any{"kind": "reply", "id": req.ID})
			continue
		}
		// Keep reading so a stop can cancel a deliberately blocked start.
		go func(req request) {
			in := &hcore.StartRequest{ConfigContent: req.Profile, ConfigName: fmt.Sprintf("synthetic-%d", req.ID), EnableRawConfig: true, DisableMemoryLimit: true}
			var response *hcore.CoreInfoResponse
			var err error
			switch req.Action {
			case "start":
				response, err = hcore.StartService(ctx, in)
			case "restart":
				response, err = hcore.Restart(ctx, in)
			case "reload":
				response, err = hcore.HotReload(ctx, in)
			case "stop":
				response, err = hcore.Stop()
			case "select":
				_, err = (&hcore.CoreService{}).SelectOutbound(ctx, &hcore.SelectOutboundRequest{GroupTag: req.Group, OutboundTag: req.Outbound})
			default:
				err = fmt.Errorf("unsupported fixture action")
			}
			emit(map[string]any{"kind": "reply", "id": req.ID, "response": response, "error": fmt.Sprint(err)})
		}(req)
	}
	if cancelLaunch != nil {
		cancelLaunch()
	}
}
