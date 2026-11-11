// Opt-in native Chromium renderer integration fixture with disposable mutual TLS.
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

type request struct {
	ID              int      `json:"id"`
	Action          string   `json:"action"`
	Profile         string   `json:"profile"`
	Command         []string `json:"command"`
	ApplicationID   string   `json:"application_id"`
	ExecutableRoot  string   `json:"executable_root"`
	ChromiumSandbox bool     `json:"chromium_sandbox"`
	Session         int      `json:"session"`
}

func launch(ctx context.Context, conn *grpc.ClientConn, req request) {
	input := &hcore.SandboxRunRequest{Command: req.Command, ApplicationId: req.ApplicationID, ExecutableRoot: req.ExecutableRoot}
	if req.ChromiumSandbox {
		// A wire field remains decodable by the old server and makes RED a
		// behavior failure rather than a build failure on its generated types.
		tag := protowire.AppendTag(nil, 4, protowire.VarintType)
		input.ProtoReflect().SetUnknown(protowire.AppendVarint(tag, 1))
	}
	stream, err := hcore.NewCoreClient(conn).RunSandbox(ctx, input)
	for err == nil {
		var event *hcore.SandboxEvent
		event, err = stream.Recv()
		if err == nil {
			emit(map[string]any{"kind": "sandbox", "id": req.ID, "state": event.State,
				"revision": event.Revision, "exit_code": event.ExitCode, "stdout": string(event.Stdout),
				"stderr": string(event.Stderr), "message": event.Message})
		}
	}
	emit(map[string]any{"kind": "stream_end", "id": req.ID, "code": status.Code(err).String(), "error": fmt.Sprint(err)})
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
	emit(map[string]any{"kind": "ready", "working_dir": dir})
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	cancelLaunch := make(map[int]context.CancelFunc)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			panic(err)
		}
		if req.Action == "launch" {
			var launchCtx context.Context
			var cancel context.CancelFunc
			launchCtx, cancel = context.WithCancel(context.Background())
			cancelLaunch[req.ID] = cancel
			go launch(launchCtx, conn, req)
			continue
		}
		if req.Action == "cancel" {
			if cancel := cancelLaunch[req.Session]; cancel != nil {
				cancel()
				delete(cancelLaunch, req.Session)
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
			case "stop":
				response, err = hcore.Stop()
			default:
				err = fmt.Errorf("unsupported fixture action")
			}
			emit(map[string]any{"kind": "reply", "id": req.ID, "response": response, "error": fmt.Sprint(err)})
		}(req)
	}
	for _, cancel := range cancelLaunch {
		cancel()
	}
}
