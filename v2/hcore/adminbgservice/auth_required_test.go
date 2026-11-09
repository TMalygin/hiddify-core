package adminbgservice

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hiddify/hiddify-core/v2/hcommon"
	"github.com/hiddify/hiddify-core/v2/hcore/adminbg"
	"github.com/hiddify/hiddify-core/v2/hcore/buildid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestControlServerRejectsMissingOrShortSecret(t *testing.T) {
	for _, secret := range []string{"", strings.Repeat("x", adminbg.MinSecretLength-1)} {
		t.Run(strings.ReplaceAll(secret, "x", "s"), func(t *testing.T) {
			service := &hiddifyNext{secret: secret}
			server, err := service.StartAdminBgGrpcServer("127.0.0.1:0")
			if server != nil {
				server.Stop()
				t.Error("control server was created without a valid secret")
			}
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "secret") {
				t.Errorf("want an explicit invalid-secret error, got %v", err)
			}
		})
	}
}

func TestMissingControlSecretStopsStartupBeforeBinding(t *testing.T) {
	// Never read or alter credentials from an installed service on the test host.
	if _, err := os.Stat(filepath.Join(legacyControlDataDir(), controlSecretFileName)); !os.IsNotExist(err) {
		t.Skip("legacy credential path is present or inaccessible")
	}
	t.Setenv("HIDDIFY_ADMIN_BG_DATA", t.TempDir())
	previousBuildID := buildid.ID
	buildid.ID = "regression-test-build"
	t.Cleanup(func() { buildid.ID = previousBuildID })
	// Keep the address occupied: the old code must not leave a service running,
	// and a bind error must not be mistaken for a credential rejection.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	previousPort := port
	port = listener.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { port = previousPort })
	for _, cachedSecret := range []string{"", strings.Repeat("s", adminbg.MinSecretLength)} {
		service := &hiddifyNext{secret: cachedSecret}
		if err := service.Start(nil); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("missing credentials must stop startup before bind, got %v", err)
		}
	}
}

func TestControlServerAuthenticatesLegacyStatus(t *testing.T) {
	// Only Status is invoked. No VPN, privileged helper or system service runs.
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("test-only-credential-", 2)
	service := &hiddifyNext{secret: secret}
	server, err := service.StartAdminBgGrpcServer(address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	client := NewHiddifyAdminBGClient(connection)
	for _, test := range []struct {
		name   string
		values []string
		code   codes.Code
	}{
		{"missing", nil, codes.Unauthenticated},
		{"wrong", []string{"wrong-test-credential"}, codes.Unauthenticated},
		{"duplicate", []string{secret, secret}, codes.Unauthenticated},
		{"valid", []string{secret}, codes.OK},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, value := range test.values {
				ctx = metadata.AppendToOutgoingContext(ctx, adminbg.SecretHeader, value)
			}
			response, err := client.Status(ctx, &hcommon.Empty{})
			if status.Code(err) != test.code {
				t.Fatalf("Status code = %v, want %v: %v", status.Code(err), test.code, err)
			}
			if test.code == codes.OK && response.GetMessage() != "stopped" {
				t.Errorf("authenticated Status = %q, want stopped", response.GetMessage())
			}
		})
	}
}
