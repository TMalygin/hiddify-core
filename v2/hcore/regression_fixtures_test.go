package hcore

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/stretchr/testify/require"
)

// Shared helpers from hotreload_test.go before its removal in 2ed0bb5.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

var clashPort int
var otherPorts []int

func hotReloadSettings(t *testing.T, mixedPort int, logLevel string) string {
	if clashPort == 0 {
		clashPort = freeTCPPort(t)
		otherPorts = []int{freeTCPPort(t), freeTCPPort(t), freeTCPPort(t)}
	}
	return fmt.Sprintf(`{"mixed-port":%d,"tproxy-port":%d,"redirect-port":%d,"direct-port":%d,"clash-api-port":%d,"log-level":%q}`,
		mixedPort, otherPorts[0], otherPorts[1], otherPorts[2], clashPort, logLevel)
}

func profile(outbounds ...string) string {
	return `{"outbounds":[` + strings.Join(outbounds, ",") + `]}`
}

func socks(tag string, port int) string {
	return fmt.Sprintf(`{"type":"socks","tag":%q,"server":"127.0.0.1","server_port":%d}`, tag, port)
}

func runningOutbound(t *testing.T, name string) adapter.Outbound {
	t.Helper()
	for _, outbound := range static.StartedService.Instance().Box().Outbound().Outbounds() {
		if strings.HasPrefix(outbound.Tag(), name) {
			return outbound
		}
	}
	return nil
}
