//go:build !linux || android

package hcore

import (
	"context"
	"github.com/sagernet/sing-box/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func sandboxBegin(ctx context.Context) context.Context { return ctx }
func sandboxPublish(context.Context, *option.Options)  {}
func sandboxSelection() func(bool)                     { return func(bool) {} }
func sandboxEmergencyRevoke()                          {}
func (s *CoreService) RunSandbox(*SandboxRunRequest, grpc.ServerStreamingServer[SandboxEvent]) error {
	return status.Error(codes.Unimplemented, "rootless sandbox is supported only on Linux")
}
