package hcore

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Panic containment for the gRPC surface.
//
// grpc-go does NOT recover handler panics, and on Android the core shares one
// process with the Flutter UI (c-shared library via gomobile): any unrecovered
// panic in a handler — or in a goroutine it spawned without its own recover —
// aborts the ENTIRE app. These interceptors convert every unary/stream handler
// panic into a codes.Internal error so the UI sees a failed RPC instead of a
// dead process. The stack is written to the core log stream and to stderr
// (redirected into data/stderr<mode>.log / crash_reports on device).

func grpcRecoveryOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.UnaryInterceptor(recoveryUnaryInterceptor),
		grpc.StreamInterceptor(recoveryStreamInterceptor),
	}
}

func recoveryUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer func() {
		if r := recover(); r != nil {
			logRecoveredPanic(info.FullMethod, r)
			resp = nil
			err = status.Errorf(codes.Internal, "core panic in %s: %v", info.FullMethod, r)
		}
	}()
	return handler(ctx, req)
}

func recoveryStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			logRecoveredPanic(info.FullMethod, r)
			err = status.Errorf(codes.Internal, "core panic in %s: %v", info.FullMethod, r)
		}
	}()
	return handler(srv, ss)
}

func logRecoveredPanic(where string, r any) {
	stack := debug.Stack()
	Log(LogLevel_FATAL, LogType_CORE, fmt.Sprintf("recovered panic in %s: %v\n%s", where, r, stack))
	// stderr is redirected per mode (stderr3/stderr4.log) and reaches logcat
	// with tag "Go" on Android — the interceptor return path alone would hide
	// the stack from device artifacts.
	fmt.Fprintf(os.Stderr, "recovered panic in %s: %v\n%s\n", where, r, stack)
}
