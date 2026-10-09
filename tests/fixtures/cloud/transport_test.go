package main

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// Real grpc framing/dispatch over an in-memory pipe: no host listener or port.
func TestGRPCTransportBearerAndMethodBoundary(t *testing.T) {
	f := testFixture(t)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.ForceServerCodec(wireCodec{}), grpc.UnknownServiceHandler(f.grpcHandler))
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close(); <-serveDone })
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithDefaultCallOptions(grpc.ForceCodec(wireCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := wire(bytesField(nil, 1, []byte(testKey)))
	var response wire
	if err := conn.Invoke(ctx, kmsService+"GetPublicKey", &request, &response); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing auth result: %v", err)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
	if err := conn.Invoke(ctx, kmsService+"GetPublicKey", &request, &response); err != nil || len(response) == 0 {
		t.Fatalf("public key transport: %v", err)
	}
	if err := conn.Invoke(ctx, kmsService+"Decrypt", &request, &response); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unlisted method result: %v", err)
	}
}
