package telemetry

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	collect "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"

	"github.com/CampusTech/cloud-8021x/internal/config"
)

func TestSDKGRPCConfiguration(t *testing.T) {
	c := config.Defaults().Telemetry
	c.Enabled = true
	c.Logs = true
	c.Traces = true
	c.Metrics = true
	c.Endpoint = "http://127.0.0.1:4317"
	c.Transport = "grpc"
	e, err := exporters(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if e.Logs == nil || e.Traces == nil || e.Metrics == nil {
		t.Fatal("missing exporters")
	}
	_ = e.Logs.Shutdown(context.Background())
	_ = e.Traces.Shutdown(context.Background())
	_ = e.Metrics.Shutdown(context.Background())
}
func TestSDKRejectsCredentialBearingOrUntrustedPlaintextEndpoint(t *testing.T) {
	for _, url := range []string{"http://public.example", "https://user:secret@example.com", "https://example.com/?token=secret"} {
		c := config.Defaults().Telemetry
		c.Enabled = true
		c.Endpoint = url
		if _, err := exporters(context.Background(), c); err == nil {
			t.Fatal("unsafe endpoint accepted", url)
		}
	}
}

type grpcLogSink struct {
	collect.UnimplementedLogsServiceServer
	calls atomic.Int32
}

func (s *grpcLogSink) Export(context.Context, *collect.ExportLogsServiceRequest) (*collect.ExportLogsServiceResponse, error) {
	s.calls.Add(1)
	return &collect.ExportLogsServiceResponse{}, nil
}
func TestSDKGRPCActualLoopbackHandoff(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	sink := &grpcLogSink{}
	collect.RegisterLogsServiceServer(server, sink)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	c := config.Defaults().Telemetry
	c.Enabled = true
	c.Logs = true
	c.Transport = "grpc"
	c.Timeout = 100 * time.Millisecond
	c.Endpoint = "http://" + listener.Addr().String()
	ex, err := exporters(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := newSDK(context.Background(), c, Identity{}, ex, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sdk.Shutdown(context.Background()) }()
	sdk.Logger.Info("policy")
	if err = sdk.logs.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sink.calls.Load() != 1 {
		t.Fatal("gRPC endpoint did not receive signal")
	}
}
