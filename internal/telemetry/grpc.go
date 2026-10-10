package telemetry

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"

	"google.golang.org/grpc/credentials/insecure"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func grpcExporters(ctx context.Context, c config.Telemetry, t *tls.Config, h map[string]string) (Exporters, error) {
	creds := credentials.NewTLS(t)
	if strings.HasPrefix(c.Endpoint, "http://") {
		creds = insecure.NewCredentials()
	}
	var e Exporters
	var err error
	defer func() {
		if err != nil {
			if e.Logs != nil {
				_ = e.Logs.Shutdown(ctx)
			}
			if e.Traces != nil {
				_ = e.Traces.Shutdown(ctx)
			}
			if e.Metrics != nil {
				_ = e.Metrics.Shutdown(ctx)
			}
		}
	}()
	if c.Logs {
		e.Logs, err = otlploggrpc.New(ctx, otlploggrpc.WithEndpointURL(c.Endpoint), otlploggrpc.WithTLSCredentials(creds), otlploggrpc.WithHeaders(h), otlploggrpc.WithTimeout(c.Timeout), otlploggrpc.WithRetry(otlploggrpc.RetryConfig{Enabled: false}), otlploggrpc.WithDialOption(grpc.WithDisableRetry()))
		if err != nil {
			e.Logs = nil
			return e, errors.New("telemetry logs initialization failed")
		}
	}
	if c.Traces {
		e.Traces, err = otlptracegrpc.New(ctx, otlptracegrpc.WithEndpointURL(c.Endpoint), otlptracegrpc.WithTLSCredentials(creds), otlptracegrpc.WithHeaders(h), otlptracegrpc.WithTimeout(c.Timeout), otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{Enabled: false}), otlptracegrpc.WithDialOption(grpc.WithDisableRetry()))
		if err != nil {
			e.Traces = nil
			return e, errors.New("telemetry traces initialization failed")
		}
	}
	if c.Metrics {
		e.Metrics, err = otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpointURL(c.Endpoint), otlpmetricgrpc.WithTLSCredentials(creds), otlpmetricgrpc.WithHeaders(h), otlpmetricgrpc.WithTimeout(c.Timeout), otlpmetricgrpc.WithRetry(otlpmetricgrpc.RetryConfig{Enabled: false}), otlpmetricgrpc.WithDialOption(grpc.WithDisableRetry()))
		if err != nil {
			e.Metrics = nil
			return e, errors.New("telemetry metrics initialization failed")
		}
	}
	return e, nil
}
