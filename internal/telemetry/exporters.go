package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/CampusTech/cloud-8021x/internal/config"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

func exporters(ctx context.Context, c config.Telemetry) (Exporters, error) {
	var ex Exporters
	if !c.Enabled {
		return ex, nil
	}

	u, parseErr := url.Parse(c.Endpoint)
	if parseErr != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ex, errors.New("invalid telemetry endpoint")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return ex, errors.New("plaintext telemetry requires loopback")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		data, err := os.ReadFile(c.CAFile)
		if err != nil {
			return ex, errors.New("telemetry trust unavailable")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return ex, errors.New("telemetry trust invalid")
		}
		tlsConfig.RootCAs = pool
	}
	headers := map[string]string{}
	if c.Credential.File != "" {
		data, err := readCredential(c.Credential.File)
		if err != nil || len(data) > 4096 {
			return ex, errors.New("telemetry credential unavailable")
		}
		headers["Authorization"] = "Bearer " + strings.TrimSpace(string(data))
	}
	if c.Transport == "grpc" {
		return grpcExporters(ctx, c, tlsConfig, headers)
	}
	if c.Transport != "http" {
		return ex, errors.New("invalid telemetry transport")
	}
	httpTLS := tlsConfig
	if u.Scheme == "http" {
		httpTLS = nil
	}
	client := &http.Client{Timeout: c.Timeout, Transport: &http.Transport{TLSClientConfig: httpTLS, Proxy: nil, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, ResponseHeaderTimeout: c.Timeout}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var err error
	defer func() {
		if err != nil {
			if ex.Logs != nil {
				_ = ex.Logs.Shutdown(ctx)
			}
			if ex.Traces != nil {
				_ = ex.Traces.Shutdown(ctx)
			}
			if ex.Metrics != nil {
				_ = ex.Metrics.Shutdown(ctx)
			}
		}
	}()
	if c.Logs {
		ex.Logs, err = otlploghttp.New(ctx, otlploghttp.WithEndpointURL(c.Endpoint), otlploghttp.WithURLPath(strings.TrimRight(u.Path, "/")+"/v1/logs"), otlploghttp.WithHTTPClient(client), otlploghttp.WithTLSClientConfig(httpTLS), otlploghttp.WithHeaders(headers), otlploghttp.WithTimeout(c.Timeout), otlploghttp.WithRetry(otlploghttp.RetryConfig{Enabled: false}))
		if err != nil {
			ex.Logs = nil
			return ex, errors.New("telemetry logs initialization failed")
		}
	}
	if c.Traces {
		ex.Traces, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(c.Endpoint), otlptracehttp.WithURLPath(strings.TrimRight(u.Path, "/")+"/v1/traces"), otlptracehttp.WithHTTPClient(client), otlptracehttp.WithTLSClientConfig(httpTLS), otlptracehttp.WithHeaders(headers), otlptracehttp.WithTimeout(c.Timeout), otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}))
		if err != nil {
			ex.Traces = nil
			return ex, errors.New("telemetry traces initialization failed")
		}
	}
	if c.Metrics {
		ex.Metrics, err = otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpointURL(c.Endpoint), otlpmetrichttp.WithURLPath(strings.TrimRight(u.Path, "/")+"/v1/metrics"), otlpmetrichttp.WithHTTPClient(client), otlpmetrichttp.WithTLSClientConfig(httpTLS), otlpmetrichttp.WithHeaders(headers), otlpmetrichttp.WithTimeout(c.Timeout), otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}))
		if err != nil {
			ex.Metrics = nil
			return ex, errors.New("telemetry metrics initialization failed")
		}
	}
	return ex, nil
}

func readCredential(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("credential unavailable")
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 || len(strings.TrimSpace(string(b))) == 0 {
		return nil, errors.New("credential invalid")
	}
	token := strings.TrimSpace(string(b))
	if strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("credential invalid")
	}
	return []byte(token), nil
}
