package stepca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// ProbeHealth reaches only a literal loopback address, while independently
// verifying the installed CA's configured DNS identity and complete trust chain.
// It performs no issuance, enrollment or remote discovery.
func ProbeHealth(ctx context.Context, address, dns string, trust []byte) error {
	host, _, err := net.SplitHostPort(address)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() || dns == "" {
		return errors.New("local CA health target required")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust) {
		return errors.New("CA health trust unavailable")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: dns}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address+"/health", nil)
	if err != nil {
		return errors.New("invalid CA health request")
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("local CA TLS health unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	var health struct {
		Status string `json:"status"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	if response.StatusCode != http.StatusOK || decoder.Decode(&health) != nil || health.Status != "ok" {
		return errors.New("local CA is not healthy")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("invalid CA health response")
	}
	return nil
}
