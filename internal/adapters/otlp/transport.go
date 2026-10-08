// Package otlp implements the synchronous, non-retrying outbox handoff. SDK
// exporters and their ordinary in-memory queues are not used for these records.
package otlp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	collect "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	logs "go.opentelemetry.io/proto/otlp/logs/v1"
	resource "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type Options struct {
	Endpoint string
	Timeout  time.Duration
	TLS      *tls.Config
	Token    string
}
type HTTP struct {
	client          *http.Client
	endpoint, token string
}

func NewHTTP(o Options) (*HTTP, error) {
	u, err := url.Parse(o.Endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || o.Timeout <= 0 || o.Timeout > time.Minute {
		return nil, errors.New("invalid OTLP endpoint")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("OTLP requires TLS or numeric loopback")
		}
	}
	if o.TLS != nil && o.TLS.InsecureSkipVerify {
		return nil, errors.New("OTLP requires verified TLS")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.TLS != nil {
		tlsConfig = o.TLS.Clone()
		tlsConfig.MinVersion = max(tls.VersionTLS12, tlsConfig.MinVersion)
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: o.Timeout}).DialContext, TLSClientConfig: tlsConfig, DisableKeepAlives: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 8192}
	u.Path = "/v1/logs"
	return &HTTP{client: &http.Client{Transport: tr, Timeout: o.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, endpoint: u.String(), token: o.Token}, nil
}

// Send has exactly one HTTP attempt, no redirect, no connection reuse or request
// replay body. Any uncertain response remains uncertain, including malformed 200s.
func (h *HTTP) Send(ctx context.Context, records []telemetry.BusinessRecord) telemetry.Receipt {
	result := telemetry.Receipt{Outcome: jobs.Uncertain, Code: "transport"}
	body, err := proto.Marshal(Request(records))
	if err != nil {
		result.Outcome = jobs.Rejected
		result.Code = "encoding"
		return result
	}
	if len(body) > 1<<20 || len(records) == 0 {
		result.Outcome = jobs.Rejected
		result.Code = "bounds"
		return result
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return result
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return result
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		result.Code = "http_" + strconv.Itoa(resp.StatusCode)
		if resp.StatusCode == 429 || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 || resp.StatusCode == 400 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.StatusCode == 413 {
			result.Outcome = jobs.Rejected
		}
		return result
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(data) > 65536 {
		return result
	}
	var response collect.ExportLogsServiceResponse
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType == "application/json" {
		err = protojson.Unmarshal(data, &response)
	} else {
		err = proto.Unmarshal(data, &response)
	}
	if err != nil {
		return result
	}
	result.Outcome, result.Code = jobs.Succeeded, "accepted"
	if p := response.PartialSuccess; p != nil && (p.RejectedLogRecords != 0 || p.ErrorMessage != "") {
		result.Outcome, result.Code, result.Rejected = jobs.Partial, "partial_success", p.RejectedLogRecords
	}
	return result
}

// Request gives each producer/category its own resource. The edge may map
// business.category to a vendor service without mutating a shared resource.
func Request(records []telemetry.BusinessRecord) *collect.ExportLogsServiceRequest {
	out := &collect.ExportLogsServiceRequest{}
	for _, r := range records {
		attrs := []*common.KeyValue{kv("service.name", "cloud-8021x"), kv("host.name", r.Host), kv("business.category", r.Category)}
		fields := make([]*common.KeyValue, 0, len(r.Fields))
		for k, v := range r.Fields {
			fields = append(fields, kv(k, v))
			if n, ok := v.(json.Number); ok {
				fields = append(fields, kv(k+"_exact", string(n)))
			}
		}
		body, _ := json.Marshal(r.Fields)
		rec := &logs.LogRecord{TimeUnixNano: timestamp(r.Received), ObservedTimeUnixNano: uint64(time.Now().UnixNano()), Body: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: string(body)}}, Attributes: fields, SeverityNumber: logs.SeverityNumber_SEVERITY_NUMBER_INFO}
		out.ResourceLogs = append(out.ResourceLogs, &logs.ResourceLogs{Resource: &resource.Resource{Attributes: attrs}, ScopeLogs: []*logs.ScopeLogs{{Scope: &common.InstrumentationScope{Name: "cloud-8021x/business"}, LogRecords: []*logs.LogRecord{rec}}}})
	}
	return out
}
func kv(k string, v any) *common.KeyValue {
	a := &common.AnyValue{}
	switch x := v.(type) {
	case bool:
		a.Value = &common.AnyValue_BoolValue{BoolValue: x}
	case int:
		a.Value = &common.AnyValue_IntValue{IntValue: int64(x)}
	case json.Number:
		if n, err := strconv.ParseInt(string(x), 10, 64); err == nil {
			a.Value = &common.AnyValue_IntValue{IntValue: n}
		} else {
			n, _ := strconv.ParseFloat(string(x), 64)
			a.Value = &common.AnyValue_DoubleValue{DoubleValue: n}
		}
	case string:
		a.Value = &common.AnyValue_StringValue{StringValue: x}
	default:
		a.Value = &common.AnyValue_StringValue{StringValue: "N/A"}
	}
	return &common.KeyValue{Key: k, Value: a}
}

func timestamp(t time.Time) uint64 {
	if t.IsZero() || t.UnixNano() < 0 {
		return 0
	}
	return uint64(t.UnixNano())
}
