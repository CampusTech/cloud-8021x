package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	logscollect "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricscollect "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	metrics "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type decodedLog struct {
	AttributeKinds map[string]string `json:"attribute_kinds"`
	Resource       map[string]any    `json:"resource"`
	Scope          string            `json:"scope"`
	Time           uint64            `json:"time_unix_nano"`
	Body           json.RawMessage   `json:"body"`
	Attributes     map[string]any    `json:"attributes"`
}
type decodedMetric struct {
	Resource map[string]any  `json:"resource"`
	Scope    string          `json:"scope"`
	Name     string          `json:"name"`
	Unit     string          `json:"unit"`
	Kind     string          `json:"kind"`
	Data     json.RawMessage `json:"data"`
}
type intakeBatch struct {
	WireSHA256    string          `json:"wire_sha256"`
	Kind          string          `json:"kind"`
	PayloadSHA256 string          `json:"payload_sha256"`
	Logs          []decodedLog    `json:"logs,omitempty"`
	Metrics       []decodedMetric `json:"metrics,omitempty"`
}

func attributes(values []*common.KeyValue) (map[string]any, error) {
	if len(values) > 128 {
		return nil, errors.New("attribute bound exceeded")
	}
	out := map[string]any{}
	for _, kv := range values {
		if kv == nil || kv.Value == nil || kv.Key == "" || len(kv.Key) > 256 {
			return nil, errors.New("invalid attribute")
		}
		if _, ok := out[kv.Key]; ok {
			return nil, errors.New("duplicate attribute")
		}
		switch v := kv.Value.Value.(type) {
		case *common.AnyValue_StringValue:
			if len(v.StringValue) > 64<<10 {
				return nil, errors.New("attribute value too large")
			}
			out[kv.Key] = v.StringValue
		case *common.AnyValue_BoolValue:
			out[kv.Key] = v.BoolValue
		case *common.AnyValue_IntValue:
			out[kv.Key] = v.IntValue
		case *common.AnyValue_DoubleValue:
			out[kv.Key] = v.DoubleValue
		default:
			return nil, errors.New("unsupported attribute type")
		}
	}
	return out, nil
}
func resourceAttributes(values []*common.KeyValue) (map[string]any, error) {
	out, err := attributes(values)
	if err != nil {
		return nil, err
	}
	host, ok := out["host.name"].(string)
	if !ok || host == "" || len(host) > 253 {
		return nil, errors.New("missing physical OTLP host")
	}
	service, ok := out["service.name"].(string)
	if !ok || service == "" || len(service) > 128 {
		return nil, errors.New("missing OTLP service")
	}
	return out, nil
}
func decodeIntake(kind string, body []byte) (intakeBatch, error) {
	batch := intakeBatch{Kind: kind}
	sum := sha256.Sum256(body)
	batch.PayloadSHA256 = hex.EncodeToString(sum[:])
	batch.WireSHA256 = batch.PayloadSHA256
	if len(body) == 0 || len(body) > maxBody {
		return batch, errors.New("empty or oversized OTLP")
	}
	switch kind {
	case "logs":
		var request logscollect.ExportLogsServiceRequest
		if proto.Unmarshal(body, &request) != nil || len(request.ProtoReflect().GetUnknown()) != 0 {
			return batch, errors.New("invalid OTLP logs protobuf")
		}
		for _, rl := range request.ResourceLogs {
			if rl.Resource == nil {
				return batch, errors.New("OTLP resource missing")
			}
			resource, err := resourceAttributes(rl.Resource.Attributes)
			if err != nil {
				return batch, err
			}
			for _, scope := range rl.ScopeLogs {
				if scope.Scope == nil || scope.Scope.Name == "" {
					return batch, errors.New("OTLP scope absent")
				}
				for _, record := range scope.LogRecords {
					attrs, err := attributes(record.Attributes)
					if err != nil {
						return batch, err
					}
					raw := record.Body.GetStringValue()
					var fields map[string]json.RawMessage
					if record.TimeUnixNano == 0 || !json.Valid([]byte(raw)) || json.Unmarshal([]byte(raw), &fields) != nil || len(fields) == 0 || len(fields) > 128 {
						return batch, errors.New("business log requires actual timestamp and JSON object body")
					}
					batch.Logs = append(batch.Logs, decodedLog{Resource: resource, Scope: scope.Scope.Name, Time: record.TimeUnixNano, Body: json.RawMessage(raw), Attributes: attrs, AttributeKinds: attributeKinds(record.Attributes)})
					if len(batch.Logs) > 1024 {
						return batch, errors.New("log record bound exceeded")
					}
				}
			}
		}
		if len(batch.Logs) == 0 {
			return batch, errors.New("no decoded log records")
		}
	case "metrics":
		var request metricscollect.ExportMetricsServiceRequest
		if proto.Unmarshal(body, &request) != nil || len(request.ProtoReflect().GetUnknown()) != 0 {
			return batch, errors.New("invalid OTLP metrics protobuf")
		}
		for _, rm := range request.ResourceMetrics {
			if rm.Resource == nil {
				return batch, errors.New("OTLP resource missing")
			}
			resource, err := resourceAttributes(rm.Resource.Attributes)
			if err != nil {
				return batch, err
			}
			for _, scope := range rm.ScopeMetrics {
				if scope.Scope == nil || scope.Scope.Name == "" {
					return batch, errors.New("OTLP scope absent")
				}
				for _, metric := range scope.Metrics {
					count := 0
					kind := ""
					switch data := metric.Data.(type) {
					case *metrics.Metric_Gauge:
						kind = "gauge"
						count = len(data.Gauge.DataPoints)
					case *metrics.Metric_Sum:
						kind = "sum"
						count = len(data.Sum.DataPoints)
					case *metrics.Metric_Histogram:
						kind = "histogram"
						count = len(data.Histogram.DataPoints)
					case *metrics.Metric_ExponentialHistogram:
						kind = "exponential_histogram"
						count = len(data.ExponentialHistogram.DataPoints)
					case *metrics.Metric_Summary:
						kind = "summary"
						count = len(data.Summary.DataPoints)
					}
					if metric.Name == "" || len(metric.Name) > 256 || count == 0 || count > 1024 || validateMetricPoints(metric) != nil {
						return batch, errors.New("invalid decoded metric")
					}
					data, err := protojson.Marshal(metric)
					if err != nil {
						return batch, err
					}
					batch.Metrics = append(batch.Metrics, decodedMetric{Resource: resource, Scope: scope.Scope.Name, Name: metric.Name, Unit: metric.Unit, Kind: kind, Data: data})
					if len(batch.Metrics) > 1024 {
						return batch, errors.New("metric bound exceeded")
					}
				}
			}
		}
		if len(batch.Metrics) == 0 {
			return batch, errors.New("no decoded metric records")
		}
	default:
		return batch, errors.New("unsupported intake signal")
	}
	return batch, nil
}
func (f *fixture) acceptIntake(kind string, body []byte) error {
	if f.phase != "active" {
		return errors.New("passive intake refused")
	}
	if f.remote.IntakeUnavailable {
		return errors.New("intake unavailable")
	}
	if len(f.remote.Batches) >= 1024 {
		return errors.New("intake batch bound reached")
	}
	batch, err := decodeIntake(kind, body)
	if err != nil {
		return err
	}
	f.remote.Batches = append(f.remote.Batches, batch)
	return nil
}
func (f *fixture) intakeHTTP(r *http.Request, body []byte) (int, any, string) {
	fail := func(code int, message string) (int, any, string) {
		return code, map[string]string{"error": message}, "application/json"
	}
	config := f.config.Contract.OTLP
	if (config.APIKey != "" && r.Header.Get("dd-api-key") != config.APIKey) || (config.APIKey == "" && (config.Authorization == "" || r.Header.Get("Authorization") != config.Authorization)) {
		return fail(401, "intake authorization rejected")
	}
	if r.Method != "POST" || (r.URL.Path != "/v1/logs" && r.URL.Path != "/v1/metrics") || r.URL.RawQuery != "" {
		return fail(404, "unlisted intake request")
	}
	if f.phase != "active" {
		return fail(403, "passive intake refused")
	}
	if f.remote.IntakeUnavailable {
		return fail(503, "intake unavailable")
	}
	if r.Header.Get("Content-Type") != "application/x-protobuf" {
		return fail(415, "only OTLP protobuf accepted")
	}
	wireHash := digestBytes(body)
	switch r.Header.Get("Content-Encoding") {
	case "":
	case "gzip":
		reader := bytes.NewReader(body)
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return fail(400, "invalid gzip")
		}
		gz.Multistream(false)
		data, err := io.ReadAll(io.LimitReader(gz, maxBody+1))
		closeErr := gz.Close()
		if err != nil || closeErr != nil || len(data) > maxBody || reader.Len() != 0 {
			return fail(400, "invalid, oversized or trailing compressed payload")
		}
		body = data
	default:
		return fail(415, "unsupported content encoding")
	}
	if err := f.acceptIntake(strings.TrimPrefix(r.URL.Path, "/v1/"), body); err != nil {
		return fail(400, err.Error())
	}
	f.remote.Batches[len(f.remote.Batches)-1].WireSHA256 = wireHash
	return 200, []byte{}, "application/x-protobuf"
}

// Every accepted metric retains an observed point; a name-only envelope is not
// telemetry evidence. This check applies to all supported OTLP point families.
func validateMetricPoints(metric *metrics.Metric) error {
	var points []interface {
		GetTimeUnixNano() uint64
		GetAttributes() []*common.KeyValue
	}
	switch data := metric.Data.(type) {
	case *metrics.Metric_Gauge:
		for _, p := range data.Gauge.DataPoints {
			if p.Value == nil {
				return errors.New("missing gauge value")
			}
			points = append(points, p)
		}
	case *metrics.Metric_Sum:
		for _, p := range data.Sum.DataPoints {
			if p.Value == nil {
				return errors.New("missing sum value")
			}
			points = append(points, p)
		}
	case *metrics.Metric_Histogram:
		for _, p := range data.Histogram.DataPoints {
			points = append(points, p)
		}
	case *metrics.Metric_ExponentialHistogram:
		for _, p := range data.ExponentialHistogram.DataPoints {
			points = append(points, p)
		}
	case *metrics.Metric_Summary:
		for _, p := range data.Summary.DataPoints {
			points = append(points, p)
		}
	}
	for _, point := range points {
		if point.GetTimeUnixNano() == 0 {
			return errors.New("metric timestamp absent")
		}
		if _, err := attributes(point.GetAttributes()); err != nil {
			return err
		}
	}
	return nil
}

// JSON persistence cannot distinguish an OTLP int from an integral double.
// Retain the actual protobuf scalar discriminant alongside each decoded value.
func attributeKinds(values []*common.KeyValue) map[string]string {
	out := map[string]string{}
	for _, kv := range values {
		switch kv.Value.Value.(type) {
		case *common.AnyValue_StringValue:
			out[kv.Key] = "string"
		case *common.AnyValue_BoolValue:
			out[kv.Key] = "bool"
		case *common.AnyValue_IntValue:
			out[kv.Key] = "int"
		case *common.AnyValue_DoubleValue:
			out[kv.Key] = "double"
		}
	}
	return out
}
