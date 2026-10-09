package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"
)

func TestOTLPDecodesActualBusinessProjectionRatherThanHashOnly(t *testing.T) {
	f := fleetFixture(t)
	f.phase = "active"
	f.config.Contract.OTLP = &otlpSeed{Host: "otlp.task11.test", Authorization: "Bearer task11-intake"}
	record := telemetry.BusinessRecord{ID: "actual-id", Category: "usage", Host: "green-task11-primary", Received: time.Unix(1800000000, 0), Fields: map[string]any{"event_id": "actual-id", "usage_id": "actual-id", "event": "Acct-Usage", "identity_verified": true, "device_id": "fleet:1", "input_bytes": json.Number("18446744073709551615")}}
	payload, err := proto.Marshal(otlp.Request([]telemetry.BusinessRecord{record}))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://otlp.task11.test/v1/logs", bytes.NewReader(payload))
	r.Header.Set("Authorization", "Bearer task11-intake")
	r.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("actual OTLP request rejected: %d %s", w.Code, w.Body.String())
	}
	state, err := json.Marshal(f.remote)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"actual-id", "green-task11-primary", "Acct-Usage", "18446744073709551615", "fleet:1"} {
		if !bytes.Contains(state, []byte(field)) {
			t.Fatalf("decoded state missing %s", field)
		}
	}
}

func TestActualDDOTBusinessGzipHeaderAndCategory(t *testing.T) {
	f := fleetFixture(t)
	f.phase = "active"
	// Parse through JSON so the pre-fix helper reproduces the actual API failure.
	raw := `{"host":"otlp.us5.datadoghq.com","api_key":"task11-dd-key"}`
	var config otlpSeed
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatal(err)
	}
	f.config.Contract.OTLP = &config
	request := otlp.Request([]telemetry.BusinessRecord{{ID: "id", Category: "auth", Host: "green-primary", Received: time.Unix(1800000000, 0), Fields: map[string]any{"event_id": "id", "event": "Access-Accept"}}})
	request.ResourceLogs[0].Resource.Attributes[0].Value.Value = &common.AnyValue_StringValue{StringValue: "radius-auth"}
	data, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://otlp.us5.datadoghq.com/v1/logs", bytes.NewReader(compressed.Bytes()))
	r.Header.Set("dd-api-key", "task11-dd-key")
	r.Header.Set("Content-Type", "application/x-protobuf")
	r.Header.Set("Content-Encoding", "gzip")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("actual shipping DDOT contract refused: %d %s", w.Code, w.Body.String())
	}
	if len(f.remote.Batches) != 1 || f.remote.Batches[0].Logs[0].Resource["service.name"] != "radius-auth" {
		t.Fatal("lost actual DDOT transform")
	}
}

func TestIntakeOutageAndMalformedEncodingNeverBecomeDecodedReceipt(t *testing.T) {
	f := fleetFixture(t)
	f.phase = "active"
	f.config.Contract.OTLP = &otlpSeed{Host: "otlp.task11.test", Authorization: "Bearer test"}
	body, err := proto.Marshal(otlp.Request([]telemetry.BusinessRecord{{ID: "id", Category: "auth", Host: "green-primary", Received: time.Unix(1800000000, 0), Fields: map[string]any{"event_id": "id", "event": "Access-Accept"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.advanceScenario("intake-unavailable", ""); err != nil {
		t.Fatal(err)
	}
	intakeRequest(t, f, "logs", body, 503)
	if len(f.remote.Batches) != 0 {
		t.Fatal("failed intake acknowledged a record")
	}
	if err = f.advanceScenario("intake-ready", ""); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, err = writer.Write(body)
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	var bomb bytes.Buffer
	writer = gzip.NewWriter(&bomb)
	_, err = writer.Write(bytes.Repeat([]byte("x"), maxBody+1))
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, encoding string
		data           []byte
		want           int
	}{{"invalid gzip", "gzip", []byte("invalid"), 400}, {"trailing gzip", "gzip", append(append([]byte{}, compressed.Bytes()...), compressed.Bytes()...), 400}, {"expanded oversized", "gzip", bomb.Bytes(), 400}, {"unrecognized encoding", "br", body, 415}, {"invalid protobuf", "", []byte("not protobuf"), 400}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://otlp.task11.test/v1/logs", bytes.NewReader(tc.data))
			r.Header.Set("Authorization", "Bearer test")
			r.Header.Set("Content-Type", "application/x-protobuf")
			r.Header.Set("Content-Encoding", tc.encoding)
			w := httptest.NewRecorder()
			f.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d", w.Code, tc.want)
			}
			if len(f.remote.Batches) != 0 {
				t.Fatal("invalid request produced a decoded receipt")
			}
		})
	}
	intakeRequest(t, f, "logs", body, 200)
	if len(f.remote.Batches) != 1 || len(f.remote.Batches[0].Logs) != 1 {
		t.Fatal("successful retry did not preserve exactly one decoded record")
	}
}
