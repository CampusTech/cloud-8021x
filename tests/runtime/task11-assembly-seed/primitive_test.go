package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	logscollect "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricscollect "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"
)

type recordedDoer func(*http.Request) (*http.Response, error)

func (f recordedDoer) Do(r *http.Request) (*http.Response, error) { return f(r) }
func TestPrimitiveIndependentProjectionAndWireRequests(t *testing.T) {
	p, files := syntheticOriginal(t)
	b, err := finalize(p, files)
	if err != nil {
		t.Fatal(err)
	}
	var input primitivePlan
	if err = json.Unmarshal(b.Primitive["driver-input.json"], &input); err != nil {
		t.Fatal(err)
	}
	expected, err := projectPrimitive(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(expected)
	if !bytes.Equal(raw, b.Primitive["expected.json"]) {
		t.Fatal("projection not derived independently from typed inputs")
	}
	before := digest(b.Primitive["expected.json"])
	for _, badCRC := range []bool{false, true} {
		calls := 0
		phase := ""
		scenario := func(_ context.Context, name string) error { phase = name; return nil }
		doer := recordedDoer(func(r *http.Request) (*http.Response, error) {
			calls++
			body, _ := io.ReadAll(r.Body)
			code := 200
			response := []byte(`{}`)
			switch r.URL.Host {
			case "secretmanager.googleapis.com":
				if r.Header.Get("Authorization") != "Bearer task11-synthetic-token-not-a-cloud-credential" {
					return nil, errors.New("synthetic auth absent")
				}
				resource := strings.TrimPrefix(r.URL.Path, "/v1/")
				if r.Method == "POST" {
					resource = strings.TrimSuffix(resource, ":addVersion")
					var payload struct {
						Payload struct {
							Data string `json:"data"`
							CRC  string `json:"dataCrc32c"`
						} `json:"payload"`
					}
					if json.Unmarshal(body, &payload) != nil || payload.Payload.Data != base64.StdEncoding.EncodeToString(input.Publications[resource]) || payload.Payload.CRC != fmt.Sprint(crc32.Checksum(input.Publications[resource], crc32.MakeTable(crc32.Castagnoli))) {
						return nil, errors.New("publication payload/CRC differs")
					}
					response, _ = json.Marshal(map[string]string{"name": resource + "/versions/2", "state": "ENABLED"})
				} else {
					resource = strings.TrimSuffix(resource, "/versions/2:access")
					value := input.Publications[resource]
					crc := fmt.Sprint(crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli)))
					if badCRC {
						crc = "0"
					}
					response, _ = json.Marshal(map[string]any{"payload": map[string]string{"data": base64.StdEncoding.EncodeToString(value), "dataCrc32c": crc}})
				}
			case "fleet.task11.test":
				if r.Method != "GET" || r.Header.Get("Authorization") != input.FleetAuthorization {
					return nil, errors.New("retained command POST or bad Fleet auth")
				}
				if strings.Contains(r.URL.Path, "results") && phase == "fleet-missing" {
					code = 404
				}
			case "otlp.task11.test":
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-protobuf" || r.Header.Get("Authorization") != input.IntakeAuthorization {
					return nil, errors.New("OTLP request differs")
				}
				switch r.URL.Path {
				case "/v1/logs":
					var request logscollect.ExportLogsServiceRequest
					if proto.Unmarshal(body, &request) != nil || !sameLogs(&request, otlp.Request(expected.Records)) {
						return nil, errors.New("real OTLP encoder/projection differs")
					}
				case "/v1/metrics":
					var request metricscollect.ExportMetricsServiceRequest
					if proto.Unmarshal(body, &request) != nil || request.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].GetGauge().DataPoints[0].GetAsInt() != 1 {
						return nil, errors.New("typed OTLP metric absent")
					}
				default:
					return nil, errors.New("unknown intake path")
				}
			default:
				return nil, errors.New("unknown endpoint")
			}
			return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(response)), Header: http.Header{}}, nil
		})
		err = drivePrimitive(context.Background(), input, doer, scenario)
		if badCRC && err == nil {
			t.Fatal("wrong remote CRC accepted")
		}
		if !badCRC && (err != nil || calls != 10) {
			t.Fatalf("bounded request program differs: %d %v", calls, err)
		}
	}
	if digest(b.Primitive["expected.json"]) != before {
		t.Fatal("traffic altered expected projection")
	}
	input.Host.ID = 2
	if _, err = projectPrimitive(input); err == nil {
		t.Fatal("independent original host binding relaxed")
	}
}

func sameLogs(a, b *logscollect.ExportLogsServiceRequest) bool {
	for _, request := range []*logscollect.ExportLogsServiceRequest{a, b} {
		for _, r := range request.ResourceLogs {
			sort.Slice(r.Resource.Attributes, func(i, j int) bool { return r.Resource.Attributes[i].Key < r.Resource.Attributes[j].Key })
			for _, s := range r.ScopeLogs {
				for _, l := range s.LogRecords {
					if l.ObservedTimeUnixNano == 0 {
						return false
					}
					l.ObservedTimeUnixNano = 0
					sort.Slice(l.Attributes, func(i, j int) bool { return l.Attributes[i].Key < l.Attributes[j].Key })
				}
			}
		}
	}
	return proto.Equal(a, b)
}
