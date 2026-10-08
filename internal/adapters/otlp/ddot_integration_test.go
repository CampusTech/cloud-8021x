package otlp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	collect "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Fixture generation and actual DDOT wire inspection are explicitly invoked by
// tests/ddot_queue.py. Normal unit tests do not require a container.
func TestDDOTWire(t *testing.T) {
	dir := os.Getenv("C8021X_DDOT_EVIDENCE")
	if dir == "" {
		t.Skip("run tests/ddot_queue.py")
	}
	records := []telemetry.BusinessRecord{}
	for i, category := range []string{"auth", "accounting", "usage"} {
		event := []string{"Access-Accept", "Acct-Stop", "Acct-Usage"}[i]
		records = append(records, telemetry.BusinessRecord{ID: category + "-record", Category: category, Host: "radius-original-a", Received: time.Unix(1800000000, 0), Fields: map[string]any{"event_id": category + "-record", "event": event, "device_owner": "Owner", "site_name": "Campus", "ap_name": "AP", "vlan_id": "200", "vlan_name": "Faculty", "input_bytes": json.Number("18446744073709551615")}})
	}
	if os.Getenv("C8021X_DDOT_GENERATE") == "1" {
		b, err := protojson.Marshal(Request(records))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "input.json"), b, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	files, err := filepath.Glob(filepath.Join(dir, "export-*.pb"))
	if err != nil || len(files) == 0 {
		t.Fatal("missing actual exporter payload", err)
	}
	seen := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var req collect.ExportLogsServiceRequest
		if err = proto.Unmarshal(data, &req); err != nil {
			t.Fatal(err)
		}
		for _, rl := range req.ResourceLogs {
			resource := map[string]string{}
			for _, a := range rl.Resource.Attributes {
				resource[a.Key] = a.Value.GetStringValue()
			}
			for _, scope := range rl.ScopeLogs {
				for _, record := range scope.LogRecords {
					fields := map[string]string{}
					for _, a := range record.Attributes {
						fields[a.Key] = a.Value.GetStringValue()
					}
					category := resource["business.category"]
					if category == "" {
						continue
					}
					expected := map[string]string{"auth": "radius-auth", "accounting": "radius-acct", "usage": "radius-usage"}[category]
					if resource["service.name"] != expected || resource["host.name"] != "radius-original-a" {
						t.Fatalf("cross-category/host corruption: %v", resource)
					}
					for _, k := range []string{"event", "device_owner", "site_name", "ap_name", "vlan_id", "vlan_name"} {
						if fields[k] == "" {
							t.Fatalf("missing facet %s: %v", k, fields)
						}
					}
					if fields["input_bytes_exact"] != "18446744073709551615" {
						t.Fatal("exact integer attribute changed")
					}
					var body map[string]json.RawMessage
					if err = json.Unmarshal([]byte(record.Body.GetStringValue()), &body); err != nil {
						t.Fatal(err)
					}
					if string(body["input_bytes"]) != "18446744073709551615" {
						t.Fatal("exact JSON integer changed")
					}
					seen[category] = true
				}
			}
		}
	}
	if len(seen) != 3 {
		t.Fatalf("missing mixed categories: %v", seen)
	}
}
