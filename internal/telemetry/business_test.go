package telemetry

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

func TestBusinessProjectionPreservesProducerAndExactCounters(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		id              string
		payload         any
		category, event string
	}{
		{"auth:a", auth.Event{ID: "a", Event: "Access-Accept", Host: "radius-origin", Received: now, DeviceOwner: "Owner", VLANID: "200"}, "auth", "Access-Accept"},
		{"accounting:b", accounting.Event{ID: "b", Status: "Stop", Host: "radius-origin", Received: now, Upload: ^uint64(0)}, "accounting", "Acct-Stop"},
		{"usage:c", accounting.Interval{ID: "c", Host: "radius-origin", Received: now, Upload: ^uint64(0)}, "usage", "Acct-Usage"},
	}
	for _, tt := range cases {
		t.Run(tt.category, func(t *testing.T) {
			raw, _ := json.Marshal(tt.payload)
			r, err := Project(jobs.Claim{ID: tt.id, Payload: raw}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if r.Host != "radius-origin" || r.Category != tt.category || r.Fields["event"] != tt.event {
				t.Fatalf("wrong projection: %+v", r)
			}
			if tt.category != "auth" && r.Fields["input_bytes"] != json.Number("18446744073709551615") {
				t.Fatalf("counter lost precision: %#v", r.Fields)
			}
		})
	}
	legacy, _ := json.Marshal(accounting.Interval{ID: "old", Received: now})
	r, err := Project(jobs.Claim{ID: "usage:old", Payload: legacy}, nil)
	if err != nil || r.Host != "N/A" {
		t.Fatalf("legacy must not borrow worker host: %+v %v", r, err)
	}
}
func TestBusinessRejectsUnknownAndDoesNotEmitRawSecrets(t *testing.T) {
	raw := json.RawMessage(`{"event_id":"a","event":"Access-Reject","host":"radius-origin","reason":"Bearer SENTINEL","password":"SENTINEL"}`)
	r, err := Project(jobs.Claim{ID: "auth:a", Payload: raw}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if string(b) == "" || r.Fields["password"] != nil || r.Fields["reject_reason"] == "Bearer SENTINEL" {
		t.Fatalf("unsafe event: %s", b)
	}
	if _, err = Project(jobs.Claim{ID: "other:a", Payload: raw}, nil); err == nil {
		t.Fatal("unknown category accepted")
	}
}

func TestAuthDashboardSerial(t *testing.T) {
	b, _ := json.Marshal(auth.Event{ID: "a", Event: "Access-Accept", Serial: "device-serial"})
	r, err := Project(jobs.Claim{ID: "auth:a", Payload: b}, nil)
	if err != nil || r.Fields["serial"] != "device-serial" {
		t.Fatal("serial projection lost", r, err)
	}
}

func TestStopReasonProjectionIncludesLegacyUnavailable(t *testing.T) {
	for _, value := range []string{"User-Request", "", "arbitrary secret"} {
		payload, _ := json.Marshal(map[string]any{"event_id": "stop", "status": "Stop", "terminate_cause": value})
		r, err := Project(jobs.Claim{ID: "accounting:stop", Payload: payload}, nil)
		want := "N/A"
		if value == "User-Request" {
			want = value
		}
		if err != nil || r.Fields["terminate_cause"] != want {
			t.Fatal(r, err)
		}
	}
}
