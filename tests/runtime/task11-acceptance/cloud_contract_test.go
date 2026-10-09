package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"

	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

func TestCloudVerifierCannotSubstitutePrimitiveOrPartialSuccess(t *testing.T) {
	p := projection{Schema: 1, Gate: "installed-traffic", ApplicationSHA256: strings.Repeat("a", 64), Records: []telemetry.BusinessRecord{{ID: "real"}}}
	good := verification{Schema: 1, Gate: p.Gate, ApplicationSHA256: p.ApplicationSHA256, Phase: "post-activation", SecretPreservation: true, FleetUncertainty: true, OTLPDecoding: true, EvidenceSHA256: strings.Repeat("b", 64), Records: 1}
	for name, change := range map[string]func(*verification){"primitive": func(v *verification) { v.Gate = "primitive-contract"; v.Phase = "primitive-only" }, "app": func(v *verification) { v.ApplicationSHA256 = strings.Repeat("c", 64) }, "missing-evidence": func(v *verification) { v.EvidenceSHA256 = "" }, "ordinary": func(v *verification) { v.OrdinaryTelemetry = true }, "no-preservation": func(v *verification) { v.SecretPreservation = false }, "wrong-count": func(v *verification) { v.Records = 2 }, "no-decoding": func(v *verification) { v.OTLPDecoding = false }} {
		t.Run(name, func(t *testing.T) {
			v := good
			change(&v)
			raw, _ := json.Marshal(v)
			if _, err := validateVerification(raw, p); err == nil {
				t.Fatal("unbound verifier success accepted")
			}
		})
	}
	raw, _ := json.Marshal(good)
	if _, err := validateVerification(raw, p); err != nil {
		t.Fatal(err)
	}
	if _, err := validateVerification(append(raw, []byte(` {"extra":true}`)...), p); err == nil {
		t.Fatal("trailing result accepted")
	}
}
func TestActualDurableOutboxProjectionRejectsUncertainOrWrongGeneration(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	event := auth.Event{ID: "actual-event", Host: "task11-green-primary", Event: "Access-Accept", Received: now}
	payload, _ := json.Marshal(event)
	receipt, _ := json.Marshal(telemetry.Receipt{Outcome: jobs.Succeeded, Code: "accepted"})
	work := durableWork{ID: "auth:actual-event", Kind: "outbox", State: "succeeded", Generation: 3, Payload: payload, Receipt: receipt, AttemptReceipt: receipt, Outcome: "succeeded", StartedAt: now, FinishedAt: now.Add(time.Second)}
	s := durableSnapshot{Deployment: "task11-green", Database: "cloud8021x_task11_green", Epoch: now.Add(-time.Minute), Work: []durableWork{work}}
	for name, change := range map[string]func(*durableWork){"uncertain": func(w *durableWork) { w.Outcome = "uncertain" }, "pending": func(w *durableWork) { w.State = "pending" }, "zero-generation": func(w *durableWork) { w.Generation = 0 }, "receipt-disagrees": func(w *durableWork) { w.AttemptReceipt = []byte(`{"outcome":"uncertain","code":"ambiguous"}`) }, "no-finish": func(w *durableWork) { w.FinishedAt = time.Time{} }, "identity": func(w *durableWork) { w.ID = "auth:replaced" }} {
		t.Run(name, func(t *testing.T) {
			v := s
			v.Work = []durableWork{work}
			change(&v.Work[0])
			if _, _, err := projectOutbox(v, nil); err == nil {
				t.Fatal("unproven durable work accepted")
			}
		})
	}
	records, rows, err := projectOutbox(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || len(rows) != 1 || records[0].ID != event.ID || rows[0].Generation != 3 || rows[0].WorkID != work.ID {
		t.Fatal("actual SQL identities lost")
	}
}
func TestPermissionNeedsExactShippingActivationResult(t *testing.T) {
	for _, raw := range []string{`{}`, `{"deployment":"task11-green","instance":"task11-green-primary","workers_active":true,"waiting_for_peer":true,"endpoint_switch_performed":false}`, `{"deployment":"wrong","instance":"task11-green-primary","workers_active":true,"waiting_for_peer":false,"endpoint_switch_performed":false}`} {
		if _, err := validateActivation([]byte(raw), "green-primary"); err == nil {
			t.Fatal("unbound activation accepted")
		}
	}
}

func TestProjectionReadsActualPublishedSnapshotMode(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "inventory.json")
	snapshot := domain.Snapshot{Version: 2, Identities: map[string]*domain.DeviceRecord{}, Certificates: map[string]*domain.DeviceRecord{}, HardwareSerials: map[string]*domain.DeviceRecord{}}
	if err := domain.PublishSnapshotFile(path, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublishedSnapshot(path, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublishedSnapshot(path, os.Getuid()); err == nil {
		t.Fatal("writable snapshot accepted")
	}
}

func TestVerifierRequiresEveryExplicitResultField(t *testing.T) {
	p := projection{Gate: "installed-traffic", ApplicationSHA256: strings.Repeat("a", 64), Records: []telemetry.BusinessRecord{{ID: "actual"}}}
	v := verification{Schema: 1, Gate: p.Gate, ApplicationSHA256: p.ApplicationSHA256, Phase: "post-activation", SecretPreservation: true, FleetUncertainty: true, OTLPDecoding: true, EvidenceSHA256: strings.Repeat("b", 64), Records: 1}
	raw, _ := json.Marshal(v)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "ordinary_telemetry")
	raw, _ = json.Marshal(fields)
	if _, err := validateVerification(raw, p); err == nil {
		t.Fatal("missing explicit signal scope accepted")
	}
}

func TestCloudPinsAndDeactivationCannotInventAuthority(t *testing.T) {
	pin := strings.Repeat("a", 64)
	p := cloudPins{HelperSHA256: pin, PrimitiveSeedSHA256: pin, PrimitiveExpectedSHA256: pin, InstalledSeedSHA256: pin, OriginalStateSHA256: pin}
	if err := p.validate(); err != nil {
		t.Fatal(err)
	}
	p.OriginalStateSHA256 = ""
	if err := p.validate(); err == nil {
		t.Fatal("missing original provenance pin accepted")
	}
	good := []byte(`{"operation":"state export","node":"radius-primary","fence_only":true,"transition":"` + pin + `","path":"","workers_blocked":true}`)
	if err := validateDeactivation(good, "radius-primary", pin); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{[]byte(`{}`), bytes.ReplaceAll(good, []byte(`"workers_blocked":true`), []byte(`"workers_blocked":false`)), bytes.ReplaceAll(good, []byte(`radius-primary`), []byte(`radius-secondary`))} {
		if err := validateDeactivation(raw, "radius-primary", pin); err == nil {
			t.Fatal("unbound worker fence accepted")
		}
	}
}

func TestExpectedProjectionPrivatePipePreservesExactUint64(t *testing.T) {
	original := projection{Records: []telemetry.BusinessRecord{{ID: "actual-usage", Fields: map[string]any{"input_bytes": json.Number("18446744073709551615"), "counter_bits": 64}}}}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var got projection
	if err = decodeExactJSON(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Records[0].Fields["input_bytes"] != json.Number("18446744073709551615") {
		t.Fatal("uint64 rounded in expected projection transport")
	}
	bad := bytes.Replace(raw, []byte(`"input_bytes":18446744073709551615`), []byte(`"input_bytes":1,"input_bytes":2`), 1)
	if err = decodeExactJSON(bad, &got); err == nil {
		t.Fatal("duplicate expected attribute accepted")
	}
}
