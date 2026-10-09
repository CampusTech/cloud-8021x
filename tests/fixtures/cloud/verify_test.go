package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	logscollect "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricscollect "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	metrics "go.opentelemetry.io/proto/otlp/metrics/v1"
	resource "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

func metricRequest() *metricscollect.ExportMetricsServiceRequest {
	point := &metrics.NumberDataPoint{TimeUnixNano: 1800000000000000000, Value: &metrics.NumberDataPoint_AsInt{AsInt: 1}}
	metric := &metrics.Metric{Name: "cloud8021x.backend.up", Unit: "1", Data: &metrics.Metric_Gauge{Gauge: &metrics.Gauge{DataPoints: []*metrics.NumberDataPoint{point}}}}
	scope := &metrics.ScopeMetrics{Scope: &common.InstrumentationScope{Name: "cloud-8021x"}, Metrics: []*metrics.Metric{metric}}
	attrs := []*common.KeyValue{{Key: "host.name", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "green-primary"}}}, {Key: "service.name", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "cloud-8021x"}}}}
	return &metricscollect.ExportMetricsServiceRequest{ResourceMetrics: []*metrics.ResourceMetrics{{Resource: &resource.Resource{Attributes: attrs}, ScopeMetrics: []*metrics.ScopeMetrics{scope}}}}
}
func intakeRequest(t *testing.T, f *fixture, kind string, body []byte, want int, peers ...string) {
	t.Helper()
	r := httptest.NewRequest("POST", "https://"+f.config.Contract.OTLP.Host+"/v1/"+kind, bytes.NewReader(body))
	if f.config.Contract.Gate == "installed-traffic" {
		r.RemoteAddr = "10.203.11.21:4321"
	}
	if len(peers) > 0 {
		r.RemoteAddr = peers[0] + ":4321"
	}
	r.Header.Set("Authorization", f.config.Contract.OTLP.Authorization)
	r.Header.Set("dd-api-key", f.config.Contract.OTLP.APIKey)
	r.Header.Set("Content-Type", "application/x-protobuf")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("intake got %d want %d: %s", w.Code, want, w.Body.String())
	}
}
func completePrimitiveEvidence(t *testing.T, alter ...func(*logscollect.ExportLogsServiceRequest)) (*fixture, projection) {
	t.Helper()
	f := fleetFixture(t)
	f.phase = "active"
	f.config.Contract.Gate = "primitive-contract"
	f.config.Contract.OTLP = &otlpSeed{Host: "otlp.task11.test", Authorization: "Bearer task11-intake"}
	pubs := map[string]string{}
	for _, name := range []string{"radius-smallstep-server-cert", "radius-smallstep-server-key"} {
		resource := "projects/111222333444/secrets/" + name
		f.config.Secrets[resource] = map[string]string{"1": base64.StdEncoding.EncodeToString([]byte("original-" + name))}
		pubs[resource] = digestBytes([]byte("new-" + name))
	}
	for _, name := range []string{"radius-smallstep-server-cert", "radius-smallstep-server-key"} {
		value := []byte("new-" + name)
		payload := `{"payload":{"data":"` + base64.StdEncoding.EncodeToString(value) + `","dataCrc32c":"` + crcString(value) + `"}}`
		secretRequest(t, f, "POST", name+":addVersion", payload, 200)
		secretRequest(t, f, "GET", name+"/versions/2:access", "", 200)
	}
	const id = "task11-retained-command-0001"
	fleetRequest(t, f, "GET", "/api/v1/fleet/hosts/1", "", 200)
	for _, step := range []struct {
		name   string
		status int
	}{{"fleet-pending", 200}, {"fleet-missing", 404}, {"fleet-terminal", 200}} {
		if err := f.advanceScenario(step.name, id); err != nil {
			t.Fatal(err)
		}
		fleetRequest(t, f, "GET", "/api/v1/fleet/commands/results?command_uuid="+id, "", step.status)
	}
	record := telemetry.BusinessRecord{ID: "actual-id", Category: "usage", Host: "green-primary", Received: time.Unix(1800000000, 0), Fields: map[string]any{"event_id": "actual-id", "usage_id": "actual-id", "event": "Acct-Usage", "identity_verified": true, "input_bytes": json.Number("18446744073709551615"), "session_time": json.Number("5")}}
	request := otlp.Request([]telemetry.BusinessRecord{record})
	for _, change := range alter {
		change(request)
	}
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	intakeRequest(t, f, "logs", payload, 200)
	payload, err = proto.Marshal(metricRequest())
	if err != nil {
		t.Fatal(err)
	}
	intakeRequest(t, f, "metrics", payload, 200)
	expected := projection{Schema: 1, Gate: "primitive-contract", ApplicationSHA256: strings.Repeat("a", 64), SeedSHA256: f.remote.SeedSHA256, Records: []telemetry.BusinessRecord{record}, Publications: pubs, Commands: []commandExpectation{legacyExpectation(f, "")}, Metrics: []metricExpectation{{Host: "green-primary", Name: "cloud8021x.backend.up", Unit: "1", Kind: "gauge"}}}
	encoded, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	expected, err = parsedProjection(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return f, expected
}
func TestVerifierRequiresActualDecodedBoundEvidence(t *testing.T) {
	f, expected := completePrimitiveEvidence(t)
	result, err := f.verifyEvidence(expected, expected.ApplicationSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if result.Phase != "primitive-only" || result.Records != 1 || result.OrdinaryTelemetry {
		t.Fatal("primitive evidence promoted to installed readiness")
	}
	for _, tc := range []struct {
		name   string
		modify func(*fixture, *projection)
	}{
		{"hash-only", func(f *fixture, _ *projection) { f.remote.Batches = nil }},
		{"missing-request", func(f *fixture, _ *projection) { f.remote.Events = nil }},
		{"duplicate-record", func(f *fixture, _ *projection) { f.remote.Batches = append(f.remote.Batches, f.remote.Batches[0]) }},
		{"conflicting-body", func(f *fixture, _ *projection) {
			f.remote.Batches[0].Logs[0].Body = json.RawMessage(`{"event_id":"actual-id","event":"Access-Reject"}`)
		}},
		{"wrong-application", func(_ *fixture, p *projection) { p.ApplicationSHA256 = strings.Repeat("b", 64) }},
		{"wrong-seed", func(_ *fixture, p *projection) { p.SeedSHA256 = strings.Repeat("b", 64) }},
		{"pending-command", func(f *fixture, _ *projection) {
			c := f.remote.Commands["task11-retained-command-0001"]
			c.Mode = "pending"
			f.remote.Commands[c.UUID] = c
		}},
		{"repeated-post", func(f *fixture, _ *projection) {
			c := f.remote.Commands["task11-retained-command-0001"]
			c.Posts = 2
			f.remote.Commands[c.UUID] = c
		}},
		{"changed-authority", func(f *fixture, _ *projection) {
			f.remote.Secrets["projects/111222333444/secrets/radius-smallstep-server-cert"]["1"] = secretVersion{Data: "Zm9yZWlnbg==", State: "ENABLED"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, p := completePrimitiveEvidence(t)
			tc.modify(f, &p)
			if _, err := f.verifyEvidence(p, strings.Repeat("a", 64)); err == nil {
				t.Fatal("unproven evidence accepted")
			}
		})
	}
}
func TestMetricWithoutActualPointTimestampRejected(t *testing.T) {
	f := fleetFixture(t)
	f.phase = "active"
	f.config.Contract.OTLP = &otlpSeed{Host: "otlp.task11.test", Authorization: "Bearer test"}
	request := metricRequest()
	request.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].GetGauge().DataPoints[0].TimeUnixNano = 0
	body, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	intakeRequest(t, f, "metrics", body, 400)
	if len(f.remote.Batches) != 0 {
		t.Fatal("invalid metric persisted")
	}
}

func installedEvidence(t *testing.T, exporter, recovery string, activate bool) (*fixture, projection) {
	t.Helper()
	f := fleetFixture(t)
	f.phase = "active"
	f.config.Contract.Gate = "installed-traffic"
	f.config.Contract.Peers = map[string]peerPolicy{}
	for ip, role := range ownedPeerRoles {
		phase := "passive"
		if strings.HasPrefix(role, "original-") {
			phase = "active"
		}
		f.config.Contract.Peers[ip] = peerPolicy{Role: role, Phase: phase}
	}
	f.config.Contract.OTLP = &otlpSeed{Host: "otlp.us5.datadoghq.com", APIKey: "synthetic-key"}
	f.config.Secrets["projects/111222333444/secrets/radius-smallstep-server-cert"] = map[string]string{"1": base64.StdEncoding.EncodeToString([]byte("original"))}
	if err := f.config.Contract.validate(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.203.11.21", "10.203.11.22"} {
		r := httptest.NewRequest("GET", "https://secretmanager.googleapis.com/v1/projects/task11-fixture/secrets/radius-smallstep-server-cert/versions/1:access", nil)
		r.RemoteAddr = ip + ":4321"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		f.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("passive read failed")
		}
		if activate {
			if err := f.runScenario("peer-active", "", ip); err != nil {
				t.Fatal(err)
			}
		}
	}
	const id = "task11-retained-command-0001"
	fleetRequest(t, f, "GET", "/api/v1/fleet/hosts/1", "", 200, recovery)
	for _, step := range []struct {
		name   string
		status int
	}{{"fleet-pending", 200}, {"fleet-missing", 404}, {"fleet-terminal", 200}} {
		if err := f.runScenario(step.name, id, ""); err != nil {
			t.Fatal(err)
		}
		fleetRequest(t, f, "GET", "/api/v1/fleet/commands/results?command_uuid="+id, "", step.status, recovery)
	}
	// This is a unit input to the real typed projector. The installed controller
	// must obtain the corresponding payload/generation from actual SQL work.
	payload, err := json.Marshal(auth.Event{ID: "auth-fixture", Event: "Access-Accept", Host: "green-primary", Received: time.Unix(1800000000, 0), DeviceID: "fleet:1", Location: "task11"})
	if err != nil {
		t.Fatal(err)
	}
	record, err := telemetry.Project(jobs.Claim{ID: "auth:auth-fixture", Payload: payload}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := otlp.Request([]telemetry.BusinessRecord{record})
	request.ResourceLogs[0].Resource.Attributes[0].Value.Value = &common.AnyValue_StringValue{StringValue: "radius-auth"}
	data, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	intakeRequest(t, f, "logs", data, 200, exporter)
	expected := projection{Schema: 1, Gate: "installed-traffic", ApplicationSHA256: strings.Repeat("a", 64), SeedSHA256: f.remote.SeedSHA256, DeploymentID: "green", Database: "cloud8021x_green", CollectionEpoch: "2026-10-08T10:00:00Z", Records: []telemetry.BusinessRecord{record}, Commands: []commandExpectation{legacyExpectation(f, "10.203.11.21")}, Outbox: []outboxExpectation{{WorkID: "auth:auth-fixture", Generation: 1, PayloadSHA256: digestBytes(payload), RecordID: record.ID, Outcome: "succeeded"}}}
	encoded, _ := json.Marshal(expected)
	expected, err = parsedProjection(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return f, expected
}
func TestInstalledProjectionRequiresPeerHistoryAndActualTypedPayload(t *testing.T) {
	f, expected := installedEvidence(t, "10.203.11.21", "10.203.11.21", true)
	result, err := f.verifyEvidence(expected, expected.ApplicationSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if result.SecretPublication || !result.SecretPreservation || result.OrdinaryTelemetry {
		t.Fatal("unchanged cache/ordinary evidence mislabeled")
	}
	saved := expected.Outbox[0]
	expected.Outbox[0].Generation = 0
	if _, err = f.verifyEvidence(expected, expected.ApplicationSHA256); err == nil {
		t.Fatal("missing real outbox generation accepted")
	}
	expected.Outbox[0] = saved
	f.remote.Events = f.remote.Events[1:]
	if _, err = f.verifyEvidence(expected, expected.ApplicationSHA256); err == nil {
		t.Fatal("missing primary passive observation accepted")
	}
}

func TestInstalledVerifierRejectsOriginalOnlyDeliveryAndRecovery(t *testing.T) {
	for _, tc := range []struct {
		name, exporter, recovery string
		activate                 bool
	}{{"original-only passive greens", "10.203.11.31", "10.203.11.31", false}, {"original delivery", "10.203.11.31", "10.203.11.21", true}, {"original recovery", "10.203.11.21", "10.203.11.31", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f, p := installedEvidence(t, tc.exporter, tc.recovery, tc.activate)
			if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err == nil {
				t.Fatal("original-node traffic certified as installed green behavior")
			}
		})
	}
}
func TestInstalledVerifierAllowsOtherGreenToExportSharedOutbox(t *testing.T) {
	f, p := installedEvidence(t, "10.203.11.22", "10.203.11.21", true)
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err != nil {
		t.Fatal(err)
	}
}
func TestVerifierRejectsMissingWrongNumericPrimaryAndPrivateExtras(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*decodedLog)
	}{
		{"missing primary", func(r *decodedLog) { delete(r.Attributes, "input_bytes") }},
		{"wrong primary", func(r *decodedLog) { r.Attributes["input_bytes"] = int64(7) }},
		{"private attribute", func(r *decodedLog) { r.Attributes["tls_private_key"] = "private" }},
		{"private resource", func(r *decodedLog) { r.Resource["tls_private_key"] = "private" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, p := completePrimitiveEvidence(t)
			tc.alter(&f.remote.Batches[0].Logs[0])
			if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err == nil {
				t.Fatal("inexact or private telemetry shape certified")
			}
		})
	}
}

func TestInstalledVerifierRejectsOriginalPublicationSubstitution(t *testing.T) {
	f, p := installedEvidence(t, "10.203.11.21", "10.203.11.21", true)
	data := []byte("renewed cache")
	payload := `{"payload":{"data":"` + base64.StdEncoding.EncodeToString(data) + `","dataCrc32c":"` + crcString(data) + `"}}`
	secretRequest(t, f, "POST", "radius-smallstep-server-cert:addVersion", payload, 200, "10.203.11.31")
	secretRequest(t, f, "GET", "radius-smallstep-server-cert/versions/2:access", "", 200, "10.203.11.21")
	p.Publications = map[string]string{"projects/111222333444/secrets/radius-smallstep-server-cert": digestBytes(data)}
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err == nil {
		t.Fatal("original publication certified as green renewal")
	}
}

func TestCommandProofRequiresIndependentOriginalTargetScriptAndTime(t *testing.T) {
	scriptBytes, err := os.ReadFile("../../../internal/adapters/fleet/windows_certificates.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"correct", "wrong-host", "wrong-script-same-nonce", "wrong-original-time", "wrong-enrollment"} {
		t.Run(mode, func(t *testing.T) {
			f := fleetFixture(t)
			f.phase = "active"
			f.config.Contract.Fleet.Commands = nil
			host := f.config.Contract.Fleet.Hosts[0]
			host.Platform = "windows"
			host.ScriptsEnabled = true
			other := host
			other.ID = 2
			other.UUID = "22222222-3333-4444-8555-666666666666"
			f.config.Contract.Fleet.Hosts = []fleetHost{host, other}
			const id = "actual-original-nonce"
			script := string(scriptBytes) + "\n# Collection nonce: " + id + "\n"
			original, err := json.Marshal(map[string]any{"host_id": host.ID, "script_contents": script})
			if err != nil {
				t.Fatal(err)
			}
			created := time.Now().UTC().Add(-time.Second)
			before := created.Add(time.Minute)
			originalExpectation := map[string]any{"command_uuid": id, "posts": 1, "require_uncertain": true, "origin": "green-work", "host_id": host.ID, "host_uuid": host.UUID, "platform": "windows", "last_mdm_enrolled_at": host.MDMEnrolledAt, "last_enrolled_at": host.EnrolledAt, "transport": "windows", "original_created_at": created.Format(time.RFC3339Nano), "accepted_before": before.Format(time.RFC3339Nano), "request_sha256": digestBytes(original), "script_sha256": digestBytes([]byte(script)), "recovery_phase": "active"}
			actualHost := host.ID
			actualScript := script
			switch mode {
			case "wrong-host":
				actualHost = other.ID
			case "wrong-script-same-nonce":
				actualScript = "Write-Output 'different script'\n# Collection nonce: " + id + "\n"
			case "wrong-original-time":
				originalExpectation["original_created_at"] = created.Add(time.Hour).Format(time.RFC3339Nano)
				originalExpectation["accepted_before"] = before.Add(time.Hour).Format(time.RFC3339Nano)
			case "wrong-enrollment":
				originalExpectation["last_enrolled_at"] = "2026-10-06T10:00:00Z"
			}
			payload, _ := json.Marshal(map[string]any{"host_id": actualHost, "script_contents": actualScript})
			if err = f.advanceScenario("fleet-uncertain", ""); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("POST", "https://fleet.task11.test/api/v1/fleet/scripts/run", bytes.NewReader(payload))
			request.Header.Set("Authorization", "Bearer task11-fleet")
			if response, e := (fixtureTransport{f}).RoundTrip(request); e == nil || response != nil {
				t.Fatal("expected accepted uncertain submission")
			}
			c := f.remote.Commands[id]
			fleetRequest(t, f, "GET", "/api/v1/fleet/hosts/"+strconv.Itoa(c.HostID), "", 200)
			for _, step := range []struct {
				name   string
				status int
			}{{"fleet-pending", 200}, {"fleet-missing", 404}, {"fleet-terminal", 200}} {
				if err = f.advanceScenario(step.name, id); err != nil {
					t.Fatal(err)
				}
				fleetRequest(t, f, "GET", "/api/v1/fleet/scripts/results/"+c.ExecutionID, "", step.status)
			}
			encoded, _ := json.Marshal(originalExpectation)
			var expected commandExpectation
			if err = json.Unmarshal(encoded, &expected); err != nil {
				t.Fatal(err)
			}
			err = f.verifyCommands([]commandExpectation{expected})
			if (err == nil) != (mode == "correct") {
				t.Fatalf("mode %s independently pinned proof: %v", mode, err)
			}
		})
	}
}

func legacyExpectation(f *fixture, peer string) commandExpectation {
	host := f.config.Contract.Fleet.Hosts[0]
	original := f.config.Contract.Fleet.Commands[0]
	return commandExpectation{UUID: original.UUID, Origin: "retained-legacy", HostID: host.ID, HostUUID: host.UUID, Platform: host.Platform, MDMEnrolledAt: host.MDMEnrolledAt, EnrolledAt: host.EnrolledAt, Transport: "apple", OriginalCreatedAt: original.CreatedAt, AcceptedBefore: original.CreatedAt, RecoveryPeer: peer, RecoveryPhase: "active"}
}

func TestVerifierRejectsWrongNumericWireType(t *testing.T) {
	f, p := completePrimitiveEvidence(t, func(r *logscollect.ExportLogsServiceRequest) {
		for _, kv := range r.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes {
			if kv.Key == "session_time" {
				kv.Value.Value = &common.AnyValue_DoubleValue{DoubleValue: 5}
			}
		}
	})
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err == nil {
		t.Fatal("wrong numeric wire representation certified")
	}
}

func TestInstalledRetainedOriginalPostRequiresPinnedProvenanceAndGreenPassiveRecovery(t *testing.T) {
	f, p := installedEvidence(t, "10.203.11.22", "10.203.11.21", true)
	const id = "independently-retained-original-command"
	host := f.config.Contract.Fleet.Hosts[0]
	created := time.Now().UTC().Add(-time.Second)
	epoch := time.Now().UTC().Add(10 * time.Second).Truncate(time.Second)
	p.CollectionEpoch = epoch.Format(time.RFC3339)
	original, _ := json.Marshal(map[string]any{"command": base64.StdEncoding.EncodeToString([]byte(applePrefix + id + appleSuffix)), "host_uuids": []string{host.UUID}})
	pinned := commandExpectation{UUID: id, Posts: 1, RequireUncertain: true, Origin: "retained-legacy", HostID: host.ID, HostUUID: host.UUID, Platform: host.Platform, MDMEnrolledAt: host.MDMEnrolledAt, EnrolledAt: host.EnrolledAt, Transport: "apple", OriginalCreatedAt: created.Format(time.RFC3339Nano), AcceptedBefore: epoch.Format(time.RFC3339Nano), RequestSHA256: digestBytes(original), SubmissionPeer: "10.203.11.31", RecoveryPeer: "10.203.11.21", RecoveryPhase: "passive"}
	if err := f.runScenario("fleet-uncertain", "", ""); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "https://fleet.task11.test/api/v1/fleet/commands/run", bytes.NewReader(original))
	request.RemoteAddr = "10.203.11.31:4321"
	request.Header.Set("Authorization", "Bearer task11-fleet")
	if response, err := (fixtureTransport{f}).RoundTrip(request); err == nil || response != nil {
		t.Fatal("retained accepted uncertainty missing")
	}
	if err := f.runScenario("peer-passive", "", "10.203.11.21"); err != nil {
		t.Fatal(err)
	}
	fleetRequest(t, f, "GET", "/api/v1/fleet/hosts/1", "", 200, "10.203.11.21")
	for _, step := range []struct {
		name   string
		status int
	}{{"fleet-pending", 200}, {"fleet-missing", 404}, {"fleet-terminal", 200}} {
		if err := f.runScenario(step.name, id, ""); err != nil {
			t.Fatal(err)
		}
		fleetRequest(t, f, "GET", "/api/v1/fleet/commands/results?command_uuid="+id, "", step.status, "10.203.11.21")
	}
	p.Commands = append(p.Commands, pinned)
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err != nil {
		t.Fatal(err)
	}
	p.Commands[1].Origin = "green-work"
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err == nil {
		t.Fatal("original POST relabeled as green work")
	}
	p.Commands[1] = pinned
	p.Commands[1].AcceptedBefore = epoch.Add(time.Second).Format(time.RFC3339Nano)
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err == nil {
		t.Fatal("retained provenance crossing handoff accepted")
	}
}
func TestInstalledPublicationRequiresExactEndpointAndActiveGreen(t *testing.T) {
	f, p := installedEvidence(t, "10.203.11.22", "10.203.11.21", true)
	data := []byte("independently pinned renewed cache")
	payload := `{"payload":{"data":"` + base64.StdEncoding.EncodeToString(data) + `","dataCrc32c":"` + crcString(data) + `"}}`
	secretRequest(t, f, "POST", "radius-smallstep-server-cert:addVersion", payload, 200, "10.203.11.21")
	secretRequest(t, f, "GET", "radius-smallstep-server-cert/versions/2:access", "", 200, "10.203.11.22")
	p.Publications = map[string]string{"projects/111222333444/secrets/radius-smallstep-server-cert": digestBytes(data)}
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err != nil {
		t.Fatal(err)
	}
	for i := range f.remote.Events {
		event := &f.remote.Events[i]
		if event.Method == "POST" && strings.HasSuffix(event.Target, ":addVersion") {
			event.Target = "foreign.invalid/v1/projects/task11-fixture/secrets/radius-smallstep-server-cert:addVersion"
		}
	}
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err == nil {
		t.Fatal("foreign endpoint substituted for publication")
	}
}

func TestCapacityRepeatCannotPassCompleteCommandVerifier(t *testing.T) {
	f, p := completePrimitiveEvidence(t)
	host := f.config.Contract.Fleet.Hosts[0]
	created := time.Now().UTC().Add(-time.Second)
	var first []byte
	for n := 1; n < 128; n++ {
		id := "capacity-command-" + strconv.Itoa(n)
		body, err := json.Marshal(map[string]any{"command": base64.StdEncoding.EncodeToString([]byte(applePrefix + id + appleSuffix)), "host_uuids": []string{host.UUID}})
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			first = append([]byte(nil), body...)
		}
		expected := commandExpectation{UUID: id, Posts: 1, Origin: "green-work", HostID: host.ID, HostUUID: host.UUID, Platform: host.Platform, MDMEnrolledAt: host.MDMEnrolledAt, EnrolledAt: host.EnrolledAt, Transport: "apple", OriginalCreatedAt: created.Format(time.RFC3339Nano), AcceptedBefore: created.Add(time.Minute).Format(time.RFC3339Nano), RequestSHA256: digestBytes(body), RecoveryPhase: "active"}
		fleetRequest(t, f, "POST", "/api/v1/fleet/commands/run", string(body), 200)
		for _, step := range []struct {
			name   string
			status int
		}{{"fleet-pending", 200}, {"fleet-missing", 404}, {"fleet-terminal", 200}} {
			if err = f.advanceScenario(step.name, id); err != nil {
				t.Fatal(err)
			}
			fleetRequest(t, f, "GET", "/api/v1/fleet/commands/results?command_uuid="+id, "", step.status)
		}
		p.Commands = append(p.Commands, expected)
	}
	if len(f.remote.Commands) != 128 {
		t.Fatal("did not reach actual command capacity")
	}
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err != nil {
		t.Fatalf("complete non-repeated capacity evidence rejected: %v", err)
	}
	next, _ := json.Marshal(map[string]any{"command": base64.StdEncoding.EncodeToString([]byte(applePrefix + "capacity-command-129" + appleSuffix)), "host_uuids": []string{host.UUID}})
	fleetRequest(t, f, "POST", "/api/v1/fleet/commands/run", string(next), 429)
	if len(f.remote.Commands) != 128 {
		t.Fatal("129th identity created")
	}
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err != nil {
		t.Fatalf("refused new identity changed original command evidence: %v", err)
	}
	request := httptest.NewRequest("POST", "https://fleet.task11.test/api/v1/fleet/commands/run", bytes.NewReader(first))
	request.Header.Set("Authorization", "Bearer task11-fleet")
	response := httptest.NewRecorder()
	f.ServeHTTP(response, request)
	if response.Code != 409 && response.Code != 429 {
		t.Fatalf("repeat was not refused: %d", response.Code)
	}
	if f.remote.Commands["capacity-command-1"].Posts != 2 {
		t.Error("capacity guard hid a repeated accepted-command submission")
	}
	if _, err := f.verifyEvidence(p, p.ApplicationSHA256); err == nil {
		t.Error("complete verifier certified repeated submission at capacity")
	}
}
