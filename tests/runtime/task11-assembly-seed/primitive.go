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
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/events/auth"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
	"github.com/CampusTech/cloud-8021x/tests/runtime/task11-assembly-seed/contract"
	metricscollect "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	metrics "go.opentelemetry.io/proto/otlp/metrics/v1"
	resource "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

const primitiveCommand = "task11-retained-command-0001"

type primitiveHost struct {
	ID            int    `json:"id"`
	UUID          string `json:"uuid"`
	Platform      string `json:"platform"`
	MDMEnrolledAt string `json:"last_mdm_enrolled_at"`
	EnrolledAt    string `json:"last_enrolled_at"`
}
type primitivePlan struct {
	Schema              int               `json:"schema"`
	ApplicationSHA256   string            `json:"application_sha256"`
	SeedSHA256          string            `json:"seed_sha256"`
	FleetAuthorization  string            `json:"fleet_authorization"`
	IntakeAuthorization string            `json:"intake_authorization"`
	Host                primitiveHost     `json:"host"`
	CreatedAt           string            `json:"created_at"`
	Auth                auth.Event        `json:"auth"`
	Publications        map[string][]byte `json:"publications"`
}
type primitiveProjection struct {
	Schema            int                        `json:"schema"`
	Gate              string                     `json:"gate"`
	ApplicationSHA256 string                     `json:"application_sha256"`
	SeedSHA256        string                     `json:"seed_sha256"`
	Records           []telemetry.BusinessRecord `json:"records"`
	Metrics           []metricExpected           `json:"metrics"`
	Publications      map[string]string          `json:"publications"`
	Commands          []commandExpected          `json:"commands"`
}
type metricExpected struct {
	Host string `json:"host"`
	Name string `json:"name"`
	Unit string `json:"unit"`
	Kind string `json:"kind"`
}
type commandExpected struct {
	Origin            string `json:"origin"`
	HostID            int    `json:"host_id"`
	HostUUID          string `json:"host_uuid"`
	Platform          string `json:"platform"`
	MDMEnrolledAt     string `json:"last_mdm_enrolled_at"`
	EnrolledAt        string `json:"last_enrolled_at"`
	Transport         string `json:"transport"`
	OriginalCreatedAt string `json:"original_created_at"`
	AcceptedBefore    string `json:"accepted_before"`
	RecoveryPhase     string `json:"recovery_phase"`
	UUID              string `json:"command_uuid"`
	Posts             int    `json:"posts"`
	RequireUncertain  bool   `json:"require_uncertain"`
}

func primitiveInputs(spec seedSpec, installed cloudSeed, ca, cert, key []byte) (map[string][]byte, error) {
	var contract map[string]json.RawMessage
	if err := json.Unmarshal(installed.Contract, &contract); err != nil {
		return nil, err
	}
	var fleet struct {
		Authorization string            `json:"authorization"`
		Hosts         []json.RawMessage `json:"hosts"`
		Commands      []json.RawMessage `json:"commands"`
	}
	if err := domain.DecodeJSONStrict(contract["fleet"], &fleet); err != nil || len(fleet.Hosts) == 0 || len(fleet.Commands) != 1 {
		return nil, errors.New("primitive original Fleet binding absent")
	}
	var host primitiveHost
	if err := json.Unmarshal(fleet.Hosts[0], &host); err != nil {
		return nil, err
	}
	var command struct {
		CreatedAt string `json:"created_at"`
	}
	if err := json.Unmarshal(fleet.Commands[0], &command); err != nil {
		return nil, err
	}
	token, err := randomText()
	if err != nil {
		return nil, err
	}
	contract["gate"] = json.RawMessage(`"primitive-contract"`)
	contract["peers"] = json.RawMessage(`{}`)
	contract["otlp"], _ = json.Marshal(map[string]string{"host": "otlp.task11.test", "authorization": "Bearer " + token})
	raw, _ := json.Marshal(contract)
	seed := cloudSeed{Schema: 1, ProjectID: spec.Project, ProjectNumber: "111222333444", Contract: raw, Secrets: map[string]map[string]string{}, Keys: map[string]string{}, Routes: []route{}}
	_, publicationCert, publicationKey, e := tlsIdentity([]string{"primitive.task11.test"}, nil, spec.ObservedAt)
	if e != nil {
		return nil, e
	}
	pubs := map[string][]byte{}
	for name, data := range map[string][]byte{"radius-smallstep-server-cert": publicationCert, "radius-smallstep-server-key": publicationKey} {
		r := "projects/111222333444/secrets/" + name
		seed.Secrets[r] = installed.Secrets[r]
		pubs[r] = bytes.Clone(data)
	}
	encoded, err := json.Marshal(seed)
	if err != nil {
		return nil, err
	}
	p := primitivePlan{Schema: 1, ApplicationSHA256: spec.Remote.ApplicationSHA256, SeedSHA256: digest(encoded), FleetAuthorization: fleet.Authorization, IntakeAuthorization: "Bearer " + token, Host: host, CreatedAt: command.CreatedAt, Auth: auth.Event{ID: "task11-primitive-auth-0001", Event: "Access-Reject", Host: "task11-primitive", Received: spec.ObservedAt, Location: "task11", Source: "10.203.11.40", Reason: "policy_denied"}, Publications: pubs}
	expected, err := projectPrimitive(p)
	if err != nil {
		return nil, err
	}
	planBytes, _ := json.Marshal(p)
	expectedBytes, _ := json.Marshal(expected)
	return map[string][]byte{"seed.json": encoded, "ca.pem": bytes.Clone(ca), "tls.pem": bytes.Clone(cert), "tls.key": bytes.Clone(key), "driver-input.json": planBytes, "expected.json": expectedBytes}, nil
}
func projectPrimitive(p primitivePlan) (primitiveProjection, error) {
	out := primitiveProjection{}
	if p.Schema != 1 || !contract.IsSHA(p.ApplicationSHA256) || !contract.IsSHA(p.SeedSHA256) || p.Host.ID != 1 || p.Host.UUID != "11111111-2222-4333-8444-555555555555" || p.Host.Platform != "darwin" || p.CreatedAt != p.Host.MDMEnrolledAt || len(p.Publications) != 2 {
		return out, errors.New("independent primitive input binding invalid")
	}
	created, err := time.Parse(time.RFC3339, p.CreatedAt)
	if err != nil || !created.Equal(p.Auth.Received) || p.Auth.ID != "task11-primitive-auth-0001" || p.Auth.Host != "task11-primitive" {
		return out, errors.New("primitive observation changed")
	}
	enrolled, err := time.Parse(time.RFC3339, p.Host.EnrolledAt)
	if err != nil || !enrolled.Equal(created.Add(-24*time.Hour)) {
		return out, errors.New("primitive enrollment differs")
	}
	payload, err := json.Marshal(p.Auth)
	if err != nil {
		return out, err
	}
	record, err := telemetry.Project(jobs.Claim{ID: "auth:" + p.Auth.ID, Payload: payload}, nil)
	if err != nil {
		return out, err
	}
	out = primitiveProjection{Schema: 1, Gate: "primitive-contract", ApplicationSHA256: p.ApplicationSHA256, SeedSHA256: p.SeedSHA256, Records: []telemetry.BusinessRecord{record}, Metrics: []metricExpected{{"task11-primitive", "cloud8021x.backend.up", "1", "gauge"}}, Publications: map[string]string{}, Commands: []commandExpected{{Origin: "retained-legacy", HostID: p.Host.ID, HostUUID: p.Host.UUID, Platform: p.Host.Platform, MDMEnrolledAt: p.Host.MDMEnrolledAt, EnrolledAt: p.Host.EnrolledAt, Transport: "apple", OriginalCreatedAt: p.CreatedAt, AcceptedBefore: p.CreatedAt, RecoveryPhase: "active", UUID: primitiveCommand}}}
	for _, name := range []string{"radius-smallstep-server-cert", "radius-smallstep-server-key"} {
		r := "projects/111222333444/secrets/" + name
		if len(p.Publications[r]) == 0 || len(p.Publications[r]) > 65536 {
			return out, errors.New("bounded independent publication required")
		}
		out.Publications[r] = digest(p.Publications[r])
	}
	return out, nil
}
func primitiveMetrics(at time.Time) []byte {
	attrs := []*common.KeyValue{{Key: "host.name", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "task11-primitive"}}}, {Key: "service.name", Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: "cloud-8021x"}}}}
	metric := &metrics.Metric{Name: "cloud8021x.backend.up", Unit: "1", Data: &metrics.Metric_Gauge{Gauge: &metrics.Gauge{DataPoints: []*metrics.NumberDataPoint{{TimeUnixNano: uint64(at.UnixNano()), Value: &metrics.NumberDataPoint_AsInt{AsInt: 1}}}}}}
	b, _ := proto.Marshal(&metricscollect.ExportMetricsServiceRequest{ResourceMetrics: []*metrics.ResourceMetrics{{Resource: &resource.Resource{Attributes: attrs}, ScopeMetrics: []*metrics.ScopeMetrics{{Scope: &common.InstrumentationScope{Name: "cloud-8021x"}, Metrics: []*metrics.Metric{metric}}}}}})
	return b
}

type requestDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Only future explicitly authorized execution supplies a real TLS client and
// pinned helper scenario runner. Expected projection is computed before traffic.
func drivePrimitive(ctx context.Context, p primitivePlan, client requestDoer, scenario func(context.Context, string) error) error {
	projection, err := projectPrimitive(p)
	if err != nil {
		return err
	}
	request := func(method, target, authz, kind string, body []byte, want int) ([]byte, error) {
		r, err := http.NewRequestWithContext(ctx, method, "https://"+target, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Authorization", authz)
		if kind != "" {
			r.Header.Set("Content-Type", kind)
		}
		response, err := client.Do(r)
		if err != nil {
			return nil, errors.New("primitive request failed")
		}
		defer func() { _ = response.Body.Close() }()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		if err != nil || len(raw) >= 2<<20 || response.StatusCode != want {
			return nil, errors.New("primitive response differs")
		}
		return raw, nil
	}
	for _, name := range []string{"radius-smallstep-server-cert", "radius-smallstep-server-key"} {
		resource := "projects/111222333444/secrets/" + name
		value := p.Publications[resource]
		body, _ := json.Marshal(map[string]any{"payload": map[string]string{"data": base64.StdEncoding.EncodeToString(value), "dataCrc32c": fmt.Sprint(crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli)))}})
		raw, err := request("POST", "secretmanager.googleapis.com/v1/"+resource+":addVersion", "Bearer task11-synthetic-token-not-a-cloud-credential", "application/json", body, 200)
		if err != nil {
			return err
		}
		var version struct {
			Name       string `json:"name"`
			State      string `json:"state"`
			CreateTime string `json:"createTime"`
		}
		if json.Unmarshal(raw, &version) != nil || version.Name != resource+"/versions/2" || version.State != "ENABLED" {
			return errors.New("primitive immutable publication differs")
		}
		raw, err = request("GET", "secretmanager.googleapis.com/v1/"+version.Name+":access", "Bearer task11-synthetic-token-not-a-cloud-credential", "", nil, 200)
		if err != nil {
			return err
		}
		var accessed struct {
			Payload struct {
				Data string `json:"data"`
				CRC  string `json:"dataCrc32c"`
			} `json:"payload"`
		}
		if json.Unmarshal(raw, &accessed) != nil || accessed.Payload.Data != base64.StdEncoding.EncodeToString(value) || accessed.Payload.CRC != fmt.Sprint(crc32.Checksum(value, crc32.MakeTable(crc32.Castagnoli))) {
			return errors.New("primitive accessed bytes/CRC differ")
		}
	}
	if _, err = request("GET", "fleet.task11.test/api/v1/fleet/hosts/1", p.FleetAuthorization, "", nil, 200); err != nil {
		return err
	}
	for _, step := range []struct {
		name string
		code int
	}{{"fleet-pending", 200}, {"fleet-missing", 404}, {"fleet-terminal", 200}} {
		if err = scenario(ctx, step.name); err != nil {
			return err
		}
		if _, err = request("GET", "fleet.task11.test/api/v1/fleet/commands/results?command_uuid="+primitiveCommand, p.FleetAuthorization, "", nil, step.code); err != nil {
			return err
		}
	}
	logs, err := proto.Marshal(otlp.Request(projection.Records))
	if err != nil {
		return err
	}
	for _, item := range []struct {
		kind string
		body []byte
	}{{"logs", logs}, {"metrics", primitiveMetrics(p.Auth.Received)}} {
		raw, e := request("POST", "otlp.task11.test/v1/"+item.kind, p.IntakeAuthorization, "application/x-protobuf", item.body, 200)
		if e != nil {
			return e
		}
		if len(raw) > 0 && strings.Contains(string(raw), "error") {
			return errors.New("primitive intake response rejected")
		}
	}
	return nil
}
