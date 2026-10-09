package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/otlp"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

type metricExpectation struct {
	Host string `json:"host"`
	Name string `json:"name"`
	Unit string `json:"unit"`
	Kind string `json:"kind"`
}
type commandExpectation struct {
	Origin            string `json:"origin"`
	HostID            int    `json:"host_id"`
	HostUUID          string `json:"host_uuid"`
	Platform          string `json:"platform"`
	MDMEnrolledAt     string `json:"last_mdm_enrolled_at"`
	EnrolledAt        string `json:"last_enrolled_at"`
	Transport         string `json:"transport"`
	OriginalCreatedAt string `json:"original_created_at"`
	AcceptedBefore    string `json:"accepted_before"`
	RequestSHA256     string `json:"request_sha256,omitempty"`
	ScriptSHA256      string `json:"script_sha256,omitempty"`
	SubmissionPeer    string `json:"submission_peer,omitempty"`
	RecoveryPeer      string `json:"recovery_peer,omitempty"`
	RecoveryPhase     string `json:"recovery_phase"`

	UUID             string `json:"command_uuid"`
	Posts            int    `json:"posts"`
	RequireUncertain bool   `json:"require_uncertain"`
}
type outboxExpectation struct {
	WorkID        string `json:"work_id"`
	Generation    int64  `json:"generation"`
	PayloadSHA256 string `json:"payload_sha256"`
	RecordID      string `json:"record_id"`
	Outcome       string `json:"outcome"`
}
type projection struct {
	Schema            int                        `json:"schema"`
	Gate              string                     `json:"gate"`
	ApplicationSHA256 string                     `json:"application_sha256"`
	SeedSHA256        string                     `json:"seed_sha256"`
	DeploymentID      string                     `json:"deployment_id,omitempty"`
	Database          string                     `json:"database,omitempty"`
	CollectionEpoch   string                     `json:"collection_epoch,omitempty"`
	Records           []telemetry.BusinessRecord `json:"records"`
	Metrics           []metricExpectation        `json:"metrics"`
	Publications      map[string]string          `json:"publications"`
	Commands          []commandExpectation       `json:"commands"`
	Outbox            []outboxExpectation        `json:"outbox,omitempty"`
}
type verification struct {
	Schema             int    `json:"schema"`
	Gate               string `json:"gate"`
	ApplicationSHA256  string `json:"application_sha256"`
	Phase              string `json:"phase"`
	SecretPublication  bool   `json:"secret_publication"`
	SecretPreservation bool   `json:"secret_preservation"`
	FleetUncertainty   bool   `json:"fleet_uncertainty"`
	OTLPDecoding       bool   `json:"otlp_decoding"`
	OrdinaryTelemetry  bool   `json:"ordinary_telemetry"`
	EvidenceSHA256     string `json:"evidence_sha256"`
	Records            int    `json:"records"`
	Metrics            int    `json:"metrics"`
}

var shaPin = regexp.MustCompile(`^[0-9a-f]{64}$`)

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	return json.Marshal(decoded)
}
func sameJSON(a, b any) bool {
	left, e1 := canonicalJSON(a)
	right, e2 := canonicalJSON(b)
	return e1 == nil && e2 == nil && bytes.Equal(left, right)
}
func (f *fixture) verifyEvidence(expected projection, application string) (verification, error) {
	out := verification{}
	if f.config.Contract == nil || expected.Schema != 1 || expected.Gate != f.config.Contract.Gate || expected.ApplicationSHA256 != application || application != f.config.Contract.ApplicationSHA256 || !shaPin.MatchString(application) || f.remote == nil || expected.SeedSHA256 != f.remote.SeedSHA256 {
		return out, errors.New("verification seed/application/gate binding rejected")
	}
	if len(expected.Records) == 0 || len(expected.Records) > 1024 || len(expected.Commands) == 0 || len(expected.Commands) > 128 {
		return out, errors.New("actual business and command evidence required")
	}
	if expected.Gate == "installed-traffic" {
		if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`).MatchString(expected.DeploymentID) || expected.Database != "cloud8021x_"+strings.ReplaceAll(expected.DeploymentID, "-", "_") || len(expected.Outbox) != len(expected.Records) {
			return out, errors.New("actual isolated database/outbox projection required")
		}
		epoch, err := time.Parse(time.RFC3339, expected.CollectionEpoch)
		if err != nil || epoch.Nanosecond() != 0 {
			return out, errors.New("invalid immutable collection epoch")
		}
		if f.config.Contract.OTLP == nil || f.config.Contract.OTLP.APIKey == "" || !strings.HasPrefix(f.config.Contract.OTLP.Host, "otlp.") || f.config.Contract.OTLP.Host == "otlp.task11.test" {
			return out, errors.New("installed business requires shipping DDOT intake")
		}
	} else if expected.Gate != "primitive-contract" || len(expected.Metrics) == 0 || len(expected.Publications) != 2 {
		return out, errors.New("complete primitive contract evidence required")
	}
	if err := f.auditPeerHistory(expected.Gate == "installed-traffic"); err != nil {
		return out, err
	}
	if err := f.verifySecrets(expected.Publications); err != nil {
		return out, err
	}
	if err := f.verifyCommands(expected.Commands, expected.CollectionEpoch); err != nil {
		return out, err
	}
	if err := f.verifyBusiness(expected); err != nil {
		return out, err
	}
	metrics := 0
	for _, wanted := range expected.Metrics {
		found := false
		for _, batch := range f.remote.Batches {
			for _, metric := range batch.Metrics {
				if metric.Name == wanted.Name && metric.Unit == wanted.Unit && metric.Kind == wanted.Kind && metric.Resource["host.name"] == wanted.Host {
					found = true
				}
			}
		}
		if !found {
			return out, fmt.Errorf("actual decoded metric absent: %s", wanted.Name)
		}
		metrics++
	}
	if len(f.remote.Events) == 0 {
		return out, errors.New("actual request journal absent")
	}
	state, err := json.Marshal(f.remote)
	if err != nil {
		return out, err
	}
	out = verification{Schema: 1, Gate: expected.Gate, ApplicationSHA256: application, Phase: "post-activation", SecretPublication: len(expected.Publications) > 0, SecretPreservation: true, FleetUncertainty: true, OTLPDecoding: true, EvidenceSHA256: digestBytes(state), Records: len(expected.Records), Metrics: metrics}
	if expected.Gate == "primitive-contract" {
		out.Phase = "primitive-only"
	}
	return out, nil
}
func (f *fixture) verifySecrets(publications map[string]string) error {
	if len(f.remote.Secrets) != len(f.config.Secrets) {
		return errors.New("secret resource set changed")
	}
	for resource, baseline := range f.config.Secrets {
		current := f.remote.Secrets[resource]
		for version, data := range baseline {
			if current[version].Data != data || current[version].State != "ENABLED" {
				return errors.New("original secret version changed")
			}
		}
		expected, renewed := publications[resource]
		if !renewed {
			if len(current) != len(baseline) {
				return errors.New("unapproved original authority publication")
			}
			continue
		}
		name := strings.TrimPrefix(resource, "projects/"+f.config.ProjectNumber+"/secrets/")
		if (name != "radius-smallstep-server-cert" && name != "radius-smallstep-server-key") || !shaPin.MatchString(expected) || len(current) != len(baseline)+1 {
			return errors.New("publication not exact allowed immutable version")
		}
		version := ""
		for number, value := range current {
			if _, old := baseline[number]; !old {
				data, err := base64.StdEncoding.DecodeString(value.Data)
				if err != nil || digestBytes(data) != expected || value.State != "ENABLED" {
					return errors.New("published payload differs")
				}
				version = resource + "/versions/" + number
			}
		}
		published, accessed := false, false
		for _, event := range f.remote.Events {
			var observation struct {
				Name          string `json:"name"`
				PayloadSHA256 string `json:"payload_sha256"`
			}
			_ = json.Unmarshal(event.Observation, &observation)
			if f.acceptedCaller(event, "active", "") && event.Protocol == "http" && event.Status == 200 && observation.Name == version {
				published = published || (event.Method == "POST" && f.secretTarget(event.Target, resource+":addVersion"))
				accessed = accessed || (event.Method == "GET" && f.secretTarget(event.Target, version+":access") && observation.PayloadSHA256 == expected)
			}
		}
		if !published || !accessed {
			return errors.New("publication/access response proof absent")
		}
	}
	for name := range publications {
		if f.config.Secrets[name] == nil {
			return errors.New("expected unlisted secret")
		}
	}
	return nil
}
func (f *fixture) verifyCommands(wanted []commandExpectation, epochs ...string) error {
	if len(wanted) != len(f.remote.Commands) {
		return errors.New("extra or missing command state")
	}
	seen := map[string]bool{}
	for _, expected := range wanted {
		c, ok := f.remote.Commands[expected.UUID]
		if !ok || seen[expected.UUID] || c.Posts != expected.Posts || c.Mode != "terminal" || expected.Posts < 0 || expected.Posts > 1 {
			return errors.New("command missing, duplicated, repeated or unresolved")
		}
		if err := f.commandBinding(expected, c, epochs); err != nil {
			return err
		}
		seen[expected.UUID] = true
		pending, missing, terminal, uncertain, submitted, hostRead := false, false, false, false, false, false
		resultTarget := "fleet.task11.test/api/v1/fleet/commands/results?command_uuid=" + c.UUID
		submitTarget := "fleet.task11.test/api/v1/fleet/commands/run"
		if c.RequestType == "Script" {
			resultTarget = "fleet.task11.test/api/v1/fleet/scripts/results/" + c.ExecutionID
			submitTarget = "fleet.task11.test/api/v1/fleet/scripts/run"
		}
		for _, event := range f.remote.Events {
			if event.Protocol != "http" {
				continue
			}
			if event.Method == "POST" && event.Target == submitTarget && event.BodySHA256 == expected.RequestSHA256 && f.submissionCaller(event, expected) {
				submitted = submitted || event.Status == 200 || event.Status == 0
				uncertain = uncertain || event.Status == 0
			}
			if event.Method != "GET" || !f.acceptedCaller(event, expected.RecoveryPhase, expected.RecoveryPeer) {
				continue
			}
			if event.Target == "fleet.task11.test/api/v1/fleet/hosts/"+strconv.Itoa(expected.HostID) && event.Status == 200 {
				var observed struct {
					Host fleetHost `json:"host"`
				}
				if strictJSON(event.Observation, &observed) == nil && expected.matchesHost(observed.Host) {
					hostRead = true
				}
			}
			if event.Target != resultTarget {
				continue
			}
			if c.RequestType == "CertificateList" {
				missing = missing || event.Status == 404
				var response struct {
					Results []struct {
						UUID    string `json:"command_uuid"`
						Host    string `json:"host_uuid"`
						Type    string `json:"request_type"`
						Status  string `json:"status"`
						Updated string `json:"updated_at"`
					} `json:"results"`
				}
				if json.Unmarshal(event.Observation, &response) == nil && event.Status == 200 && len(response.Results) == 1 {
					r := response.Results[0]
					if r.UUID != c.UUID || r.Host != c.HostUUID || r.Type != "CertificateList" {
						return errors.New("unbound command response")
					}
					pending = pending || r.Status == "NotNow"
					if r.Status == "Error" {
						created, e1 := time.Parse(time.RFC3339Nano, c.CreatedAt)
						updated, e2 := time.Parse(time.RFC3339Nano, r.Updated)
						terminal = e1 == nil && e2 == nil && !updated.Before(created)
					}
				}
			}
			if c.RequestType == "Script" {
				missing = missing || event.Status == 404
				var r struct {
					HostID    int    `json:"host_id"`
					Execution string `json:"execution_id"`
					Script    string `json:"script_contents"`
					Exit      *int   `json:"exit_code"`
					Created   string `json:"created_at"`
				}
				if json.Unmarshal(event.Observation, &r) == nil && event.Status == 200 {
					if r.HostID != c.HostID || r.Execution != c.ExecutionID || r.Script != c.Script || r.Created != c.CreatedAt {
						return errors.New("unbound exact script result")
					}
					pending = pending || r.Exit == nil
					terminal = terminal || r.Exit != nil
				}
			}
		}
		if !hostRead || !pending || !missing || !terminal || (expected.Posts == 1 && !submitted) || (expected.RequireUncertain && !uncertain) {
			return errors.New("pending/missing/terminal or uncertainty observation absent")
		}
	}
	return nil
}
func (f *fixture) verifyBusiness(expected projection) error {
	records := map[string]telemetry.BusinessRecord{}
	for _, r := range expected.Records {
		if r.ID == "" || r.Fields["event_id"] != r.ID || r.Host == "" || r.Received.IsZero() {
			return errors.New("invalid actual business projection")
		}
		if _, exists := records[r.ID]; exists {
			return errors.New("duplicate expected identity")
		}
		records[r.ID] = r
	}
	if expected.Gate == "installed-traffic" {
		seen := map[string]bool{}
		for _, row := range expected.Outbox {
			r, ok := records[row.RecordID]
			if !ok || seen[row.RecordID] || row.WorkID != r.Category+":"+r.ID || row.Generation < 1 || !shaPin.MatchString(row.PayloadSHA256) || row.Outcome != "succeeded" {
				return errors.New("outbox identity/generation/receipt mismatch")
			}
			seen[row.RecordID] = true
		}
	}
	seen := map[string]bool{}
	for _, batch := range f.remote.Batches {
		requestFound := false
		for _, event := range f.remote.Events {
			if event.Protocol == "http" && event.Method == "POST" && event.Status == 200 && f.acceptedCaller(event, "active", "") && event.BodySHA256 == batch.WireSHA256 && f.config.Contract.OTLP != nil && event.Target == f.config.Contract.OTLP.Host+"/v1/"+batch.Kind {
				requestFound = true
			}
		}
		if !requestFound {
			return errors.New("decoded intake lacks actual accepted request receipt")
		}
		for _, actual := range batch.Logs {
			var body map[string]json.RawMessage
			if json.Unmarshal(actual.Body, &body) != nil {
				return errors.New("invalid decoded body")
			}
			var id string
			if json.Unmarshal(body["event_id"], &id) != nil {
				return errors.New("event identity absent")
			}
			r, ok := records[id]
			if !ok || seen[id] {
				return errors.New("unexpected or duplicate actual business record")
			}
			seen[id] = true
			service := "cloud-8021x"
			if expected.Gate == "installed-traffic" {
				service = map[string]string{"auth": "radius-auth", "accounting": "radius-acct", "usage": "radius-usage"}[r.Category]
			}
			if service == "" || actual.Resource["service.name"] != service || actual.Resource["host.name"] != r.Host || actual.Resource["business.category"] != r.Category || actual.Scope != "cloud-8021x/business" || actual.Time != uint64(r.Received.UnixNano()) || !sameJSON(actual.Body, r.Fields) {
				return errors.New("decoded category/host/time/body differs from actual projection")
			}
			normalized := r
			normalized.Fields = map[string]any{}
			for name, value := range r.Fields {
				// Project emits these two counts as int; JSON projection decode
				// deliberately preserves numbers and therefore needs this typed
				// restoration before invoking the production OTLP encoder.
				if n, ok := value.(json.Number); ok && (name == "nas_port_type_count" || name == "counter_bits") {
					integer, err := strconv.Atoi(string(n))
					if err != nil {
						return errors.New("invalid typed projected count")
					}
					value = integer
				}
				normalized.Fields[name] = value
			}
			wire := otlp.Request([]telemetry.BusinessRecord{normalized}).ResourceLogs[0]
			expectedAttrs, err := attributes(wire.ScopeLogs[0].LogRecords[0].Attributes)
			if err != nil {
				return err
			}
			expectedResource, err := attributes(wire.Resource.Attributes)
			if err != nil {
				return err
			}
			expectedResource["service.name"] = service
			if !sameJSON(actual.Attributes, expectedAttrs) || !sameJSON(actual.AttributeKinds, attributeKinds(wire.ScopeLogs[0].LogRecords[0].Attributes)) || !sameJSON(actual.Resource, expectedResource) {
				return errors.New("complete production attribute/resource shape differs")
			}
		}
	}
	if len(seen) != len(records) {
		return errors.New("missing actual business record")
	}
	return nil
}
func parsedProjection(data []byte) (projection, error) {
	var out projection
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return out, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return out, errors.New("trailing projection input")
	}
	// JSON numbers remain exact through BusinessRecord maps and integer counters.
	for _, r := range out.Records {
		for _, value := range r.Fields {
			if number, ok := value.(json.Number); ok {
				if _, err := strconv.ParseUint(string(number), 10, 64); err != nil {
					return out, errors.New("nonintegral/out-of-range business number")
				}
			}
		}
	}
	return out, nil
}

func (f *fixture) acceptedCaller(event remoteEvent, phase, peerIP string) bool {
	if event.Phase != phase {
		return false
	}
	if f.config.Contract.Gate != "installed-traffic" {
		return peerIP == "" || event.PeerIP == peerIP
	}
	return (event.PeerIP == "10.203.11.21" || event.PeerIP == "10.203.11.22") && event.PeerRole == ownedPeerRoles[event.PeerIP] && (peerIP == "" || event.PeerIP == peerIP)
}
func (f *fixture) secretTarget(target, resource string) bool {
	prefix := "secretmanager.googleapis.com/v1/"
	return target == prefix+resource || target == prefix+strings.Replace(resource, "projects/"+f.config.ProjectNumber+"/", "projects/"+f.config.ProjectID+"/", 1)
}
func (e commandExpectation) matchesHost(h fleetHost) bool {
	return h.ID == e.HostID && h.UUID == e.HostUUID && h.Platform == e.Platform && h.MDMEnrolledAt == e.MDMEnrolledAt && h.EnrolledAt == e.EnrolledAt
}
func (f *fixture) commandBinding(e commandExpectation, c fleetCommand, epochs []string) error {
	if e.HostID < 1 || e.HostID != c.HostID || e.HostUUID != c.HostUUID || (e.RecoveryPhase != "active" && e.RecoveryPhase != "passive") {
		return errors.New("original command target/scope differs")
	}
	var host *fleetHost
	for i := range f.config.Contract.Fleet.Hosts {
		if f.config.Contract.Fleet.Hosts[i].ID == e.HostID {
			host = &f.config.Contract.Fleet.Hosts[i]
		}
	}
	if host == nil || !e.matchesHost(*host) {
		return errors.New("original host enrollment differs")
	}
	created, err1 := time.Parse(time.RFC3339Nano, e.OriginalCreatedAt)
	before, err2 := time.Parse(time.RFC3339Nano, e.AcceptedBefore)
	accepted, err3 := time.Parse(time.RFC3339Nano, c.CreatedAt)
	enrollment, err4 := time.Parse(time.RFC3339Nano, e.EnrolledAt)
	if e.Transport == "apple" {
		enrollment, err4 = time.Parse(time.RFC3339Nano, e.MDMEnrolledAt)
	}
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || created.Before(enrollment) || before.Before(created) || before.Sub(created) > 10*time.Minute || accepted.Before(created) || accepted.After(before) {
		return errors.New("original submission time bounds differ")
	}
	switch e.Transport {
	case "apple":
		if e.Platform != "darwin" || c.RequestType != "CertificateList" || e.ScriptSHA256 != "" {
			return errors.New("original Apple transport differs")
		}
	case "windows":
		if e.Platform != "windows" || c.RequestType != "Script" || !shaPin.MatchString(e.ScriptSHA256) || digestBytes([]byte(c.Script)) != e.ScriptSHA256 || !strings.HasSuffix(c.Script, "\n# Collection nonce: "+e.UUID+"\n") {
			return errors.New("original Windows script/nonce differs")
		}
	default:
		return errors.New("original transport absent")
	}
	if e.Origin != "retained-legacy" && e.Origin != "green-work" {
		return errors.New("command origin absent")
	}
	if e.Posts == 0 {
		if e.Origin != "retained-legacy" || e.RequireUncertain || e.RequestSHA256 != "" || e.SubmissionPeer != "" || !accepted.Equal(created) || !before.Equal(created) {
			return errors.New("unobserved submission provenance differs")
		}
		found := false
		for _, seeded := range f.config.Contract.Fleet.Commands {
			found = found || seeded.UUID == e.UUID && seeded.HostID == e.HostID && seeded.HostUUID == e.HostUUID && seeded.CreatedAt == e.OriginalCreatedAt && seeded.RequestType == c.RequestType
		}
		if !found {
			return errors.New("unobserved command was not retained original seed")
		}
	} else if !shaPin.MatchString(e.RequestSHA256) || c.BodySHA256 != e.RequestSHA256 {
		return errors.New("original request bytes differ")
	}
	if f.config.Contract.Gate == "installed-traffic" {
		if e.RecoveryPeer != "10.203.11.21" && e.RecoveryPeer != "10.203.11.22" {
			return errors.New("approved green recovery caller absent")
		}
		if e.Origin == "retained-legacy" {
			if len(epochs) != 1 {
				return errors.New("original handoff epoch absent")
			}
			epoch, err := time.Parse(time.RFC3339, epochs[0])
			if err != nil || before.After(epoch) {
				return errors.New("retained original submission crosses handoff")
			}
			if e.Posts == 1 && e.SubmissionPeer != "10.203.11.31" && e.SubmissionPeer != "10.203.11.32" {
				return errors.New("original submission caller absent")
			}
		} else if e.Posts != 1 || (e.SubmissionPeer != "10.203.11.21" && e.SubmissionPeer != "10.203.11.22") {
			return errors.New("green submission caller absent")
		}
	}
	return nil
}
func (f *fixture) submissionCaller(event remoteEvent, e commandExpectation) bool {
	if event.Phase != "active" || (e.SubmissionPeer != "" && event.PeerIP != e.SubmissionPeer) {
		return false
	}
	if f.config.Contract.Gate != "installed-traffic" {
		return true
	}
	return event.PeerIP == e.SubmissionPeer && event.PeerRole == ownedPeerRoles[event.PeerIP]
}
