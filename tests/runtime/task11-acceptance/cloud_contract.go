package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
	"github.com/CampusTech/cloud-8021x/internal/telemetry"
)

// Wire types match the separately reviewed development cloud verifier; this
// package does not import its API implementation or its observed intake state.
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

type durableWork struct {
	ID, Kind, State, Owner                    string
	Generation                                int64
	Payload                                   []byte // Opaque wire encoding preserves the exact PostgreSQL payload digest.
	Receipt, AttemptReceipt, RecoveryEvidence json.RawMessage
	Outcome                                   string
	StartedAt, FinishedAt                     time.Time
}
type durableSnapshot struct {
	Deployment, Database, Transition, Manifest string
	Epoch                                      time.Time
	Work                                       []durableWork
	Guards                                     []durableGuard
}

func validSHA(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func projectOutbox(s durableSnapshot, display telemetry.Display) ([]telemetry.BusinessRecord, []outboxExpectation, error) {
	records := []telemetry.BusinessRecord{}
	rows := []outboxExpectation{}
	seen := map[string]bool{}
	if s.Deployment != "task11-green" || s.Database != "cloud8021x_task11_green" || s.Epoch.IsZero() || s.Epoch.Nanosecond() != 0 || len(s.Work) > 1152 {
		return nil, nil, errors.New("isolated durable projection binding rejected")
	}
	for _, w := range s.Work {
		if w.Kind != "outbox" {
			continue
		}
		var receipt, attempt telemetry.Receipt
		if w.State != "succeeded" || w.Outcome != "succeeded" || w.Generation < 1 || w.StartedAt.Before(s.Epoch) || w.FinishedAt.Before(w.StartedAt) || w.FinishedAt.IsZero() || domain.DecodeJSONStrict(w.Receipt, &receipt) != nil || domain.DecodeJSONStrict(w.AttemptReceipt, &attempt) != nil || !reflect.DeepEqual(receipt, attempt) || receipt.Outcome != jobs.Succeeded || receipt.Code != "accepted" || receipt.Rejected != 0 {
			return nil, nil, errors.New("durable outbox has unresolved or mismatched original attempt")
		}
		r, err := telemetry.Project(jobs.Claim{ID: w.ID, Kind: w.Kind, Payload: w.Payload}, display)
		if err != nil || seen[r.ID] || r.Received.Before(s.Epoch) || (r.Host != "task11-green-primary" && r.Host != "task11-green-secondary") {
			return nil, nil, errors.New("actual outbox record identity/epoch differs")
		}
		seen[r.ID] = true
		records = append(records, r)
		rows = append(rows, outboxExpectation{WorkID: w.ID, Generation: w.Generation, PayloadSHA256: adoption.Digest(w.Payload), RecordID: r.ID, Outcome: w.Outcome})
	}
	if len(records) == 0 || len(records) > 1024 {
		return nil, nil, errors.New("bounded nonempty actual outbox required")
	}
	return records, rows, nil
}
func validateVerification(raw []byte, expected projection) (verification, error) {
	var v verification
	var fields map[string]json.RawMessage
	if domain.DecodeJSONStrict(raw, &fields) != nil || len(fields) != 12 {
		return v, errors.New("complete explicit verifier result required")
	}
	for _, key := range []string{"schema", "gate", "application_sha256", "phase", "secret_publication", "secret_preservation", "fleet_uncertainty", "otlp_decoding", "ordinary_telemetry", "evidence_sha256", "records", "metrics"} {
		if _, ok := fields[key]; !ok {
			return v, errors.New("verifier field missing")
		}
	}

	phase := "post-activation"
	if expected.Gate == "primitive-contract" {
		phase = "primitive-only"
	} else if expected.Gate != "installed-traffic" {
		return v, errors.New("unknown verifier gate")
	}
	if len(raw) > 8192 || domain.DecodeJSONStrict(raw, &v) != nil || v.Schema != 1 || v.Gate != expected.Gate || v.Phase != phase || v.ApplicationSHA256 != expected.ApplicationSHA256 || !validSHA(v.ApplicationSHA256) || !validSHA(v.EvidenceSHA256) || !v.SecretPreservation || !v.FleetUncertainty || !v.OTLPDecoding || v.OrdinaryTelemetry || v.SecretPublication != (len(expected.Publications) > 0) || v.Records != len(expected.Records) || v.Metrics != len(expected.Metrics) {
		return v, errors.New("cloud verifier result is incomplete or mismatched")
	}
	return v, nil
}
func validateActivation(raw []byte, node string) (bool, error) {
	var v struct {
		Deployment string `json:"deployment"`
		Instance   string `json:"instance"`
		Active     *bool  `json:"workers_active"`
		Waiting    *bool  `json:"waiting_for_peer"`
		Switch     *bool  `json:"endpoint_switch_performed"`
	}
	if domain.DecodeJSONStrict(raw, &v) != nil || v.Deployment != "task11-green" || v.Instance != "task11-"+node || v.Active == nil || v.Waiting == nil || v.Switch == nil || *v.Switch || *v.Active == *v.Waiting {
		return false, errors.New("exact shipping activation result required")
	}
	return *v.Active, nil
}

// Decode twice: production strict traversal rejects duplicate/trailing keys, then
// UseNumber preserves the projector's uint64 companions across private pipes.
func decodeExactJSON(raw []byte, out any) error {
	var check json.RawMessage
	if err := domain.DecodeJSONStrict(raw, &check); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	return d.Decode(out)
}

type cloudPins struct {
	HelperSHA256, PrimitiveSeedSHA256, PrimitiveExpectedSHA256, InstalledSeedSHA256, OriginalStateSHA256 string
}

func (p cloudPins) validate() error {
	for _, v := range []string{p.HelperSHA256, p.PrimitiveSeedSHA256, p.PrimitiveExpectedSHA256, p.InstalledSeedSHA256, p.OriginalStateSHA256} {
		if !validSHA(v) {
			return errors.New("independently reviewed cloud inputs required")
		}
	}
	return nil
}

func validateDeactivation(raw []byte, node, transition string) error {
	var v struct {
		Operation  string `json:"operation"`
		Node       string `json:"node"`
		Fence      *bool  `json:"fence_only"`
		Transition string `json:"transition"`
		Path       string `json:"path"`
		Blocked    *bool  `json:"workers_blocked"`
	}
	if domain.DecodeJSONStrict(raw, &v) != nil || v.Operation != "state export" || v.Node != node || v.Transition != transition || v.Fence == nil || !*v.Fence || v.Blocked == nil || !*v.Blocked {
		return errors.New("exact protected worker fence result required")
	}
	return nil
}
