package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
	"github.com/CampusTech/cloud-8021x/internal/adapters/stepca"
	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/inventory"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

type requestTransport func(*http.Request) (*http.Response, error)

func (f requestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type requestLedger struct {
	claim   *jobs.Claim
	payload json.RawMessage
}

func (l *requestLedger) Reserve(context.Context, string, string, json.RawMessage) error {
	return errors.New("unexpected reserve")
}
func (l *requestLedger) ReserveCollection(_ context.Context, id, kind, _ string, p json.RawMessage, _ time.Duration, _ int) (bool, error) {
	l.payload = append(json.RawMessage{}, p...)
	l.claim = &jobs.Claim{ID: id, Kind: kind, Payload: l.payload, Generation: 1, LeaseUntil: time.Now().Add(time.Minute)}
	return true, nil
}
func (l *requestLedger) Claim(_ context.Context, _ string, owner string, _ time.Duration) (*jobs.Claim, error) {
	c := l.claim
	l.claim = nil
	if c != nil {
		c.Owner = owner
	}
	return c, nil
}
func (l *requestLedger) StartAttempt(context.Context, jobs.Claim) error { return nil }
func (l *requestLedger) FinishAttempt(context.Context, jobs.Claim, jobs.Outcome, json.RawMessage) error {
	return nil
}
func (l *requestLedger) ListCollection(context.Context, string) ([]inventory.CollectionWork, error) {
	return nil, nil
}
func (l *requestLedger) ReconcileSuccess(context.Context, string, int64, json.RawMessage) error {
	return errors.New("unexpected reconcile")
}
func (l *requestLedger) RecordCollectionResult(context.Context, string, int64, json.RawMessage, json.RawMessage) error {
	return errors.New("unexpected result")
}
func TestProjectedPOSTMatchesActualShippingFleetCollector(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, err := syntheticCA(stepca.EC, now)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := fleet.NewTrust(ca.material.Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []string{"darwin", "windows"} {
		t.Run(platform, func(t *testing.T) {
			ledger := &requestLedger{}
			posts := 0
			host := map[string]any{"id": 1, "uuid": syntheticDevice, "platform": platform, "os_version": "15.0", "last_mdm_enrolled_at": now.Add(-time.Hour).Format(time.RFC3339), "last_enrolled_at": now.Add(-time.Hour).Format(time.RFC3339), "scripts_enabled": true, "mdm": map[string]any{"enrollment_status": "On (automatic)"}}
			hc := &http.Client{Transport: requestTransport(func(r *http.Request) (*http.Response, error) {
				var response any
				switch {
				case r.Method == "GET" && r.URL.Path == "/api/v1/fleet/hosts":
					response = map[string]any{"hosts": []any{host}}
				case r.Method == "GET" && r.URL.Path == "/api/v1/fleet/hosts/1":
					response = map[string]any{"host": host}
				case r.Method == "POST":
					posts++
					actual, err := io.ReadAll(r.Body)
					if err != nil {
						return nil, err
					}
					var p collectionPayload
					if err = decodeExactJSON(ledger.payload, &p); err != nil {
						return nil, err
					}
					expected, err := originalRequest(p)
					if err != nil {
						return nil, err
					}
					if !bytes.Equal(actual, expected) {
						t.Error("projected original POST differs from shipping adapter")
					}
					if platform == "windows" {
						response = map[string]any{"host_id": 1, "execution_id": "actual-wire-execution"}
					} else {
						response = map[string]any{"command_uuid": p.UUID, "request_type": "CertificateList"}
					}
				default:
					return nil, errors.New("unexpected request")
				}
				raw, err := json.Marshal(response)
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}, nil
			})}
			client, err := fleet.NewClient("https://fleet.task11.test", "synthetic-only", hc, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			collector := fleet.Collector{Maintainer: client, Repository: ledger, Trust: trust, Owner: "radius-primary", Now: func() time.Time { return now }}
			batch := domain.DeviceSnapshot{Complete: true, Scope: domain.InventoryScope{ProviderID: "fleet"}, Devices: []domain.Device{{ID: "fleet:1", Identities: []string{syntheticDevice}, Enrolled: true}}}
			if err = collector.Prepare(context.Background(), batch); err != nil {
				t.Fatal(err)
			}
			if _, err = collector.Collect(context.Background(), domain.CertificateCollectionRequest{DeviceID: "fleet:1"}); !errors.Is(err, inventory.ErrPending) {
				t.Fatal(err)
			}
			if posts != 1 {
				t.Fatalf("actual submission count %d", posts)
			}
		})
	}
}
