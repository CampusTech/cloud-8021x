package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/config"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

type scheduledSourceStore struct {
	payload           json.RawMessage
	started, finished bool
	failStart         bool
}

func (s *scheduledSourceStore) Reserve(_ context.Context, _ string, _ string, p json.RawMessage) error {
	s.payload = p
	return nil
}
func (s *scheduledSourceStore) ClaimSource(context.Context, string, string, time.Duration) (*jobs.Claim, error) {
	return &jobs.Claim{Kind: "sources:radius-primary", Payload: s.payload}, nil
}
func (s *scheduledSourceStore) StartAttempt(context.Context, jobs.Claim) error {
	if s.failStart {
		return errors.New("commit uncertain")
	}
	s.started = true
	return nil
}
func (s *scheduledSourceStore) FinishAttempt(context.Context, jobs.Claim, jobs.Outcome, json.RawMessage) error {
	s.finished = true
	return nil
}
func TestRootSourceSchedulePersistsBeforeApplyingExactCandidate(t *testing.T) {
	store := new(scheduledSourceStore)
	candidates := []domain.SourceCandidate{{ProviderID: "test"}}
	called := false
	err := coordinateSources(context.Background(), store, "radius-primary", "root", candidates, func(_ context.Context, got []domain.SourceCandidate, digest string) error {
		called = true
		if !store.started || len(got) != 1 || got[0].ProviderID != "test" || len(digest) != 64 {
			t.Fatal("unclaimed/mismatched source apply")
		}
		return nil
	})
	if err != nil || !called || !store.finished {
		t.Fatal(err)
	}
	store.failStart = true
	called = false
	err = coordinateSources(context.Background(), store, "radius-primary", "root", candidates, func(context.Context, []domain.SourceCandidate, string) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("started uncertainty dispatched external mutation")
	}
	if strings.Contains(string(store.payload), "sudo") {
		t.Fatal("command in candidate")
	}
}

func TestSourceMaintenanceIdentityBindsNodeConfigAttempt(t *testing.T) {
	cfg := config.Config{InstanceID: "radius-primary", StateTransition: strings.Repeat("a", 64)}
	cfg.Network.Discovery.Firewall.Node = "radius-primary"
	p := json.RawMessage(`{"node":"radius-primary","candidate":[{"provider_id":"test"}]}`)
	first, e := sourceMaintenanceIdentity(cfg, "sources:"+strings.Repeat("b", 64), 1, p)
	if e != nil {
		t.Fatal(e)
	}
	second, e := sourceMaintenanceIdentity(cfg, "sources:"+strings.Repeat("b", 64), 2, p)
	if e != nil || first == second {
		t.Fatal("generation not bound", e)
	}
	cfg.Debug = true
	third, e := sourceMaintenanceIdentity(cfg, "sources:"+strings.Repeat("b", 64), 1, p)
	if e != nil || first == third {
		t.Fatal("config not bound", e)
	}
	cfg.Network.Discovery.Firewall.Node = "radius-secondary"
	if _, e = sourceMaintenanceIdentity(cfg, "sources:"+strings.Repeat("b", 64), 1, p); e == nil {
		t.Fatal("peer attempt accepted")
	}
}

func TestParallelSourceMaintenanceKeepsLogicalClaimAndPhysicalTarget(t *testing.T) {
	c := config.Defaults()
	c.InstanceID = "radius-primary"
	c.StateTransition = strings.Repeat("a", 64)
	c.Database.Name = "cloud8021x_green"
	c.Deployment = config.Deployment{Mode: "parallel", ID: "green", Instance: "green-primary", SourceID: "blue", SourcePrimary: "radius-primary", SourceSecondary: "radius-secondary", CollectionEpoch: time.Now().UTC().Truncate(time.Second)}
	c.Network.Discovery.Enabled = true
	c.Network.Discovery.Firewall.Node = "green-primary"
	raw := json.RawMessage(`{"node":"radius-primary","candidate":[]}`)
	if _, e := sourceMaintenanceIdentity(c, "sources:"+strings.Repeat("b", 64), 1, raw); e != nil {
		t.Fatal(e)
	}
	c.Network.Discovery.Firewall.Node = "radius-primary"
	if _, e := sourceMaintenanceIdentity(c, "sources:"+strings.Repeat("b", 64), 1, raw); e == nil {
		t.Fatal("blue firewall admitted by green logical claim")
	}
}
