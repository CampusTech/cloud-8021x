package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

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
