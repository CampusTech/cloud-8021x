package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

type claimStore struct {
	startErr error
	started  bool
	finished Receipt
}

func (*claimStore) Reserve(context.Context, string, string, json.RawMessage) error { return nil }
func (*claimStore) Claim(context.Context, string, string, time.Duration) (*jobs.Claim, error) {
	return &jobs.Claim{ID: "auth:a", Payload: json.RawMessage(`{"event_id":"a","event":"Access-Accept","host":"origin"}`), LeaseUntil: time.Now().Add(time.Minute)}, nil
}
func (s *claimStore) StartAttempt(context.Context, jobs.Claim) error {
	s.started = true
	return s.startErr
}
func (s *claimStore) FinishAttempt(_ context.Context, _ jobs.Claim, _ jobs.Outcome, b json.RawMessage) error {
	return json.Unmarshal(b, &s.finished)
}

type transportFunc func(context.Context, []BusinessRecord) Receipt

func (f transportFunc) Send(c context.Context, r []BusinessRecord) Receipt { return f(c, r) }
func TestOutboxDoesNotSendAfterUncertainOrFencedStart(t *testing.T) {
	for _, err := range []error{jobs.ErrFenced, errors.New("uncertain commit")} {
		s := &claimStore{startErr: err}
		o := Outbox{Store: s, Owner: "b", Timeout: time.Second, Transport: transportFunc(func(context.Context, []BusinessRecord) Receipt { t.Fatal("I/O after failed start"); return Receipt{} })}
		if _, got := o.One(context.Background()); got == nil {
			t.Fatal("start error suppressed")
		}
	}
}
func TestBusinessIndependentOfSamplingAndCancelledFinish(t *testing.T) {
	s := &claimStore{}
	ctx, cancel := context.WithCancel(context.Background())
	o := Outbox{Store: s, Owner: "b", Timeout: time.Second, Transport: transportFunc(func(c context.Context, r []BusinessRecord) Receipt {
		if !s.started || r[0].Host != "origin" {
			t.Fatal("invalid handoff")
		}
		cancel()
		return Receipt{Outcome: jobs.Partial, Code: "partial_success"}
	})}
	if _, err := o.One(ctx); err != nil {
		t.Fatal(err)
	}
	if s.finished.Outcome != jobs.Partial {
		t.Fatal("cancel lost receipt")
	}
}
