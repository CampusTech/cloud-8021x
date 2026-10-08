package network

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

type coordinator struct {
	payload        json.RawMessage
	failStart      bool
	started        bool
	outcome        jobs.Outcome
	claimedPayload json.RawMessage
}

func (c *coordinator) Reserve(_ context.Context, _, _ string, p json.RawMessage) error {
	c.payload = p
	return nil
}
func (c *coordinator) ClaimSource(_ context.Context, node, owner string, _ time.Duration) (*jobs.Claim, error) {
	p := c.payload
	if c.claimedPayload != nil {
		p = c.claimedPayload
	}
	return &jobs.Claim{ID: "persisted", Kind: "sources:" + node, Owner: owner, Payload: p}, nil
}
func (c *coordinator) StartAttempt(context.Context, jobs.Claim) error {
	if c.failStart {
		return errors.New("commit response lost")
	}
	c.started = true
	return nil
}
func (c *coordinator) FinishAttempt(_ context.Context, _ jobs.Claim, outcome jobs.Outcome, _ json.RawMessage) error {
	c.outcome = outcome
	return nil
}
func TestDurableStartAndExactClaimedCandidate(t *testing.T) {
	candidate := json.RawMessage(`[{"ProviderID":"u","SiteID":"c","CIDRs":["8.8.8.8/32"],"ObservedAt":1}]`)
	for _, fail := range []bool{true, false} {
		c := &coordinator{failStart: fail}
		called := false
		j := ApplyJob{Coordinator: c, Owner: "worker", Node: "radius-primary", Apply: func(_ context.Context, p json.RawMessage) error {
			called = true
			if !c.started {
				t.Fatal("I/O before durable start")
			}
			return errors.New("unknown external result")
		}}
		if e := j.Run(context.Background(), candidate); e == nil {
			t.Fatal("uncertain result hidden")
		}
		if fail && called {
			t.Fatal("uncertain Start performed I/O")
		}
		if !fail && (!called || c.outcome != jobs.Uncertain) {
			t.Fatal("uncertain outcome not retained")
		}
	}
	old := json.RawMessage(`[{"ProviderID":"u","SiteID":"c","CIDRs":["9.9.9.9/32"],"ObservedAt":1}]`)
	payload, _ := json.Marshal(sourceWork{Node: "radius-primary", Candidate: old})
	c := &coordinator{claimedPayload: payload}
	j := ApplyJob{Coordinator: c, Owner: "worker", Node: "radius-primary", Apply: func(_ context.Context, p json.RawMessage) error {
		if string(p) != string(old) {
			t.Fatal("used new caller bytes instead of persisted claim")
		}
		return nil
	}}
	if e := j.Run(context.Background(), candidate); e != nil || c.outcome != jobs.Succeeded {
		t.Fatal(e)
	}
}
