package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/domain"
	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

// SourceCoordinator must exclusively serialize each fixed node across revisions.
// Generic Coordinator.Claim does not provide this contract and is never used.
type SourceCoordinator interface {
	Reserve(context.Context, string, string, json.RawMessage) error
	ClaimSource(context.Context, string, string, time.Duration) (*jobs.Claim, error)
	StartAttempt(context.Context, jobs.Claim) error
	FinishAttempt(context.Context, jobs.Claim, jobs.Outcome, json.RawMessage) error
}
type sourceWork struct {
	Node      string          `json:"node"`
	Candidate json.RawMessage `json:"candidate"`
}

// ApplyJob dispatches the exact persisted candidate after durable StartAttempt.
// The fixed helper must re-read that candidate from its private configured path
// and authenticate it again. The callback is installed code, never a command.
// An error after Start is conservatively uncertain and blocks this node's next
// revisions until authenticated actual-state evidence is explicitly reconciled.
type ApplyJob struct {
	Coordinator SourceCoordinator
	Owner, Node string
	Apply       func(context.Context, json.RawMessage) error
	ApplyClaim  func(context.Context, jobs.Claim, json.RawMessage) error
}

func (j ApplyJob) Run(ctx context.Context, candidate []byte) error {
	if j.Coordinator == nil || (j.Apply == nil && j.ApplyClaim == nil) || j.Owner == "" || (j.Node != "radius-primary" && j.Node != "radius-secondary") || len(candidate) > 1<<19 {
		return errors.New("source apply coordination unavailable")
	}
	var proposed []domain.SourceCandidate
	if domain.DecodeJSONStrict(candidate, &proposed) != nil || len(proposed) == 0 || len(proposed) > 128 {
		return errors.New("invalid scheduled source candidate")
	}
	canonical, e := json.Marshal(proposed)
	if e != nil {
		return e
	}
	payload, _ := json.Marshal(sourceWork{Node: j.Node, Candidate: canonical})
	sum := sha256.Sum256(payload)
	id := "sources:" + hex.EncodeToString(sum[:])
	if e = j.Coordinator.Reserve(ctx, id, "sources:"+j.Node, payload); e != nil {
		return e
	}
	claim, e := j.Coordinator.ClaimSource(ctx, j.Node, j.Owner, 3*time.Minute)
	if e != nil {
		return e
	}
	if claim == nil {
		return errors.New("source work is already claimed, completed or requires reconciliation")
	}
	var work sourceWork
	if domain.DecodeJSONStrict(claim.Payload, &work) != nil || work.Node != j.Node || claim.Kind != "sources:"+j.Node || len(work.Candidate) == 0 {
		return errors.New("invalid persisted source claim")
	}
	if e = j.Coordinator.StartAttempt(ctx, *claim); e != nil {
		return e
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if j.ApplyClaim != nil {
		e = j.ApplyClaim(bounded, *claim, append(json.RawMessage(nil), work.Candidate...))
	} else {
		e = j.Apply(bounded, append(json.RawMessage(nil), work.Candidate...))
	}
	outcome := jobs.Succeeded
	if e != nil {
		outcome = jobs.Uncertain
	}
	digest := sha256.Sum256(work.Candidate)
	receipt, _ := json.Marshal(struct {
		Node, Digest string
		Succeeded    bool
	}{j.Node, hex.EncodeToString(digest[:]), e == nil})
	finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer finishCancel()
	finish := j.Coordinator.FinishAttempt(finishCtx, *claim, outcome, receipt)
	if e != nil {
		return errors.New("source application uncertain; authenticated state reconciliation required")
	}
	return finish
}
