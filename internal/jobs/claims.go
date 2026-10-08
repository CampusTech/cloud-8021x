// Package jobs defines durable external-work claims shared by collection and
// telemetry. Start must commit BEFORE external I/O; a started expired claim is
// uncertain, never an automatic resubmission candidate.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var ErrFenced = errors.New("work claim expired or superseded")
var ErrConflict = errors.New("stable work identity has different content")

type Outcome string

const (
	Succeeded Outcome = "succeeded"
	Uncertain Outcome = "uncertain"
	Partial   Outcome = "partial"
	Rejected  Outcome = "rejected"
)

type Claim struct {
	ID, Kind, Owner string
	Generation      int64
	LeaseUntil      time.Time
	Payload         json.RawMessage
}
type Coordinator interface {
	Reserve(context.Context, string, string, json.RawMessage) error
	Claim(context.Context, string, string, time.Duration) (*Claim, error)
	StartAttempt(context.Context, Claim) error
	FinishAttempt(context.Context, Claim, Outcome, json.RawMessage) error
}
