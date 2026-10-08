// Package inventory defines durable collection storage independent of providers.
package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

var ErrPending = errors.New("certificate collection pending")
var ErrIneligible = errors.New("device outside certificate collection scope")

// CollectionWork retains started/uncertain work and the original receipt. It is
// never permission to resend; adapters must authenticate reconciliation evidence.
type CollectionWork struct {
	ID         string
	State      string
	Generation int64
	Payload    json.RawMessage
	Receipt    json.RawMessage
	CreatedAt  time.Time
}
type CollectionRepository interface {
	jobs.Coordinator
	// Collection key scopes source, host and enrollment. The durable gate enforces
	// cadence and the two-outstanding-command budget under a transaction lock.
	ReserveCollection(context.Context, string, string, string, json.RawMessage, time.Duration, int) (bool, error)
	ListCollection(context.Context, string) ([]CollectionWork, error)
	ReconcileSuccess(context.Context, string, int64, json.RawMessage) error
	RecordCollectionResult(context.Context, string, int64, json.RawMessage, json.RawMessage) error
}
