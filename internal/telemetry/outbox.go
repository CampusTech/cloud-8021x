package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/jobs"
)

type Receipt struct {
	Outcome  jobs.Outcome `json:"outcome"`
	Code     string       `json:"code"`
	Rejected int64        `json:"rejected,omitempty"`
}
type Transport interface {
	Send(context.Context, []BusinessRecord) Receipt
}
type Outbox struct {
	Store     jobs.Coordinator
	Transport Transport
	Display   Display
	Owner     string
	Timeout   time.Duration
}

// One claims existing atomic ledger work. The caller's scheduler controls polling;
// this method never automatically republishes a partial or uncertain attempt.
func (o Outbox) One(ctx context.Context) (bool, error) {
	if o.Store == nil || o.Transport == nil || o.Owner == "" || o.Timeout <= 0 || o.Timeout > time.Minute {
		return false, errors.New("invalid outbox configuration")
	}
	c, err := o.Store.Claim(ctx, "outbox", o.Owner, 2*o.Timeout+10*time.Second)
	if err != nil || c == nil {
		return false, err
	}
	record, projectionErr := Project(*c, o.Display)
	if err = o.Store.StartAttempt(ctx, *c); err != nil {
		return true, err
	}
	receipt := Receipt{Outcome: jobs.Rejected, Code: "invalid_payload"}
	if projectionErr == nil && time.Until(c.LeaseUntil) > o.Timeout+5*time.Second {
		call, cancel := context.WithDeadline(ctx, time.Now().Add(o.Timeout))
		receipt = o.Transport.Send(call, []BusinessRecord{record})
		cancel()
	}
	body, _ := json.Marshal(receipt)
	// A cancelled worker still gets a bounded chance to persist its receipt. Failure
	// leaves started work for the durable expiry-to-quarantine sweep, never resend.
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return true, o.Store.FinishAttempt(finish, *c, receipt.Outcome, body)
}
