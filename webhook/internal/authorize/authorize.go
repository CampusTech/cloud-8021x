// Package authorize holds the allow rule: a device serial is authorized iff
// it resolves to an enrolled Fleet host (and, when an allow-label is
// configured, that host carries the label). Every uncertain case denies.
package authorize

import (
	"context"

	"github.com/CampusTech/cloud-8021x/webhook/internal/fleet"
	"github.com/sirupsen/logrus"
)

// Lookup is the slice of the Fleet client this package needs.
type Lookup interface {
	LookupHostBySerial(ctx context.Context, serial string) (*fleet.Host, error)
}

type Authorizer struct {
	lookup     Lookup
	allowLabel string // empty = no label gate
}

func New(lookup Lookup, allowLabel string) *Authorizer {
	return &Authorizer{lookup: lookup, allowLabel: allowLabel}
}

// Decide returns true only when issuance should be allowed. Fail-closed.
func (a *Authorizer) Decide(ctx context.Context, serial string) bool {
	if serial == "" {
		logrus.WithField("reason", "empty serial").Info("deny")
		return false
	}
	host, err := a.lookup.LookupHostBySerial(ctx, serial)
	if err != nil {
		// Don't log the raw serial — it's a long-lived device identifier. A short
		// suffix is enough to correlate during debugging without retaining the
		// full ID in centralized logs.
		logrus.WithError(err).WithField("serial_suffix", serialSuffix(serial)).Warn("deny: fleet lookup failed (fail-closed)")
		return false
	}
	if host == nil || !host.Enrolled {
		logrus.WithField("serial_suffix", serialSuffix(serial)).Info("deny: serial not an enrolled Fleet host")
		return false
	}
	if a.allowLabel != "" && !host.HasLabel(a.allowLabel) {
		logrus.WithFields(logrus.Fields{"host_id": host.ID, "required_label": a.allowLabel}).Info("deny: host lacks required label")
		return false
	}
	logrus.WithField("host_id", host.ID).Info("allow")
	return true
}

// serialSuffix returns a short, non-identifying tail of the serial for log
// correlation (avoids retaining the full long-lived device identifier).
func serialSuffix(serial string) string {
	if len(serial) <= 4 {
		return "****"
	}
	return "***" + serial[len(serial)-4:]
}
