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
		logrus.WithError(err).WithField("serial", serial).Warn("deny: fleet lookup failed (fail-closed)")
		return false
	}
	if host == nil || !host.Enrolled {
		logrus.WithField("serial", serial).Info("deny: serial not an enrolled Fleet host")
		return false
	}
	if a.allowLabel != "" && !host.HasLabel(a.allowLabel) {
		logrus.WithFields(logrus.Fields{"serial": serial, "required_label": a.allowLabel}).Info("deny: host lacks required label")
		return false
	}
	logrus.WithFields(logrus.Fields{"serial": serial, "host_id": host.ID}).Info("allow")
	return true
}
