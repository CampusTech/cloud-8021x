package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPostgresLegacyCapturePreparationProof(t *testing.T) {
	s, _ := integration(t)
	reset(t, s)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,bootstrap_private.transitions,bootstrap_private.ca_publication CASCADE"); e != nil {
		t.Fatal(e)
	}
	id, hash, writer := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)
	gate := MaintenanceGate{Store: s}
	operation := "legacy-capture:" + strings.Repeat("4", 64)
	var attempt int64
	if e := gate.With(ctx, operation, func(ctx context.Context) error {
		for _, node := range []string{"radius-primary", "radius-secondary"} {
			if e := s.RecordWriterFence(ctx, id, node, hash, writer); e != nil {
				return e
			}
		}
		var e error
		attempt, e = s.LegacyCaptureAttempt(ctx, operation)
		if e != nil {
			return e
		}
		if e = s.LegacyCaptureBeforeInstall(ctx, id, "radius-primary", hash, writer); e != nil {
			return e
		}
		if e = s.LegacyCaptureBeforeInstall(ctx, id, "radius-primary", hash, strings.Repeat("f", 64)); e == nil {
			t.Fatal("foreign writer receipt accepted")
		}
		return errors.New("fixture before capture completion ACK")
	}); e == nil {
		t.Fatal("interruption missing")
	}
	if _, e := s.pool.Exec(ctx, `UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, attempt); e != nil {
		t.Fatal(e)
	}
	if e := s.ReconcileMaintenance(ctx, attempt, func(ctx context.Context, m MaintenanceEvidence) error {
		if m.Operation != operation || m.Installation != "" {
			return errors.New("foreign preparation")
		}
		return s.LegacyCaptureBeforeInstall(ctx, id, "radius-primary", hash, writer)
	}); e != nil {
		t.Fatal(e)
	}
	if _, e := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.ca_publication(reference,secret,sha256) VALUES($1,'fixture',$1)`, strings.Repeat("c", 64)); e != nil {
		t.Fatal(e)
	}
	if e := s.LegacyCaptureBeforeInstall(ctx, id, "radius-primary", hash, writer); e == nil {
		t.Fatal("later CA phase ignored")
	}
	if _, e := s.pool.Exec(ctx, `DELETE FROM bootstrap_private.ca_publication`); e != nil {
		t.Fatal(e)
	}
}
