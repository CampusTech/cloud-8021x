package postgres

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/CampusTech/cloud-8021x/internal/migration"
)

func TestPostgresFreshInitialAuthorityRequiresBothOriginalSeedsAndEmptySharedState(t *testing.T) {
	s, c := integration(t)
	reset(t, s)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.fresh_inventory,bootstrap_private.fresh_seeds,bootstrap_private.maintenance,bootstrap_private.transitions CASCADE"); e != nil {
		t.Fatal(e)
	}
	id, hash := strings.Repeat("6", 64), strings.Repeat("5", 64)
	primary, _ := migration.FreshBundle("radius-primary", hash, strings.Repeat("4", 64))
	secondary, _ := migration.FreshBundle("radius-secondary", hash, strings.Repeat("3", 64))
	snapshot := []byte(`{"version":2,"updated_at":1791453600.123456,"identities":{"uuid":{"device_id":"fleet:1","groups":[],"enrolled":true}},"certificates":{},"hardware_serials":{}}`)
	if e := s.RecordFreshSeed(ctx, id, hash, primary); e == nil {
		t.Fatal("seed outside protected gate")
	}
	gate := MaintenanceGate{Store: s}
	if e := gate.With(ctx, "fresh-fixture", func(ctx context.Context) error {
		if e := s.RecordFreshSeed(ctx, id, hash, primary); e != nil {
			return e
		}
		if e := s.RecordWriterFence(ctx, id, "radius-primary", hash, hash); e != nil {
			return e
		}
		if e := s.RecordFreshInventory(ctx, id, "radius-primary", hash, bundleDigest(primary), snapshot); e == nil {
			t.Fatal("one fresh node authorized initial policy")
		}
		badClass, _ := migration.FreshBundle("radius-secondary", strings.Repeat("a", 64), strings.Repeat("3", 64))
		if e := s.RecordFreshSeed(ctx, id, hash, badClass); e == nil {
			t.Fatal("different pre-provisioned Class accepted")
		}
		if e := s.RecordFreshSeed(ctx, id, hash, secondary); e != nil {
			return e
		}
		if e := s.RecordWriterFence(ctx, id, "radius-secondary", hash, hash); e != nil {
			return e
		}
		if _, e := s.pool.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload) VALUES('existing-authority','fixture','{}')`); e != nil {
			return e
		}
		if e := s.RequireFreshEmpty(ctx, id); e == nil {
			t.Fatal("existing work ignored by fresh seed")
		}
		if _, e := s.pool.Exec(ctx, "DELETE FROM ledger.work WHERE id='existing-authority'"); e != nil {
			return e
		}
		if e := s.RecordFreshInventory(ctx, id, "radius-primary", hash, bundleDigest(primary), snapshot); e != nil {
			return e
		}
		if e := s.RecordFreshInventory(ctx, id, "radius-secondary", hash, bundleDigest(secondary), snapshot); e != nil {
			return e
		}
		if e := s.RecordFreshInventory(ctx, id, "radius-primary", hash, bundleDigest(primary), bytes.ReplaceAll(snapshot, []byte("1791453600"), []byte("1791453700"))); e == nil {
			t.Fatal("original fresh observation rewritten")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	got, e := s.FreshInventory(ctx, id, "radius-primary", hash, bundleDigest(primary))
	if e != nil || !bytes.Equal(got, snapshot) {
		t.Fatal("exact initial SQL authority lost", e)
	}
	runtime := runtimeStore(t, s, c)
	if _, e = runtime.FreshInventory(ctx, id, "radius-primary", hash, bundleDigest(primary)); e == nil {
		t.Fatal("runtime read root authority receipt")
	}
	if e = gate.With(ctx, "fresh-import", func(ctx context.Context) error {
		for _, raw := range [][]byte{primary, secondary} {
			if _, e := s.ImportLegacyBundle(ctx, id, raw); e != nil {
				return e
			}
		}
		if e := s.RequireFreshEmpty(ctx, id); e == nil {
			t.Fatal("fresh seed allowed over original imports")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = s.WorkersAllowed(ctx, id); e == nil {
		t.Fatal("fresh initial refresh enabled workers before protected local publication")
	}
}

func TestPostgresFreshInitialCommitAcknowledgementProof(t *testing.T) {
	s, _ := integration(t)
	reset(t, s)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.fresh_inventory,bootstrap_private.fresh_seeds,bootstrap_private.maintenance,bootstrap_private.transitions,bootstrap_private.ca_publication CASCADE"); e != nil {
		t.Fatal(e)
	}
	id, hash := strings.Repeat("6", 64), strings.Repeat("5", 64)
	primary, _ := migration.FreshBundle("radius-primary", hash, strings.Repeat("4", 64))
	secondary, _ := migration.FreshBundle("radius-secondary", hash, strings.Repeat("3", 64))
	snapshot := []byte(`{"version":2,"updated_at":1791453600.123456,"identities":{"uuid":{"device_id":"fleet:1","groups":[],"enrolled":true}},"certificates":{},"hardware_serials":{}}`)
	gate := MaintenanceGate{Store: s}
	operation := "fresh-initial:" + strings.Repeat("a", 64)
	var attempt int64
	for _, committed := range []bool{false, true} {
		e := gate.With(ctx, operation, func(ctx context.Context) error {
			for _, raw := range [][]byte{primary, secondary} {
				b, _ := migration.DecodeBundle(raw)
				if e := s.RecordFreshSeed(ctx, id, hash, raw); e != nil {
					return e
				}
				if e := s.RecordWriterFence(ctx, id, b.Node, hash, hash); e != nil {
					return e
				}
			}
			var e error
			attempt, e = s.FreshInitialAttempt(ctx, operation)
			if e != nil {
				return e
			}
			if committed {
				if e = s.RecordFreshInventory(ctx, id, "radius-primary", hash, bundleDigest(primary), snapshot); e != nil {
					return e
				}
			}
			return errors.New("fixture interruption")
		})
		if e == nil {
			t.Fatal("interruption omitted")
		}
		got, e := s.FreshInitialRecorded(ctx, id, "radius-primary", hash, bundleDigest(primary), snapshot)
		if e != nil || got != committed {
			t.Fatal("exact state proof", got, e)
		}
		if committed {
			if _, e = s.FreshInitialRecorded(ctx, id, "radius-primary", hash, bundleDigest(primary), []byte(`{}`)); e == nil {
				t.Fatal("changed snapshot accepted")
			}
		}
		if _, e = s.pool.Exec(ctx, `UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, attempt); e != nil {
			t.Fatal(e)
		}
		if e = s.ReconcileMaintenance(ctx, attempt, func(ctx context.Context, m MaintenanceEvidence) error {
			if m.Operation != operation || m.Installation != "" {
				return errors.New("changed identity")
			}
			got, e := s.FreshInitialRecorded(ctx, id, "radius-primary", hash, bundleDigest(primary), snapshot)
			if e != nil {
				return e
			}
			if got != committed {
				return errors.New("changed commit state")
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.pool.Exec(ctx, `DELETE FROM bootstrap_private.fresh_inventory`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.pool.Exec(ctx, `INSERT INTO bootstrap_private.ca_publication(reference,secret,sha256) VALUES($1,'fixture',$1)`, strings.Repeat("c", 64)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.FreshInitialRecorded(ctx, id, "radius-primary", hash, bundleDigest(primary), snapshot); e == nil {
		t.Fatal("later CA phase treated as safe absence")
	}
	if _, e := s.pool.Exec(ctx, `DELETE FROM bootstrap_private.ca_publication`); e != nil {
		t.Fatal(e)
	}

}
