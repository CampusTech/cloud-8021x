package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPostgresProtectedTransitionRequiresTwoFencesAndActivation(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	runtime := runtimeStore(t, s, c)
	id := strings.Repeat("9", 64)
	hash := strings.Repeat("a", 64)
	_, err := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.writer_fences,bootstrap_private.transitions CASCADE")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.WorkersAllowed(ctx, id) == nil {
		t.Fatal("workers enabled before fences")
	}
	gate := MaintenanceGate{Store: s}
	for i, node := range []string{"radius-primary", "radius-secondary"} {
		if err = gate.With(ctx, "state-fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, node, hash, hash) }); err != nil {
			t.Fatal(err)
		}
		if runtime.WorkersAllowed(ctx, id) == nil {
			t.Fatal("fences alone enabled workers")
		}
		if i == 0 && s.RequireWriterFences(ctx, id) == nil {
			t.Fatal("one node fence accepted")
		}
	}
	if err = s.RequireWriterFences(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = runtime.RecordWriterFence(ctx, id, "radius-primary", hash, hash); err == nil {
		t.Fatal("runtime forged root receipt")
	}
	if _, err = runtime.pool.Exec(ctx, `UPDATE bootstrap_private.transitions SET enabled=true`); err == nil {
		t.Fatal("runtime modified private transition")
	}
	// The protected activation workflow is covered by the parallel suite.
	if _, err = s.pool.Exec(ctx, `UPDATE bootstrap_private.transitions SET enabled=true WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err = runtime.WorkersAllowed(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err = s.BlockTransition(ctx, id); err != nil {
		t.Fatal(err)
	}
	if runtime.WorkersAllowed(ctx, id) == nil {
		t.Fatal("revoked transition still enables new work")
	}
}

// A revocation must wait for an already authorized transaction, then reject
// every subsequent claim/progress transaction, even if its caller checked early.
func TestPostgresTransitionOrdersRevocationAgainstProgress(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	id, hash := strings.Repeat("8", 64), strings.Repeat("a", 64)
	if _, err := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.transitions CASCADE"); err != nil {
		t.Fatal(err)
	}
	gate := MaintenanceGate{Store: s}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if err := gate.With(ctx, "state-fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, node, hash, hash) }); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.pool.Exec(ctx, `UPDATE bootstrap_private.transitions SET enabled=true WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	worker := runtimeStore(t, s, c).ForTransition(id)
	tx, err := worker.begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	done := make(chan error, 1)
	go func() { done <- s.BlockTransition(ctx, id) }()
	select {
	case err := <-done:
		t.Fatalf("revocation overtook live progress transaction: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := commit(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := worker.Reserve(ctx, "post-revoke", "outbox", json.RawMessage(`{}`)); err == nil {
		t.Fatal("reservation after revocation")
	}
	if tx, err := worker.begin(ctx); err == nil {
		rollback(tx)
		t.Fatal("progress after revocation")
	}
	if _, err := worker.Claim(ctx, "outbox", "worker", time.Minute); err == nil {
		t.Fatal("claim after revocation")
	}
	if tx, err := runtimeStore(t, s, c).ForTransition("").begin(ctx); err == nil {
		rollback(tx)
		t.Fatal("empty transition bypass")
	}
}

func TestPostgresWriterUpgradePreservesOriginalEvidence(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	id := strings.Repeat("6", 64)
	old := strings.Repeat("a", 64)
	next := strings.Repeat("b", 64)
	receipt := strings.Repeat("c", 64)
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.transitions CASCADE"); e != nil {
		t.Fatal(e)
	}
	gate := MaintenanceGate{Store: s}
	for _, node := range []string{"radius-primary", "radius-secondary"} {
		if e := gate.With(ctx, "state-fence", func(ctx context.Context) error { return s.RecordWriterFence(ctx, id, node, old, receipt) }); e != nil {
			t.Fatal(e)
		}
	}
	if e := runtimeStore(t, s, c).RebindWriterFence(ctx, id, "radius-primary", old, next, receipt); e == nil {
		t.Fatal("runtime forged upgrade")
	}
	if e := gate.With(ctx, "state-fence", func(ctx context.Context) error {
		return s.RebindWriterFence(ctx, id, "radius-primary", old, next, receipt)
	}); e != nil {
		t.Fatal(e)
	}
	for _, hash := range []string{old, next} {
		if e := s.RequireNodeWriterFences(ctx, id, "radius-primary", hash); e != nil {
			t.Fatal(e)
		}
	}
	var original string
	if e := s.pool.QueryRow(ctx, `SELECT config_sha256 FROM bootstrap_private.writer_fences WHERE transition=$1 AND node='radius-primary'`, id).Scan(&original); e != nil || original != old {
		t.Fatal("original receipt changed", original, e)
	}
	if e := gate.With(ctx, "state-fence", func(ctx context.Context) error {
		return s.RebindWriterFence(ctx, id, "radius-primary", next, strings.Repeat("d", 64), old)
	}); e == nil {
		t.Fatal("foreign receipt accepted")
	}
}

func TestPostgresResumeWriterFenceIsExactAndKeepsUnknownQuarantined(t *testing.T) {
	s, c := integration(t)
	ctx := context.Background()
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance CASCADE"); e != nil {
		t.Fatal(e)
	}
	identity := WriterFenceIdentity{Transition: strings.Repeat("5", 64), Node: "radius-primary", ConfigSHA256: strings.Repeat("a", 64)}
	operation, e := identity.Operation()
	if e != nil {
		t.Fatal(e)
	}
	var id int64
	if e = s.pool.QueryRow(ctx, `INSERT INTO bootstrap_private.maintenance(operation,expires_at,outcome) VALUES($1,clock_timestamp()-interval '1 second','uncertain') RETURNING id`, operation).Scan(&id); e != nil {
		t.Fatal(e)
	}
	calls := 0
	resume := func(context.Context) (string, error) { calls++; return strings.Repeat("b", 64), nil }
	if e = runtimeStore(t, s, c).ResumeWriterFence(ctx, id, identity, resume); e == nil || calls != 0 {
		t.Fatal("runtime entered recovery")
	}
	wrong := identity
	wrong.Node = "radius-secondary"
	if e = s.ResumeWriterFence(ctx, id, wrong, resume); e == nil || calls != 0 {
		t.Fatal("different node entered recovery")
	}
	if e = s.ResumeWriterFence(ctx, id, identity, func(context.Context) (string, error) { return "", errors.New("unknown file") }); e == nil {
		t.Fatal("unknown state completed")
	}
	if _, e = s.pool.Exec(ctx, `UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if e = s.ResumeWriterFence(ctx, id, identity, resume); e != nil || calls != 1 {
		t.Fatal("exact recovery failed", e)
	}
	var outcome string
	if e = s.pool.QueryRow(ctx, `SELECT outcome FROM bootstrap_private.maintenance WHERE id=$1`, id).Scan(&outcome); e != nil || outcome != "complete" {
		t.Fatal(outcome, e)
	}
	if e = s.ResumeWriterFence(ctx, id, identity, resume); e == nil || calls != 1 {
		t.Fatal("completed attempt rerun")
	}
}
