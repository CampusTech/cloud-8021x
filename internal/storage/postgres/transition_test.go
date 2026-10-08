package postgres

import (
	"context"
	"strings"
	"testing"
)

func TestPostgresProtectedTransitionRequiresTwoFencesAndImport(t *testing.T) {
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
	if err = s.EnableImportedTransition(ctx, id); err == nil {
		t.Fatal("activated without import marker")
	}
	if err = runtime.RecordWriterFence(ctx, id, "radius-primary", hash, hash); err == nil {
		t.Fatal("runtime forged root receipt")
	}
	if _, err = runtime.pool.Exec(ctx, `UPDATE bootstrap_private.transitions SET enabled=true`); err == nil {
		t.Fatal("runtime modified private transition")
	}
	if _, err = s.pool.Exec(ctx, `INSERT INTO ledger.import_markers(id,checksum) VALUES($1,$2) ON CONFLICT DO NOTHING`, "state:"+id, hash); err != nil {
		t.Fatal(err)
	}
	if err = s.EnableImportedTransition(ctx, id); err != nil {
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
