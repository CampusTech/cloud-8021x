package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/adapters/fleet"
)

func TestPostgresLegacyGuardCommittedResolutionProof(t *testing.T) {
	s, c := integration(t)
	reset(t, s)
	ctx := context.Background()
	id := strings.Repeat("d", 64)
	if _, e := s.pool.Exec(ctx, "TRUNCATE bootstrap_private.maintenance,ledger.legacy_collection_guards CASCADE"); e != nil {
		t.Fatal(e)
	}
	command := `{"uuid":"command","created_at":1791450000.123456789,"hosts":{"host":[42,1791450000.123456789,null]}}`
	observation := `{"binding":[42,1791450000.123456789,null],"last_attempt":1791450000.123456789,"platform":"darwin"}`
	if _, e := s.pool.Exec(ctx, `INSERT INTO ledger.legacy_collection_guards(id,scope,source,host_id,host_uuid,command_uuid,document,observation) VALUES($1,$2,'https://fixture.invalid',42,'host','command',$3,$4)`, id, id, []byte(command), []byte(observation)); e != nil {
		t.Fatal(e)
	}
	runtime := runtimeStore(t, s, c)
	payload, _ := json.Marshal(map[string]string{"collection_key": "new-format-key", "legacy_scope": id})
	if changed, e := runtime.ReserveCollection(ctx, "new-request", "fleet-cert", "new-format-key", payload, time.Hour, 2); e != nil || changed {
		t.Fatal("inherited command guard did not block duplicate collection", changed, e)
	}
	if _, e := runtime.pool.Exec(ctx, `UPDATE ledger.legacy_collection_guards SET state='resolved'`); e == nil {
		t.Fatal("runtime released protected inherited command guard")
	}
	if e := s.LegacyCollectionResolved(ctx, id); e == nil {
		t.Fatal("pending guard counted as completed")
	}
	proof := fleet.LegacyRecoveryEvidence{CommandUUID: "command", HostUUID: "host", HostID: 42, Outcome: "terminal", Response: json.RawMessage(`{"original":"terminal"}`)}
	if e := s.ResolveLegacyCollection(ctx, id, proof); e == nil {
		t.Fatal("unprivileged resolution")
	}
	operation := "fixture-original-resolution"
	gate := MaintenanceGate{Store: s}
	if e := gate.With(ctx, operation, func(ctx context.Context) error {
		if e := s.ResolveLegacyCollection(ctx, id, proof); e != nil {
			return e
		}
		return errors.New("completion ACK lost")
	}); e == nil {
		t.Fatal("missing uncertainty")
	}
	if e := s.LegacyCollectionResolved(ctx, id); e != nil {
		t.Fatal("committed original proof absent", e)
	}
	var attempt int64
	if e := s.pool.QueryRow(ctx, `UPDATE bootstrap_private.maintenance SET expires_at=clock_timestamp()-interval '1 second' WHERE operation=$1 RETURNING id`, operation).Scan(&attempt); e != nil {
		t.Fatal(e)
	}
	if e := s.ReconcileMaintenance(ctx, attempt, func(ctx context.Context, m MaintenanceEvidence) error {
		if m.Operation != operation || m.Installation != "" {
			return errors.New("wrong original")
		}
		return s.LegacyCollectionResolved(ctx, id)
	}); e != nil {
		t.Fatal(e)
	}
	if changed, e := runtime.ReserveCollection(ctx, "new-request", "fleet-cert", "new-format-key", payload, time.Hour, 2); e != nil || !changed {
		t.Fatal("authenticated terminal proof did not release the inherited command guard", changed, e)
	}
	var retainedCommand, retainedHost []byte
	if e := s.pool.QueryRow(ctx, "SELECT document,observation FROM ledger.legacy_collection_guards WHERE id=$1", id).Scan(&retainedCommand, &retainedHost); e != nil || !bytes.Equal(retainedCommand, []byte(command)) || !bytes.Equal(retainedHost, []byte(observation)) {
		t.Fatal("original evidence changed", e)
	}
}
