package postgres

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/CampusTech/cloud-8021x/internal/accounting"
	"github.com/CampusTech/cloud-8021x/internal/accounting/binding"
	"github.com/CampusTech/cloud-8021x/internal/adoption"
	"github.com/CampusTech/cloud-8021x/internal/config"
	"github.com/CampusTech/cloud-8021x/internal/migration"
	"github.com/jackc/pgx/v5"
)

func TestPostgresParallelEpochIsolation(t *testing.T) {
	admin, c := integration(t)
	ctx := context.Background()
	name := "cloud8021x_greenfixture"
	if _, err := admin.pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.pool.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)") })
	dsn, _ := url.Parse(os.Getenv("C8021X_PG_TEST_DSN"))
	dsn.Path = "/" + name
	c.Name = name
	green, err := NewMigration(ctx, dsn.String(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer green.Close()
	if err = green.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); err != nil {
		t.Fatal(err)
	}
	id, manifest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	epoch := time.Unix(1800000000, 0)
	if err = green.PrepareCollectionEpoch(ctx, "greenfixture", id, manifest, epoch); err == nil {
		t.Fatal("unprotected epoch write accepted")
	}
	gate := MaintenanceGate{Store: green}
	if err = gate.With(ctx, "parallel-epoch-fixture", func(ctx context.Context) error {
		return green.PrepareCollectionEpoch(ctx, "greenfixture", id, manifest, epoch)
	}); err != nil {
		t.Fatal(err)
	}
	if err = gate.With(ctx, "parallel-epoch-idempotent", func(ctx context.Context) error {
		return green.PrepareCollectionEpoch(ctx, "greenfixture", id, manifest, epoch)
	}); err != nil {
		t.Fatal(err)
	}
	if err = gate.With(ctx, "parallel-epoch-change", func(ctx context.Context) error {
		return green.PrepareCollectionEpoch(ctx, "greenfixture", id, manifest, epoch.Add(time.Second))
	}); err == nil {
		t.Fatal("epoch changed")
	}
	var blueEpochs int
	if err = admin.pool.QueryRow(ctx, "SELECT count(*) FROM ledger.collection_epoch").Scan(&blueEpochs); err != nil || blueEpochs != 0 {
		t.Fatal("blue epoch changed", err)
	}
	// The same session's pre-epoch Start is consumed without establishing state.
	r := testRaw("epoch-session", "Start")
	r.Received = epoch.Add(-time.Second)
	rows := []accounting.Raw{r}
	r = testRaw("epoch-session", "Interim-Update")
	r.Received = epoch
	r.Duration.Value = "900"
	r.Input.Value = "10000"
	rows = append(rows, r)
	r.Duration.Value = "930"
	r.Input.Value = "10025"
	r.Received = epoch.Add(time.Minute)
	r.ReplayID = "next"
	rows = append(rows, r)
	for _, raw := range rows {
		if err = insertRaw(ctx, green, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err = drain(ctx, green); err != nil {
		t.Fatal(err)
	}
	var upload, seconds string
	if err = green.pool.QueryRow(ctx, "SELECT upload::text,seconds::text FROM ledger.intervals").Scan(&upload, &seconds); err != nil || upload != "25" || seconds != "30" {
		t.Fatalf("historical usage credited: %s %s %v", upload, seconds, err)
	}
	if count(t, green, "intervals") != 1 {
		t.Fatal("duplicate historical interval")
	}
	if _, err = green.ProcessOne(ctx, testKey, binding.MaxAge); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresParallelSignedHandoffAndActivation(t *testing.T) {
	admin, c := integration(t)
	ctx := context.Background()
	name := "cloud8021x_handofffixture"
	if _, err := admin.pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.pool.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)") })
	dsn, _ := url.Parse(os.Getenv("C8021X_PG_TEST_DSN"))
	dsn.Path = "/" + name
	c.Name = name
	green, err := NewMigration(ctx, dsn.String(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer green.Close()
	if err = green.Migrate(ctx, Roles{Runtime: "app_runtime", Native: "app_native"}); err != nil {
		t.Fatal(err)
	}
	primary, keyPrimary, _ := ed25519.GenerateKey(rand.Reader)
	secondary, keySecondary, _ := ed25519.GenerateKey(rand.Reader)
	cfg := config.Defaults()
	cfg.Inventory.Fleet.BaseURL = "https://fleet.example.test"
	cfg.Database = c
	cfg.InstanceID = "radius-primary"
	cfg.StateTransition = strings.Repeat("a", 64)
	cfg.Deployment = config.Deployment{Mode: "parallel", ID: "handofffixture", Instance: "handofffixture-primary", SourceID: "blue", SourcePrimary: "radius-primary", SourceSecondary: "radius-secondary", SourcePrimaryKey: hex.EncodeToString(primary), SourceSecondaryKey: hex.EncodeToString(secondary), DestinationPrimaryKey: strings.Repeat("2", 64), DestinationSecondaryKey: strings.Repeat("3", 64), CollectionEpoch: time.Now().UTC().Truncate(time.Second)}
	cfg.Bootstrap.LocalAddress = "10.0.0.1"
	cfg.Bootstrap.PeerAddress = "10.0.0.2"
	manifest, err := cfg.ParallelManifest()
	if err != nil {
		t.Fatal(err)
	}
	gate := MaintenanceGate{Store: green}
	if err = gate.With(ctx, "epoch-handoff", func(ctx context.Context) error {
		return green.PrepareCollectionEpoch(ctx, cfg.Deployment.ID, cfg.StateTransition, manifest, cfg.Deployment.CollectionEpoch)
	}); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if i == 1 {
			cfg.InstanceID = "radius-secondary"
			cfg.Deployment.Instance = "handofffixture-secondary"
			cfg.Bootstrap.LocalAddress, cfg.Bootstrap.PeerAddress = cfg.Bootstrap.PeerAddress, cfg.Bootstrap.LocalAddress
		}
		b, err := parallelBinding(cfg, strings.Repeat("d", 64))
		if err != nil {
			t.Fatal(err)
		}
		doc := adoption.Authorization{Binding: b, CapturedAt: time.Now().UTC(), FenceSHA256: strings.Repeat("e", 64), SourceConfigSHA256: strings.Repeat("f", 64), ClassSHA256: strings.Repeat("1", 64), TrustSHA256: strings.Repeat("7", 64), FingerprintEnforced: true, Policy: json.RawMessage(`{"version":2,"updated_at":1800000000,"identities":{},"certificates":{},"hardware_serials":{}}`), Certificates: json.RawMessage(`{"version":1,"source":"https://fleet.example.test","trust":null,"hosts":{"host":{"binding":[1,1791450000.125,null],"last_attempt":1791450010.25,"platform":"darwin"}},"commands":[{"uuid":"original-command","created_at":1791450010.25,"hosts":{"host":[1,1791450000.125,null]}}]}`)}
		key := keyPrimary
		if i == 1 {
			key = keySecondary
		}
		raw, err := adoption.Sign(doc, key)
		if err != nil {
			t.Fatal(err)
		}
		if err = gate.With(ctx, "handoff-"+cfg.InstanceID, func(ctx context.Context) error {
			if e := green.ImportParallelAuthorization(ctx, cfg, b.ReleaseSHA256, raw); e != nil {
				return e
			}
			return green.RecordParallelPrepared(ctx, cfg, strings.Repeat(strconv.Itoa(i+1), 32), strings.Repeat("7", 64))
		}); err != nil {
			t.Fatal(err)
		}
		if i == 0 && green.RequireParallelPrepared(ctx, cfg) == nil {
			t.Fatal("single green node was activatable")
		}
	}
	if err = green.RequireParallelPrepared(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"release_sha256", "trust_sha256", "config"} {
		var prior string
		query := `SELECT ` + pgx.Identifier{column}.Sanitize() + ` FROM bootstrap_private.parallel_nodes WHERE role='radius-secondary'`
		if err = green.pool.QueryRow(ctx, query).Scan(&prior); err != nil {
			t.Fatal(err)
		}
		query = `UPDATE bootstrap_private.parallel_nodes SET ` + pgx.Identifier{column}.Sanitize() + `=$1 WHERE role='radius-secondary'`
		if _, err = green.pool.Exec(ctx, query, strings.Repeat("0", 64)); err != nil {
			t.Fatal(err)
		}
		if green.RequireParallelPrepared(ctx, cfg) == nil {
			t.Fatal("mismatched peer publication accepted", column)
		}
		if _, err = green.pool.Exec(ctx, query, prior); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		if i == 1 {
			cfg.InstanceID = "radius-primary"
			cfg.Deployment.Instance = "handofffixture-primary"
			cfg.Bootstrap.LocalAddress, cfg.Bootstrap.PeerAddress = cfg.Bootstrap.PeerAddress, cfg.Bootstrap.LocalAddress
		}
		if err = gate.With(ctx, "activate-"+cfg.InstanceID, func(ctx context.Context) error {
			active, e := green.ReadyParallelNode(ctx, cfg, true)
			if e == nil && active != (i == 1) {
				t.Fatal("authority enabled before both publications")
			}
			return e
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err = green.WorkersAllowed(ctx, cfg.StateTransition); err != nil {
		t.Fatal(err)
	}
	if err = green.BlockTransition(ctx, cfg.StateTransition); err != nil {
		t.Fatal(err)
	}
	if green.WorkersAllowed(ctx, cfg.StateTransition) == nil {
		t.Fatal("rollback left green work enabled")
	}
	if count(t, green, "sessions") != 0 || count(t, green, "work") != 0 {
		t.Fatal("handoff imported historical accounting or outbox")
	}
	if green.RequireParallelRollbackReady(ctx, cfg) == nil {
		t.Fatal("rollback approved without two physical green fences")
	}
	for _, role := range []string{"radius-primary", "radius-secondary"} {
		state := migration.NodeState{Version: 1, Node: role, Inventory: json.RawMessage(`{"version":2,"updated_at":1800000000,"identities":{},"certificates":{},"hardware_serials":{}}`), ClassKeySHA256: strings.Repeat("1", 64), FingerprintEnforced: true, ProviderCaches: map[string]json.RawMessage{}}
		raw, _ := json.Marshal(state)
		if err = gate.With(ctx, "green-reverse-"+role, func(ctx context.Context) error {
			return green.RecordWorkerState(ctx, cfg.StateTransition, strings.Repeat("8", 64), raw)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if green.RequireParallelRollbackReady(ctx, cfg) == nil {
		t.Fatal("old pending command provenance silently dropped")
	}
	var guards int
	if err = green.pool.QueryRow(ctx, `SELECT count(*) FROM ledger.legacy_collection_guards WHERE state='quarantine'`).Scan(&guards); err != nil || guards != 1 {
		t.Fatal("idempotent peer command guards lost", guards, err)
	}
	// Synthetic terminal evidence stands in for the separately tested protected
	// original-command reconciler; no real Fleet request runs in this fixture.
	if _, err = green.pool.Exec(ctx, `UPDATE ledger.legacy_collection_guards SET state='resolved',evidence='{"outcome":"terminal"}'`); err != nil {
		t.Fatal(err)
	}
	if err = green.RequireParallelRollbackReady(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = green.pool.Exec(ctx, `INSERT INTO ledger.work(id,kind,payload,state,generation,receipt) VALUES('fleet-cert:unknown','fleet-cert:scope','{"collection_key":"original","command_uuid":"original-command"}','started',1,'{"pending":true}')`); err != nil {
		t.Fatal(err)
	}
	if green.RequireParallelRollbackReady(ctx, cfg) == nil {
		t.Fatal("unknown external command allowed source resume")
	}
	if _, err = green.pool.Exec(ctx, `UPDATE ledger.work SET state='succeeded',receipt='{"pending":false}' WHERE id='fleet-cert:unknown'`); err != nil {
		t.Fatal(err)
	}
	if err = green.RequireParallelRollbackReady(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	// Recovery is bound to one exact expired node/config operation; runtime SQL
	// roles and another physical node cannot invoke its callback.
	cfg.StateTransition = strings.Repeat("9", 64)
	var attempt int64
	if err = green.pool.QueryRow(ctx, `INSERT INTO bootstrap_private.maintenance(operation,expires_at,outcome) VALUES($1,clock_timestamp()-interval '1 second','uncertain') RETURNING id`, ParallelPrepareOperation(cfg)).Scan(&attempt); err != nil {
		t.Fatal(err)
	}
	calls := 0
	prove := func(context.Context, string) (string, string, error) { calls++; return "", "", nil }
	wrong := cfg
	wrong.InstanceID = "radius-secondary"
	if green.ResumeParallelPrepare(ctx, attempt, wrong, prove) == nil || calls != 0 {
		t.Fatal("foreign preparation resumed")
	}
	if err = green.ResumeParallelPrepare(ctx, attempt, cfg, prove); err != nil || calls != 1 {
		t.Fatal("exact passive preparation recovery failed", err)
	}
	if green.ResumeParallelPrepare(ctx, attempt, cfg, prove) == nil || calls != 1 {
		t.Fatal("completed preparation attempt replayed")
	}

	if err = green.pool.QueryRow(ctx, `INSERT INTO bootstrap_private.maintenance(operation,expires_at,outcome) VALUES($1,clock_timestamp()-interval '1 second','uncertain') RETURNING id`, ParallelActivateOperation(cfg)).Scan(&attempt); err != nil {
		t.Fatal(err)
	}
	activationCalls := 0
	activate := func(context.Context) error { activationCalls++; return nil }
	if green.ResumeParallelActivation(ctx, attempt, wrong, activate) == nil || activationCalls != 0 {
		t.Fatal("foreign activation recovered")
	}
	if err = green.ResumeParallelActivation(ctx, attempt, cfg, activate); err != nil || activationCalls != 1 {
		t.Fatal("exact activation recovery failed", err)
	}
	if green.ResumeParallelActivation(ctx, attempt, cfg, activate) == nil || activationCalls != 1 {
		t.Fatal("completed activation replayed")
	}

}
