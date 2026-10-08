# Task 3 implementation report

Status: DONE. Task-owned implementation is ready for controller review and push.
Branch: `codex/unified-go-daemon` (draft PR 39); implementation base:
`8fad8bd86eae4282c90d4aae11abd4a739942319`. The controller owns delivery.
No production, Fleet, cloud API, deployment, release, merge, or push occurred.
No subagents were used.

## Delivered

- Pure exact accounting normalization and conservative state transitions in
  `internal/accounting`, preserving Start-zero, first mid-session baseline,
  terminal Stop, late/reordered suppression, reset rebaseline, precision changes,
  legacy marked/unmarked uncertainty, signed original-receipt attribution, and
  counter-coordinate usage IDs. Native low/high words parse as uint32 and combine
  as uint64; absent high words mean zero, malformed/present high words do not.
  Invalid/duplicate Class produces an unattributed observation and quarantine.
  Earlier verified attribution can persist in legacy-compatible session usage;
  later display metadata never invents identity or replaces signed VLAN.
- Versioned logged PostgreSQL schema for native intake, sessions, immutable
  observations and intervals, work reservations/outbox, attempts, quarantine,
  reconciliation evidence, auth cursors, and import markers. All processed
  unsigned counters have NUMERIC(20,0) with explicit uint64 range checks.
- Native scalar/raw/count intake contract, including trusted original receipt,
  client/location/source, original host/replay ID, counter/status/identity counts,
  and authenticator/delivery/display context. Unknown status and malformed raw
  counters survive INSERT and become downstream quarantine. No stock RADIUS SQL
  authentication tables, Go detail parser, accounting REST, or Datadog readback.
- The accepted narrow migration-owned SECURITY DEFINER trigger uses a fixed
  `pg_catalog,pg_temp` search path, qualified application objects, no dynamic SQL,
  and revoked PUBLIC execute. It creates/queues sessions atomically with native
  intake and forces local synchronous_commit=on, including malformed raw rows.
  Generated keys reject missing/ambiguous/placeholder/non-IP network identities,
  invalid station identity, and oversized session IDs without rejecting raw intake.
- Workers lock/select a session before selecting its raw event. Already committed
  raw Start is prioritized even when Interim was inserted first. There is no
  separate normalization stage that can hide Start. Parallel sessions can proceed;
  concurrent initial-session creation is atomic. Dedup, observation, high-water,
  interval, and business outbox changes commit together. Serialization/deadlock
  retries are bounded to three attempts with bounded backoff.
- Lazy bounded pgx pools, explicit verified hostname TLS by default, and optional
  explicit unique instance-CA mode validating canonical instance ID, exact PEM-byte
  SHA-256, exactly one CA, and the full server chain. No plaintext fallback; DSN
  sslmode cannot weaken configured TLS. Generic operational errors never include
  full DSNs/passwords. Server fsync/full_page_writes/wal_level and synchronous
  commit are checked on connections; Go transactions reassert synchronous commit
  both at begin and immediately before commit.
- Explicit privileged migrations under advisory transaction lock `(8021,1)`.
  Migration rejects any database other than dedicated `cloud8021x` before DDL.
  Runtime/native roles must be distinct unprivileged roles with no memberships or
  object ownership. Native gets INSERT intake and required sequence/function use,
  never SELECT. Runtime cannot DDL or rewrite immutable observations/intervals.
- Persisted external-work started attempts before I/O, bounded leases and renewal,
  generations/fencing, retained success/partial/uncertain/rejected outcomes.
  Expired unstarted claims may be reclaimed; expired started attempts quarantine
  for reconciliation and never automatically resend. Explicit success
  reconciliation records separate evidence and retains original attempt and
  quarantine history. Payloads and receipts remain after success.
- Auth cursor advancement plus stable auth business event outbox in one transaction;
  conflicting stable payload cannot advance a cursor. ImportOnce commits callback
  state and checksum marker atomically under `(8021,2)`, supporting Task 9 imports.

## APIs and downstream contracts

See `migrations/README.md` for the complete native column/count table, grants,
transaction protocol, and downstream integration notes. `001_ledger.sql` is the
stable schema source and is embedded through the `migrations` package.

- `postgres.New(ctx, dsn, config.Database)` is lazy, runtime-restricted;
  `NewMigration` is separate. Caller reads the appropriate protected DSN reference.
  Both return generic errors. `Close`, `CheckDurability`, and `Migrate(ctx, Roles)`
  are available. Existing typed config already supplies all connection bounds;
  no new config fields were necessary. Warm pool minimum is deliberately zero.
- `ProcessOne(ctx, retainedClassKey, classMaxAge)` returns stable intake/event/usage
  IDs and processing reason. `ResolveIntake` checks the durable intake result after
  uncertainty. A lost COMMIT response resolves via DB lookup using the same identity.
- Task 4/7 coordination: `Reserve`, `Claim`, `StartAttempt`, `FinishAttempt`,
  `LookupWork`, `Renew`, `ReconcileSuccess`; neutral Claim/Outcome/Coordinator types
  live in `internal/jobs`. Outbox kind is `outbox`; event IDs are prefixed
  `accounting:`, `usage:`, or `auth:`. Collectors choose their own stable scoped
  work IDs and kind. Never issue I/O after an uncertain StartAttempt return.
  ReconcileSuccess requires adapter-authenticated external success evidence; no
  automatic blind republish/retry API was introduced.
- Task 6 final-auth: `AuthEvent(source, expected, next, eventID, payload)` and
  `Cursor`. Native replay writes raw rows directly and needs no application INSERT
  endpoint. All first-raw plus occurrence-count fields must be populated correctly.
- Task 9 import: `ImportOnce(id, checksum, func(ctx, pgx.Tx) error)` plus the schema.
  Validate legacy snapshots before the callback; import exact numbers, marked/bits,
  terminal state, original timestamps/identity, and pending/uncertain work there.
  Stop/fence old and new processing workers during import. Checksum mismatch is an
  error; replay of an already imported checksum does not rerun the callback.
- Task 7 can consume typed `accounting.Event`/`Interval` JSON payloads. Original
  host/location/called-station/NAS-port display context is retained; presentation
  mapping/enrichment remains Task 7 and must use N/A rather than invented names.

## Actual RED evidence

1. Before the accounting implementation:
   `go test ./internal/accounting` failed to compile with `undefined: Raw`,
   `undefined: Event`, `undefined: Normalize`. The tests specified exact uint64,
   baseline/reset/precision/reorder/Stop, Class attribution, and semantic retries.
2. Before PostgreSQL implementation:
   `go test ./internal/storage/postgres` failed with `undefined: New`,
   `undefined: Store`, `undefined: Roles`.
3. Before shared work APIs:
   `go test ./internal/storage/postgres` failed because `internal/jobs` did not
   exist. Later reconciliation/renewal tests failed with `s.Renew undefined` and
   `s.ReconcileSuccess undefined` before implementing those methods.
4. Self-review regressions, executed against actual PostgreSQL:
   `scripts/test_postgres.sh -run 'TestPostgres(AuthConflict|MigrationRejects)'`
   failed with `changed stable event advanced cursor` and
   `migration accepted privileged native writer`. Enqueue now rejects changed
   content transactionally, and migration preflight rejects elevated roles.
5. `go test ./internal/accounting -run TestUnknownNetworkIdentityCannotCreateSharedSession`
   failed with `invalid source accepted unknown`. Go and generated SQL session
   keys now reject placeholder/non-IP/ambiguous source or NAS identities while
   preserving raw intake for quarantine.
6. `scripts/test_postgres.sh -run TestPostgresMigrationRejectsWrongDatabase`
   failed with `migration created application schema in CA database`. The final
   migration checks the dedicated database before any application schema DDL.

Fixture-only corrections during development: readiness now waits for the final
TCP server rather than the temporary init server; reloadable TLS uses ALTER SYSTEM
init SQL rather than command-line settings; the loss relay captures the immutable
upstream address before returning its local listener address. Final runs are clean.

## Actual GREEN evidence

- `go test -race ./...`: passed across all root packages, including original
  webhook packages. This normal invocation skips environment-gated PostgreSQL
  integration, so it is not the database evidence below. It ran after the full
  implementation; final small identity/schema/scan guards were additionally
  verified by the final affected package race suite and real PostgreSQL suite.
- Final affected `go test -race ./internal/accounting ./internal/storage/postgres`:
  passed. `goimports` applied to every task Go file.
- `golangci-lint run`: `0 issues.` including after final Go guard changes.
- `git diff --check`: clean.
- Final `scripts/test_postgres.sh`: PASS, actual PostgreSQL 16, race enabled,
  `ok github.com/CampusTech/cloud-8021x/internal/storage/postgres 3.099s`.
  No integration cases skipped. The helper test is executed as a real subprocess
  for process-death scenarios. Covered:
  - migrations, all logged application tables, exact max uint64 round trip and
    numeric range rejection;
  - two independent workers with raw Interim inserted before queued Start,
    exactly one full legitimate max-uint64 interval and one usage outbox;
  - twelve concurrent raw deliveries atomically creating one session;
  - unrelated sessions progressing while one session is locked;
  - cross-host/replay/receipt semantic retry dedup;
  - invalid Class, duplicate identity, malformed high word, unknown status,
    unattributed observations and durable quarantine;
  - actual killed database backend before commit: no partial observation,
    high-water, interval or outbox; recovery emits once;
  - actual child process exits without cleanup before and after COMMIT:
    committed state survives, uncommitted work resumes exactly once;
  - actual TLS PostgreSQL protocol relay receives the server's COMMIT
    CommandComplete then severs the connection before returning it to pgx:
    accounting resolves committed stable identity without duplication;
  - the same actual lost-response test around StartAttempt: persisted started
    attempt expires to quarantine, and another worker cannot resubmit;
  - auth cursor/outbox replay, conflicts and import checksum/rollback atomicity;
  - per-transaction and native-trigger synchronous_commit forced on even when
    the acquired session/transaction was explicitly set off;
  - SQL/Go key parity, Unicode session IDs, normalized MAC/whitespace, bounded
    identity, and all invalid network rows retained/quarantined;
  - real TLS hostname success/failure, exact pinned instance chain success,
    wrong pin, extra CA, wrong chain, unsafe modes, DSN disable attempt, actual
    PostgreSQL SSL disabled, lazy outage construction and sentinel redaction;
  - native SELECT/UPDATE/DELETE/DDL/TEMP denial; runtime DDL/role creation,
    immutable observation update and interval delete denial;
  - temp/search-path hijack and SQL-looking raw session values cannot redirect
    the trigger; runtime/native cannot connect to the separate CA sentinel DB;
  - powerful inherited role/elevated runtime rejection, elevated native migration
    rejection, wrong database migration rejection, and unchanged CA sentinel;
  - expired unstarted generation reclaim, stale generation/owner finalization
    denial, partial result quarantine, success payload/attempt retention, bounded
    renewal and explicit evidence-backed reconciliation preserving history.
- Focused final guard command also passed:
  `scripts/test_postgres.sh -run 'TestPostgres(MigrationRejectsWrongDatabase|TransactionDurability)'`.

The runner used only labeled `cloud8021x-pg-task3-*` containers, generated local
TLS and synthetic credentials. Its EXIT trap removed each container and temporary
certificate directory. No parent Task 6 container was touched.

## Self-review, boundaries and remaining integration work

Self-review caught and fixed auth payload conflicts, privileged native roles,
placeholder network identity, wrong-database migrations, and explicit native
commit durability. No unresolved correctness blocker is known.

This is Task 3, not completion of the daemon. Task 6 still owns actual
FreeRADIUS detail/SQL replay and duplicate/count delivery proof; Task 7 owns OTLP
mapping and actual Collector persistence/acknowledgment behavior; Task 8 verifies
Google's authenticated unique-instance CA assertion; Tasks 9/10 wire CLI/runtime,
real legacy import/export/retention, credentials/grants, monitoring and deployment.
The application RuntimeServices migration dispatch remains unsupported until Task
9, while the migration/storage API here is real and integration-tested.

The disposable sentinel proves isolation and unchanged CA data, not production
Cloud SQL load, HA capacity or zero-loss failover. Bootstrap must revoke PUBLIC
CA database CONNECT/TEMP and preserve explicit CA role access; application
migrations never touch CA databases. Application pool maximum is bounded per
process, so deployment must budget the combined two-daemon/native pools against
reserved CA capacity. Pool construction is lazy; operations fail safely during
outage and offline snapshot authorization remains independent.

There is deliberately no automatic retention deletion or uncertain downstream
republishing. Payload/history retention and explicit recovery policy remain to be
wired; exact totals come from the PostgreSQL ledger, not an end-to-end
exactly-once telemetry guarantee. ImportOnce coordinates imports transactionally
but does not itself stop legacy processes. No production readiness claim is made.
