# Shared PostgreSQL contract

The application owns `ledger` in the dedicated `cloud8021x` PostgreSQL 16+
database. FreeRADIUS ships an INSERT adapter, not a schema migrator. There are no
stock `radcheck`, `radreply`, `radacct`, or SQL authentication/client lookup tables.

Run `postgres.NewMigration(...).Migrate(ctx, Roles{Runtime: ..., Native: ...})`
with the separate migration credential. Migrations use advisory transaction lock
`(8021,1)`, reject other database names before DDL, and store schema version 2 (v1 upgrades with the collection scope indexes).
The runtime/native roles must already exist without elevated flags, membership,
or object ownership. Migrations reset grants on application objects and grant:

- runtime: application reads, specific mutable state updates, append-only
  observations/intervals/quarantine/reconciliation/import markers; no DDL;
- native: INSERT on `ledger.intake`, its identity-sequence USAGE, schema USAGE,
  and the safe generated-key function; no SELECT or UPDATE;
- migration: ownership of schema/functions/tables. Keep this credential out of
  the daemon and FreeRADIUS runtime accounts.

Privileged bootstrap must also remove PUBLIC connection access to CA databases,
retain explicit existing CA-role access, and grant no application roles CA access.
Application migrations deliberately never modify a CA database. Runtime pgx
connections reject elevated roles, memberships, DB CREATE/TEMP, and public/ledger
schema CREATE. Bound total pools across both daemons and native replay to reserve
CA capacity. Production Cloud SQL capacity/HA validation belongs to rollout.

## Native INSERT contract for the buffered accounting server

Use a plain append-only `INSERT INTO ledger.intake (...) VALUES (...)`. Every
successful replay must affect exactly one row. Preserve the server-generated
replay ID and original host namespace across replay/retry; duplicate raw rows are
expected. Do not use `ON CONFLICT DO NOTHING`, RETURNING, SELECT, or unsafe casts.
Use native SQL escaping for every expanded scalar.

Required trusted values:

| Columns | Meaning |
| --- | --- |
| `received_at` | Original server receipt, `timestamptz`; never NAS time or replay time |
| `source_ip`, `client_id`, `location_id` | Authenticated transport/client/config context, not packet-selected policy |
| `host`, `replay_id` | Original server namespace and server-controlled replay identity |

Nullable raw TEXT plus nonnegative occurrence count (zero = absent):

| Raw column | Count column |
| --- | --- |
| `status` | `status_count` |
| `session_id` | `session_count` |
| `nas_ip` | `nas_count` |
| `station` | `station_count` |
| `class` | `class_count` |
| `input_octets` | `input_octets_count` |
| `output_octets` | `output_octets_count` |
| `input_gigawords` | `input_gigawords_count` |
| `output_gigawords` | `output_gigawords_count` |
| `session_time` | `session_time_count` |

Preserve the first scalar plus the total count; never collapse duplicate
attributes into a single trusted value. Optional raw TEXT context columns are
`event_timestamp`, `delay_time`, `packet_id`, `request_authenticator`,
`called_station`, and `nas_port`. They are not counter identity coordinates.
The writer must not supply generated/application columns (`id`, `inserted_at`,
`session_key`, `processed_at`, `observation_id`).

Missing, duplicate, unknown-status, and malformed counter input can be inserted
for downstream quarantine. Counters are never SQL-cast during intake. A missing
Gigawords attribute is zero only for ordinary native 64-bit counter format;
present malformed high words are invalid. Non-Start requires low words and
session duration. Processed counters use range-checked `NUMERIC(20,0)`.

The migration-owned, fixed-search-path trigger forces transaction
`synchronous_commit=on` and queues/creates the session row atomically. Native
INSERT does not gain general access to sessions. The generated identity uses
valid source/NAS IP strings, normalized station MAC, and a bounded session ID;
invalid/ambiguous identities remain raw with NULL session key for quarantine.
Workers lock a session before selecting its next raw record, prioritize any
already committed Start, and commit observation/dedup/high-water/interval/outbox
state together. There is no separate normalization queue that can hide Start.

## Go integration contracts

`postgres.New(ctx, dsn, config.Database)` is a lazy runtime pool;
`NewMigration` is separate. Both use verified TLS, bounded connections/queries,
server durability checks, and generic secret-free errors. Pool warm minimum is
intentionally zero, preserving construction during outages. Hostname verification
is the default. Instance-CA mode requires the exact PEM SHA-256, one CA, canonical
instance ID, and complete chain verification; root bootstrap must authenticate
Google's instance CA mode/certificate before installing that configuration.

`ProcessOne` processes one raw record; call with a valid retained Class key and
max age. `ResolveIntake` resolves a stable intake identity after uncertainty.
`accounting.Normalize`/`Apply` are pure; PostgreSQL is authoritative. Usage IDs
hash exact session and counter coordinates and exclude receipt/delivery fields.
Raw observations with invalid Class remain unattributed and are quarantined;
legacy usage state can retain earlier verified session attribution.

`Reserve`, `Claim`, `StartAttempt`, `FinishAttempt`, `LookupWork`, `Renew`, and
`ReconcileSuccess` support collection and OTLP outbox work. Use `kind="outbox"`
for business-event delivery; collectors use their own bounded kind. Start must
commit before external I/O. Do not submit after an uncertain Start response.
Expired started attempts become durable quarantine, not retry candidates.
Unstarted expired claims can be reclaimed with a new generation. Partial,
uncertain, and rejected outcomes quarantine; success retains payload and receipt.
`ReconcileSuccess` requires authenticated external success evidence and preserves
attempt/quarantine history. It never permits blind resend.

`AuthEvent(source, expectedCursor, nextCursor, eventID, payload)` atomically
advances a native final-auth log cursor and appends its outbox record. Conflicting
stable event content cannot advance a cursor. Use `Cursor` for recovery.

`ImportOnce(id, checksum, callback)` holds advisory transaction lock `(8021,2)`
and commits callback state plus its import marker atomically. The callback gets a
`pgx.Tx`, permitting Task 9 to import exact high-water/precision/terminal state and
pending/ambiguous work using this documented schema. Parse/validate legacy data
before the callback; stop/fence legacy and new processing workers during import.
A repeated checksum is a no-op; changing a used marker's checksum is an error.
The migration/import methods do not fence legacy processes themselves.

No retention delete job is installed here: payloads, attempts, reconciliation
records, and terminal/high-water state remain available for explicit migration,
rollback and recovery policy. This is not end-to-end exactly-once telemetry.

## Local verification

Run `scripts/test_postgres.sh` to create a labeled disposable PostgreSQL 16
container with generated TLS and synthetic roles, execute the real race-enabled
suite, and remove only that fixture. The script needs local Docker permission;
it never reads production credentials. Ordinary `go test` without the explicit
fixture environment skips integration cases, so it is not equivalent evidence.

## Managed certificate collection (Task 4)

`ReserveCollection` atomically gates a source/host/enrollment/trust/script key
under a transaction advisory lock, using the DB clock for cadence >= one hour
and at most two pending/uncertain requests. A successful remote submission has
`receipt.pending=true`; it continues consuming the budget until authenticated
terminal evidence is persisted. Payloads include `collection_key`, exact host,
UUID/enrollment times, locally generated command/nonce, public SYSTEM script and
public trust digest. Credentials and private keys never enter the ledger.

`ListCollection` returns at most two unresolved plus two latest terminal work
records; history remains retained. `RecordCollectionResult` transactionally
persists the adapter's exact authenticated result and reconciliation evidence,
retaining original attempt/quarantine history. It never permits submission.
The optional neutral repository contract lives in `internal/inventory`.

Schema version 2 adds only partial indexes for recent and pending collection
keys; reviewed v1 installations upgrade under the existing migration lock.
Accounting/native contracts and privileges are unchanged.

## Discovered RADIUS source work (Task 5)

Source work uses `kind=sources:radius-primary` or `sources:radius-secondary`.
`ClaimSource(ctx, node, owner, lease)` is the only supported claim API for these
kinds; generic `Claim` rejects them. An advisory transaction lock serializes the
fixed node across candidate revisions. Active leases/started attempts and all
unresolved quarantine block another revision; expired started attempts become
retained uncertainty. Primary and secondary are independent resources. Expired
unstarted leases may be reclaimed with a new fenced generation. No schema change
is required.

`jobs/network.ApplyJob` reserves the exact candidate JSON, invokes ClaimSource,
commits StartAttempt before external I/O, and passes the **persisted claimed**
candidate to its callback. The installed callback must stage those bytes only in
the configured private candidate path and invoke the fixed root helper with
`--candidate-sha256` of canonical `json.Marshal([]domain.SourceCandidate)` bytes.
A concurrently replaced candidate cannot be applied under another claim. Unknown
start/finish or application outcomes never authorize automatic resubmission.

Before calling `ReconcileSuccess` for a source work ID/generation, obtain actual
root-authenticated `sources.Applier.ReconcileApplied` evidence: fresh exact pinned
controller set, protected config identity, byte-exact expected client include,
original public applied state, fixed node firewall identity/ranges and actual
service health. Persist that evidence and retain original attempts/quarantine;
reconciliation neither performs an apply nor refreshes source TTL. If exact
success cannot be proven, leave the source resource blocked for explicit recovery.

Task 8/9 additionally own the shared backend-maintenance gate and live peer
readiness before root-started FreeRADIUS restarts. The source-specific database
claim isolates each firewall node; it is not permission to restart both HA nodes
simultaneously. Static configured clients remain independent of dynamic-source
outages and TTL.
