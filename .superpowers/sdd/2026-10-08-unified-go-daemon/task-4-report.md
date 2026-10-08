# Task 4 report: Fleet inventory and managed certificate collection

Status: IMPLEMENTED; local commit is ready for controller review/push.
Branch: `codex/unified-go-daemon`, PR 39; base `c3328d6`.
No production/cloud/Fleet API calls, apply, push, merge, release, or subagents.
Only local fake HTTPS Fleet servers and own labeled disposable PostgreSQL 16
fixtures were used. Original webhook issuance and legacy Python remain unchanged.

## Delivered contracts

- `fleet.Observer.Fetch` implements the reviewed neutral device inventory contract:
  complete bounded pagination, cancellation, bounded GET-only 429 retries,
  duplicate host/page and duplicate JSON rejection, optional hardware serial,
  normalized UUID aliases, namespaced device/group IDs and retained Fleet display
  metadata. Configured host IDs, team/fleet IDs, label and requested host scope
  intersect. Nil scopes and explicit empty scopes remain distinct.
- Observer and maintainer use separate protected 0600 credential files and
  separately constructed clients; application construction rejects equal tokens.
  HTTPS is mandatory; redirects cannot receive credentials; operational errors
  contain no response body, token or DSN. HTTP injection only supports local
  fixtures/custom trusted transports; operational construction uses normal TLS.
- `inventory.CachedProvider` caches complete inventory-only responses privately
  with original timestamps and exact requested scope. The application also binds
  it to an opaque digest of Fleet origin, nil/empty host/team filters, label and
  observer credential; changed scope/source/credential cannot reuse prior data.
  Cached data never gets a fresh observation timestamp; expired cache cannot mask
  refresh failure. Cache files contain no plaintext credentials or certificates.
- `jobs/inventory.Service.Sync` is the real shared sync job. It strips every
  inventory-supplied fingerprint, explicitly accepts a separate optional managed
  certificate capability, rejects untrusted/wrong-device/missing-provenance
  observations, preserves independent certificate times, and validates a complete
  generation before atomic file publication and immutable store replacement.
  Failed page/parse/file publication preserves the prior authorization generation.
  An inventory-only fake demonstrates capability separation and no fingerprint
  injection/bypass. Dry run constructs only the observer and performs reads with
  no cache, DB reservation, certificate submission or generation publication.
- Deferred Task 2 fix: `SnapshotStore.Set` now publishes sanitized decoded metadata
  and additionally rejects malformed original UTF-8 before JSON replacement.
  It preserves original authorization identities, certificate times, ambiguity
  entries, valid metadata and original snapshot fields via the cloned generation.
- New explicit `inventory.fleet.client_ca_file` is required for enabled managed
  collection. It is a protected public CA bundle, distinct from attested issuer
  and database trust. EC/RSA CA topology is accepted; roots come only from this
  configured bundle. Chain, purpose, validity, non-CA leaf and exact DER are
  checked. A successful collection may contain no identities under these CAs;
  unrelated well-formed identities are omitted, malformed/duplicate/oversized
  results fail closed. Public CA contents are reloaded/pinned once per prepared
  pass; their exact-byte digest participates in durable binding, invalidating
  cached observations on same-path content changes.

## Managed collection, scope and provenance

`fleet.Collector.Prepare` intersects a complete observer generation with a
complete authenticated scoped-maintainer host list. Each collection rechecks
current detail ID, UUID, platform, enrollment and enrollment timestamps. UUID,
enrollment, Fleet source, trust content or SYSTEM script changes invalidate the
old binding. Windows additionally requires scripts enabled and current MDM
status; hardware serial and certificate subject are never identity authority.

Retained minimum scope is unchanged: nil SCEP profile list permits eligible
non-exempt hosts, explicit [] queues none, configured SCEP installation narrows
collection, and configured verified installed attested-ACME profiles exempt Apple
hosts absent SCEP. Pending/failed ACME installs do not establish exemption. No
new per-hour ACME CertificateList or per-device Wi-Fi profile issuance is added.
Cadence is >= one hour, pass submission budget <= 100, and durable per-binding
pending budget is two, including uncertain and successfully submitted-but-pending
requests. `MaxPendingAge` does not authorize abandoning an uncertain reservation;
unknown Windows execution-ID reservations remain retained indefinitely.

Apple proof is exact authenticated command UUID/type, target host UUID,
enrollment/request/freshness window, acknowledged status, plist command and
UDID/EnrollmentID, IsIdentity, original exact DER, pinned CA/purpose/validity and
explicit durable `ManagedOnly=true` request provenance. The primary Apple schema
has **no IsManaged result field**; the actual-schema positive fixtures omit it.
The controller confirmed the documented minimum ManagedOnly OS versions: macOS
10.15 and iOS/iPadOS 13. Unknown/older versions do not submit/trust this collection.
Sources: https://developer.apple.com/documentation/devicemanagement/certificatelistresponse/certificatelistitem
and https://developer.apple.com/tutorials/data/documentation/devicemanagement/certificatelistcommand/command-data.dictionary.json

XML plist parsing rejects duplicate dictionary keys, nested scalar values,
partial/malformed/trailing containers and oversized data. Binary plist00 support
uses the cached maintained `howett.net/plist` dependency after bounded structural
prevalidation (object counts/references/depth/container lengths/duplicate keys,
UTF-16 validity and cyclic graphs). The library otherwise silently collapses
binary duplicate dictionary keys and allocates from document counts; neither is
trusted before prevalidation. Unsupported/exotic encodings fail closed.

Windows embeds an exact copy of the retained SYSTEM/LocalMachine/My read-only
PowerShell collector. It still proves SYSTEM and HasPrivateKey while emitting
only public DER. A locally generated nonce is part of exact script contents;
authenticated result host ID, execution ID, exact script/nonce, integer successful
exit code, original request-created timestamp and strict bounded result JSON are
required. Duplicate DER/keys and malformed results reject. Known authenticated
failed executions release only their exact pending reservation, with no identity.
Repolling/cached results never freshen observed_at.

## PostgreSQL and uncertain requests

The reviewed work/attempt ledger remains authoritative. New neutral repository
APIs are `ReserveCollection`, `ListCollection`, `RecordCollectionResult` plus the
existing `Claim`, `StartAttempt`, `FinishAttempt`/fencing protocol. A scoped
transaction advisory lock and database clock enforce cadence/budget across
processes. Every attempt starts durably before remote POST; mutating HTTP never
retries. Successful POST receipts retain `pending=true` until terminal proof;
submission success is not certificate observation success.

Expired started claims are quarantined by the reviewed Claim sweep. Apple
reconciles by its pre-reserved command UUID. Windows lost execution-ID responses
remain quarantined with no discovery guess/resend. `ReconcileWindows` accepts
execution-ID hints only after authenticated GET proves exact unique host,
SYSTEM script+nonce, enrollment/request timestamp and trusted result. Wrong or
multiple matching candidates remain quarantined. `RecordCollectionResult` stores
terminal observation and evidence atomically, preserves original attempt and
quarantine history, is idempotent for the same receipt, and rejects replacing an
already terminal observation. No credentials/private keys enter payloads.

Migration version **2** adds only partial recent/pending collection-key indexes;
reviewed v1 installs upgrade under the existing migration lock and role checks.
Scope queries avoid unrelated accounting/outbox volume and read at most two
unresolved plus two latest terminal records. Full history remains retained.
Accounting/native contracts and grants are unchanged; no runtime DDL is added.

## Actual test-first evidence

Before corresponding product changes:

- `go test ./internal/domain -run TestSetSanitizesDisplayMetadataAndPreservesAuthorization -count=1`:
  FAIL, `Set published oversized display metadata`.
- `go test ./internal/domain -run TestSetRejectsInvalidUTF8DisplayMetadataBeforeJSONReplacement -count=1`:
  FAIL, `invalid UTF8 metadata became trusted display text via JSON replacement`.
- Initial sync, Fleet transport/observer, certificate parsing, scope/collector,
  cache, explicit trust config and operational constructor fixtures failed on
  absent Service/NewClient/Observer/reservation/NewTrust/Collector/cache/config
  fields/InventoryServiceFromConfig. Corresponding focused suites then passed.
- `go test ./internal/adapters/fleet -run TestManagedOnlyRequiresSupportedOS -count=1`:
  FAIL, unsupported/unknown ManagedOnly OS accepted.
- `go test ./internal/adapters/fleet -run TestWindowsTerminalFailureRequiresExactProvenance -count=1`:
  FAIL, authenticated terminal failure retained its pending slot.
- `go test ./internal/adapters/fleet -run TestAppleRejectsNestedScalarAndDuplicateDER -count=1`:
  FAIL, malformed nested scalar accepted.
- `C8021X_PG_FIXTURE_TASK=task4 scripts/test_postgres.sh -run TestPostgresCollectionMigrationUpgradesV1AndUsesScopedIndexes`:
  actual PostgreSQL FAIL, `v1 collection migration not applied 1 <nil>`.
- Same disposable runner, `-run TestPostgresCollectionResultImmutableAndSubmissionRemainsPending`:
  FAIL, idempotent terminal evidence caused SQLSTATE 23505. Receipt replay is now
  idempotent and conflicting replacement is rejected without duplicated evidence.
- Source/filter cache identity and prepared-pass trust reload were added with
  compile RED for absent Key/ReloadTrust, then focused race/real PG GREEN.

## GREEN verification

- Focused provider/sync/cache/domain/config/app suites passed during development.
- Focused race on adapter, inventory, sync, app and domain passed.
- `C8021X_PG_FIXTURE_TASK=task4 scripts/test_postgres.sh -run 'TestPostgres(Collection|Fleet)'`:
  **all five actual PG16/race cases passed**, final full Task4 checkpoint 1.731s:
  cross-worker cadence/two-command uncertainty budget; v1-to-v2 upgrade; pending
  submission budget plus immutable/idempotent result; real fake HTTPS Windows
  mutation only after durable Start followed by lost response/no resend/wrong or
  ambiguous candidates/reconciliation/history/original time; Apple exact managed
  XML submission + actual binary schema, wrong-target/duplicate rejection,
  pending no repeat, repoll times and enrollment invalidation.
- After final same-path trust-content reload guard, real PG/race
  `-run TestPostgresFleetAppleExactCommandAndPendingBudget`: passed, 1.505s, including
  trust-content change invalidating the earlier cached observation.
- `go test -race ./...`: passed once across the root module, including original
  webhook packages. Environment-gated PG cases skip in this invocation; the real
  evidence is the explicit disposable runner above. The final small source/trust
  guards were verified with affected race tests, without repeating unchanged full
  suites as the controller requested.
- Final `go test -race ./internal/app ./internal/adapters/fleet ./internal/inventory -count=1`:
  passed (1.230s / 1.538s / 1.119s), including mixed EC/RSA trust and wrong
  CA/purpose/expired/not-yet-valid leaf rejection.
- `goimports -w` applied to every changed Go file; `GOPROXY=off go mod tidy` used
  the already cached plist dependency. Final `golangci-lint run`: **0 issues**.
- Final `GOOS=linux GOARCH=amd64 go build -o /private/tmp/cloud8021x-task4-linux ./cmd/cloud-8021x`:
  passed; `git diff --check`: clean.
- Only generated `cloud8021x-pg-task4-*` containers with `cloud8021x.test=task4`
  and disposable=true labels were used. EXIT traps removed each fixture and its
  synthetic TLS/credential directory; final own-label container inventory empty.
- Legacy Python/SCEP suites were not repeated; no Python tests/resources were
  touched, so the existing mocked HTTPError ResourceWarning cleanup is still
  deferred to the legacy retirement/validation tasks.

## Task 9 APIs and genuine remaining limits

Use `app.InventoryServiceFromConfig(ctx,cfg,localService.Snapshots(),false,nil)`
to obtain the real job and Close function. Call `Service.Sync(ctx,false)` from
inventory schedule or command; it automatically prepares the optional collector.
`RuntimeServices.Run(OperationInventorySync,...)` now dispatches the real one-shot
operation; dry run is observer-only. Logger uses structured safe provider/count/
observation fields. Serve lifecycle/scheduling/telemetry remain Tasks 7/9.
`Collector.Prepare`, `Collect` and explicit `ReconcileWindows` are available for
orchestration/recovery; all collection proof stays inside the adapter.

No production readiness claim: bootstrap must install matching RADIUS public CA
bundle and private observer/maintainer/runtime-DB files, run the separate v2
migration and import/fence legacy pending state before switching workers. Unknown
Windows execution IDs require explicit evidence-backed recovery; there is no
undocumented activity lookup or blind resubmission. Invalid/stale/malformed exact
results fail closed and can require explicit operator recovery rather than
turning uncertainty into unbounded retries. The Windows SYSTEM behavior is
retained, not newly live-validated on Windows. The embedded script copy should
become the single packaged source when legacy Python is retired in Task 10.
Binary parsing intentionally bounds the CertificateList schema rather than
accepting arbitrary plist object graphs. No Fleet server/upstream API changes,
Wi-Fi profile minting, new webhook protocols or privileged runtime migration were
introduced. Self-review addressed metadata, XML, cache source/filter identity,
trust-content reload, pending-budget accounting and terminal-result replay.
