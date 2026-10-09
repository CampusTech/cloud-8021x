# Development-only synthetic cloud contracts

This package is never a shipping dependency or production service. It uses the
root module's existing Go/gRPC/protobuf dependencies. Shipping clients retain
their real transports, endpoint names and TLS checks; guest-only DNS/trust and
unrouted namespaces reach the synthetic API. Execution requires Linux root and
`/etc/cloud8021x-task11-fixture` containing `synthetic-only-v1\n`.

The original metadata/KMS executable used for the separately recorded R108
shipped step-ca SDK interoperability proof remains frozen. These stateful source
extensions do **not** inherit that binary's execution proof. The focused tests
exercise real in-process HTTP/gRPC framing, the actual Fleet recovery client,
and actual typed business projection/OTLP encoding. They do not prove installed
services, production IAM/KMS, real Fleet delivery or Datadog processing.

## API contracts

- Exact method/host/path allowlists; unknown requests fail closed. Synthetic
  metadata uses the exact scoped token URI requested by the shipped step-ca SDK.
- Secret Manager canonicalizes the seeded project ID to its numeric identity.
  Enabled versions are immutable, numeric and newest-first; access returns exact
  base64 and CRC32C. Publication validates the payload CRC, allocates a new enabled
  version and permits only already-seeded `radius-smallstep-server-cert` and
  `radius-smallstep-server-key`. No CA identity secret can be published.
- Fleet uses `fleet.task11.test` and a configured synthetic bearer. Inventory
  supports bounded real pagination, host details and an explicit error scenario.
  Retained Apple CertificateList results progress only through controller-chosen
  pending, missing/404 and terminal Error states. Missing is never terminal.
  New Apple or Windows requests retain their actual command/script, nonce, host,
  digest and submission count. The uncertainty scenario persists acceptance then
  aborts the response; a repeated submission is recorded and refused. Windows
  results return the exact accepted script/execution identity, never a rebuilt
  approximation. No remote script is executed by this helper.
- Business intake accepts strictly decoded OTLP protobuf, optionally one bounded
  gzip stream. Shipping DDOT uses `otlp_http/business` at
  `https://otlp.<site>/v1/logs`, `dd-api-key`, and services `radius-auth`,
  `radius-acct`, `radius-usage`. The helper preserves decoded resource, scope,
  timestamp, body and attributes, including exact unsigned counter companions.
  Ordinary `datadog/ordinary` exporter traffic cannot satisfy business evidence.
  A separate primitive OTLP endpoint is `otlp.task11.test` with a bearer. Primitive
  metric proof retains actual typed points, timestamps, units and resources.
- KMS REST/gRPC GetPublicKey/AsymmetricSign retains real synthetic EC/RSA signing
  and checksums. The two-method codec follows the cached official Google KMS
  protobuf definitions; unknown methods/fields and passive signing are refused.

## Private seed and durable state

The existing schema1 `seed.json` has a `task11-` project ID, project number
`111222333444`, exact numeric-resource secret maps (one enabled version each),
exact KMS version-resource to PKCS8 filename mappings, and explicit static
`routes`. Static routes are remote mocks, never provider delivery proof. All
seeds, keys, expected projections, journals and state are synthetic private
runtime artifacts; they must never be added to Git or printed over serial.

The optional `contract` object adds `schema:1`, `gate`, `application_sha256`,
`fleet`, `otlp` and `peers`. `fleet` contains `authorization`, bounded typed
`hosts`, and original retained `commands` with UUID, host ID/UUID, original
creation time and `request_type:CertificateList`. Seeded commands cannot contain
prefilled outcomes, submissions or request evidence. `otlp` contains the exact
allowed `host` and either primitive `authorization` or shipping `api_key`.

For `gate:installed-traffic`, `peers` must initially contain exactly:

| Address | Role | API mutation policy |
| --- | --- | --- |
| 10.203.11.31 | original-primary | active |
| 10.203.11.32 | original-secondary | active |
| 10.203.11.21 | green-primary | passive |
| 10.203.11.22 | green-secondary | passive |

The actual connection address (HTTP RemoteAddr/gRPC peer), never a forwarded
header, chooses that policy. Unknown peers are refused. Journals retain observed
address/role/policy independently of source KMS signing. Node-local metadata
instances must use separate non-contract seeds/journals; their loopback traffic
must not be misattributed to shared API callers. Source IP preservation and the
complete guest exposure must be reviewed before launch.

The state directory must be real, private mode0700. Files must be regular,
mode0600, single-link and owned by the process (root in the guest). Ancestors and
final files are opened without following links. An interprocess flock serializes
API requests, scenario commands and verification. Each request appends and syncs
its bounded journal before atomic state publication; a crash between those steps
causes a fail-closed journal/state mismatch, not an invented successful receipt.
A different seed, malformed state or edited journal also refuses reuse. Limits
include 2MiB expanded requests, 1024 intake batches, 8192 journal events and
32MiB private state/journal files.

The private journal contains request hashes and semantic response evidence;
secret response bodies and bearer credentials are excluded. Actual secret bytes,
accepted scripts and decoded telemetry remain protected in private API state;
Fleet semantic response evidence may include the exact submitted script.
Neither the journal nor state is a readiness marker.

## Fixed controller commands

Install the reviewed development executable as
`/usr/local/libexec/task11-cloud-contract`; the controller separately pins its
SHA256. Existing serving mode is `--fixture-root DIR --phase passive|active`,
with fixed TLS address `10.203.11.10:443`, or `--metadata` for node-local metadata.
Contract serving resumes only matching private state/journal. Do not reuse a
legacy hash-only journal as contract evidence.

Controller subcommands accept no filesystem path override. Their fixed roots
are `/var/lib/cloud8021x-task11/control/primitive-api` and
`/var/lib/cloud8021x-task11/control/original-seed/api` respectively:

```sh
/usr/local/libexec/task11-cloud-contract scenario fleet-missing \
  --gate installed-traffic --command task11-retained-command-0001
/usr/local/libexec/task11-cloud-contract scenario peer-active \
  --gate installed-traffic --peer 10.203.11.21
/usr/local/libexec/task11-cloud-contract verify --gate installed-traffic \
  --application-sha256 APP_SHA256 --expected-sha256 EXPECTED_FILE_SHA256
```

Scenarios are `fleet-pending`, `fleet-missing`, `fleet-terminal` (exact existing
command required); `fleet-uncertain`, `inventory-error`, `inventory-ready`,
`intake-unavailable`, `intake-ready` (no command); and `peer-active`/`peer-passive`
(exact seeded green IP only). Terminal results cannot be reopened. Peer changes
are replayed from the controller journal; direct state edits are refused.
Changing API permission is **not** proof that a product node activated. The
controller must verify real shipping CLI/PID1/receipt gates independently before
changing permission. Installed verification requires actual reads from both
greens while passive and rejects even denied mutation attempts during passive
periods. Deliberate primitive denial tests belong in separate evidence roots.

## Passive peer audit

The separately pinned development helper also exposes a read-only audit of one
installed green peer's actual remote API journal. It always uses
`/var/lib/cloud8021x-task11/control/original-seed/api`, requires the existing
Linux-root guest guard, and accepts no gate or filesystem path override:

```sh
/usr/local/libexec/task11-cloud-contract passive-audit baseline \
  --seed-sha256 SEED_FILE_SHA256 --peer 10.203.11.21
/usr/local/libexec/task11-cloud-contract passive-audit final \
  --seed-sha256 SEED_FILE_SHA256 --peer 10.203.11.21 \
  --after-sequence BASELINE_TO_SEQUENCE --baseline-sha256 BASELINE_SHA256
```

The controller must retain the actual baseline result before the independently
verified preparation or deactivation/reboot operation. The prefix hash binds the
exact seed bytes, seeded green IP/role, actual journal sequence and full prefix.
It is a consistency check, not an authorization token or product lifecycle
receipt. Only the seeded `.21` and `.22` greens are accepted. An original caller
or a different peer's baseline cannot substitute for the selected green.

Both commands reopen the private state under its existing lock and verify
journal/state consistency. The audit replays the complete policy and controller
history, checks seeded and subsequently observed command identities and legal
scenario transitions, and compares replayed policy/control state to persisted
state. Unknown protocols, methods, transport peers or controls refuse the audit.
The selected peer must be passive at the baseline, throughout the final window
and currently. Every selected-peer mutation attempt in the window fails,
including refused HTTP requests and denied KMS signing. Known original-node
activity remains separate evidence. Historical active work before a newly
recorded passive baseline is permitted; an earlier prepared baseline cannot be
reused across that active interval.

Success returns bounded nonsecret JSON: `schema:1`, `kind:passive-peer-audit`,
`mode:baseline|final`, `seed_sha256`, `peer`, `role`, `policy:passive`,
`from_sequence`, `to_sequence`, `baseline_sha256`, `evidence_sha256`, `events`,
`read_attempts`, `successful_reads`, `http_requests`, `grpc_requests`,
`control_events`, `other_peer_events`, and `mutation_attempts:0`. Hashes are
64 lowercase hexadecimal characters. The maximum history is 8192 events and the
result is bounded to 2048 bytes. Baseline has equal sequence boundaries and zero
window counts. Final counts the interval `(from_sequence, to_sequence]`:
`events` counts the selected peer's HTTP/gRPC requests, `control_events` counts
controller scenarios, and `other_peer_events` counts other seeded callers.
Successful reads are actual HTTP 2xx or gRPC OK reads. No reads are required:
a passive boot with no external requests legitimately produces zero counts.
Failure emits no success result. Auditing does not write state or journal.

Before either HTTP body decoding or gRPC RecvMsg, serving exclusively creates and
syncs a fixed private `transport-incomplete` sentinel under the existing state
lock. Only that request may remove its exact file after journal and state are
durably committed; directory creation/removal is synced too. Oversized or broken
receives, exhausted evidence bounds, interrupted processing and failed persistence
leave the sentinel in place. Any existing sentinel, even empty or malformed,
blocks subsequent serving, scenarios and verification after reopening. It is an
incomplete-evidence failure marker, never a success receipt; no automatic reset
or cleanup command is provided. A run with incomplete evidence cannot be reused
as acceptance proof. Journal/request limits are unchanged. Static GET mutation
classification uses the dispatcher's identical authority normalization and exact
method/path/query match, including explicit ports.

This result proves only the bounded remote history. It does not establish that
preparation, deactivation, a reboot or product activation occurred, nor that
local sockets or services were passive. The controller's actual CLI/PID1/boot
and node-observer evidence must establish those separate facts and delimit the
window. Rebuilding and enrolling this reviewed helper/source/seed identity is
required before controller integration; the frozen R108 executable has no audit
execution proof.

## Projection and verifier result

The fixed root0600 `expected.json` must be produced from actual durable SQL work
using production `telemetry.Project`, with its bytes independently pinned by the
controller. It is not generated from intake records and is not a hand-authored
list of expected fixture event IDs. Its schema is:

- `schema:1`, `gate`, `application_sha256`, `seed_sha256` (SHA256 of the exact reviewed
  seed file bytes, independently pinned by the controller).
- `records`: actual `telemetry.BusinessRecord` JSON (`ID`, `Category`, `Host`,
  `Received`, `Fields`). Preserve numbers exactly when decoding.
- `commands`: independently projected `command_uuid`, `posts:0|1`,
  `require_uncertain`, `origin:retained-legacy|green-work`, `host_id`, `host_uuid`,
  `platform`, `last_mdm_enrolled_at`, `last_enrolled_at`, `transport:apple|windows`,
  `original_created_at`, `accepted_before`, `request_sha256`, `script_sha256`,
  `submission_peer`, `recovery_peer`, `recovery_phase`. Creation bounds use
  RFC3339Nano, cannot predate original enrollment and span at most ten minutes.
  A seeded legacy command with posts0 must have the exact original creation time
  at both bounds and no invented request/submission provenance. Observed posts1
  require the exact original POST body hash; Windows additionally pins the whole
  original script including its nonce. These pins come from original retained
  work, never the helper's accepted command. A learned execution ID must still
  match that pinned request/target/script. Actual host/enrollment, pending,404 and
  terminal reads must match the approved recovery caller and phase.
  Installed recovery permits one explicitly pinned green in active or passive
  phase (rollback recovery is read-only). Installed green-work submissions require
  an active green; observed retained-legacy submissions require an explicitly
  pinned active original and creation upper bound no later than collection epoch.
  This narrow original provenance does not certify original-only recovery.
- `publications`: exact numeric secret resource to new payload SHA256. Use an
  empty object for the normal preserved valid cache; an explicit renewal proof
  names the two permitted server cache secrets. Original versions must remain
  unchanged in all cases.
- `metrics`: primitive `{host,name,unit,kind}` expectations; these never prove the
  installed ordinary Datadog exporter.
- Installed only: `deployment_id`, derived `database`, immutable whole-second
  RFC3339 `collection_epoch`, and `outbox` rows
  `{work_id,generation,payload_sha256,record_id,outcome:"succeeded"}` from actual
  SQL receipts. All records must have exactly one matching durable work row.

Installed business delivery and cache publication/access require recorded active
approved green callers on the exact configured intake or Google endpoint. Either
green may export shared-outbox records regardless of the record's producer host;
original-node delivery/publication cannot satisfy installed green evidence.

Log attributes must exactly match the production OTLP encoder: both primary
numeric value/type and exact companion where emitted. Protobuf scalar kinds are
retained through JSON state persistence. The complete business resource allowlist
is exactly `service.name`, `host.name`, `business.category`; the actual DDOT
business pipeline changes only service.name. There is no allowance for extra
collector/private attributes or resources. The two projector integer fields
`nas_port_type_count` and `counter_bits` are restored to int after exact JSON
projection decoding before invoking the shipping encoder.

Verification rejects mismatched app/seed/gate pins, missing or extra commands,
repeated submissions, changed original secrets, missing/extra/duplicate/conflicting
business records, altered host/category/body/attributes, and absent accepted
request evidence. HTTP200 or hashes alone never pass. Primitive verification
also requires real publication/access of both server secrets and decoded metrics.

Success emits only strict JSON: `schema`, `gate`, `application_sha256`, `phase`
(`primitive-only` or `post-activation`), `secret_publication` (false for unchanged
cache), `secret_preservation`, `fleet_uncertainty`, `otlp_decoding`,
`ordinary_telemetry:false`, `evidence_sha256`, `records`, and `metrics`. A primitive
result cannot satisfy the installed gate. The result proves the bounded private
remote evidence against the pinned projection; installed traffic, SQL extraction,
controller enrollment and actual service/rollback gates remain separate required
execution evidence.
