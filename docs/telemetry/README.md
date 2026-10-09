# Daemon telemetry and durable DDOT delivery

`internal/telemetry` supplies OTel SDK providers, the structured logrus bridge,
safe HTTP/job wrappers, neutral measurements, local display enrichment and the
shared outbox worker. Task 9 owns wiring these into `serve` and its scheduler;
this package does not install a second global provider or change policy decisions.

## Runtime integration

- Call `telemetry.Initialize` once with typed `config.Telemetry`, executable
  version, instance, environment and canonical hostname, plus local log output.
  A second initialization fails. Use the returned logger with `WithContext`.
  Log machine event names and structured `operation`, `outcome`, `error_class`,
  `backend` fields; unknown fields/raw messages are filtered before local output
  and the `otellogrus` bridge. Never pass bodies, tokens, DSNs or raw errors.
- Ordinary `endpoint` is an OTLP base URL: HTTP appends `/v1/logs`, `/v1/traces`,
  `/v1/metrics`; gRPC is also supported. TLS is verified; plaintext requires
  numeric loopback. Credential-file values become bearer headers. SDK queues,
  export deadlines, metric cardinality and shutdown time are bounded. Exporter
  errors increment a counter instead of recursively logging through the exporter.
- `SDK.Handler(operation, handler)` excludes health probes and accepts only W3C
  trace context, never baggage as authority. `HTTPTransport` excludes URL/body/
  headers/errors and removes baggage. `SDK.Job(ctx, operation, links, fn)` creates
  bounded operation spans; use links for deferred accounting work. The trace API
  remains available for safe explicit instrumentation. Sampling never controls
  the independent business worker.
- Construct `otlp.NewHTTP` from `business_endpoint` (default
  `http://127.0.0.1:4319`), timeout and, if remote, verified TLS/bearer material.
  Construct `telemetry.Outbox` with the Task 3 Store, unique worker owner,
  transport, optional `NewDisplay(config, snapshots, metadata)` and timeout.
  Both nodes may call `One`. It claims existing atomic ledger work, persists
  StartAttempt before network I/O, checks remaining lease, sends once, then
  persists a bounded receipt even when the caller cancels. An uncertain Start
  never permits I/O. Failure to finish leaves started work for expiry quarantine.
  There is no automatic retry/republication/reconciliation or payload deletion.
- `postgres.ObserveDelivery` queries actual active sessions, pending intake,
  quarantine records, pending/leased/started business outbox and oldest age.
  `UsageAge` is time since the last usage work item was created (processing
  freshness). Nil ages mean unavailable/no observations, never fabricated zero.
  Poll independently of auth and report errors as unavailable measurements.
- `Measurements.ObserveComponent(ctx, name, component, value)` is required for
  `backend.up` / `backend.uptime` (components `freeradius`, `step-ca`, `postgres`,
  `collector`) and `job.age` (`inventory`, `certificates`, `sites`, `sources`,
  `accounting`, `usage`, `outbox`, `metrics`). Each category has its own series.
  Unknown names/labels, negative or nonfinite values are omitted. Do not record
  fabricated values for unavailable components. `Observe` cannot create unlabeled
  versions of these component gauges.
- `Measurements.Observe` accepts only the other named instruments below; Retry bounds
  its backend labels. Durations/concurrency, Go heap/GC/goroutines/process uptime
  and export errors are measured directly. The scheduler supplies real backend
  process uptime/status, native spool metadata, source/inventory freshness and
  ledger observations. VM uptime is not backend uptime. Task 6 `ObserveSpool`
  needs only its separate metadata group; never read accounting bytes. Native
  write/replay failures require real native observations, otherwise omit them.

Instruments use the `cloud8021x.` prefix: `process.uptime`, `process.heap`,
`process.goroutines`, `process.gc`, `telemetry.errors`, `operation.duration`,
`operation.active`, `api.retries`, `backend.up`, `backend.uptime`, `spool.files`,
`spool.bytes`, `spool.oldest_age`, `spool.free_bytes`, `native.write_failures`,
`native.replay_failures`, `inventory.age`, `source.age`, `ledger.sessions`,
`ledger.intake`, `ledger.quarantine`, `outbox.depth`, `outbox.oldest_age`,
`usage.age`, `job.age`, `claim.errors`, `export.errors`. Observation gauges are
not initialized to success. Owner/device/site names are never metric labels.

## Business event and dashboard contract

Domain payloads remain vendor-neutral. The adapter projects known fields from
`auth.Event`, `accounting.Event` and `accounting.Interval`. Auth emits only final
Access-Accept/Reject; accounting emits Acct-Start/Update/Stop; intervals emit
Acct-Usage. Stable event/usage IDs, source/NAS/station/session, original receipt,
verified identity/fingerprint/VLAN and local owner/site/AP/VLAN metadata survive.
`network.metadata_max_age` independently bounds site/AP/VLAN display cache age:
its default is 1h and accepted range is greater than zero through 24h. Both final
native-auth enrichment and `NewDisplay` use it; inventory display still uses
`policy.inventory_max_age`, while source authorization uses discovery freshness.
Task 9 must pass this independent field to any network cache display resolution.
Unavailable display values are `N/A`. Raw Class, certificates and credentials do
not enter OTLP. Mutable cache metadata cannot change signed device/VLAN authority.

Each business record gets its own OTLP ResourceLogs containing its original
`host.name` and `business.category`. Collector resource-context transformation
maps categories to `radius-auth`, `radius-acct`, `radius-usage`. This prevents a
mixed batch from sharing a last-record service/host; the export worker is never
substituted for the original native producer. Ordinary process resources use
`cloud-8021x` and the worker's canonical hostname.

Auth payloads additionally retain cached display Serial; absent legacy serial is N/A.
Intervals now additionally retain Host, Location, CalledStation and NASPort from
the producing accounting event. These JSON additions do not change semantic
usage IDs, counters, signed attribution or dedup. Legacy payloads remain immutable;
missing host becomes `N/A`, never the worker host. No old payload is rewritten or
republished. An imported legacy interval cannot invent absent original metadata.

Accounting Stop events additionally project `terminate_cause` for the existing
stop-reason widget. Migration 003 appends optional raw value and occurrence count;
native detail already retains `Acct-Terminate-Cause`, and native SQL now records
its dictionary-expanded string with native escaping. Normalization accepts the
installed standard RFC2866/RFC3580 names (values 1–22). Absent, duplicated or
unknown values become `N/A`, as do absent legacy JSON fields. This is display-only:
event/usage IDs, counters, signed attribution, deduplication and existing immutable
payloads do not change. A retransmission with richer metadata cannot rewrite or
republish an existing observation. Task 10 must migrate to schema 3 before enabling
the new native SQL template. No native dictionary/package patch or Go accounting
spool reader is introduced. [Native Stop proof](evidence/termination-native.json)
and the `--native-mode termination` fixture gate cover the actual path.

Fields are scalar OTLP log attributes, not a nested attributes map in the body.
The JSON body retains exact decimal uint64 literals. Numeric counter attributes
support existing dashboard measures; values above int64 use an approximate double.
Every counter also has a decimal-string `*_exact` attribute. The ledger and raw
JSON/exact strings preserve `18446744073709551615`; dashboards cannot represent
all uint64 values exactly. Datadog's [mapping implementation at the tested release](https://github.com/DataDog/datadog-agent/blob/7.82.0/pkg/opentelemetry-mapping-go/otlp/logs/transform.go)
projects scalar log attributes to top-level additional properties, and maps
resource service/hostname. Actual DDOT outbound protobuf tests assert mixed
categories, host, all dashboard facets, numeric/exact counters and JSON body.
The recommended [OTLP Collector setup](https://docs.datadoghq.com/opentelemetry/setup/collector_exporter/)
uses resource service/host semantics for direct OTLP intake. We did not call a real
Datadog intake, query logs or change remote processing; tenant-side indexing and
custom remappers remain an installation acceptance check, not a claim made by the
fake sink. Existing dashboard queries/service names are unchanged. The usage
note explicitly says downstream sums can include duplicate exported intervals.

## DDOT edge and installation ownership (Tasks 8/10)

Render `ddot.Options{QueueDirectory, QueueBytes, LogsEndpoint, Site}`. For Campus,
use `Site: "us5.datadoghq.com"` and
`LogsEndpoint: "https://otlp.us5.datadoghq.com/v1/logs"`. The exact US5 endpoint
comes from the official [logs intake page's site selector](https://docs.datadoghq.com/opentelemetry/setup/otlp_ingest/logs/?site=us5),
not an inferred US1 hostname; the selector asset/provenance is in the evidence
manifest. HTTP protobuf and `dd-api-key` are required. Inject DD_API_KEY from the
existing protected Agent credential path; never put a real key in application YAML.
The generic daemon only sees OTLP, not a Datadog SDK or key.

Use **Agent 7.82.0-full**, not the default image, for this tested artifact. The
actual default 7.82.0 arm64 and amd64 images lacked `otel-agent`, despite broad
installation wording in upstream docs. The tested full arm64 image includes
DDOT/Collector 0.155.0 (stable components 1.61.0), Go 1.26.5, commit ffd5b575990.
Full image index/platform digests, binary digest and authenticated registry source
are recorded in `evidence/provenance.json`. Registry TLS + content digests were
verified; no independent release signature claim is made. The amd64 full digest
is resolved but not executed here. A Debian package is not equivalent evidence:
Task10 must install the tested full artifact or validate its selected exact package
and target architecture before deployment. Do not substitute a default artifact
without the collector.

Merge `ddot.AgentFragment` into existing Agent config, preserving canonical host,
US5 site, host/integration and FreeRADIUS checks. Explicit exporter site is required:
the converter can retain an exporter's US1 default even when core Agent site is
US5. Restrict converter features to ddflare; it must not replace original producer
metadata. Local app output/final-auth records must not also be remotely tailed.
No filelog/journald receiver is installed. The separate native accounting detail
remains for native replay, not remote log collection. Keep DDOT local listeners
and flare on loopback and protect credentials/config/storage ownership.

Business receiver 4319 has a 1 MiB request limit and no volatile batch processor.
Its `otlp_http/business` exporter has fsync file_storage, a byte-sized queue,
nonblocking failed overflow, two consumers, 10s network timeout, unlimited retry
elapsed time and bounded 1s–30s retry intervals. Use a 64 MiB queue on a dedicated
persistent filesystem with a 512 MiB quota and monitor free bytes; queue capacity
alone does not cap bbolt file growth/temporary compaction. Set a service memory
limit appropriate to the Agent/ordinary pipelines (fixture used 768 MiB). Task8/10
owns enforcing filesystem quota, service resource limits and monitoring. ENOSPC
is tested as an actual failed handoff. Do not put a batch processor before the
persistent queue. Ordinary logs/traces/metrics use batch and datadog/ordinary.

The stock DDOT datadog logs exporter is intentionally excluded from business
work: its [factory](https://github.com/DataDog/datadog-agent/blob/7.82.0/comp/otelcol/otlp/components/exporter/logsagentexporter/factory.go)
uses default retry settings, and its [consumer](https://github.com/DataDog/datadog-agent/blob/7.82.0/comp/otelcol/otlp/components/exporter/logsagentexporter/logs_exporter.go)
returns after handing records to an Agent in-memory channel. A queue there does
not keep entries until the remote intake responds. The dedicated OTLP HTTP
exporter maintains the required persistent retry boundary.

## Delivery and recovery limits

Collector ACK means durable local queue handoff, not exactly-once remote intake.
A downstream lost response can duplicate accepted records. Partial success or
lost response at the daemon hop quarantines the entire attempted payload and
retains its receipt/history, with no automatic resend. Collector downstream
permanent rejection/partial acceptance can still lose rejected records after ACK;
monitor collector failures and reconcile from the retained ledger. Local queue
disk/host loss after ACK is not covered by PostgreSQL replication. SIGKILL tests
prove process-crash retention, not power-loss or disk-loss survival.

Retain exported payloads/attempts/receipts for **at least 30 days**, and uncertain/
partial work until explicitly resolved. Current code deletes none. Task9 owns a
reviewed retention/recovery command; explicit republishing must disclose possible
downstream duplicates and use separate audited evidence. Exact usage totals come
from the shared PostgreSQL ledger, never a Datadog aggregate sum/readback.

## Reproducible verification

```
go test -race ./...
scripts/test_telemetry_postgres.sh
# Prepared, labeled disposable native fixture with matched campus3 packages and synthetic TLS PG:
python3 tests/radius_integration.py --native --container "$TASK7_NATIVE_FIXTURE" --native-mode termination
python3 tests/ddot_queue.py --packages "$VERIFIED_MONITORING_OUTPUT" --architecture arm64 --evidence /private/tmp/task7-ddot-proof --full-config
python3 tests/ddot_queue.py --packages "$VERIFIED_MONITORING_OUTPUT" --architecture arm64 --evidence /private/tmp/task7-ddot-full-proof --storage-full
golangci-lint run
```

The PG runner generates TLS/synthetic roles in its own network-none PostgreSQL 16
container, runs a Linux test binary, and exposes no host port. Its integration
binary is not race-instrumented when cross-compiled from macOS; the full native
root suite is race-tested separately. The DDOT runner uses its own labeled
network-none container, synthetic keys, loopback fake sink and no host ports.
It validates actual converter output (including complete ordinary configuration),
503 retries, SIGKILL, restart without daemon resend, overflow 503, actual protobuf
projection, and a separate 64 KiB ENOSPC filesystem with 10 MiB queue capacity.
All runners remove only their own fixtures. Task6 retained fixtures are untouched.

The reviewable `daemon-dashboard.json` supplements the retained business-log
widgets. Import it explicitly through the normal dashboard delivery workflow;
these tests do not publish it. Every shared ledger/outbox gauge is `max` grouped
by the protected transition's `cluster`, with `scope:shared`; summing the two node
reporters would double-count. Local auth/spool/source/inventory gauges stay per
host. Missing samples remain unavailable. Auth file thresholds are 2048 soft,
3584 critical, and 4096 reader bound: capacity is not an instruction to discard
files or restart native authentication.

### Protected host Agent lifecycle

The protected installer now writes the core `datadog-agent.service` as well as
its credential drop-in and the separate DDOT unit. Minimal rebuilt packages have
no maintainer-script service activation; a fresh node therefore does not depend
on a previously installed vendor unit. The core Agent runs as `dd-agent` with
read-only system paths, no capabilities, and its existing private
`/opt/datadog-agent/run` directory as the writable IPC location. Core Agent and
DDOT share the token and IPC certificate paths there. Their diagnostics go to
stdout/journald instead of assuming a writable vendor log directory. Remote
configuration is disabled so it cannot change the reviewed local pipeline.
Ordinary host check configuration, host identity and tags remain preserved.

The unit and configuration regressions pass with the minimal artifact interface;
actual final-package service/ownership acceptance is still a separate shipping
gate. The historical 7.82 fixture evidence above is not a security approval for
shipping that old binary.
