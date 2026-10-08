# Unified Go daemon and buffered accounting

Date: 2026-10-08
Status: Proposed architecture for issue #30; implementation pending design review.
Base: PR #38, `codex/accounting-dashboard-draft`.

## Outcome and scope

Replace the server-side Bash/Python application helpers, including Python emitted by Bash, with one versioned `cloud-8021x` Go executable. Use Cobra commands, typed YAML configuration, structured logrus logging, and OpenTelemetry. The long-running daemon owns routine collection, local policy decisions, enrichment, accounting processing, and export. Small privileged invocations of the same executable own installation, protected configuration, certificate operations, and service activation.

Retain FreeRADIUS for RADIUS/EAP-TLS, step-ca for ACME/SCEP/CA operations, and Datadog as the observability destination. Remove all Okta CA and Jamf support as explicitly requested; Fleet is the supported built-in inventory integration. Preserve their current production behavior and identity/security contracts. Do not implement replacement RADIUS or CA servers in this PR. Put the existing integrations behind narrow interfaces so those implementations can change later without changing policy or accounting code.

Consume accounting locally instead of reading it back from Datadog. Application telemetry uses OpenTelemetry APIs and OTLP, including tracing and structured logging for the Go application itself. Use the Datadog Distribution of OpenTelemetry (DDOT) Collector as the preferred local export pipeline; Datadog credentials and mappings belong at the export edge. An optional Datadog SDK integration is permitted behind the telemetry adapter when it supplies a required capability, without coupling policy/accounting code to Datadog. This PR does not deploy production or authorize a Fleet GitOps apply.

## Selected approach and alternatives

Use a Go daemon with a bounded local FreeRADIUS REST adapter, native FreeRADIUS detail buffering/replay, a transactional local ledger, and OTLP export. This keeps protocol handling in the mature existing servers while removing application-code generation and Python runtime dependencies.

An incremental wrapper around the existing Python jobs would be smaller initially but would retain the maintenance problem and duplicate runtime/configuration layers. Replacing FreeRADIUS and step-ca now would greatly expand the protocol, issuance, security, and interoperability scope. Neither alternative meets the requested scope as well as the selected approach.

Commit the migration in independently testable stages within the new PR. Temporary compatibility adapters are acceptable during development; the final enabled runtime must not require the retired server-side Python helpers. Development parity fixtures can retain Python until equivalent coverage is established. The Windows-side PowerShell certificate collector remains because it accesses Windows certificate stores.

## Executable and package boundaries

Move the existing webhook Go implementation into the root application module and reuse its tested authorization, Fleet, challenge, broker, TLS, and configuration behavior. Keep dashboard development tooling separate. Thin Cobra commands call reusable packages:

- `serve`: run policy, webhook/broker listeners, inventory/site schedules, accounting ingestion, peer forwarding, usage processing, and telemetry workers.
- `bootstrap`: install packages and embedded templates, adopt or initialize CA state, validate and activate services.
- `config validate`: validate typed, versioned configuration without side effects.
- `inventory sync`, `sites sync`, `metrics emit`: one-shot operations for diagnostics and compatibility.
- `certificates renew`: privileged certificate validation and renewal.
- `radius verify-leaf`: consume the FreeRADIUS TLS-verified certificate file and create the private single-use identity handoff.
- `sources apply`: privileged application of a validated discovery candidate to fixed configuration/firewall resources.
- `state migrate`, `doctor`, and existing operator/profile-generation commands: explicit migration, diagnostics, and operational compatibility.

All mutating commands support meaningful `--dry-run`; all commands support `--debug` and cancellation. Dry-run performs validation and reports planned actions with secret references only. It does not submit MDM commands, issue certificates, change remote infrastructure, consume live handoffs, or advance durable accounting state.

Packages separate domain policy, certificate identity, immutable inventory snapshots, accounting/Class verification, durable state, telemetry, configuration, and adapters for Fleet, UniFi, Meraki, FreeRADIUS, and step-ca. Fleet host IDs are opaque adapter IDs such as `fleet:428`; domain policy does not depend on Fleet API objects.

FreeRADIUS adapters decode raw attributes into a typed, RADIUS-neutral `AccountingEvent`. Class verification, durable intake, session processing, and telemetry consume this type rather than FreeRADIUS attribute maps. Preserve trusted receipt/source context and exact counters in this conversion.

The domain authorizer takes a `VerifiedCertificate` and `TrustedNetworkContext`, returning an opaque device identity and an optional VLAN decision. Only an adapter that has validated the certificate boundary can construct a verified input. Accounting bindings cannot construct one. A CA backend exposes the issuance/renewal and readiness operations actually used by this application; a RADIUS backend exposes configuration validation, activation, and health. Avoid a generic plugin framework or interfaces that attempt to abstract every feature of either server.

## Pluggable device and network inventory

Define separate Go interfaces for device inventory and network inventory. Select and construct implementations from typed YAML configuration at the application boundary, and inject them into synchronization/enrichment services. Start with Fleet for device inventory and UniFi and Meraki for network inventory. Adding a provider must not require changes to the authorizer, accounting processor, or telemetry event types. This is interface-based extensibility within the binary; runtime-loaded shared-library plugins are unnecessary.

`DeviceInventoryProvider` fetches a vendor-neutral `DeviceSnapshot` containing opaque namespaced device IDs, enrollment state, group memberships, hardware identifiers where available, owner/device display metadata, and their observation/provenance timestamps. The snapshot contract identifies the requested scope and successful completeness. Failed or incomplete pagination cannot replace a complete authorization snapshot or freshen its timestamps. Normalized groups and device IDs keep provider namespaces to prevent collisions. Vendor API objects, host IDs, credentials, pagination, rate limits, and response caches remain inside the adapter.

Keep optional managed-certificate collection behind a separate `ManagedCertificateProvider` capability, implemented initially by Fleet. Inventory-only providers need not implement MDM commands, scripts, or certificate delivery. Certificate collection retains exact DER fingerprint provenance, original observation times, authenticated host/result binding, existing minimum polling scope, and durable pending-command handling. An adapter without this capability cannot silently supply unverified certificate bindings or bypass fingerprint policy. Fleet SCEP/profile delivery and challenge operations remain distinct adapter capabilities rather than mandatory methods on every device inventory provider.

`NetworkInventoryProvider` fetches a vendor-neutral `NetworkSnapshot` for a configured controller/site scope: sites, authenticators (APs and supported switches/ports), MAC/identifier mappings, VLAN IDs/names, and source-discovery candidates where supported. Return provider-namespaced stable IDs, configured scope, per-scope success/freshness, and explicit unsupported-capability results. Distinguish unsupported data from an empty successful inventory or a failed API request; do not erase cached metadata or freshen a failed scope. Use a separate optional source-discovery capability so providers that supply metadata but cannot discover WAN addresses remain usable.

UniFi and Meraki normalize their data into these shared types. The metadata consumer resolves AP/switch/site/VLAN display information without branching on vendor names. Scope mappings associate configured policy locations with provider/site IDs, so equal VLAN numbers or authenticator names at different sites/providers cannot collide. No device owner or VLAN display name is an authorization credential.

Source-discovery output is a candidate for the existing validated privileged source-application path. Inventory data alone does not authenticate a RADIUS packet or authorize arbitrary client/firewall changes. Static configured clients/CIDRs remain usable independently of provider outages; trusted policy location still comes from the authenticated configured RADIUS client.

Contract-test every built-in provider against the same normalized interface semantics, including complete pagination, cancellation, rate limiting, stale/partial refreshes, missing optional capabilities, identifier collisions, and scoped VLAN/AP names. Add a fake device provider and fake network provider to prove that policy/enrichment/accounting consume shared types and do not require Fleet, UniFi, or Meraki clients. Keep provider selection and secrets in configuration, with no vendor-specific fields in domain policy.

## Configuration, templates, and privileges

Terraform supplies a versioned, non-secret YAML document and secret references rather than application-code heredocs. CLI flags override explicitly supported configuration fields. Reject unsupported versions, unknown security-sensitive fields, ambiguous site mappings, invalid VLANs, and missing required secret references. Render YAML/JSON with serializers and bundle reviewed FreeRADIUS, Collector, and systemd templates using `go:embed`.

Run `serve` as a dedicated application user, separate from `freerad` and root. The daemon has private runtime credentials for its existing API scopes and local listeners; it cannot read CA private keys or change services/firewall configuration. Root invocations obtain protected secrets and perform fixed, validated operations. The daemon's source-discovery candidate contains data, never executable commands or arbitrary paths.

Block the unprivileged daemon from obtaining the VM service account's privileged metadata credentials; UID separation alone is insufficient on GCP. Provision credentials into protected runtime files and verify the metadata network restriction against supported endpoint/address variants. Do not give the daemon a general-purpose root proxy. Keep observer inventory and maintainer certificate-collection clients distinct, including the current host-scope intersection.

Write candidates on the destination filesystem, validate before activation, preserve a last-known-good copy, and atomically replace files. Activation failures restore prior configuration. Root-only keys remain root-only; shared runtime files have the minimum ownership required by their consumers. Secrets and certificate private keys never appear in plans, debug logs, traces, or error bodies.

The remaining startup script only downloads a pinned artifact, verifies its mandatory SHA-256 checksum, and invokes bootstrap. Retain compatible command/release aliases for the existing webhook during transition. No unchecked download fallback. Config/state schema versions and executable version are recorded independently.

## Authorization and local FreeRADIUS adapter

Move the existing policy semantics into Go and compare them against current fixtures. Authentication reads validated local snapshots; it never waits for Fleet, UniFi, Meraki, Datadog, or a CA API. Background failures preserve the last valid snapshot and its original freshness timestamps.

Certificate identity is the SHA-256 of the TLS-verified leaf DER. Never authenticate using an arbitrary request fingerprint, username, CN, NAS field, or accounting Class. Preserve the attested ACME exception only when the pinned issuer, certificate chain/purpose/validity, provisioner extension, permanent identifier, and serial constraints all pass existing checks. Invalid attestation recognition falls back to exact fingerprint binding.

Keep the small verified-leaf hook at completed TLS verification. It creates the existing private, single-use handoff with exclusive creation, restrictive permissions, replay/expiry checks, no symlink following, and unlink-before-use semantics. Keep compatibility with the existing handoff schema and paths during transition. Do not launch a child process for each EAP packet.

Use authenticated loopback HTTP for the initial `rlm_rest` integration, with a private local token file and separate endpoints for authorization, auth events, and accounting. Do not expose these listeners publicly. A Unix socket can replace transport later if the selected FreeRADIUS build supports it and integration tests verify it. Authentication uses a bounded request body, concurrency limit, and deadline; invalid credentials, malformed responses, unavailable/overloaded daemon, or expired handoffs fail closed before EAP-Success/MPPE. Accounting/export workers have separate resource limits. Configure accounting `rlm_rest` without `connect_uri` precaching or startup pool connections so daemon reachability is not required for FreeRADIUS startup.

Certificate mode continues to disable TLS resumption when the exact leaf identity cannot be restored. Legacy resumed sessions still recheck current enrollment/inventory policy. Unknown, ambiguous, unenrolled, or stale identities deny. Inventory freshness and certificate observation freshness are independent; refreshing inventory cannot refresh a certificate observation.

Trusted location comes from the authenticated configured RADIUS client, stored as server-controlled context. Untrusted NAS identifiers, IP attributes, or certificate names cannot select a site. Preserve explicit site opt-out, conflicting-rule rejection, fallback semantics, and VLAN range 1–4094. Enabled assignments send exactly Tunnel-Type 13, Tunnel-Medium-Type 6, and the decimal Tunnel-Private-Group-Id. Opt-out omits tunnel attributes while retaining full authorization and signed accounting identity.

## Buffered accounting and acknowledgment

Use FreeRADIUS's native detail module and buffered detail virtual server to manage disk spool rotation, progress, and replay. Its replay calls the Go adapter; the Go daemon owns the durable inbox, validation, attribution, usage computation, and OTLP outbox. This avoids maintaining a second parser/locking protocol for FreeRADIUS detail files.

For each live accounting packet, FreeRADIUS validates the packet/source and overwrites the trusted source, location, and receipt-time fields before writing detail. These values must survive replay: a buffered reader's synthetic client must never replace the original authenticated network context. Configure locking and progress tracking, and test the exact deployed FreeRADIUS version.

The detail writer does not itself establish power-loss durability. Therefore the live accounting path also submits the record to the local Go inbox and sends the NAS Accounting-Response only after a successful durable Go commit. If the local commit fails, suppress the response even if detail buffering succeeded; the NAS can retry/fail over, and native detail replay also retries delivery. Auth processing remains independently available. Replayed records receive HTTP 204 only after commit or successful duplicate recognition. Permanent malformed records are durably quarantined before acknowledgment; disk exhaustion, unavailable storage, and other transient failures are not acknowledged.

Use an embedded bbolt database with synchronous transactional commits and no `NoSync` mode for local inbox/state/outbox. Bound individual payload size and queue capacity, reserve disk space for authentication/configuration, and report backlog size/age and rejected intake. Database files and backups are private. A database version mismatch or corruption stops accounting ingestion without silently recreating an empty store. Backup/restore and compaction are explicit operations.

Give transport deliveries stable IDs for local retry recognition. Semantic deduplication excludes delivery host, retry delay, RADIUS packet ID/authenticator, and processing time. Preserve the existing session identity/collision protections; changing WAN addresses does not justify blindly dropping source identity from the key.

Verify signed Class using the original trusted receipt time, office, station MAC, and retained key material. Preserve the `c8021x.1` wire format and shared accounting key across both servers/upgrades. Class authenticates attribution, not authorization. Missing, duplicate, expired, malformed, wrong-key, cross-site, or wrong-station bindings produce unattributed accounting; they do not fabricate a verified identity. Later inventory changes never rewrite the signed original VLAN. Owner/AP/site/VLAN names are display metadata with bounded caches.

Combine high/low octets using exact unsigned 64-bit arithmetic. Preserve missing/invalid counters and precision uncertainty rather than substituting zero. Keep the current conservative treatment of first mid-session baselines, counter resets, changed precision, old/reordered reports, duplicate stops, and gaps. Interval traffic is credited when the later valid report arrives; it is not reconstructed from missing reports.

## Two-server deduplication and session state

Both RADIUS servers maintain durable local intake. Preserve the current primary-only usage-processing role with one transactional high-water ledger. Secondary forwards its queued records over authenticated private-network mutual TLS; the primary acknowledges only after durable intake. Both servers retain records while the processor is unavailable.

Commit deduplication, session high-water, usage interval, and export outbox together. A process/database lock fences concurrent writers. Do not automatically promote an empty secondary database: transferring the processing role requires stopping/fencing the old writer and moving verified durable state. This preserves correctness during RADIUS failover without introducing a distributed database in this PR. A future shared transactional store can replace this boundary.

Replace MariaDB/radacct-dependent application features with the same durable session ledger once accounting parity is proven. Online-session counts retain explicit stale-session rules. During migration keep the old database untouched and export/import active-session state before removing the SQL module from generated configuration. Do not equate a transport acknowledgment with a billable usage interval.

## Application tracing, logging, OpenTelemetry, and DDOT

Instrument the Go application through OpenTelemetry APIs, with the OpenTelemetry Go SDK and the `otellogrus` bridge as the default provider implementation. Support an optional Datadog SDK adapter if needed; do not install competing global trace providers or duplicate instrumentation. Keep device/owner attributes in logs rather than high-cardinality metric labels. Never record shared secrets, challenges, private keys, bearer credentials, or complete certificate contents. Resource attributes distinguish the two servers and preserve the established canonical production host names.

Export OTLP logs, metrics, and traces through the local DDOT Collector included with the Datadog Agent, using a dedicated accounting pipeline and persistent exporter queue. The generic OTLP endpoint remains configurable so a standard OpenTelemetry Collector can replace DDOT without changing domain packages. Pin and validate the Collector release/configuration, enable `file_storage.fsync=true` and persistent `sending_queue.storage`, bound queue/disk use, and configure retries that do not expire silently. Queue overflow or storage failure must return a failed handoff, never a success acknowledgment. Avoid an in-memory batch stage ahead of accounting's durable queue. Ordinary SDK buffering is not the durable accounting acknowledgment boundary.

The application outbox submits OTLP records synchronously through a vendor-neutral transport interface. Populate stable event/usage IDs and the dashboard's existing structured field semantics. Datadog-specific attribute mapping, credentials, tags, and log routing are confined to Collector/Terraform configuration. Do not put Datadog SDK calls or vendor-specific types in domain packages, and do not use Datadog log-read APIs or credentials for accounting. If a Datadog SDK is selected, contain it in the telemetry adapter and preserve the generic OTel/OTLP mode. Enable DDOT while retaining existing Datadog Agent host/integration checks and canonical hostname attribution; do not collect the same application logs through both file/journal tailing and OTLP.

OTLP acknowledgment confirms the next hop, not end-to-end exactly-once delivery. Disable automatic daemon transport retries for ambiguous outcomes and quarantine them for reconciliation. Collector-to-Datadog export is at least once: its downstream retries can duplicate accepted records even after the daemon receives a successful Collector acknowledgment. The daemon cannot reconcile uncertainty inside that later hop. A lost response can create duplicates; a stable ID alone does not make Datadog aggregate sums deduplicate. Persist daemon export attempts and ambiguous outcomes, and preserve the current conservative reconciliation behavior for that hop. Document downstream aggregate totals as observed telemetry subject to at-least-once export duplicates; exact totals come from the local ledger, not a claim of end-to-end exactly-once log delivery. OTLP partial success with rejected records goes to durable quarantine; do not retry an entire partially accepted batch. Local accounting state is authoritative and downstream delivery health is shown separately. Test actual Collector persistent-queue acknowledgment/crash behavior before relying on it.

Expose neutral metrics for daemon/backend health, FreeRADIUS process uptime, source/inventory ages, queue depth and oldest age, intake/export failures, unattributed records, active sessions, and usage-processing freshness. Dashboard definitions remain Datadog-owned infrastructure; application event/metric contracts remain vendor-neutral.

### Go application instrumentation contract

Initialize telemetry once per process from typed YAML/CLI configuration. Set `service.name=cloud-8021x`, the executable's `service.version`, `service.instance.id`, `deployment.environment.name`, and canonical `host.name`. Configure signal enablement, OTLP endpoint/transport, TLS and credential-file references, export timeouts/queue limits, and trace sampling. Use parent-based configurable ratio sampling for routine traces; do not make required auth/accounting events depend on sampling. Telemetry failures cannot turn an authorization accept into a reject or block its critical path. Durable accounting acknowledgment still depends on its local ledger commit, not successful telemetry export.

Create spans for inbound webhook/broker and local RADIUS requests, outbound adapter HTTP calls, inventory/certificate collection, site/metadata refresh, certificate renewal/bootstrap activation, accounting durable intake, peer forwarding, usage processing, and outbox export. Record bounded operation names, durations, outcome/error classifications, retry counts, and safe backend/site attributes. Record span errors/status where appropriate. Exclude high-frequency health probes by default. Do not record bodies, authorization headers, URL query credentials, SCEP challenges, private keys, or complete certificates. Incoming trace context is only correlation metadata and cannot supply trusted identity, location, or policy inputs; avoid propagating arbitrary baggage.

Propagate request/job context through Go calls. Use span links for deferred accounting/replay work instead of leaving request spans open while records wait on disk. Trace identifiers are auxiliary metadata and never participate in semantic accounting deduplication or usage calculation.

Keep structured logrus output available locally for systemd/operator diagnosis and bridge it to OTel log records. Attach the active trace/span context to logs, with consistent severity, operation, outcome, and error-class fields so Datadog can correlate logs with traces. Business events retain existing dashboard metadata, while operational logs avoid unnecessary owner/device details and high-cardinality metric attributes. Maintain exactly one remote collection path for each record; local output is not also remotely tailed when bridged logs are exported.

Measure Go runtime/process health and daemon work: uptime, heap/GC/goroutines, request duration/error/concurrency, API retry/rate-limit outcomes, background job latency/freshness, ledger/inbox/outbox backlog, and exporter failures. Use bounded labels. Export ordinary application telemetry asynchronously with bounded queues and cancellation; retain local fallback logging, avoid recursive logging on exporter errors, and flush providers with a bounded shutdown deadline. SIGTERM stops new jobs/intake cleanly and never deletes pending durable state.

Test traces, logs, and metrics with in-memory OTel providers and a fake OTLP receiver: correlation, resource attributes, sampling independence of business events, secret redaction, cancellation/shutdown, nonblocking exporter failure, and duplicate remote collection prevention. Validate pinned DDOT configuration and crash/restart accounting queue behavior in a disposable integration environment; merely accepting OTLP in a receiver is not proof of durable forwarding.

## Removal of Okta CA and Jamf support

Remove Okta/dual client-trust modes, Okta CA configuration variables and runtime fetches, Jamf OAuth/inventory clients, related IAM grants, generated helpers, profile examples, operator options, and documentation describing these integrations as supported. Update defaults to the supported Smallstep deployment and Fleet enrichment. Keep serial-based Smallstep/ACME compatibility where it is still required; removing vendors does not mean removing the serial path or its current resumption checks.

Reject obsolete vendor settings with an actionable migration error rather than silently ignoring them. Bootstrap preflight refuses to activate on an Okta-dependent deployment; this PR does not automatically migrate client trust roots or reissue deployed device certificates. Retain old secrets and CA material outside active support for explicit rollback. When removing Terraform-managed secret resources, use a reviewed state-removal migration that leaves the actual secrets intact instead of scheduling their destruction.

## State, CA compatibility, and rollback

Import existing inventory, pending Fleet command reservations/results, discovery state, display metadata, accounting Class keys, downgrade guard, and PR #38 usage tracker/checkpoint state. Preserve original timestamps, ambiguities, precision flags, terminal sessions, and pending/ambiguous export batches. Stop and fence the old collector before importing. A Datadog read checkpoint is not a detail-spool cursor: spool progress starts separately, with overlap handled against imported session high-water state. Do not replay ambiguous legacy export batches automatically or invent unrecoverable historical traffic.

Adopt existing CA material before considering initialization. Distinguish a missing enabled secret version from an error reading an existing version. An API outage must never cause a replacement CA. Preserve KMS signers, EC/RSA root/intermediate certificates, SCEP decryption keys, CA databases, and readiness-marker ordering. Intentionally deleted root private keys remain deleted. Adopt the existing Smallstep server certificate cache and validate chain, key match, ownership, permissions, and FreeRADIUS configuration before renewal activation. Preserve obsolete certificate secrets as rollback data; do not retain an Okta or self-signed CA issuance/renewal path in the new runtime.

Preserve ACME attestation, SCEP challenge versions/lifetimes, Fleet-compatible NDES responses, webhook/broker mutual TLS and DNS identities, renewal metadata, and device-side certificate/profile behavior. Existing ACME devices retain their certificates. No increase in periodic device polling: keep the current minimum SCEP/BYOD collection scope and pending-command deduplication.

Discovery preserves static-site availability, unique secrets, overlap checks, bounded stale state, and scoped firewall mutation. Publish discovery freshness only after validated FreeRADIUS configuration and per-node firewall changes converge. A failed API refresh does not refresh stale metadata timestamps.

Before activation take validated backups and retain the prior executable/configuration. Rollback preserves keys, inventory command state, fingerprint downgrade marker, CA databases, and queued accounting. Maintain a legacy-compatible snapshot/usage-checkpoint export for rollback of the accounting processor; stop/fence processing before exporting it. Never run old and new usage writers together. Native spool files remain pending until acknowledged. A production rollout requires a separate approval and one-server-at-a-time restart with actual failover/authentication checks.

## Validation and completion criteria

Establish the current unit/integration baseline first. Build parity fixtures before replacing each helper. Unit tests cover typed config, secret redaction, atomic activation/recovery, cache migration, pagination completeness, collector scope, signed Class compatibility, exact counters, session deduplication, and retained state.

Run real FreeRADIUS EAP-TLS tests for verified-leaf spoof/replay/symlink defenses, enrollment/freshness/ambiguity rejection, valid and invalid attestation, legacy resumption, BYOD fingerprint mode, conflicts, source discovery, site opt-out, and exact VLAN attributes. Test REST failure/overload/authentication/malformed responses before EAP success.

Run accounting Start/Interim/Stop and cross-server retries through the real detail/replay path. Interrupt the daemon, buffered reader, processor, and Collector around commit/ack boundaries. Cover queue/disk full, crash/restart, duplicates, reordered reports, resets, delayed Class validity, quarantine, partial OTLP success, and ambiguous responses. Verify emitted field/metric contracts against the dashboard fixtures without reading Datadog in the usage path.

Run CA adoption, issuance, renewal, broker/webhook, and generated config integration suites. Format Go with goimports and run golangci-lint, race-enabled tests, dependency vulnerability checks, release checks, and Terraform validation. Document any environment-dependent checks not run. Production and platform pilot verification are rollout gates, not claims made from unit tests.

The PR is ready for implementation review only when the runtime migration, templates, state/rollback tooling, release pinning, examples, operator docs, and meaningful tests are complete. A design-only draft does not complete issue #30.

## Source references

- [Issue #30](https://github.com/CampusTech/cloud-8021x/issues/30): migration requirements.
- [FreeRADIUS buffered virtual server](https://raw.githubusercontent.com/FreeRADIUS/freeradius-server/release_3_2_8/raddb/sites-available/buffered-sql): native detail replay model.
- [FreeRADIUS detail implementation](https://raw.githubusercontent.com/FreeRADIUS/freeradius-server/v3.2.x/src/modules/rlm_detail/rlm_detail.c): detail write/close behavior; the durable acknowledgment rule above is our design requirement.
- [bbolt](https://github.com/etcd-io/bbolt): embedded transactional storage.
- [OpenTelemetry Collector resiliency](https://opentelemetry.io/docs/collector/resiliency/): persistent queues, retries, and remaining loss conditions.
- [DDOT Collector](https://docs.datadoghq.com/opentelemetry/setup/ddot_collector/): preferred local OTel/Datadog pipeline and included components.
- [OTel Go instrumentation](https://opentelemetry.io/docs/languages/go/instrumentation/) and [otellogrus](https://pkg.go.dev/go.opentelemetry.io/contrib/bridges/otellogrus): application providers and structured logging bridge.
- [OTLP specification](https://opentelemetry.io/docs/specs/otlp/): transport and partial-success semantics.
