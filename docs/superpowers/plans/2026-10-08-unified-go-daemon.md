# Unified Go daemon implementation plan

Goal: Deliver issue #30 completely in PR #39, replacing server-side Bash/Python with one Go executable while retaining FreeRADIUS, step-ca, and Datadog.
Architecture: An unprivileged daemon uses immutable policy/inventory snapshots, pluggable device/network providers, synchronous local RADIUS authorization, shared HA PostgreSQL accounting/state, and OTLP export. Privileged subcommands manage fixed templates, CA adoption/renewal, and activation. Native FreeRADIUS detail replay writes accounting into PostgreSQL.
Tech Stack: Go 1.27.1, Cobra, logrus, YAML, pgx, OpenTelemetry, FreeRADIUS 3, step-ca, PostgreSQL 16, Terraform, DDOT.
Spec: docs/superpowers/specs/2026-10-08-unified-go-daemon-design.md
Review Focus: Authentication trust boundaries, freshness, Class/counter parity, cross-server concurrency, safe CA adoption, durable export uncertainty, executable/config migration.

## Global Constraints

- Everything is committed and pushed to codex/unified-go-daemon / PR #39. No production operations, Fleet apply, merge, or release publication.
- Keep FreeRADIUS, step-ca, Datadog. Remove active Okta/Jamf support. Preserve existing deployed Smallstep certificates, keys, CA databases and legacy serial compatibility.
- Authorization is synchronous local REST and uses TLS-verified leaf identity with single-use handoff. Accounting uses native detail buffering/replay to PostgreSQL, never REST and never Datadog readback. Native final-auth logs have a separate Go reader.
- Use opaque device/group IDs and provider-neutral domain types. Auth location is selected by authenticated configured RADIUS client, never packet NAS fields. UniFi/Meraki numeric VLAN reply is exactly 13/6/decimal string. Wired remains off; site opt-outs remain.
- Reuse existing regional HA PostgreSQL, separate database/roles, verified TLS, bounded pools; preserve step-ca capacity. All authoritative mutable state is shared PostgreSQL. Preserve original cert observation timestamps.
- No public policy listener or live vendor requests in policy decisions. No remote secret values in logs/plans. Block daemon metadata credential access.
- Test first for new behavior and bugs, retain meaningful parity fixtures; goimports and golangci-lint before Go commits; test/race/integration evidence before completion claims.
- During development legacy helpers may remain; final enabled runtime must not depend on them. Windows PowerShell and development tests may remain. No placeholder subcommands or permanently disabled replacement features.

## Task 1: Root executable and validated configuration

Files: root go.mod/go.sum, cmd/cloud-8021x, internal/app, internal/config, moved internal/webhook packages, examples/cloud-8021x.yaml; existing webhook compatibility entrypoint.

- [x] Add failing CLI/config tests for strict versioned YAML, unknown fields, bounds, secret-file references, debug/meaningful dry-run, flags overriding config, cancellation.
- [x] Move/reuse existing tested webhook code into root module under internal/webhook; preserve old executable alias and existing challenge commands/listener behavior through reusable app package. Update imports/harness module paths without replacing tested protocol logic.
- [x] Define typed application config for listeners, inventory/policy/network scopes, PostgreSQL runtime/migration/native-writer refs, telemetry, CA, backend paths, schedules; validate sensitive combinations and reject Okta/Jamf.
- [x] CLI owns construction only; injected services drive commands, later tasks fill real runtime. No pretend-success stubs; unfinished operations return explicit unsupported until their implementation task.
- [x] Run root/webhook compatibility tests, existing SCEP tests, formatting/lint; commit task.

## Task 2: Policy, identity and hardware VLAN encoding

Files: internal/domain, internal/policy, internal/identity, internal/accounting/binding, internal/adapters/network/signaling, internal/adapters/freeradius/policy.

- [x] Port tests/fixtures for inventory v1/v2, enrollment/ambiguity/freshness, group conflicts, site opt-out, fallback, IPv4/CIDR trust and unknown contexts. Establish failures before implementation.
- [x] Implement provider-neutral snapshots/decisions/context, validated numeric standard signaling and protected attribute validation; fake alternate vendor tests prove extensibility.
- [x] Port exact leaf hashing and attested ACME recognition, private one-use handoff (exclusive creation, mode, nofollow/flock/link checks, unlink before validation, age bounds), downgrade guard and bounded authenticated local REST. Preserve legacy serial mode without accepting arbitrary fingerprints.
- [x] Port signed Class byte format, HMAC, MAC/site/time validation, duplicate/hex handling and original receipt timestamps. Preserve key compatibility and conservative missing identity.
- [x] Wire real radius verify-leaf/policy service and unit/parity/race tests; commit.

## Task 3: Shared PostgreSQL state and accounting engine

Files: internal/storage/postgres, internal/accounting, migrations, internal/jobs; database Terraform in later integration task.

- [x] Add failing accounting tests for exact uint64 counters, mid-session baseline, resets, precision changes, reordered/duplicate stops, retry dedup, queued Start before Interim, invalid Class quarantine and unattributed events.
- [x] Add versioned logged PostgreSQL schema: raw intake, immutable observations, sessions, intervals, reservations, auth cursors, outbox/attempts/quarantine/import markers. Runtime/migration/native insert-only grants separate.
- [x] Implement pgx TLS/pools/query bounds, migration advisory lock, transactional work selection/session creation and locks, semantic dedup/high-water/outbox atomicity, uncertainty-safe lookup, bounded retry. No in-memory authoritative state.
- [x] Implement external-work claims with persisted started attempts, leases/generation/fencing; expired started attempts quarantine/reconcile rather than resubmit.
- [x] Exercise disposable PostgreSQL with two workers/crash/connection-loss/race tests, numeric boundaries and role permissions; commit.

## Task 4: Fleet device and managed certificate providers

Files: internal/inventory, internal/adapters/fleet, internal/jobs/inventory, Windows script retained.

- [x] Add provider contract and Fleet fixture tests for full pagination, cancellation/rate limits, incomplete refresh, host scope intersection, minimum polling scope, observed_at independence and pending command/result binding.
- [x] Port Fleet inventory/metadata and existing Apple MDM/Windows SYSTEM certificate collectors, immutable local cache publication and namespaced devices/groups. Keep observer/maintainer credentials separate.
- [x] Coordinate collection/reservations with PostgreSQL; persist submission attempts before remote requests; reconcile uncertain submissions and enforce exact authenticated host/result provenance.
- [x] Wire scheduled and inventory sync commands, fake provider contract proves domain independence. No increase in ACME device polling.
- [x] Run provider/storage/race parity tests; commit.

## Task 5: UniFi/Meraki inventory and source discovery

Files: internal/adapters/unifi, internal/adapters/meraki, internal/network, internal/jobs/network, internal/privileged/sources.

- [x] Add normalized provider tests covering scoped sites/APs/switch ports/VLAN names, hardware-MAC mapping, complete pagination/cancellation/429, unsupported versus empty versus failed scope, collision isolation.
- [x] Port API clients with bounded retries and development disk caches; registry injects inventory and optional VLANSignaler/source-discovery capabilities. No API calls on auth path.
- [x] Port trusted pinned-controller WAN/CIDR discovery candidate validation/static fallback/overlap/TTL, atomic metadata publication retaining successful timestamps.
- [x] Implement fixed privileged sources apply with config validation, FreeRADIUS/firewall convergence before freshness commit, rollback and meaningful dry-run; no generic root command proxy.
- [x] Wire sites sync/schedules, scoped fake provider tests; commit.

## Task 6: Native FreeRADIUS templates and event ingestion

Files: internal/adapters/freeradius, internal/templates/freeradius, internal/events/auth, tests/radius_integration.py and disposable accounting harness.

- [x] Add actual FreeRADIUS config/packet tests before replacing runtime hooks. Policy failure/overload must precede EAP success/MPPE; fingerprint TLS resumption disabled; legacy current-policy checks retained.
- [x] Embed static EAP/REST/verified-leaf/source templates and native accounting detail writer/buffered reader/PostgreSQL SQL module. Replay uses plain append INSERT, catchall nullable raw fields, zero startup connections and bounded retries; only replay invokes SQL.
- [x] SQL intake preserves original native receipt/source context and replay identity. Failure prevents replay advancement. Native local buffer is not replicated/fsynced; acknowledge/document that boundary honestly.
- [x] Embed separate final post-auth logs recording final outcomes with sensitive attrs suppressed before disk. Go reader handles escaped/bounded grammar, incomplete tails, file generation IDs and PostgreSQL cursor/event/outbox atomicity; retain files through outages.
- [x] Add a bounded native detail writer ferror/fclose error-check patch under patches/freeradius; build against selected exact distribution/source ABI and prove /dev/full suppresses accounting ACK while ordinary buffering/replay and observational auth logging preserve behavior. No fsync/second spool/REST dependency.
- [x] Validate configs with real FreeRADIUS, run actual Start/Interim/Stop/duplicate/database-outage replay and secret-redaction tests; commit.

## Task 7: OTel telemetry and durable OTLP export

Files: internal/telemetry, internal/adapters/otlp, internal/templates/ddot, telemetry Terraform/dashboard contracts.

- [x] Add in-memory OTel/fake OTLP tests for resources, logs/spans correlation, sampling independence, safe attributes/redaction, cancellation and bounded failure.
- [x] Implement single SDK initialization, logrus bridge, safe instrumented HTTP, runtime/job/backend metrics, independent business events and bounded shutdown. Ordinary signals async; accounting durable outbox uses synchronous OTLP transport.
- [x] Persist export attempts before I/O, disable daemon ambiguous retry, handle partial success through durable quarantine and retain payload/history for explicit recovery. Local shared ledger provides authoritative usage.
- [x] Embed DDOT config with dedicated persistent file_storage fsync queue and unlimited bounded-delay retry, no volatile prequeue batch, no duplicate remote log collection; preserve Agent host/FreeRADIUS checks.
- [x] Test receiver failure/partial/lost response and real Collector persistence/restart where available; commit.

## Task 8: CA and protected bootstrap operations

Files: internal/adapters/stepca, internal/adapters/gcp, internal/privileged, internal/templates/systemd, internal/app commands.

- [x] Add adoption/initialization tests distinguishing no enabled secret version from read outage, immutable CA trust material, key/chain validation and activate/rollback failures.
- [x] Port Smallstep EC/RSA KMS initialization/adoption, ACME/SCEP/webhook config, persisted readiness ordering, certificate cache/renewal and FR validation before activation. Root keys intentionally deleted stay deleted.
- [x] Port privileged package/user/template/service operations with fixed paths and typed actions. Render serialized config; atomic last-known-good activation/rollback; renewal/source jobs use same binary.
- [x] Dedicated daemon user cannot access CA keys/modify services; root fetches runtime secrets into private files; systemd/network rules block GCP metadata credentials including endpoint variants.
- [x] Wire bootstrap/certificates renew/doctor/metrics commands with true dry-run, context and safe structured operation output; CA mock/local integration tests; commit.

## Task 9: Full daemon orchestration and migration/rollback

Files: internal/app, internal/jobs, internal/migration, CLI operational/profile commands and fixtures.

- [x] Add lifecycle tests for atomic listener binding, cancellation, separate worker resources, DB outage preserving fresh local auth, scheduling, healthy readiness versus unavailable dependency.
- [x] Wire all real providers, policy/webhook/broker listeners, native auth reader, shared accounting workers/export, network/inventory jobs and health/metrics into serve. No placeholder operations remain.
- [x] Import existing inventory/pending commands/discovery/metadata/Class key/downgrade guard and PR38 usage checkpoint precision/terminal/uncertain batches with idempotent markers under DB migration lock. Fence old writers; never confuse DD cursor with native spool progress.
- [x] Implement state migrate/export rollback paths preserving original observations and usage counters; require workers fenced before either transition. Port retained profile/challenge operator workflows into Go.
- [x] Full unit/race/migration and old/new parity tests; commit.

## Task 10: Terraform, release and legacy removal

Files: root *.tf, scripts/startup.sh, .github/workflows, VERSION, examples, README/CLAUDE/docs.

- [ ] Provision cloud8021x DB/least-privilege roles/secrets on existing HA PostgreSQL without changing step-ca DBs. Non-secret YAML + secret references, daemon/DDOT/native replay config. Preserve opt-out/Wi-Fi scope.
- [ ] Replace 3991-line startup with pinned binary download, mandatory checksum and bootstrap. No generated executable Bash/Python, MySQL/MariaDB, old usage collector or DD read credentials in enabled runtime.
- [ ] Remove all active Okta/Jamf variables/resources/options/examples/docs. Use explicit reviewed Terraform state-removal migration preserving obsolete rollback secrets, not destructive resource deletion.
- [ ] Build one application binary and compatibility aliases plus the narrowly patched native FreeRADIUS artifact/package from exact verified source/ABI; pin versions/mandatory checksums, detect incompatible replacement, update root CI/security/lint and module harnesses. Keep backend as FreeRADIUS. Do not publish a release in this task.
- [ ] Keep development Python parity tests only where useful, Windows PowerShell; retire server Python/Bash files and update docs/profile examples for actual new paths and rollback/HA/ack limitations.
- [ ] Terraform fmt/validate, template/render/checksum/release tests; commit.

## Task 11: Integration, security and final review

Files: tests, docs, all task-owned paths as required for fixes; PR body.

- [ ] Run root race tests, goimports/golangci-lint, govulncheck, existing/new SCEP and disposable FreeRADIUS/PG/Collector/CA integration suites.
- [ ] Exercise trust-boundary attacks, final packet VLAN/Class parity, native replay progress/failure, concurrent workers/fencing, counter/queue limits, uncertain export/Fleet submission, source/CA atomic recovery and migration rollback.
- [ ] Check final runtime for Bash/Python/Datadog-readback/Okta/Jamf remnants, module/release pinning and complete commands.
- [ ] Separate whole-branch spec/security/code review, address findings with tests and re-review. Document genuinely unavailable environment-dependent checks without claiming completion.
- [ ] Push final verified branch, update PR description around implemented behavior/tests/limits and request review. No merge or production deploy.
