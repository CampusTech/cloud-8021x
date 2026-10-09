# Task 10 runtime implementation report

Branch: codex/unified-go-daemon; shared isolated worktree. No cloud/prod/Fleet/Datadog API calls, real Terraform operations, pushes or releases were performed. Local commit window was passed from packaging to runtime under Ruling82; final checks completed with an empty index before exact-path staging.

## Implemented contract

- Closed Cobra commands: `bootstrap source-key`, `capture`, `prepare`, `activate`, `deactivate`, `rollback-proof`, `resume-source`. Preparation/capture/source helpers use only the fixed incoming release; active/reverse green operations use completed installed configuration. Dry run performs no helper action. Actual executing helper digest and incoming binary/config/database-trust checks bind the reviewed release.
- Four distinct pinned per-host root Ed25519 keys, physical hostname checks, normalized common pair manifest plus full node configuration digest, source/destination/release/epoch/Class/CA trust bindings. Strict signed authorization envelope preserves original policy/certificate observations and command provenance; bounded private webhook/native section remains local and is stripped before PostgreSQL publication.
- Original source capture persists the existing scheduler/helper fences, scans processes/locks and fixed original files, and never stops original native authentication/CA or imports accounting. Empty/missing certificate provenance is refused.
- Adoption-only EC/RSA CA material and server cache: enabled versions, existing key/certificate relationships, KMS public identity, original native CA JSON/templates and webhook key/certificate. Read errors, partial/missing material and changed trust fail; no initialization/renewal fallback during prepare.
- New deployment-owned application database namespace; fixed CA databases unchanged. Immutable collection epoch, no accounting history/outbox import, no pre-epoch export/credit, first ongoing report baseline zero, later exact deltas. Original command guards are append-only/idempotent and quarantine incomplete/uncertain submissions.
- Durable passive systemd conditions are installed before package work and retained after failure. Source, renewal, runtime, native CA/RADIUS and monitoring cannot become active on reboot solely because volatile masks disappear. A clean not-yet-installed unit is accepted only from positive not-found/inactive/PID0 properties and absent fixed unit files.
- Completed passive preparation reuses the exact physical installation receipt and can publish fresh final source capture without reinstalling. Both passive nodes publish final source captures before activation, avoiding obsolete prestage peer evidence. Original helper PID-start/config/release and shared/local installation references bind typed interrupted prepare recovery; partial recovery rolls back while retaining passive conditions.
- Two-node prepared/source/trust/Class/release checks plus authenticated local/peer readiness enable one green worker authority. Final signed authorization is installed before services start. First activation waits for peer; primary→secondary→primary completes local timer start. Already active repeats do not need fresh source captures. Interrupted activation recovery either acknowledges an already enabled healthy epoch or returns the isolated local node to stopped/passive readiness; it never re-enables a revoked epoch.
- Deactivate revokes SQL authority before local stops and reuses the existing typed cold worker fence/PID/native-state receipt protocol. Reverse proof requires both physical green receipts, revoked authority and resolved attempted certificate commands. Original/green pending or unknown delivery prevents source resume; a 404 is not proof of absence. Unattempted queued/leased work remains in the permanently revoked green epoch. Two fresh pinned destination signatures bind pair/release/roles/fences before restoring only original scheduler/helper files. No CA/accounting reverse restore.
- Source work keeps fixed logical SQL claim roles while full configuration and target mapping constrain mutations exclusively to green physical firewall names/tags. Physical instance telemetry and peer readiness distinguish blue/green.
- Activated certificate renewal uses existing CA adoption and current server-cache renewal with peer restart checks; no CA initialization path. Generated inherited webhook key is accepted only at its fixed credential path. Root `metrics`/diagnostics retain existing ownership; no new deployment or endpoint switch API was added.

## Evidence

- Final `go test -race` passes for all nine affected package groups: app/config/adoption/stepca/accounting/host/sources/GCP/native (1.19–4.73s each). Package owner separately repaired its deliberate sudo RED before this final runtime check.
- Compatible `/private/tmp/cloud8021x-pr38-security-bin/golangci-lint` 2.14.0: zero issues on runtime-owned package set. The initial PATH linter was 2.13.2 and could not decode Go1.27.2 export data; no source workaround was used.
- Real TLS PostgreSQL16, owned labelled container, no host ports: `TestPostgresParallelSessionsAndConcurrentCreation`, `TestPostgresParallelEpochIsolation`, `TestPostgresParallelSignedHandoffAndActivation` pass. New fixture covers a distinct green app database, blue untouched, immutable epoch, pre-epoch suppression/ongoing baseline/exact delta, both source signatures/preparations, duplicate pending guard preservation, both-node activation, epoch revocation, missing physical reverse proof, unresolved original/green command refusal, and exact expired prepare/activation recovery identity/replay refusal. Negative peer release/trust/config publication mutations also refuse readiness.
- Owned Linux source fixture: `TestInstalledParallelSourceCaptureRetainsAuthorizationOnly` passes with actual root files, freerad UID, process/lock scanning and key signing. It proves original timestamps/guard preserved, poisoned accounting never imported, no native/CA stop, missing command cache rejected, wrong physical source rejected, zero/one destination proof rejected, two signatures restore original scheduler files, live helper rejected, dead PID-start helper accepted only under matching config, and passive barrier bytes retained. Service calls are injected; no production host service runs.
- Packaging peer reports actual ARM64 and AMD64 62-archive native/package acceptance plus Debian13 `systemd-analyze verify` for six rendered base units and passive condition files, and actual ConditionPathExists negative/positive marker evaluation. Evidence: `/private/tmp/cloud8021x-task10-closure62-arm64-units.log`; packaging owns its final evidence/report. This is explicitly not PID1 reboot proof.
- Reproducible owned fixture harness added: `sh tests/runtime/parallel-fixtures.sh`; cached postgres16 only, unique names/labels, readonly host input mounts, no published ports, automatic owned cleanup. The final committed-harness run passed source/reverse Linux (0.38s), default parallel accounting (0.30s), preserved original whole-bundle pending guards (0.14s), isolated epoch (0.69s), and signed handoff/activation/recovery (0.33s).
- Meaningful RED→GREEN: clean uninstalled systemd units initially prevented passive prepare; focused synthetic reproducer failed then passed after fixed absent-file/property proof. App database-outage test retained its real local socket outage while correcting its synthetic DSN to the newly explicit default cloud8021x namespace.

## Self-review and review boundaries

Self-review corrected actual-source trust digest omission, final Class-versus-committed credential check, mixed-release peer preparation, actual executing helper hash binding, missing reverse pins at immutable preparation, final capture refresh ordering, physical green key/hostname proof, active retry capture dependency, source SQL logical/physical mismatch, cold command uncertainty and typed interrupted preparation/activation handling. These were not left as documentary exceptions.

No live deployment, Fleet terminal response, actual cloud key/secret rotation, real PID1 reboot, real HA endpoint/NAS cutover, or production readiness is claimed. CA JSON/template adoption intentionally refuses changed enrollment/DB/KMS/provisioner semantics; operator input must describe preserved current CA identities. Original source is the supported legacy Python/native installation; absent original files are not converted into a fresh source. Root-owned operator configuration/release and authenticated pin transfer remain the trust boundary.

A broad initial reverse-code write was rejected by automatic approval review for unclear workflow authorization. Parent supplied exact Task10/Ruling79 local-development authorization. Pure codec tests and the narrowly scoped subsequent code/owned-fixture calls were approved; no approval blocker remains and no production action was attempted.

Ownership preserved: infrastructure owns internal/provisioning/Terraform/loader/global docs; packaging owns artifacts/package mechanics/DDOT and its fixtures. Runtime explicitly handed packaging only the narrow `internal/privileged/host/packages.go` absent-sudo safety guard on request; that path is excluded from runtime staging. Existing completed Tasks1–9 were not broadly reopened.

## Runtime paths for exact staging

- docs/parallel-adoption.md
- tests/runtime/parallel-fixtures.sh
- internal/accounting/epoch.go, epoch_test.go
- internal/adapters/freeradius/native/readiness.go, readiness_test.go
- internal/adapters/gcp/firewall.go
- internal/adapters/stepca/adopt.go, adopt_native.go, adopt_test.go
- internal/adoption/handoff.go, handoff_test.go, rollback.go, rollback_test.go
- internal/app/command.go, command_test.go, daemon.go, outage_test.go, profile_test.go, protected_sources.go, runtime.go, parallel.go, parallel_renew.go, source_schedule_test.go
- internal/config/bootstrap.go, config.go, network.go, deployment.go, deployment_test.go, parallel_manifest.go
- internal/privileged/host/backend.go, files.go, parallel_activation.go, parallel_passive.go, parallel_passive_test.go, parallel_prepare.go, parallel_rollback.go, parallel_source.go, parallel_source_linux_test.go
- internal/privileged/sources/operations.go, deployment.go, deployment_test.go
- internal/storage/postgres/accounting.go, connection.go, legacy_bundle.go, migrate.go, native.go, native_test.go, parallel.go, parallel_epoch.go, parallel_epoch_test.go, parallel_recovery.go
- .superpowers/sdd/2026-10-08-unified-go-daemon/task-10-runtime-report.md
