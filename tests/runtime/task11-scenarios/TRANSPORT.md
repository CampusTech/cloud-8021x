# Requested closed controller extension ABI (source preparation)

This is a request to the original controller owner, not an implemented or accepted runtime interface. No generic command runner, path/argv, SQL text, endpoint, FSM override or success marker is permitted. Controller remains MainPID of `task11-acceptance.service` and retains its existing protected lock, namespace descriptors, operation cgroups and uncertain/quarantine semantics. Scenario code checks actual observations rather than trusting exit0.

## Files and stage completion

Root-private0700 directory `/var/lib/cloud8021x-task11/control/scenarios`; root0600 no-follow single-link regular files. Driver installs exclusive `requests/<attempt_id>-<sequence>.json` before starting controller service; sequence is a canonical decimal1..24, never an arbitrary path. Controller cannot accept overwritten/duplicate requests or resume an uncertain previous sequence. Fixed controller stage file contains stage="scenario-operation", attempt_id, sequence and independently pinned request_sha256. Path derives only from validated attempt ID/sequence; SHA cannot come only from request content. Action completion writes exclusive `results/<attempt_id>-<sequence>.json` only after actual child retirement; a failed action writes bounded `failures/<attempt_id>-<sequence>.json` preserving uncertainty and returns nonzero. No automatic restart/rerun of a retained attempt. The driver waits actual service completion and checks MainPID, Result, action/request pins and record status. A result is evidence, never a readiness/pass marker.

Request schema1, exact snake_case fields:

```
schema: 1
attempt_id: "task11-<32 lower hex>"
sequence: canonical integer1..24; predecessor must be actually retired successfully
action: closed name below
plan_sha256: independently pinned original scenario-plan bytes
platform_sha256: independently pinned platform-inventory bytes
enrollment_sha256: independently pinned CURRENT post-keys enrollment bytes
application_sha256: exact enrolled shipping app
scenario_sha256: exact new helper executable descriptor
node: "green-primary" | "green-secondary" | "blue-primary" | "blue-secondary"
sessions: [] fixed independently planned task11-* accounting session IDs, max8
```

Action validation uses a closed action/role/phase combination; irrelevant node/sessions fields MUST be absent, not ignored:

* `probe-active-pair`: no node/sessions; both genuinely active greens.
* `read-accounting`: green-primary or green-secondary, 1..8 unique sessions of max64 ASCII `[a-z0-9-]` beginning task11-; fixed original accounting NAS .40. Read-only actual green ledger, no query/DSN option.
* `stop-green-primary`, `start-green-primary`, `reboot-green-primary`: node green-primary only, no sessions. Fixed outer unit task11-node-green-primary.service. Actual old Leader retirement/start/registration/boot observed; failed cleanup/uncertain stage prevents another action.
* `nas-native`, `nas-ongoing`, `nas-duplicates`, `nas-outage`: no node/sessions in transport; fixed pinned plan supplies the closed .21/.22 selection and counters. NAS-only new helper invocation is fixed `task11-scenarios nas <closed action>` with plan through private stdin. Target aliases/routes/secret/client keys are not transport overrides. Retain actual NAS root+net namespace FDs and fixed helper executable descriptor.
* `nas-ca-original`, `nas-ca-adopted`, `nas-ca-passive`: no node/sessions in transport; plan selects exact enrolled .31/.32 (original) or .21/.22 (adopted/passive), fixed original CA DNS/provisioner/broker TLS pins. No reseed/alternate CA or synthetic challenge creation.
* `stop-postgres`, `start-postgres`: no node/sessions; only task11-postgres.service, read-only fresh topology/unit identity before mutation. Outage bounded by plan1..60s and original driver attempt; restoration failure is nonzero/uncertain, not cleanup success.

Business API intake controls remain fixed genuine cloud helper `scenario intake-unavailable|intake-ready --gate installed-traffic`, independently pinned executable/seed and retired child process. Whether controller exposes these as additional closed actions or its existing fixed stage handoff is for the original owner; no arbitrary cloud scenario command.

## Result envelope and observations

Strict schema1 JSON, max8MiB, no secret/Class/token/DSN/raw TLS. Required `kind:"scenario-operation"`, action, attempt_id, sequence, request_sha256, plan_sha256, enrollment_sha256, application_sha256, `started_at`/`finished_at` UTC RFC3339Nano, `retired:true` only after actual scoped cgroup populated0, and exactly one action-specific body. Unknown fields/body combinations refuse. Errors expose only action/code, never child private stderr.

Probe body `nodes` keyed exactly green-primary/secondary. Per node: machine, root, machine_id32, boot_idUUID, leader integer>1, leader_start_ticks>0, namespaces{pid,mnt,uts,net,cgroup} actual inode integers, application_sha256, config_sha256 CURRENT enrollment, deployment="task11-green", epoch original actual SQL time, workers_active=true, workers_blocked=false, ready_roles=2. `units` closed shipping unit map: unit name, active_state, sub_state, main_pid, executable_sha256, control_group, process_cgroup, fragment_path, drop_in_paths. Collector: backing_file exact bootstrapcollector.ext4, file_device, file_inode, byte_size=536870912, filesystem="ext4", mount_device, options nodev/nosuid/noexec, mount_active. These are measured values; current state/registration rechecked after collection. Scenarios compare same physical node/app/config/epoch/collector inode across reboot and require actual old Leader pidfd retirement + new boot.

Read-accounting body: deployment, database="cloud8021x_task11_green", epoch, config_sha256, read_only=true, isolation="repeatable-read", and bounded selected `sessions`, `observations`, `intervals`, `outbox`. Sessions actual production session_key/state/native_baseline_required/pending. Observations include actual event_id/intake_id/session_key/received_at, typed production Event and reason. Intervals include usage_id/event_id/session_key and typed production Interval. Outbox includes original id/kind/payload/created_at/state and actual delivery receipts when present. Payload and all receipt/recovery byte fields MUST use opaque []byte/base64 across JSON, preserving exact PostgreSQL whitespace/large numbers; never json.RawMessage roundtrip, redacted or reconstructed payload comparisons. Read only matching selected session/context IDs, max128 events/intervals and256 work rows; unexpected missing/extra/multiple rows refuse. Protected migration config, production verified TLS, reserved actual one-connection capacity, repeatable-read readonly transaction; no production source/global query or updates. Exact wire spelling of production typed payloads must retain their existing JSON tags.

NAS body emits nonsecret planned request authenticator/packet ID/session/status/counter evidence, actual response authenticator validation, actual signed Class verification attribution fingerprint/device/VLAN and token SHA only, pre-transmission expected event/usage IDs+counter totals, observed receipt time brackets, ACK/no-response/reject semantics. Actual Class and private keys stay NAS-private. Expected counters/session freeze before EAP; expected IDs derive from genuine verified Class BEFORE accounting transmission/SQL/intake reads. Final accounting and delivery claims require separate measured SQL and controller verify-cloud.

CA body emits genuine request/issued leaf SHA, serial, subject/EKU/public-key SHA, original root/intermediate/decrypter hashes, chain verified against exact preserved roots and original/renewal signer continuity. CA database observation is still a missing separate fixed interface: root hashes do not establish an existing issued-record.

## Genuine issued certificate selection (requested separate read-only action)

Random issued serial/DER identity cannot be in the immutable pre-issuance plan. After an actual retired NAS CA result, driver exclusively writes fixed `ca-selections/<attempt_id>-<issuance_sequence>.json` root0600. Schema1 fields: attempt_id, issuance_sequence, result_sha256, authority=ec|rsa, serial=canonical positive decimal (max64digits), leaf_der_sha256, original_root_sha256, original_intermediate_sha256. Next independently pinned controller request supplies selection_sha256 and the exact validated predecessor coordinates, never SQL/DSN/table/path. Controller verifies immutable actual result bytes and identical public leaf DER fingerprint/serial before querying.

Read-only `read-ca-issued` response includes authority, exact fixed database identity, read_only=true, isolation=repeatable-read, selected serial, original selection/result hashes and actual opaque []byte/base64 nkey/nvalue bytes (bounded) from the shipping-pinned certificate bucket. Return actual parsed stored certificate DER hash/serial and provenance only after parsing those preserved bytes; unknown bucket/schema/version or missing/multiple row refuses. Original-before-capture and adopted-after observations compare exact stored row key/value bytes plus the independent genuine issued leaf/chain identities. EC is conditional on a genuine supported issuance interface (shipping EC attested-ACME cannot be replaced with a JWK provisioner); RSA uses actual SCEP. CA DB continuity remains pending confirmation of authenticated certificates source and stored-bucket schema, never accepted by configuration/root hashes alone.
