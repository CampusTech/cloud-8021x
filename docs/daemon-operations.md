# Unified daemon operations and retained-state recovery

Use the infrastructure-rendered protected configuration and the same
`state_transition` on both green nodes. Protected commands reject alternate
configuration paths and listener overrides. Preserve original incoming artifacts,
configuration, Class identity and protected receipts through interrupted work.
Commands below are operator procedures; deployment, traffic switching and real
client/HA acceptance remain separately reviewed actions.

## Prepare and activate the green pair

Follow [parallel adoption](parallel-adoption.md) for source key enrollment, signed
source capture, passive green preparation and two-node activation. The preparation
requirements are also summarized in [bootstrap preparation](bootstrap-preparation.md).
Source capture preserves original policy/certificate observations and pending
Fleet command provenance while original native RADIUS and CA services continue.
Green preparation adopts the existing CA material and starts an empty accounting
epoch in its separate application database.

Accounting history, SQL snapshots, checkpoints and outbox records are not imported.
Pre-epoch records create no credit or export; the first ongoing Interim/Stop
establishes a zero-credit baseline, and later measured deltas use normal session
locking and deduplication. Original certificate observation times remain unchanged.
An interrupted prepare or activation uses its own exact reported
`--resume-attempt N` in the parallel workflow. Preserve its original helper,
configuration and installation receipts; expiry alone never proves process exit.

## Serving and readiness

`serve` binds policy, private readiness, metrics and enabled webhook/broker
listeners atomically before starting jobs. It emits `READY=1` only after local
policy, observed inventory and the protected public RADIUS certificate mirror are
ready. PostgreSQL/API outages make background jobs unavailable without making a
fresh local authorization snapshot depend on a network call. Expired snapshots
still deny; failed refreshes do not extend their age. Inventory/certificate,
network, accounting/auth and export work have bounded independent resources.
Cancellation stops new work, drains within bounds and flushes ordinary telemetry;
retained business work is not deleted.

The native unit depends on daemon notification readiness. Passive preparation
keeps green services and workers behind persistent activation barriers. Protected
activation checks both green publications, source fences, CA/Class trust and
authenticated peer readiness before enabling shared authority. Deactivation
revokes that authority before physical service fencing; an unavailable peer or
expired lease never proves that its workers stopped.

Use `doctor` for bounded real dependency observations and `metrics emit` for their
OTel projection. Unknown values are omitted. The
[dashboard](telemetry/daemon-dashboard.json) uses `max` by shared cluster for shared
PG session/intake/outbox gauges; summing two node reporters doubles the same state.
Native process/spool/capacity metrics remain host-local. OTLP acceptance is a
next-hop receipt, not proof that Datadog received or deduplicated an event.

## Green deactivation and retained work

Follow the [reverse handoff](parallel-adoption.md#reverse-handoff) on both green
hosts:

```sh
sudo /usr/local/bin/cloud-8021x bootstrap deactivate
```

Deactivation permanently revokes the shared worker epoch before stopping local
production services and retaining physical worker/PID/native and current-state
receipts. Plan disruption and client failover through the reviewed cutover
procedure. An interrupted fence uses `bootstrap deactivate --resume-attempt N`
with its original reported attempt. Both actual physical fence/state receipts are
required by the root work recovery modes below and by rollback proof.

Resolve imported original certificate-command guards and all attempted green
certificate delivery using the exact retained recovery paths. Unknown or pending
responses remain unresolved. Never-attempted queued/leased work remains retained
in the revoked green epoch. Green accounting, outbox payloads, attempts,
reconciliation history and uncertain deliveries stay in PostgreSQL; there is no
compatible accounting archive export or backwards merge into the original system.

After both fences and command reconciliation, use `bootstrap rollback-proof` and
transfer both signed root-only proofs as specified by parallel adoption. Only
`bootstrap resume-source --incoming` on the original physical hosts verifies
those proofs and restores their original scheduler/helper files. Traffic
restoration remains a separate reviewed action. Keep the original deployment,
CA databases/keys/KMS references, Class identity, fingerprint guard, unknown work,
native pending accounting spool and DDOT queue intact. Receipt expiry, missing
nodes or presumed delivery success never justify discarding retained state.

## Exact retained collection and delivery recovery

Imported legacy Fleet reservations retain their existing terminal-only path:

```sh
sudo /usr/local/bin/cloud-8021x state recover-collection --guard ORIGINAL_GUARD --dry-run
sudo /usr/local/bin/cloud-8021x state recover-collection --guard ORIGINAL_GUARD
```

For Windows with an unknown original execution identity, add `--execution-id ID`;
the ID is only a hint checked against original host/script/nonce. `404`, empty and
pending responses never prove non-submission or release a guard. A lost local
resolution acknowledgement uses this command's exact `--resume-attempt N` to prove
only the already committed original terminal resolution.

New Go work uses the closed `state recover-work` modes. Obtain the original work
ID/generation through approved read-only administrative inspection of `ledger.work`
and its original attempts. Inspection reports the exact PG payload digest without
writing work or sending anything:

```sh
sudo /usr/local/bin/cloud-8021x state recover-work --kind fleet-terminal --work WORK_ID --generation GENERATION --dry-run
sudo /usr/local/bin/cloud-8021x state recover-work --kind fleet-terminal --work WORK_ID --generation GENERATION --payload-sha256 PAYLOAD_SHA256 --request UNIQUE_64_HEX
```

Both physical worker fences and blocked transition are mandatory. Configured
Fleet GETs must prove exact original provider, device/enrollment, command and
terminal response. Windows supports bounded comma-separated `--execution-id` hints;
ambiguous matches refuse. No submissions or certificate observations are generated.
Original result/attempt bytes remain in append-only recovery evidence; only proven
terminal pending collection is settled. Ordinary safe automatic result polling
remains separately governed by its existing collection scope and claim rules.

To inspect a known original outbox success already committed in PG:

```sh
sudo /usr/local/bin/cloud-8021x state recover-work --kind outbox-receipt --work WORK_ID --generation GENERATION --payload-sha256 PAYLOAD_SHA256
```

This proves only its original stored next-hop receipt, not downstream delivery.
There is no outbox terminal-success override based on logs, empty searches or a
missing Collector record. After Collector disk loss, or a deliberately selected
unknown/partial delivery, explicit republication is possible:

```sh
sudo /usr/local/bin/cloud-8021x state recover-work --kind outbox-republish --work WORK_ID --generation GENERATION --dry-run
sudo /usr/local/bin/cloud-8021x state recover-work --kind outbox-republish --work WORK_ID --generation GENERATION --payload-sha256 PAYLOAD_SHA256 --request UNIQUE_64_HEX --accept-possible-duplicates
```

This sends exactly one retained record through the configured neutral synchronous
OTLP transport. It preserves the original stable event ID, producer host, timestamp
and counters without recalculating ledger usage. It can duplicate telemetry,
including an already accepted portion of a partial response. Exact totals remain
in PG; downstream log aggregates are subject to at-least-once duplicates. The new
operator attempt is persisted before I/O, with original helper/config/binary and
payload evidence. Original work/quarantine/attempts remain unchanged. Workers stay
fenced. Repeating the same request returns its retained outcome and never sends
again; an intentional later republication needs a new unique request and explicit
duplicate acknowledgement.

For an interrupted new-work operation, repeat its exact arguments with
`--resume-attempt N`. Recovery sends nothing and performs no Fleet GET. Original
helper PID/start exit, fixed flock, binary/config/request and original work bytes
must match. A retained result settles only that exact maintenance acknowledgement.
A started operator attempt without a durable result becomes retained `uncertain`,
never successful. If primary PG proves its operator row absent and protected
original work unchanged, `no_send_proven` means only that this **new operator send**
never started; original delivery remains unknown. Query failure is not absence.
Insufficient or changed proof stays blocked. Never delete a request to resend it.

## Source history and native retention

The root source timer runs the fixed `sources apply` command once per minute when
discovery is enabled. Go daemon discovery only writes data candidates. Root uses
per-node durable claims/StartAttempt and the exact persisted candidate SHA before
independently verifying pinned controller scope and changing the fixed native and
firewall targets. `--candidate-sha256 SHA` can constrain an operator invocation.
The daemon has no sudo/service/firewall control.

For a quarantined original source operation, use its exact work/generation and,
when its maintenance acknowledgement was lost, the original attempt:

```sh
sudo /usr/local/bin/cloud-8021x sources apply --reconcile-work SOURCE_WORK_ID --generation GENERATION --resume-attempt N
```

Historical recovery verifies installed original proof/state/client/firewall bytes,
original helper exit and the fixed apply flock. It does not apply, fetch new
controller authority, replace timestamps or extend expired source authorization.
A committed source-history row is read back exactly after lost ACK; an original
uncommitted/expired-started attempt can record history only under its exact stopped
proof. New WAN state can subsequently enter the normal fresh verified path. If the
fixed installed/firewall evidence itself differs, leave the attempt quarantined
and use the separately approved fixed-target rollback procedure; arbitrary SQL
success, timer retries and cache timestamp edits cannot establish convergence.
Proof cleanup retains current, previous, unresolved and incomplete generations;
unknown reference/overflow stops cleanup rather than guessing.

Native final-auth file identity is original producer host plus immutable generation
filename and byte offset. Backup/restore must preserve that host and exact name;
copying inodes does not recount committed events. Truncation below a committed
cursor refuses. Never rename a restored file as a new producer. Native accounting
spool delivery remains FreeRADIUS buffered SQL to PG, with independent progress.

A complete malformed auth record deliberately blocks that reader. With the native
producer stopped under the normal approved maintenance/failover procedure:

```sh
sudo /usr/local/bin/cloud-8021x state recover-auth --file EXACT_BASENAME --offset OFFSET --dry-run
sudo /usr/local/bin/cloud-8021x state recover-auth --file EXACT_BASENAME --offset OFFSET --sha256 ORIGINAL_RANGE_SHA256
```

Dry-run reports the exact original range/digest. Mutation retains its original
bytes and source/offset/digest in private PG and advances only the matched cursor
atomically. A lost ACK is reconciled with the same arguments and
`--resume-attempt N`; partial, changed, linked or nonmatching records refuse.
No automatic malformed-record drop or external payload override exists.

Closed auth generations are pruned only during an already required guarded native
stop, after actual native UID process exit, original producer closure and committed
PG cursor at EOF. Current and rollback generations remain; unconsumed/uncertain
files remain. Cleanup does not periodically restart native. Monitor host-local
`auth.files`/`auth.capacity` and disk/spool health before the bounded retention
limit, then schedule ordinary approved maintenance and resolve any malformed or
uncommitted records. Do not remove queued records merely to reclaim space.

## Optional profiles and compatibility

`byod-profile` replaces the server-side Python generator and writes a new private
mobileconfig plus optional `--fleet-command-out` JSON. It performs no delivery.
Use the retained `--identity`, `--provisioner`, `--scep-url`, `--ssid`,
`--radius-server-name`, `--radius-ca-cert`, `--signing-key-file`, `--ttl` and `--out`
flags. Shared Fleet dynamic SCEP remains the normal workflow; per-device profiles
are optional. The stable UUID5 namespace, RSA2048 nonextractable key, exact device
CN, pinned root/server, EAP13 and fresh per-issuance OU match the retained Python
profile. `scep-challenge` retains challenge versions/lifetime and private output;
dry-run validates without minting or writing. The unified command uses committed
file references.

Fleet observers and maintainers remain distinct. Collection intersects their
scopes, keeps ACME-only devices exempt and only polls the configured minimum
SCEP/BYOD scope. Class wire bytes and original receipt-time verification are
unchanged. VLAN/AP display labels come from scoped controller observations;
failed metadata refreshes do not extend their original age.
