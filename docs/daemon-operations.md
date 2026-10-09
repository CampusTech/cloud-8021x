# Unified daemon migration and retained-state recovery

These procedures describe the Go replacement. Deployment, real client EAP/failover
approval and the signed Debian package release gates are separate. Use the fixed
protected configuration and the same `state_transition` on `radius-primary` and
`radius-secondary`. Root commands reject alternate configuration paths and listener
overrides. Preserve the original incoming artifact, configuration and Class key
throughout an interrupted operation. Commands below are operator procedures, not
permission to act on production.

## Prepare and import the pair

Follow [bootstrap preparation](bootstrap-preparation.md) before installing either
node. Fence-only on both nodes persistently stops the known legacy scheduled
writers and retains their exact originals; it does not stop native RADIUS or
capture live SQL. For the first legacy node, separately verify actual client
EAP/failover on the remaining peer, CA readiness and spool preservation, then stop
only the migrating node's old native and application listeners. New signed peer
readiness cannot be inferred from a legacy peer. The protected helper independently
proves native inactivity, process exit and free ports. This first adoption is
explicitly disruptive. After the first Go node passes actual client EAP and signed
readiness, upgrade the second with the normal authenticated peer contract.

Keep MariaDB running and its data intact until immutable capture/import completes.
The fixed Go Unix-socket adapter reads `radius.radacct` in a repeatable read-only
transaction after its old native producer is stopped. A missing socket is unknown,
not an empty database. SQL-only partial preparation remains quarantined; never
replace it with a newer snapshot. Fresh hosts instead require positively proven
absence of all prior native/SQL/state/writer/data footprints, both matching fresh
seeds and the original Class key. Their initial observer-only Fleet GET must yield
real usable inventory before local policy readiness; no certificate commands,
source mutation or shared workers run during that preparation.

After both bootstraps, run on each installed node:

```sh
sudo /usr/local/bin/cloud-8021x state migrate --dry-run
sudo /usr/local/bin/cloud-8021x state migrate
```

Migration validates the complete original bundle before importing under the shared
migration lock. Original policy age, certificate observation times, ambiguity,
fingerprint guard, pending collection reservations, SQL counters/nulls and PR38
checkpoint precision/terminal state survive. Local publication archives the exact
bundle and binds the original helper/attempt before acknowledging it in private
PostgreSQL. Both local acknowledgements are required to enable shared workers.
The first node can report `workers_enabled=false` while waiting for the other.
An import marker alone is not permission to process. The old Datadog `through`
checkpoint remains historical data; native spool progress starts independently.

If publication is interrupted, retain its exact reported attempt and use:

```sh
sudo /usr/local/bin/cloud-8021x state migrate --resume-attempt N
```

This requires the original helper to have exited, its fixed flock to be available,
and unchanged original bundle/config/Class/local publication evidence. It resumes
only that committed import/publication. Short, linked, foreign-owned, substituted
or uncertain evidence refuses; no deletion/recreation of receipts is a repair.
Preparation interruptions use the incoming `bootstrap --incoming --resume-attempt N`
procedure instead. An interrupted fence uses its own command with its original
`--resume-attempt N`; these attempt selectors are not interchangeable.

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

The native unit depends on daemon notification readiness. Guarded activation stops
native before replacing its synchronous Go dependency, retains a runtime mask,
then checks Go, both CAs, Collector and actual native readiness before release.
A first legacy failure restores files/ownership but leaves originally stopped
legacy services stopped. A subsequent Go rollback uses the exact known prior Go
configuration. Never start an unknown old service merely to clear readiness.

Use `doctor` for bounded real dependency observations and `metrics emit` for their
OTel projection. Unknown values are omitted. The
[dashboard](telemetry/daemon-dashboard.json) uses `max` by shared cluster for shared
PG session/intake/outbox gauges; summing two node reporters doubles the same state.
Native process/spool/capacity metrics remain host-local. OTLP acceptance is a
next-hop receipt, not proof that Datadog received or deduplicated an event.

## Cold rollback and retained work

Cold export deliberately blocks the transition permanently. It is not a pause or
a general daemon restart mechanism. Plan service disruption and client failover
before using it. Fence the new native producer and daemon/root workers on each
node under the protected peer-ready or proven-stopped contract:

```sh
sudo /usr/local/bin/cloud-8021x state export --fence-only --dry-run
sudo /usr/local/bin/cloud-8021x state export --fence-only
```

The first call revokes shared new work before physical fencing. Each node retains
its original unit/process/PID-start/flock, configuration, native-file and current
snapshot evidence. The second node requires its own positive local stop proof if
the first is already stopped; do not assert that an unavailable peer is ready.
The helper checks process exit and fixed units, not just lease expiry. If a fence
is interrupted, repeat `state export --fence-only --resume-attempt N` only for its
reported attempt. Both actual fences/current-state receipts are needed for export
or the root new-work recovery modes below.

Resolve any deliberately selected retained work **before writing the final cold
export**. Then, on an installed node:

```sh
sudo /usr/local/bin/cloud-8021x state export --dry-run
sudo /usr/local/bin/cloud-8021x state export
```

Output names the root-only immutable file
`/var/lib/cloud-8021x-bootstrap/writers/<state_transition>/rollback.json`.
`original` retains exact captured bundles; `legacy` contains the compatible current
policy/device projection; `current` preserves typed provider caches, protected
sources and native file identities; `ledger` retains work, attempts, reconciliation,
operator successor lineage/outcomes, exact sessions/counters, intake and cursors.
The usage checkpoint retains its original precision, terminal and ambiguous
batches. Original Class bytes and sticky identity cannot be downgraded. A different
second export is refused rather than overwriting the first archive.

Legacy code cannot safely interpret new pending/started/unknown work. Keep that
sidecar and PostgreSQL ledger; do not turn it into a legacy pending-send batch.
Unstarted pending new work stays retained; normal Go workers can drain eligible
work before entering the irreversible cold fence. Unknown original deliveries stay
unknown unless the typed evidence below proves a narrower fact. No command here
unfences workers or restores old writers. Restoring old executables/units/ownership
is a separately approved cold rollback using preserved original files/package
archives and the final compatible export, with the new pair still fenced. Keep
old MariaDB, both CA databases/keys/KMS references, Class key, fingerprint marker,
all unknown work, native pending accounting spool and DDOT queue. Never run old and
new usage writers together or delete spool files on presumed delivery success.

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
and its original attempts before writing the final cold export. Inspection reports the exact PG
payload digest without writing work or sending anything:

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
file references, not the compatibility executable's environment fallback.

Fleet observers and maintainers remain distinct. Collection intersects their
scopes, keeps ACME-only devices exempt and only polls the configured minimum
SCEP/BYOD scope. Class wire bytes and original receipt-time verification are
unchanged. Legacy display labels map only when original source/config establishes
exact provider origin, console/site/location scope. Otherwise historical raw bytes
remain in export and display is unavailable. Fallback age is capped at the original
one-hour TTL and the current metadata maximum, independent of inventory/source TTL.
A successful current VLAN observation, including an empty one, supersedes fallback.

## Interrupted legacy baseline checkpoints

A deployed PR38 version2 checkpoint with `phase: baseline` records an incomplete
historical source scan. Migration preserves the exact original document,
`credit_start`, `through`, original timestamps and integer counters. Its scan
`through` is never a native spool cursor or proof of delivered traffic.

A protected migration-only floor in PostgreSQL suppresses usage intervals for
original receipts before the original credit floor. Valid reports still update
counter baselines. Each session then learns its first valid, non-predating native
observation at or after that floor without credit, preventing a delta across
unobserved history; subsequent valid intervals use ordinary processing. A delayed
pre-floor report that advances counters re-arms that baseline requirement. This
can conservatively undercount a first interval; it does not reconstruct missing
history or change ordinary version1 checkpoint semantics.

Cold rollback export of an incomplete version2 checkpoint returns its exact
original baseline state, independently from the advanced sessions, intervals,
outcomes and floor retained in the full current ledger sidecar. It includes
`legacy_usage_recovery: incomplete_history_manual_reconciliation`. **Reconcile
the retained sidecar before reactivating legacy usage writers.** Never combine
the original scan cursor with advanced native counters, discard the sidecar,
automatically replay/send events, or mark the legacy scan complete based on a
native receipt time. Only an actual resumed legacy scan can finish its original
baseline and return to version1. The new enabled runtime performs no Datadog
readback.
