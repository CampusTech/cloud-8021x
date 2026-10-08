# Preparing an existing pair or a fresh pair

The incoming application and configuration are the verified files in
`/var/cache/cloud-8021x/artifacts`. The two configurations must name the same
`state_transition`, the fixed `radius-primary` and `radius-secondary` identities,
and the same pre-provisioned Class signing key. Bootstrap never rotates that key
to make migration succeed. Keep the incoming files and original protected
receipts unchanged throughout preparation.

On each node, inspect the plan and then fence the legacy scheduled/application
writers:

```sh
sudo /var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap --incoming --fence-only --dry-run
sudo /var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap --incoming --fence-only
```

Both protected node receipts are required before full bootstrap. Fence-only does
not capture a running legacy SQL producer and does not install or activate the new
native service. An interrupted writer fence uses that same command with
`--resume-attempt N`, for its exact recorded attempt.

## Existing legacy installation

Before full bootstrap, independently quiesce the local old native service under
the planned maintenance procedure. A real ready peer or an already-stopped local
service is required by the native maintenance contract. Keep the old MariaDB
service and data available until its immutable snapshot and state import complete.
Stopping or retiring MariaDB first makes the snapshot unavailable; a missing
socket is never evidence of an empty database.

```sh
sudo /var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap --incoming --dry-run
sudo /var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap --incoming
```

Before CA, package, application or native-tree changes, the fixed
`legacy-capture` preparation checks the original writer receipt, masked/stopped
legacy writers, native process exit, original policy and Class, and the fixed
local MariaDB socket. It then archives a read-only repeatable snapshot of
`radius.radacct` and the complete original local state. The Go adapter uses Unix
root peer authentication at `/run/mysqld/mysqld.sock`; it accepts no DSN, query,
network fallback, or operator-generated JSON. It changes no database row/schema
or service. Original unsigned integers, nulls, database-returned timestamp text,
and session/system timezone evidence are retained without guessing UTC.

The original SQL archive, bundle and helper receipts are root-only under
`/var/lib/cloud-8021x-bootstrap/writers/<state_transition>/`. Native files, old
MariaDB data and the original key remain available for cold rollback. A saved
capture is reused only with its exact binding and unchanged physical native
configuration plus producer quiescence; it is never refreshed from current data.

## Positively proven fresh installation

Fence-only selects fresh preparation only after positive protected absence checks
for all fixed prior native, SQL, application, state, data and writer footprints.
A partially removed installation, unknown rejoin, existing shared authoritative
state, or missing required credential is refused. A missing socket alone cannot
select this path.

The immutable fresh bundle records unavailable observations. It is not an empty
Fleet authorization snapshot. Before entering the normal CA/install gate, the
fixed `fresh-initial` preparation performs bounded authenticated inventory GETs
with the configured Fleet observer credential. Both fresh originals and both
writer fences must exist. It retains the real response/source times in an exact
root-private PostgreSQL snapshot and protected local receipt. No certificate
submission/result polling, source apply or shared-worker enable occurs. Empty or
failed inventory refuses activation. The derived local snapshot must pass policy
readiness before native activation. Complete initial preparation/bootstrap on
both nodes before either node's state import; source age is never reset to extend
this window.

## Interrupted preparation

Use the original incoming files, original transition and the exact reported
maintenance attempt:

```sh
sudo /var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap --incoming --resume-attempt N
```

Without `--fence-only`, this performs preparation reconciliation only and then
returns. It does not install, call a CA, fetch another inventory response, or
capture new SQL. The original helper must have exited with the recorded PID/start
identity and the protected operation flock must be available. Expiry alone is
not process-exit evidence. After successful proof, rerun normal bootstrap.

For fresh preparation, exact committed PostgreSQL snapshot bytes must match the
immutable local original. An absent row is recoverable only with exact original
fresh absence, an exited helper and positive proof that no later phase exists.
A new preparation attempt then uses the same archived observation. For legacy
capture, exact durable SQL plus full bundle proves completion even if the local
completion marker write or gate acknowledgement was interrupted. If neither
capture exists, proof of helper exit and no later phase permits retry. A SQL-only
partial archive, short/foreign receipt, changed data/configuration, active helper,
unknown acknowledgement or unprovable later state remains quarantined. Retain the
original bytes and resolve the missing proof; do not delete receipts or relabel a
new snapshot as the original.

After both installations, use each installed daemon's `state migrate` command to
import its original bundle and publish the exact local state under the protected
gate. Both protected local publication acknowledgements are required before
shared workers can run. Fresh publication consumes the proven initial snapshot;
its unavailable original seed remains immutable.

The isolated fixtures exercise real Linux files/processes, real MariaDB and
PostgreSQL, with injected systemctl probes. Signed Debian 13 package installation
and complete systemd/packet acceptance remain separate release gates.
