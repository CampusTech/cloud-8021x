# Fixed original-blue schema initializer

Development fixture code only. The single future operation invokes shipping
`postgres.NewMigration` then `Store.Migrate` for `cloud8021x_task11_blue`, with
exact `cloud8021x_task11_blue_runtime` and `cloud8021x_task11_blue_native` roles.
It never selects `stepca`, `stepca_rsa` or the green database, creates alternate
schema SQL, or writes an installation/activation/observer receipt. Role and
database creation remain the separate reviewed seed SQL prerequisite.

No binary or SQL operation has been run. Future execution requires separate
root approval after the347-package/empty-audit and nspawn/private-PG gates.

```
task11-blue-migration --plan-sha256 INDEPENDENT_EXACT_PLAN_SHA --dry-run
```

Removing `--dry-run` is the actual separately gated mutation. There is no config,
DSN, database, role, input path or endpoint override. `--debug` logs only the fixed
database and dry-run status; private values never appear in output or errors.

The executable requires Linux effective UID0, root-owned0644
`/etc/cloud8021x-task11-fixture` containing exactly `synthetic-only-v1\n`, actual
hostname `task11-blue-primary`, the independently pinned machine ID and actual
systemd PID1/executable. Blue-secondary and every green identity are refused.

Root-private0600 plan at
`/var/lib/cloud8021x-task11/control/blue-migration.json` uses strict JSON fields:
`Schema:1`, `MachineID` (32hex), `ConfigSHA256`, `InputSHA256`, `DSNSHA256`,
`CASHA256` (all exact64hex). The command independently checks the entire plan
against the caller's SHA. The plan is not generated from current observed data.

Only these fixed inputs are read:

- `/etc/cloud8021x-task11-source.yaml` and `/etc/cloud-8021x/config.yaml`, both
  root-owned0640, byte-identical and matching ConfigSHA256. The actual shipping
  strict config decoder/validator is used, followed by closed blue physical,
  DB/role/reference/TLS/source-policy predicates.
- `/var/lib/cloud8021x-task11/control/original-seed/assembly-input.json`,
  root0600 and matching InputSHA256; validated with the finalized seed contract.
- Same original root's `api/seed.json`, root0600, matching the finalized Input's
  exact InstalledSeedSHA256. The original version1 numeric Secret Manager
  `postgres-blue-migration-dsn` value must exactly equal the private DSN bytes.
- `/run/cloud-8021x-root/postgres-migration-dsn`, root0600 and matching DSNSHA256.
  It must be one PostgreSQL URL for exact private10.203.11.11:5432, blue database,
  blue `_migrate` user, a nonempty password and exact `sslmode=verify-full` query.
  No alternate hosts/ports/databases/roles or extra options are accepted.
- `/etc/cloud-8021x/postgres-ca.pem`, root0644, matching both CASHA256 and the
  finalized Input's CA pin. Exactly one real X.509 CA certificate is required.

All protected reads walk no-follow root-owned non-group/world-writable ancestry
and require a bounded single-link regular leaf with exact mode. The API seed
bound is8MiB, config/Input/CA1MiB, plan16KiB and DSN8KiB. Machine identity has its
own small bound. Missing or changed protected input refuses before connection.

The shipping config selects its explicit pinned `cloudsql-instance-ca` mode;
`NewMigration` installs that actual TLS chain verifier, drops DSN fallback and
runtime options, and uses the original configured connect/query timeouts. This
is the existing product per-instance CA contract, not disabled certificate
verification. Unit tests call the actual shipping TLS verifier with a real
synthetic signed leaf and prove wrong-chain and wrong-pin refusal without TCP.

A real operation acquires the fixed root0600 single-link no-follow
`control/blue-migration.lock` exclusively/nonblocking, then rereads and revalidates
all inputs before constructing a pool. The pool uses one connection, minimum0,
within the finalized blue migration role cap2 and source config aggregate bounds.
Overall deadline is min(3*query timeout + connect timeout,4minutes); shipping
per-query bounds remain intact. The pool closes before the lock is released.
There is no constructor, lock creation or connection in dry-run. Dry-run still
requires all actual root/identity/plan/material guards.

A migration error reports possible uncertainty and requires inspection before a
retry. Success JSON reflects only the completed shipping migration call, never
activation or installation acceptance. No database/table/work state is invented.

Local tests are pure identity/input/decoder/TLS/role/pool/dry-run tests. They do
not call NewMigration/Migrate, connect to PostgreSQL, create the fixed root paths,
execute an external helper or prove installed schema/ACL behavior. Actual
application migrations/native schema and role isolation must still be observed
against the reviewed private PostgreSQL instance in the real blue namespace.
