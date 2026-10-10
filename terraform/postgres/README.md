# Private PostgreSQL provisioning

This is a separate Terraform root and state for a private administrator runner.
It connects to the existing private PostgreSQL16 primary with verified TLS and
creates only `cloud8021x`, `cloud8021x_migrate`, `cloud8021x_runtime` and
`cloud8021x_native`. The migration identity owns that application database;
application roles have no superuser, CREATEDB, CREATEROLE, replication, bypass-RLS
or inherited memberships. Native/runtime get CONNECT only before the protected
Go migrations grant their exact schema permissions. Destruction is blocked.

Do not substitute `google_sql_user` for these roles. The root Google5.45.2
provider lacks custom database roles; Cloud SQL's default API-created built-in
users inherit `cloudsqlsuperuser`, CREATEDB and CREATEROLE. SQL-created roles do
not require those grants. [Cloud SQL user semantics](https://docs.cloud.google.com/sql/docs/postgres/users)
and the actual pinned provider schema were checked during implementation.

The pinned PostgreSQL1.27.0 provider reads its administrator password from
`PGPASSWORD`. It is never a Terraform variable, external-data query, output,
Secret Manager resource or VM startup input. Use an ephemeral private runner
with authenticated private connectivity and separately controlled state access.
The administrator password must not be logged or put in shell history. The
application passwords and output DSNs are sensitive and do appear in this
protected Terraform state; use distinct long randomly generated values and a
protected encrypted backend for real operation.

## Ordered preparation

1. Complete the infrastructure state first: existing HA instance and CA databases,
   fixed application secret containers, private network, and root/runtime-scoped
   VM access. Obtain the exact existing instance identity, private address,
   public server CA PEM and its SHA256 from reviewed infrastructure outputs.
   `cloudsql-instance-ca` requires the unique per-instance CA mode, exact PEM
   bytes and one certificate; shared/custom CA deployments use `verify-full`
   with a matching server name. Never use `require`, plaintext or an arbitrary
   replacement CA. This module verifies the pin before the provider can apply.
2. Build the reviewed helper on the administrator runner from the root module:
   `go build -o /protected/bin/cloud8021x-postgres-admin ./tools/postgres-admin`.
   The application release builder does not include this administrator tool.
3. Supply this root's declared variables through protected `.tfvars` or runner
   inputs: connection/CA identity, absolute helper path, three application
   passwords, the matching aggregate runtime budget per node, reviewed CA capacity reservation, exact
   original owners/ACLs for **both** `stepca` and `stepca_rsa`, and the complete
   explicitly approved existing CA client access list. A grant record contains
   `grantor`, `role`, `privilege` (`CONNECT`, `TEMPORARY`, `CREATE`) and `grantable`.
   Preserve every existing non-PUBLIC grant. Do not infer legitimate clients
   merely from the current PUBLIC grant or assume only one client exists.
4. `terraform init`, then review `terraform plan`. Its read-only prerequisite
   checks exact hardened CA ACLs, existing application-role safety, verified TLS,
   durability and combined connection capacity **before** role creation. Failed
   prerequisites block provisioning. No CA owner, role, password, table, schema,
   signing key or instance capacity setting is changed by this root.
5. After separately authorized provisioning, publish the sensitive
   `application_dsns` output only into the fixed application runtime/native/
   migration secret versions. Supply the matching pool limit, CA identity and
   references to the daemon configuration. Bootstrap remains blocked until these
   exact application credentials exist. No administrator credential is delivered.
   Run the protected Go migration/bootstrap flow; Terraform does not manage the
   daemon ledger tables or mutate CA data.

`runtime_connections_per_node` is an integer 8..64 aggregate budget, matching
`database.max_connections` on both daemons; `min_connections` must be zero.
Each node reserves auth intake1, certificate work2 and observations1; accounting
gets floor((budget-4)/2), and export gets the remainder. The production pool
constructors and per-class process locks enforce these caps; concurrent periodic
and operator observers cannot create a second observation pool. Default8 means
2 accounting +2 export +1 auth +2 certificate +1 observation, not four pools of8.
Private-green exposes the exact deployment-bound `application_capacity` output;
green compute refuses a mismatched base YAML and renders matching values in both
configs. Disabled certificate work leaves its reservation unused, not borrowed.

The module's capacity calculation reserves two aggregate runtime budgets and two
complete protected migration pools at the configured per-node maximum, plus
four native SQL connections (the native template has max2 per node). The
explicit `reserved_ca_connections` includes existing CA demand, other approved
clients and their headroom; it is at least20. The calculation separately reserves nine private-administrator connections:
two provider pools of four (postgres and cloud8021x) plus one prerequisite
connection. Provider1.27.0 database creation holds a lock transaction while
issuing a second connection operation; max_connections=1 can deadlock, reproduced
in the disposable fixture. PostgreSQL server-reserved
slots are excluded from available capacity. This is a configuration bound, not
proof of production load headroom or permission to resize/retune the CA instance.

## Separately approved CA ACL prerequisite

Default provisioning only verifies CA access. If PUBLIC CONNECT/TEMP remains,
review the exact ACL/owner/client inventory and obtain separate approval for
hardening. Produce the nonsecret helper input without applying the module:

```sh
terraform console <<<'jsonencode(local.prerequisite)' | jq -r . > reviewed-ca-prerequisite.json
/protected/bin/cloud8021x-postgres-admin harden-ca-acl --config reviewed-ca-prerequisite.json
```

This default dry-run reads only. Once the exact operation is separately approved,
`--dry-run=false` executes it. The helper first matches both original ACLs and
owners (or their exact already-completed results); requires the connection to be
the approved database owner and all approved client roles already to exist; adds
required explicit client CONNECT/TEMP grants on both databases; then removes only
PUBLIC CONNECT/TEMP; and verifies the exact resulting owner/ACL maps in the same
transaction. Unexpected PUBLIC CREATE/grant-option, unknown changed grants,
missing roles or any mismatch aborts. Existing non-PUBLIC grants remain byte-for-
field equivalent; no schema/data/owner/role/password/capacity changes are offered.

A lost commit acknowledgement is reported as unknown, not retried as a new
operation. The read-only `check --config reviewed-ca-prerequisite.json` proves
only the exact approved final ACL state. Unknown state remains blocked. Keep the
reviewed before/after inventory as the administrator change record. This helper
is intentionally separate from VM bootstrap and never runs automatically there.

## Validation

`terraform init -backend=false` and `terraform validate` need no cloud credentials.
The development test
`C8021X_PG_FIXTURE_TASK=task10 C8021X_PG_FIXTURE_PACKAGE=./internal/provisioning scripts/test_postgres.sh`
uses only an owned disposable loopback TLS PostgreSQL16 container. It exercises
actual provider apply with a NOSUPERUSER/CREATEDB/CREATEROLE administrator, exact
least-role attributes, application-only ownership, the real Go migrations,
preserved CA ACLs and working CA sessions, forbidden app/native CA access,
wrong-CA rejection, capacity rejection, dry-run and unknown-ACL refusal. This is
not a production plan/apply or Cloud SQL load/HA acceptance claim.
