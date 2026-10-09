# Private Task11 assembly inputs

This development-only helper completes the controller's synthetic original seed
before enrollment. It is not a shipping dependency, installer, readiness marker,
or authorization to start any service. The reviewed cloud helper remains the
unchanged Linux ARM64 binary with SHA256
`e6c0a5373ca718e17cf288f28095223c67dbfefa88461233ed1660ec2d5fd0d4`.

The pure functions and protected-file tests run locally. The commands require
Linux root and the protected `/etc/cloud8021x-task11-fixture` marker containing
`synthetic-only-v1\n`. They accept no configurable production root or endpoint.
`--dry-run` validates inputs without writes or requests; `--debug` emits bounded
error classifications, never secrets. No actual helper/driver execution is
established by these tests.

## Finalize before independent pins

After a separately authorized controller `seed`, and **before** enrollment,
write root0600 `/var/lib/cloud8021x-task11/control/assembly-seed-plan.json`:

```json
{
  "schema": 1,
  "seed_sha256": "SHA256 of original-seed/api/seed.json before finalization",
  "manifest_sha256": "SHA256 of original-seed/original-manifest.json before finalization",
  "collection_epoch": "explicit reviewed whole-second UTC timestamp"
}
```

The initial hashes detect input drift; they are not final enrollment pins. The
original spec must use a `task11-` project, distinct `ec.task11.test` and
`rsa.task11.test` CA DNS names (other single-label `.task11.test` names allowed),
`radius.task11.test` server DNS, supported `otlp.us5.datadoghq.com` intake, and a
32–64 alphanumeric intake API key accepted by the actual collector validator.
The Fleet bearer is already chosen by the original spec. CA DSNs must retain
`postgresql`, user `stepca`, the same preserved password, private host
`10.203.11.11`, port5432 (or default), separate `stepca`/`stepca_rsa` databases,
`sslmode=verify-full`, and
`sslrootcert=/etc/cloud-8021x/postgres-ca.pem`. The finalizer refuses incompatible
originals; it never rewrites their CA configs or observation timestamps.

Future authorized commands:

```sh
/usr/local/libexec/task11-assembly-seed finalize --dry-run
/usr/local/libexec/task11-assembly-seed finalize
```

Finalization requires the exact unused 27-file controller original tree, its
exact 20-input manifest, and absence of enrollment, stage, existing remote
state/journal, finalized output or prior finalization lock. It preserves every
original file except the explicitly completed API seed and its recomputed
20-input manifest. All inherited secret version1 bytes, original Class key,
source policy/certificate state, spec timestamps, CA configs and key aliases
remain unchanged. No observation is freshened. An exclusive permanent
`assembly-finalization.lock` prevents repeats, including after interruption;
there is no automatic repair/reset command. `assembly-input.json` is published
last, only after all output writes and the two original replacements are synced.
An incomplete or mismatched tree must never be enrolled.

Final output under `control/original-seed`:

- `api/seed.json`: immutable inherited version1 values plus complete closed green
  and blue credential sets, one exact SQL Admin route and three read-only UniFi
  metadata routes; original Fleet host/command contract unchanged.
- `api/{ca.pem,tls.pem,tls.key}`: separate synthetic API TLS identity for the exact
  Google Secret Manager/KMS/SQLAdmin, Fleet, installed/primitive OTLP and UniFi
  hostnames. Guest-only trust/DNS and source-IP preservation are separate builder
  responsibilities. No TLS verification bypass.
- `postgres/{postgres-ca.pem,server.pem,server.key,init.sql,postgresql.conf,pg_hba.conf}`:
  synthetic TLS leaf with actual10.203.11.11 IP SAN; private role/database SQL
  candidates, never executed here. The SQL creates no application tables,
  bootstrap records, epochs, receipts or success rows.
- `metadata/task11-{blue,green}-{primary,secondary}/seed.json`: separate
  non-contract metadata seed files. Each must get its own node-local server and
  journal; metadata traffic cannot become shared API peer evidence.
- `assembly-input.json`: the importable `contract.Input` handoff, exact file/pin
  map, preserved original timestamps, explicit collection epoch, closed
  credential references and separately scoped SourceCredentials. Relative paths
  resolve only against this finalized original tree. This is preparation data,
  not installed evidence.

API and PG keys/secrets/SQL are root0600 in private0700 directories. No API CA
private signing key is retained. Install public trust and protected PostgreSQL
server files later under separately approved ownership: all four nodes require
`/etc/cloud-8021x/postgres-ca.pem`; the PG service requires
`/etc/task11-postgres/{server.pem,server.key,pg_hba.conf}` (server key restricted to
the PostgreSQL account). Its generated config binds only10.203.11.11:5432.

Green database `cloud8021x_task11_green` and blue database
`cloud8021x_task11_blue` each have their own runtime/native/migrate roles and
passwords with aggregate connection limits16/4/2. Each node's runtime budget is8.
HBA allows each app database only from its matching `.21/.22` or `.31/.32` pair.
The preserved `stepca` role alone owns/connects to both CA databases, with total
limit20. PUBLIC database/schema grants are revoked. Maximum100 minus reserved3
covers both app sets44, CA20 and administrator reserve9. Real shipping migration
and native schema setup are required later for **both** databases; source
accounting never writes to the green collection epoch. Generated DSNs pass the
actual production native/TLS parser against the exact incoming CA bytes.

SQL Admin's sole exact authenticated GET reports the configured connection name,
`GOOGLE_MANAGED_INTERNAL_CA` and the exact incoming PostgreSQL CA PEM; its digest
is the handoff/config pin. UniFi routes are fixed site `task11-site`, console
`task11-console`, with a named `N/A` site and empty device/network metadata pages.
They support no discovery or mutation. The frozen static helper cannot check
`X-API-Key`: these synthetic routes **do not prove UniFi authentication**. The
real adapter supplies that header, covered separately by runtime/provider tests.
No API key is placed in route response, journal, expected projection or report.

## Separately authorized primitive traffic

Finalization creates a **separate** `control/primitive-api` tree containing its
own seed, API TLS files, private driver inputs and independent expected JSON.
It copies no installed journal/state and never creates either. A separate
synthetic TLS cert/key pair supplies the two candidate server-cache publication
payloads; API server private keys are not reused as publication inputs.

The typed primitive input fixes one original Apple host/retained command,
original enrollment/creation time, two publication payloads and a synthetic
`auth.Event`. Expected records are derived through actual `telemetry.Project`
before traffic; `otlp.Request` supplies the actual protobuf encoding. Expected
publication digests come from these independent input bytes. No expectation is
read from intake, accepted command state or a remote result. The one metric is
an explicitly synthetic primitive sample, not installed health.

Only after separately approved API service/root exposure and independent pins:

```sh
/usr/local/libexec/task11-assembly-seed primitive --dry-run \
  --seed-sha256 EXACT_PRIMITIVE_SEED \
  --input-sha256 EXACT_DRIVER_INPUT \
  --expected-sha256 EXACT_INDEPENDENT_EXPECTED
/usr/local/libexec/task11-assembly-seed primitive \
  --seed-sha256 EXACT_PRIMITIVE_SEED \
  --input-sha256 EXACT_DRIVER_INPUT \
  --expected-sha256 EXACT_INDEPENDENT_EXPECTED
```

This future driver uses verified HTTPS, no proxies/redirects, fixed approved
hostnames routed only to10.203.11.10:443, bounded responses and no retries. It
performs actual immutable Secret Manager publication+access with CRC32C; actual
Fleet host/pending/404/terminal GETs using the pinned helper's root-only scenario
command; then encoded OTLP logs and metrics. The retained command is never
POSTed. It invokes the pinned cloud helper's real primitive verifier and saves
only that verifier's actual output as `verified-result.json`. HTTP200 alone
never creates a success result. An exclusive driver-attempt lock prevents a
second run after any partial/uncertain failure.

The API service must use this primitive root in active mode during that distinct
stage, sharing the exact private root with the verifier. This helper does not
start, restart, switch or install the API service. Installed API seed and
passive peer histories are a different root/stage. Primitive result hashes may
enter enrollment only after genuine execution; generated expected files alone
are not evidence. Actual SDK KMS/project-alias behavior, installed business
outbox reconciliation, the347-package/nspawn platform, four-node operations,
passive reboots, HA, reverse handoff and complete acceptance remain open gates.
