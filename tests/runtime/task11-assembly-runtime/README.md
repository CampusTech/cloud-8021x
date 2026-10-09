# Task11 private runtime assembly candidates

Development-only preparation. This command reads independently pinned inputs and
writes a new private candidate tree. It does not install files, assign live
machine identities, create source keys, migrate SQL, start services, enroll a
running namespace, or produce bootstrap/activation/passive proof.

```
task11-assembly-runtime --plan /absolute/private/plan.json \
  --plan-sha256 EXACT_REVIEWED_PLAN_SHA --out /absolute/new/candidates
```

`--dry-run` performs the same input verification/rendering without writing.
`--debug` emits only public counts. Plans and finalized seed files must be owned
single-link mode0600 regular files, with no symlink in their path. Public binary
and package inputs may be readable, but cannot be group/world writable. Paths
are canonical absolute paths (on macOS use `/private/tmp`, not the `/tmp` alias).
No input tree is modified; an existing output directory is refused. Output ancestry
must additionally be owned by root or the invoking user and not group/world
writable. An output beneath `/private/tmp` is therefore refused; use a protected
private user directory or the reviewed root-owned guest control directory.
Checked no-follow directory descriptors remain held through all exclusive child
and index writes. Every retained path binding and permission is rechecked; a
substituted directory or index symlink refuses without following/truncating it.

## Independent inputs

Strict JSON `plan` uses exported Go field names:

- `Schema: 1`; `OriginalDirectory`; exact `InputSHA256` of the finalizer's
  `assembly-input.json`. The imported seed contract validates all 15 green and
  three blue credential bindings, original timestamps, CA pins and fixed DNS.
  Every `Input.Files` byte pin is verified, with an 8MiB per-file/32MiB aggregate
  bound. The original twenty-file manifest and exact source path set are checked.
- `ArtifactDirectory`; `ManifestSHA256` of actual `package-manifest.json`.
  All 62 package identities pass shipping `host.Manifest.Validate("arm64")` and
  every exact archive SHA is verified. Packages are referenced, not duplicated
  into this candidate output. Per-archive bound256MiB.
- `Application`, `Controller`, `Observer`, `Cloud`, each `{Path,SHA256}`.
  Application bytes additionally require actual Go build metadata for clean
  LinuxARM64 `cmd/cloud-8021x` at `ApplicationSourceSHA` (40hex).
  Development helpers are independently hash-pinned and are not called clean
  shipping artifacts. Each binary is bounded160MiB.
- `ObserverSourceSHA256`, `CloudSourceSHA256`, actual reviewed source receipts;
  `PrimitiveSeedSHA256`, `PrimitiveExpectedSHA256` from the independently
  reviewed primitive inputs. Having these pins does not assert primitive tests
  executed: genuine cloud verifier evidence remains required by the controller.
- `Transition`, independent fixed64hex identity; `MachineIDs` with exactly
  `blue-primary`, `blue-secondary`, `green-primary`, `green-secondary`, each a
  distinct32hex identity supplied by the builder. They are proposed physical
  bindings until verified against actual registered machines by the controller.

No receipt key is supplied/generated. The unsigned enrollment candidate has
empty node `Pin` fields and an empty passive `Manifests` map. Actual source-key
CLI, authenticated root-to-root transfer and later phase-specific manifests are
separate reviewed operations. No passive observer manifest is inferred here.

## Candidate destinations and ownership

`files/<node>/<absolute-destination-without-leading-slash>` holds candidate bytes
mode0600 inside an exclusive0700 output. `candidate-index.json` gives each exact
SHA and intended installed owner/group/mode; these modes are metadata only.
The builder must verify this index plus current source references before any
future install. Failure retains the incomplete private tree for diagnosis; only
a complete index can describe a completed preparation. Never treat it as an
installation receipt.

Each of four nodes receives staged `config.yaml`, `manifest.json` and public
`postgres-ca.pem` under `/var/cache/cloud-8021x/artifacts`, plus references to the
exact application, controller, observer and62 archives. Primary blue/green staged
config bytes are identical, as are secondary blue/green bytes. Each manifest is
derived from that exact config, original PostgreSQL CA and chosen application;
all package/collector hashes remain original. Green installed configuration,
trust, accounts, native units and services are solely the real shipping prepare's
responsibility. No green installed marker or credential cache is fabricated.

Blue receives a separate installed source configuration at
`/etc/cloud-8021x/config.yaml` and `/etc/cloud8021x-task11-source.yaml`, with database
`cloud8021x_task11_blue`, blue runtime/native roles and only the three app DB
credential mappings swapped. CA databases and preserved CA JSON remain unchanged.
The complete neutral UniFi profile is fixed to task11-console/task11-site,
sole NAS10.203.11.40/32 and VLAN120. Source policy retains its exact original
fingerprint/cache/Class paths, loopback9082 and unprivileged cloud8021x account.

The exact original source files are copied byte-for-byte. The additional native
server-cert filename and trust bundles are derived from those original bytes.
Public PostgreSQL CA is root0644 on blue so libpq can read it. The actual shipping
native renderer consumes only blue SQL credentials and this exact CA. No SQL is
contacted. The generated source FreeRADIUS unit retains shipping executable,
config directory, verify-leaf sudoers rule and native privilege settings, with
only fixture source service dependencies replacing the green daemon dependency.

Source CA units run actual `/usr/bin/step-ca` and retained CA configs. Source
webhook uses the actual shipping application copied under its supported
`acme-authz-webhook` alias and `serve`, with a protected EnvironmentFile containing
only synthetic credential values; no standalone replacement webhook is added.
Environment controls/newlines are rejected and double-quoted escapes preserved.
The source writer/timer calls the existing development `source-writer`, proving
scheduler/lock activity only. It does not renew certificates or mimic real
production legacy Python delivery.

The source tmpfiles leaf directory is0700 freerad:freerad, matching the actual
rendered native TLS writer and shipping root-helper constraint across reboot.
Source runtime credentials have protected persistent copies plus fixed tmpfiles
restore candidates for reboot. Before services, the builder must establish
cloud8021x/freerad/dd-agent and the reviewed event/spool groups, required runtime
and state directories, file ownership and parent directory permissions, native
packages, private TLS/DNS/network topology and complete original seed. Unit files
are candidates, not systemd verification or startup evidence.

## Ordered remaining execution gates

1. Actual321+26=347 package installation, empty interrupted-package audit, then
   real nspawn PID1/cgroup/network/loop/reboot canary must pass under root review.
2. Generate original seed once; finalize TLS/PG/SM/SQLAdmin/UniFi metadata with the
   separate reviewed seed helper. Freeze its exact Input and original manifest.
   Run the separate primitive cloud contract with actual requests and preserve
   its independent expected/seed pins and evidence.
3. Review concrete plan and candidate index. Builder assembles actual four roots,
   accounts, namespace enrollment, trust/DNS and private PostgreSQL topology.
   Initialize roles/databases from reviewed seed SQL. Blue schema initialization
   must call the actual shipping `postgres.NewMigration`/`Store.Migrate` API under
   a separately reviewed fixed-blue fixture operation; `state migrate` is the
   legacy publication CLI and cannot substitute for schema initialization.
   That execution operation is not implemented in this generator.
4. Execute actual source provenance preflight / controller `source-render`, native
   config validation, source policy, CA/webhook and scheduler readiness. Preserve
   exact config/source/cache/certificate hashes and original observation times.
5. Stage real shipping artifacts; verify actual physical machine IDs, app/helper
   hashes and cgroup ownership. Then real source-key/capture/transfer/prepare,
   observer manifest derivation, passive API windows and genuine reboot evidence.
6. Follow controller R123 permission-ready window and real shared activation;
   only after actual worker/PID1/SQL proof release business intake. Actual SQL
   projection, durable OTLP verification, uncertainty GET recovery, deactivate,
   passive reboot, reverse handoff and source resume remain independent gates.

Pure tests use temporary synthetic source bytes to test transformations and real
shipping renderer/config APIs. They do not validate a generated final seed,
actual installation, native packet flow, TLS connectivity, SQL or systemd boot.
The public testdata manifest is the exact existing ARM62 package inventory, not
an assertion that a test executed those archives.
