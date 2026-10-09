# Protected Go bootstrap and recovery contract

Shipping activation requires Debian 13; existing Debian 12 nodes first need the
[separately approved staged OS upgrade](../debian13-rollout.md). Incoming fence-only
preparation remains available on the old OS. Terraform image drift does not
upgrade an existing disk and cannot authorize its replacement.

The Go helper owns installation, CA adoption, certificate renewal, native
activation, rollback and root source application. The unprivileged daemon owns
policy, discovery and durable work coordination. Root operations reopen
`/etc/cloud-8021x/config.yaml` through protected descriptors **before parsing**;
there is no arbitrary root config, package, command, URL or signing proxy.
`--dry-run` validates configuration and emits a nonsecret plan without fetching
credentials, issuing certificates, changing SQL state or restarting services.
`--debug` uses structured operation fields and never emits credential payloads.

This is an implementation contract, not production rollout approval. Runtime
`serve` orchestration is Task 9, authenticated artifact acquisition/Terraform and
legacy retirement are Task 10, and complete installed boot/crash/EAP verification
is Task 11. Existing Task 6 native and Task 7 collector evidence remains separate.

## Installation inputs and retained state

The downloader stages into the fixed root-owned, non-writable directory
`/var/cache/cloud-8021x/artifacts`. It must authenticate the release and manifest
before invoking the verified incoming executable:

```sh
/var/cache/cloud-8021x/artifacts/cloud-8021x --config /etc/cloud-8021x/config.yaml bootstrap --incoming
```

Only this selector reads `artifacts/config.yaml`. It does not accept a caller path.
Go verifies mandatory SHA256 values, package metadata and architecture, then
snapshots the **actual** active binary/config inside the shared gate. The thin
startup downloader must not overwrite active paths or implement a parallel Bash
backup/activation engine.

`manifest.json` is strict JSON with these fields:

| Field | Required contract |
|---|---|
| `schema` | `1` |
| `architecture` | `arm64` or `amd64`, equal to executing binary architecture |
| `application_version` | Bounded release identifier, required for `--incoming` |
| `application_sha256`, `config_sha256` | Lowercase SHA256 of incoming fixed `cloud-8021x` and `config.yaml` |
| `collector_sha256` | Mandatory lowercase SHA256 of the installed standalone collector executable |
| `artifacts` | Exactly the ten allowlisted product records below, each with `name`, `version`, `architecture`, `sha256` |

Archives are named `<name>_<version>_<architecture>.deb` in that directory.
The coherent FreeRADIUS family is `freeradius`, `freeradius-common`,
`freeradius-config`, `freeradius-utils`, `freeradius-rest`,
`freeradius-postgresql`, `libfreeradius3`, all version
`3.2.10+dfsg-2~bookworm+campus3`. Only `freeradius-common` may use architecture
`all`. The other packages are `step-ca`, `datadog-agent`, `datadog-agent-ddot`; Agent and DDOT versions must match.
Task 10 supplies authenticated, scanned compatible versions and all required
base-image dependencies. There is no unverified fallback, apt resolver, broad
upgrade or automatic downgrade of unrelated packages.

Before changing an installed package, Go independently reads protected dpkg
state and requires its exact prior archive in
`artifacts/rollback/<name>_<version>_<architecture>.deb`, with a protected
`rollback/manifest.json` (schema/architecture/artifact records as above).
Missing or mismatched prior archives refuse before disturbing authentication.
Only packages independently proven originally absent can be removed on rollback.
The unused `step-cli` and `step-kms-plugin` utilities are not forward artifacts.
When installed, their exact authenticated cold archives are mandatory before
protected removal. Go verifies package ownership of known executable paths,
including the official `step` alternative; unmanaged shadow copies or foreign
alternatives require explicit repair. The journal retains the removal plan and
exact prior packages for interrupted rollback. CA initialization and signing use
Go and direct KMS; `step-ca` remains the service. Historical `step_binary` values
are decoded only for protected old configuration and are never executed. Operators
who need a CLI must provide separately maintained operator tooling.

A prior native family must contain all seven matching versions or none. Old,
potentially vulnerable archives are rollback data, never the shipping default;
retain them only for the controlled rollback window, then retry the reviewed
upgrade or follow the deployment's security exception process.

Go suppresses maintainer service actions with a restored `policy-rc.d`, a
journaled native runtime mask and the official Agent installer bypass
`DOCKER_DD_AGENT=1` in the fixed dpkg-only environment. It explicitly provisions
required accounts and service files. The package mask remains held throughout
candidate preparation and validation, including daemon recovery via `Wants=`;
only guarded companion readiness releases it. Prior-generation rollback retains
the same barrier through its validation and companion readiness. No caller
environment selects executables.

Root-only `/var/lib/cloud-8021x-bootstrap/<32-hex-id>/receipt.json` contains exact
prior file bytes, ownership/modes, package plan and native tree snapshot.
`radius/` preserves Debian's original internal symlinks without following them.
The complete candidate tree is validated with real `freeradius -XC` before service
activation. Original parent ownership evidence is stored beside the receipt and
restored on rollback. Incomplete/displaced trees and receipts are retained for
reconciliation, not automatically deleted. `current.json` binds a completed
installation to actual application/config hashes. Its exact prior bytes, owner and
mode enter the root-private receipt before replacement. A rename or directory-sync
failure rolls back that binding with the prior credential cache and installed files.
Once publication is durable, the live transaction refuses further rollback. Receipt
phase `complete` records successful activation; the matching durable `current.json`
and credential-cache binding establish installation publication. A receipt alone is
not permission to retry or undo an installation.

Result output occurs after the shared maintenance gate completes. A closed output
pipe reports a delivery error without rolling back installed state or marking the
journal uncertain. Lost database completion acknowledgement still leaves shared
maintenance uncertain and blocks subsequent changes; no retry or new generation is
automatic. Explicit future rollback of a completed installation requires a new
coordinated transaction, not replaying its old receipt.

Discovery-enabled bootstrap and renewal prepare only the fixed
`/etc/cloud-8021x/sources/clients.conf` include. Missing parents are safely created;
only a missing include is initialized. An existing protected include remains exact,
and unsafe or unreadable existing files fail closed.

## CA trust, secrets and boot credentials

The YAML `bootstrap` section in [the example](../../examples/cloud-8021x.yaml)
requires the pinned project ID **and numeric project number**, two exact KMS
versions, EC/RSA DNS names and root-only staging secret references. GCP adapters
bind returned canonical resources to that exact ID/number pair and suffix, and
verify Secret Manager and KMS CRC32C fields. Enabled-version queries use Google's
newest-first filtered first page, at most 100 entries; an empty result with a next
page token is refused. Errors, denied access and unreadable versions are never
interpreted as missing.

The EC/RSA roots, KMS intermediates and software SCEP decrypter cert/key pairs
are adopted after topology, key, algorithm and validity checks. A new root private
key exists only transiently in memory and is never journaled or written locally.
Before publishing **any** shared component, the immutable complete public
certificate/SCEP-private-key bundle is durably written and read back from its
fixed root-only Secret Manager staging secret. Root-private PG records only the
exact definition/KMS-public-key digest, staging hash/reference/version and
publication status. Intermediate publication remains last. A second node can
recover the original bundle after first-component publication and root signer
loss. Partial old state without its matching staging journal is refused; no new
root or trust replacement is inferred. Ambiguous staging publication retains the
expected hash and requires explicit evidence reconciliation of the original
bundle. Intentionally deleted root key files stay deleted.

Step-ca remains the client ACME/SCEP server, preserving `stepca` and `stepca_rsa`
databases with the existing `stepca` user. Bootstrap verifies that runtime/native
roles have neither CONNECT nor TEMP on either database and that stepca access
remains. Database migration must already use the intended dedicated migration
role, not Cloud SQL's default powerful role. Optional Cloud SQL instance-CA mode
verifies the exact instance identity, internal CA mode and PEM SHA256.

The RADIUS leaf is signed directly by the existing EC KMS intermediate with the
fixed DNS/serverAuth profile. No new JWK provisioner/secret is introduced.
Protected local and Secret Manager caches require matching issuer/key/SAN/usage;
malformed, partial, unsafe-permission or unreadable caches require recovery.
A healthy local leaf can be adopted when both remote cache objects are genuinely
absent. Valid leaves renew below 30 days; remote partial publication is refused.

Only the legacy loopback webhook leaf is self-signed: EC P256, CA=false,
serverAuth, localhost and 127.0.0.1. A valid existing pair is adopted; missing-both
can initialize; renewal uses the same guarded activation/trust refresh. This is
not a RADIUS or device CA fallback. Webhook client mTLS requires the complete
preserved trust bundle and both configured EC/RSA CA DNS names.

Secret mappings select exactly `root`, `runtime` or `collector` ownership under
`/run/cloud-8021x-root`, `/run/cloud-8021x/credentials` or
`/run/cloud-8021x-collector`. Generated webhook/env/marker paths cannot be mapped.
The daemon cannot read CA keys, root migration/native credentials, collector
credentials or root recovery files. Its UID cannot reach GCP metadata endpoints
(including IPv6/mapped variants), except TCP/UDP53 for metadata DNS. It has
NoNewPrivileges, no capabilities and no sudo/service-control permission. The only
sudo rule is the fixed native `radius verify-leaf` certificate handoff.

Bootstrap pins the entire credential set in root-only
`/var/lib/cloud-8021x-bootstrap/active-credentials.json`, bound to the receipt,
application/config and complete managed native tree hashes. Private bytes remain
**local**, never in PG. The root-owned volatile
`/run/cloud-8021x-root/credential-set.json` marker validates the exact staged set
during activation. At reboot, the required credential unit restores only the
completed set offline; it never refetches latest or needs PG/Secret Manager.
An interrupted/unbound candidate or changed native/config bytes prevents startup.
Out-of-band live credential edits fail verification instead of being overwritten.

Explicit bootstrap owns credential rotation under the shared gate. Certificates
renew and root sources apply retain committed app/native/health/Fleet/DB bytes;
renewal may access its fixed PKI secrets/KMS. Existing Class signing bytes may not
change: that requires a separately designed migration. The legacy Secret Manager
object is `radius-accounting-key`. Before any stop, existing
`/run/radius-accounting-key` bytes must match exactly. Its ownership is changed
transactionally from freerad to the app, with exact old ownership restored on
failure. The fixed `/etc/systemd/system/freeradius.service.d/accounting-key.conf`
is snapshotted and replaced with a comment to remove the old boot refetch
relationship; failure restores its exact contents. Task 10 subsequently retires
`radius-accounting-key.service` and `/usr/local/bin/radius-accounting-key.sh`.
State migration retains the original shared key when importing legacy Class bindings. Secret Manager revocation
alone does not erase a committed local boot cache; emergency revocation/rotation
must coordinate backend credentials, guarded bootstrap and service activation.
Protect root-local LKG/cache backups with the same controls as the original keys.

## Activation, availability and explicit recovery

`bootstrap_private.maintenance` is root-owned, inaccessible to runtime/native
roles. Every external operation enters a durable started record before I/O.
Loss of lease, cancellation, process death or ambiguous completion leaves work
uncertain. Time passing never reclaims it. Nested operations share only their
live parent scope. PG installation metadata is an opaque receipt reference;
serialized file snapshots, private CA keys, SQL/Fleet/RADIUS credentials and private
configs are not accepted as journal data.

Before stopping active local RADIUS, the helper requires an authenticated private
UDP Status-Server response from the configured peer and a nonce-bound HMAC HTTP
readiness response matching shared policy/config, trust and server DNS, with
`Ready=true`. HTTP success alone is insufficient. Unknown peer state refuses.
Proven-stopped local startup instead requires inactive/dead/MainPID=0 plus
exclusive authentication/accounting/private-status listener binds.

Guarded activation stops native listeners before replacing the synchronous policy
dependency, keeping a journaled runtime native mask. It then refreshes system
trust, restarts the daemon, waits for signed local readiness, restarts both CAs,
verifies their pinned TLS `/health`, and starts the collector. Only then does it
unmask and start RADIUS, verifying actual native and signed local readiness.
Failure restores prior artifacts, packages, native tree, credentials and ownership
before activating the **known prior Go configuration**. Caller cancellation does
not abandon necessary rollback, which has its own bounded context. Failure to
prove safe rollback retains uncertainty rather than reporting success.

The fixed boot/recovery units are:

- `cloud-8021x.service`: Type=notify, NotifyAccess=main, 30-second startup limit,
  Restart=on-failure, Wants=freeradius.service; unprivileged and without sudo.
- `freeradius.service` drop-in: After/Requires/BindsTo=cloud-8021x.service, plus
  required committed credentials. App loss stops native; automatic app restart
  schedules native startup only after READY. The maintenance runtime mask prevents
  that Wants relationship from bypassing guarded activation.
- `cloud-8021x-credentials.service`: offline exact committed credential restore;
  `cloud-8021x-metadata.service`: fixed metadata deny/DNS exception rules.
- Root `cloud-8021x-renew.service` and hourly randomized renewal timer.
- Root `cloud-8021x-sources.service` and one-minute source timer. The fixed root
  command uses the durable per-node claim, StartAttempt and exact persisted
  candidate SHA before its protected action; the daemon writes candidates only.

The daemon emits READY=1 only after the policy and private readiness listeners
are actually available with fresh observed policy/certificate readiness. The
private readiness handler is `native.ReadinessHandler`; fixed private HTTP18122
allows only configured local/peer IPv4 addresses, with a separate shared health
secret. UDP18121 is restricted to the same peers; public1812/1813 do not expose
Status-Server. Task 10 must install matching private network rules. Full systemd
boot/daemon-crash/recovery behavior still requires Task 11's real unit-manager test.

For the **first legacy pair** there is no new signed readiness endpoint on the
remaining legacy peer. The narrow prerequisite is a separately approved operator
check of real EAP/failover on that peer, CA/policy readiness and spool preservation;
then deliberately stop only the migrating node's legacy native/app/listener units
and old writers, retaining files, unit state and ownership evidence. Go separately
refuses occupied replacement listener ports. This path is not zero-impact.
If initial activation fails, Go restores snapshotted files/packages/ownership and
leaves the originally stopped legacy services stopped. Manual rollback reinstates
the retained legacy units/ownership and starts only that node after rechecking the
remaining peer and preserved data. No unknown legacy code is automatically started.
The first upgraded node needs real EAP and new authenticated readiness before a
normal second-node upgrade. Task 9 owns writer fencing/import; Task 10 owns the
explicit legacy retirement/manual rollback runbook. No spool or ledger deletion.

Uncertain maintenance requires proof the original helper is quiescent and
read-only comparison against the exact local receipt, shared CA staging/version,
installed files/packages, service/listener state and firewall/source evidence.
`Store.ReconcileMaintenance` takes the exact attempt ID and a verifier receiving
`MaintenanceEvidence{Operation, Installation}`; it only permits expired unresolved
attempts and never retries their mutation. There is intentionally no generic
shell, SQL or arbitrary-path repair proxy. Do not mark a receipt complete or clear
an uncertain attempt solely to retry. Original staging publication ambiguity must
be resolved to its exact original hash/version before another node resumes.

## Source and observability installation

Root source apply independently revalidates configured pinned controllers and
scope, consumes the fixed candidate plus `--candidate-sha256`, and uses the shared
maintenance gate and actual peer health before native restart. It can patch only
the fixed node firewall source ranges, with a deny sentinel for the empty set.
Existing source claims/quarantine are not bypassed. Proof retention preserves
current, previous, every unresolved persisted reference and incomplete staging;
it validates every removal and never changes original observation timestamps.
Unknown/malformed references or bounded-query overflow stop cleanup/application.

Fixed source paths remain `/etc/cloud-8021x/sources/clients.conf`,
`/var/lib/cloud-8021x-source-state/state.json` and
`/var/lib/cloud-8021x-source-proof`. Bootstrap creates an empty discovered-client
include only when genuinely absent. The integrated command uses SourceCoordinator
and the exact canonical persisted candidate payload before invoking this root action.

The Agent YAML merge preserves host checks/tags and removes duplicate legacy
application/auth/accounting/source/bootstrap log tails from the native integration.
Agent/DDOT use collector-only `/run/cloud-8021x-collector/datadog.env`; no inline
API key is written to their YAML. Fixed standalone collector:
`/opt/datadog-agent/embedded/bin/otel-agent`, `datadog-agent-ddot.service`,
`/etc/cloud-8021x/ddot.yaml`. Agent and DDOT each have a 768MiB unit limit.

The dedicated persistent ext4 image
`/var/lib/cloud-8021x-bootstrap/collector.ext4` is 512MiB and mounts at
`/var/lib/cloud8021x/collector` through `var-lib-cloud8021x-collector.mount` with
loop,nodev,nosuid,noexec. DDOT's fsync queue is
`/var/lib/cloud8021x/collector/queue`, configured at 64MiB inside that hard limit.
An existing image is validated/adopted, never reformatted or truncated. Queue
records survive installation rollback. Full/corrupt/incomplete storage is explicit
failure; do not delete queued business records to recover space.

`doctor` observes actual native + signed policy, both CA TLS health endpoints,
read-only PG delivery state, actual collector process plus loopback transport,
and metadata-only accounting spool state. `metrics emit` exports these bounded
observations through the existing OTel SDK. Unknown observations are omitted,
never fabricated uptime or successful remote business delivery. Collector process
and transport availability is not a Datadog receipt.

## Artifact provenance and evidence boundaries

The separate Debian DDOT package/service/path and installer bypass are grounded
in official Datadog Agent tag `7.82.0`, commit
`ffd5b5759900f0d00080dab5e2e6aeebc0a9c14d`:

- [Standalone DDOT package compatibility mapping](https://github.com/DataDog/datadog-agent/blob/ffd5b5759900f0d00080dab5e2e6aeebc0a9c14d/pkg/fleet/installer/packages/datadog_agent_ddot_linux.go)
- [Official DDOT service](https://github.com/DataDog/datadog-agent/blob/ffd5b5759900f0d00080dab5e2e6aeebc0a9c14d/pkg/fleet/installer/packages/embedded/tmpl/gen/debrpm/datadog-agent-ddot.service)
- [Agent postinst](https://github.com/DataDog/datadog-agent/blob/ffd5b5759900f0d00080dab5e2e6aeebc0a9c14d/omnibus/package-scripts/agent-deb/postinst), [DDOT postinst](https://github.com/DataDog/datadog-agent/blob/ffd5b5759900f0d00080dab5e2e6aeebc0a9c14d/omnibus/package-scripts/ddot-deb/postinst)

Task 10 must authenticate and scan the actual matched Debian package versions,
record every archive and installed collector SHA, and run affected shipping-binary
config/projection/queue tests. The existing [Task 7 full-container evidence](../telemetry/README.md)
does not certify these Debian archives. There is no vulnerable/default fallback.

Task 8 targeted local proofs are reproducible with
`scripts/test_bootstrap_isolation.sh`, `scripts/test_bootstrap_native.sh`,
`scripts/test_bootstrap_storage.sh`, and selected tests through
`C8021X_PG_FIXTURE_TASK=task8 scripts/test_postgres.sh`. Each creates/removes only
its own labeled disposable Linux/PostgreSQL fixture. The native fixture consumes
seven SHA-verified retained campus3 arm64 archives and uses actual native Status
and signed local policy; its peer condition is injected, not a two-node EAP proof.
Its failed collector activation restores actual prior native/policy readiness.
Package rollback uses actual dpkg with synthetic fixed allowlisted package payloads
and tests maintainer suppression; it is not shipping Agent/Smallstep packaging
certification. The storage fixture tests actual loop mounts and ENOSPC on its own
image. No host services, production cloud, Fleet, vendor or Datadog endpoints are
mutated. The SCEP fixture uses Go-rendered product config and actual local step-ca;
its local signer substitute does not certify production KMS or Cloud SQL.

For the integrated daemon import/publication, cold rollback export and retained-work procedures, see the [daemon operator runbook](../daemon-operations.md). Source scheduling now uses the protected per-node claim and exact persisted candidate before the root action; the installed timer is enabled only through that guarded integration.
