# Native FreeRADIUS package contract

The selected security-fixed source is Debian `3.2.10+dfsg-2`, rebuilt as the
complete `3.2.10+dfsg-2~bookworm+campus3` family against Bookworm libraries.
The earlier 3.2.1 probe is a failure baseline, **not a deployment artifact**.
Never copy a patched module into another server/package ABI.

`build-bookworm.sh` is a build-container recipe, not a server runtime script.
Run it in a fresh disposable Debian 12 container with this directory mounted
read-only. It requires root inside that container and refuses other operating
systems. It enables only **source** metadata from sid; binary build dependencies
remain Bookworm. It builds every package and installs none. Its extraction,
patch application, dependency resolution and resulting selected C/packaging
files were checked against the full build used for the native gates.

Source authentication uses both signed APT metadata and the signed `.dsc`:

- `dscverify` validates the maintainer signature and both referenced archives.
- Expected `.dsc` signer: `D6E01EC516A5DFCEF71956D3775079E5B850BC93`
  (Bernhard Schmidt, Debian); signature time 2026-09-10 11:24:56 UTC.
- `source.sha256` additionally pins the exact authenticated files.
- The fixture's sid InRelease was signed by subkey
  `B8E5F13176D2A7A75220028078DBA3BC47EF2265`, primary
  `04B54C3CDCA79751B16BC6B5225629DF75B188BD` (Debian Archive Automatic
  Signing Key 13/trixie). InRelease SHA-256:
  `0c6d3bb2607dcf106976353b656c3b3abd99f22fc1a538c5094c53c136bbd917`.

Do not disable signature verification if the exact version leaves current APT
metadata. Use authenticated Debian snapshot metadata containing this version.
The captured build used moving Bookworm repositories; the `.buildinfo` records
all resolved versions. This is a reproducible source/patch contract, not a claim
that a fresh build against moving repositories is byte-for-byte reproducible.
Task 10 must pin the build image and dated binary repositories for CI/release.

## Explicit Bookworm packaging rebase

`bookworm-packaging.patch` retains Debian's configure options, hardening and
original quilt series. It removes the unavailable `dh-sequence-installsysusers`
dependency and explicitly enables Bookworm debhelper's existing
`--with=installsysusers` sequence. It permits Bookworm's `libwbclient-dev`
(unused winbind modules are not enabled at runtime) and changes newer sysusers
`u!` to Bookworm's `u` account directive. The service account remains locked and
noninteractive. This is an explicitly rebased package, not an unmodified sid
binary installation. The committed diff is the complete packaging rebase.

The tested arm64 build used Debian image ID
`sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`,
GCC 12.2, debhelper 13.11.4, libc 2.36, OpenSSL 3.0, libpq 15 and libcurl 7.88.
See `campus3-arm64.buildinfo`, `campus3-arm64-installed.tsv` and
`campus3-arm64-artifacts.sha256`. All seven deployed packages must come from
the same build: freeradius, libfreeradius3, freeradius-common, freeradius-config,
freeradius-rest, freeradius-postgresql, freeradius-utils. Other built optional
modules are not installed/enabled by this change.

The local outputs are unsigned. Task 10 must retain/sign the artifact manifest
or publish through an authenticated package repository before distribution.
Build a separate complete family and manifest for each target architecture.

## Two bounded native changes

`detail-close-error.patch` checks `ferror` and final `fclose`, propagates a module
failure and releases the existing native file handle exactly once. `/dev/full`
now suppresses Accounting-Response. This does **not** add fsync, replication,
partial-record rollback or a second spool. A NAS ACK means a successful native
buffered write/close; a subsequent power loss, disk loss or partial failed write
can still lose data or leave a bad tail. Auth-detail failure stays observational
and cannot turn an otherwise valid EAP authentication into failure.

`source-fresh.patch` adds only the zero-argument `source_fresh` xlat to rlm_expr.
The immutable client properties select a protected configuration SHA, SHA-256
of configured client ID and bounded MaxAge. Actual packet IPv4 selects the
marker; NAS attributes cannot select a path or receipt time. The fixed tree is:

```
/var/lib/cloud-8021x-source-proof/current       # regular 0644, exactly 64 hex bytes
/var/lib/cloud-8021x-source-proof/<generation>/<config SHA>/<client SHA>/<IPv4>
```

Every path component is opened descriptor-relative with `O_NOFOLLOW`, must be
root-owned and not group/world writable. The pointer and zero-byte marker must
be regular files with one link. Marker mtime is the original authenticated
observation, floored to seconds; no future marker is accepted. MaxAge is a
protected integer in 1..3600 seconds. Static clients are explicitly exempt.
Nonempty xlat arguments and missing/malformed dynamic properties fail closed.
There is no general file-stat function, per-packet command or accounting REST.

Root stages and syncs a full generation, validates/activates/converges the native
configuration and firewall, writes public source state, then atomically publishes
the regular pointer last. Identical rendered clients skip activation, retaining
validation and health checks. Rollback restores the original pointer; read-only
reconciliation checks its exact generation/content/mtimes. Original accepted
accounting records replay later without rechecking freshness against replay time.

## Installation/runtime boundaries

Task 8 installs protected directories, matching packages/configuration and fixed
service commands; Task 9 owns supervision and the HA maintenance gate for changes
that require restart. Task 6 performs neither production installation nor a live
firewall change. `native.Environment` strips inherited HOME, PG* and LD_* from
root-started FreeRADIUS. Otherwise libpq can accidentally select root's default
certificate location after dropping to freerad.

Use dedicated `cloud8021x-events` for final-auth files: directory
`freerad:cloud8021x-events 2750`, files `0640`; app reads and cannot write.
Accounting spool directory uses a distinct `cloud8021x-spool-metadata` group
with `2750`; files stay freerad `0600`. The app may list/stat but never read,
parse, remove or acknowledge accounting detail. Give the app neither `freerad`,
`shadow` nor `ssl-cert` membership. Remove unnecessary Debian-default freerad
supplementary groups when installing this EAP-only service; the tested fixture
ran final gates with freerad's event group only. The fixed certificate helper
and private verified-leaf/handoff directories retain Task 2's UID contract.

Generation retention is intentionally not automatic in this task. The root
staging directory has a 4096-entry limit and fails closed at the bound. Task 8/9
must retain current/previous/unresolved generations and clean obsolete ones
under the source lock before the limit is reached. `ExpectedProofGeneration`
derives references from original candidates plus protected configuration;
`ReconciliationEvidence.ProofGeneration` exposes the verified applied reference.
Auth generations likewise remain on disk through DB outages; Task 9 must perform
safe retention based on committed cursors instead of allowing the bounded reader
directory to grow forever.

## Development gates

`tests/native_fixture` is a development-only Go CLI. It renders real templates,
runs the actual policy service, imports final-auth events and processes the real
shared PostgreSQL ledger. `tests/native_radius_container.py` is development-only
packet orchestration; no Python file is installed as a server runtime hook.

The host entry point is:

```
python3 tests/radius_integration.py --native --container <owned fixture> --native-mode test
```

It requires a prepared container labeled `cloud8021x.test=task6` (the reserved
PR39 fixture is also accepted), no published host ports, and all seven exact
packages fully configured. It builds/copies Go binaries and uses fake/private
fixture configuration only. Additional modes: sources, full, legacy, attested,
zero, outage, replay, replay-duplicate, ports, permissions, sqltls, ipv6. IPv6 listeners are generated only
when static configured CIDRs require them; dynamic discovery stays IPv4-only.
`outage` expects the disposable PG
container stopped and saves a manifest of the three uniquely identified retained
records plus an untouched native-detail copy. `replay` expects it running again
and requires those exact receipt/source/replay identities in PostgreSQL and their
pending work drained. `replay-duplicate` additionally resubmits the retained
native records and requires two intake rows per identity but one shared-ledger
observation/outbox item. Run a fresh `outage` before each replay scenario; a
previously duplicated manifest intentionally fails the single-copy check.
These gates require `psql` in the development container and use only its synthetic
verified-TLS database credentials. Database failure, absent rows, changed context
or undrained matching work fail the gate. The main `test` mode likewise verifies
every ACKed accounting test packet reaches intake. `ports` exercises 65/128
duplicate types and the common final accept/reject context with redaction.
Each test mutates only its
explicit disposable fixture. The existing Terraform/Python legacy suite remains
available separately until Task 10 replaces release/CI wiring.

Fixture preparation uses a synthetic CA/leaf inventory generated by the native
container harness `prepare` mode; never reuse real tenant secrets. PostgreSQL 16
runs on internal port 55432 sharing the RADIUS fixture's network namespace, with
synthetic `app_native`, `app_runtime` and migration roles and verified localhost
TLS. The Go `migrate` action applies the actual ledger migrations. The task report
records the exact already-executed artifact, packet, cursor and replay evidence.

The historical Task6 implementation and packet-validation record is retained in
[the durable Bookworm validation record](../../docs/native/bookworm-validation.md).
It proves only the explicitly recorded Bookworm/campus3 artifacts and test
boundaries; it is not provenance or acceptance evidence for a Debian13 rebuild.
