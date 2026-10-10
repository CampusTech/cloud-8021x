# Native FreeRADIUS package contract

## Debian13 shipping family

The current family is **3.2.10+dfsg-2+trixie.campus4** on amd64 and arm64,
from the authenticated Debian3.2.10+dfsg-2 source pinned in `source.sha256`.
`scripts/build-debian.sh native ARCH EMPTY_OUTPUT_DIRECTORY` uses pinned Debian13
image/immutable20261008T000000Z Debian and Debian-security metadata, verified
signatures and exact Release hashes. Its native recipe builds at an invariant
source path and fixed changelog timestamp: upstream embeds compiler diagnostic
flags, so a random temporary build path would change two output archives.

Only `detail-close-error.patch` and `source-fresh.patch` are applied.
Actual stock Trixie3.2.10 still emits Accounting-Response after `/dev/full` failure;
its version number is insufficient to remove the close-error patch. The tested
source freshness check preserves the original packet receipt deadline, including
a request delayed across expiry, and is retained until a replacement has the same
packet/security/rollback proof.

`scripts/build-debian.sh dependencies ARCH EMPTY_OUTPUT_DIRECTORY` acquires only
the explicit static `trixie-dependencies.txt` allowlist from the same authenticated
snapshot. This is development/CI acquisition, never on-node apt resolution.
`scripts/build-bundle.py` verifies complete mandatory input hashes and exact
package identities; the protected Go installer verifies dependency compatibility,
keeps already satisfied dependencies unchanged, requires exact cold archives for
changed installed packages, and rejects unreviewed base/helper replacement.
The supported image must already supply compatible libc, libssl, systemd,
perl-base and other OS base packages; application publication cannot upgrade them.
The base must also already provide compatible sudo. Debian refuses to remove a
new sudo package on a locked-root system, so protected preflight rejects its
original absence before mutation; it never bypasses that removal safeguard.
The reviewed closure contains52 dependency archives plus10 product archives.

`tests/native_package_acceptance.sh ARCH VERIFIED_BUNDLE_DIRECTORY` uses a clean
networkless Debian13 fixture and the actual protected package planner/installer,
then exercises loaded ABI, successful accounting, failed-close noACK and original
source-receipt semantics. A helper exits after installation; recovery uses the
persisted package plan to restore the exact prior inventory. The separate
systemd/two-node/whole-policy acceptance gates still apply. Packages are produced
locally/CI, with mandatory hash manifests and provenance; this task publishes none.

The existing bootstrap harness also requires the current complete bundle:
`scripts/test_bootstrap_native.sh ARCH VERIFIED_BUNDLE_DIRECTORY`. It keeps the
actual native status/private health, policy activation ordering and maintainer
suppression/exact rollback assertions. It creates its own labelled networkless
fixture; no historical container supplies binaries. Missing or tampered bundle
inputs fail before Docker is accessed. The development base supplies pinned
iproute2 solely for its isolated loopback-address tests.

For the broader prepared native packet fixture, set `C8021X_NATIVE_BUNDLE` to
that verified bundle before running `tests/radius_integration.py --native`.
The explicitly selected container must be Debian13, carry `cloud8021x.test=task10` (or `task11`),
`cloud8021x.disposable=true` and `cloud8021x.bundle.sha256` equal to the package
manifest hash, have no published host ports, and contain the exact matching
native family. The runner never provisions or borrows a historical container.
Its full PostgreSQL/EAP preparation and acceptance remain separate.

`scripts/test_auth_retention.sh ARCH VERIFIED_BUNDLE_DIRECTORY` uses the same
verified inputs for real cached-descriptor, stopped-producer, privacy, generation
retention and clock-rollback assertions. Its development-only pinned libfaketime
selects the target architecture; process identity still requires the exact
protected service command. Architecture emulation that changes `/proc` arguments
cannot substitute for the native-architecture CI process-identity gate.

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

## Runtime boundaries and validation

Native FreeRADIUS runs separately from the daemon. Final-auth files use a dedicated
`cloud8021x-events` group: directories are `freerad:cloud8021x-events 2750` and
files are `0640`; the daemon reads and cannot write. Accounting spool directories
use a distinct `cloud8021x-spool-metadata` group with `2750`; files stay freerad
`0600`. The daemon may list/stat those files but never reads, parses, removes or
acknowledges accounting detail. Native replay writes the shared PostgreSQL intake.
The daemon has no `freerad`, `shadow` or `ssl-cert` membership.

Protected installation strips inherited HOME, PG* and LD_* from native processes,
preserves CA identities and credentials, and uses the HA maintenance gate for
restart-requiring changes. Auth retention requires a stopped producer, completed
closure evidence and a committed EOF cursor. Current, rollback, unconsumed and
uncertain generations remain protected.

[The test guide](../../tests/README.md) lists the existing native package, packet,
PostgreSQL, SCEP and monitoring entrypoints. `tests/native_fixture` and
`tests/native_radius_container.py` use synthetic tenant data in explicitly owned,
disposable containers. No Python test file is installed as a runtime hook.
Those component tests do not replace systemd boot/reboot, cloud IAM/KMS,
production CA adoption, two-node cutover or physical-device acceptance.

Retired Debian 12 build recipes and their checkpoint reports remain in Git history.
They are not inputs or acceptance evidence for the current Debian 13 family.
