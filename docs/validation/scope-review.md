# PR39 validation scope review

## Decision

The custom installed-VM acceptance harness grew into a separate application.
At `319ba6c`, PR39 contained 108 commits and 1,031 changed files; `tests/runtime`
alone held 362 files and 46,553 added lines. It had not passed the full installed
migration/failover/rollback chain. These figures describe that checkpoint, not
the current diff.

Remove that harness and its orphan cloud simulator. Preserve only the short
parallel and monitoring runners, relocated into `tests/integration`, and reuse
assertions in `internal` and the existing package/packet/Collector/SCEP tests.
A thin entrypoint and ordinary CI jobs replace the VM controller, custom image
assembly, evidence-publication state machines and scenario-specific executables.
Git history preserves the removed work; it is not copied into another active
source directory. The harness removal did not change production behavior. The subsequent
application cleanup below changes only the implementation under review; nothing
has been deployed.

## Application audit

The core already separates device inventory, network inventory/VLAN signaling,
policy, native FreeRADIUS, CA, storage and OpenTelemetry. No production Go package
imports the removed test harness. No active Okta or Jamf adapter was found.
Keep Fleet, UniFi and Meraki behind their domain interfaces. Preserve authenticated
CA adoption, certificate freshness, pending Fleet command handoff and worker
fencing when simplifying the deployment code.

The application cleanup removes the environment-configured webhook basename
entrypoint and release aliases, in-place capture/import/export CLI and their
MySQL dependency, legacy usage baseline queries, and imported display-cache
loading. Shared protocol handlers, signed parallel source capture, current
worker-state receipts and pending-command recovery remain. The startup loader
uniformly invokes `bootstrap prepare --incoming`; unsupported nonparallel
configuration fails before installation.

Original certificate-state decoding and fixed-path read-only capture remain for
CA/identity adoption. The protected current downgrade marker is deliberately
root-written during adoption; it is not an immutable imported cache. No database
migration drops inherited tables or changes an old production database. Version
4 is reserved without the obsolete accounting-baseline DDL.

## Harness-removal verification (2026-10-10, `e31cef1`)

- Root `go test -race -count=1 ./...`: 41 tested packages pass; fixture-gated
  integration assertions are reported separately below.
- Compatible pinned `golangci-lint`: zero issues. Root imported-package/test
  `govulncheck`: no vulnerabilities found. Both-architecture executable/alias
  checksum test and nine replay-gate regression tests pass.
- `tests/integration/run.sh postgres`: 81 top-level tests pass against owned
  PostgreSQL16 fixtures, including real TLS, process death, ambiguous commits,
  concurrent workers, CA ACL preservation, isolated Terraform provisioning,
  signed green handoff and assembled-daemon database outage/cancellation.
  The separate mock-Terraform CA-wrapper test remains opt-in and was skipped.
- ARM64 packet fixture: actual EAP-TLS, unknown/ambiguous certificates, signed
  accounting context, failed-write noACK, policy/database outages, retained
  replay, duplicate usage/outbox prevention and real expired-account sudo
  restrictions pass. The same 160-line runner/container recipe also passes
  the actual packaged step-ca SCEP suite on both Badger and TLS PostgreSQL.
- Relocated monitoring fixture: real Agent OpenMetrics/HTTP/process checks,
  native statistics, both CA endpoint checks, wrong CA/hostname rejection
  and signed-handoff tampering assertions pass.
- Independent review of the recovery delta found no material correctness or
  safety findings. Its missing Terraform prerequisite was added to the docs.

Two retained PostgreSQL security tests initially stopped at the newer constructor
identity check. Test-only fixes now assert both constructor and migration guards
and independently inspect the unchanged CA sentinel. No runtime guard was relaxed.

New CI jobs run the real database suite and both-architecture native suite;
superseded PR revisions are canceled. CI results apply to their own revision,
not automatically to these local results. No full systemd boot is claimed.

## Acceptance limits

Automated integration has separate observable results for PostgreSQL, native
packets, CA issuance, Agent checks and DDOT persistence. A result in one suite
cannot establish the others. `tests/README.md` lists reproducible commands and
what each suite measures. Missing tools/archives are failures of prerequisites,
not successful tests or reasons to fabricate acceptance receipts.

Full systemd boot/reboot, real cloud KMS/IAM, inherited production CA adoption,
both-node cutover/failover and physical client profile/renewal acceptance remain
staging gates. Preserve old production and its CA state until those pass. This
PR does not deploy, switch traffic, merge, publish a release or apply Fleet GitOps.

## Application cleanup and review (2026-10-10)

The broad subsystem review found three correctness issues in the parallel path:
ordinary preparation did not produce the auth attestation required by renewal;
the first pending certificate refresh discarded inherited observations; and
closed auth-generation pruning had no production caller. Regression tests first
reproduced renewal attestation failure with the actual native producer and
identity loss through signed import, PostgreSQL, Fleet collection and inventory
publication. These are implementation findings, not reports of a production
incident.

The fixes preserve those boundaries:

- Completed preparation independently records exact native configuration hashes.
  Renewal validates the completed receipt and current module before accepting a
  restarted or proven-stopped producer. Those cases retain uncertain logs and
  supply no fabricated closure evidence. Tampered, incomplete and malformed
  attestation still blocks renewal.
- Signed source imports retain certificate observations in a separate cache that
  runtime can only read. The current authenticated Fleet enrollment, source,
  trust, platform and Windows script binding must match. Original observation
  age and certificate expiry still apply; imports create no collection work.
  Peer ordering preserves original attempt cadence, including new enrollments
  with no result. Equal-activity conflicting bindings fail closed. A real empty
  result replaces inherited authority and preserves the existing real-receipt
  tie order.
- Renewal wires pruning into its already required protected stop. Pruning needs
  native process exit, completed closure evidence and a committed EOF cursor.
  Actual current, next, rollback, unconsumed and uncertain generations survive.
  The separate rollback backend has no pruning callback.

Application cleanup verification:

- Full root `go test -race -count=1 ./...`: 38 tested packages pass. Fixture-gated
  assertions are exercised separately, not counted as unit-test acceptance.
- `tests/integration/run.sh postgres`: the complete entrypoint passes with owned
  TLS PostgreSQL fixtures, including signed import/activation, first inventory
  refresh, current-binding/expiry/cadence checks, peer ordering, privilege
  isolation, real empty receipts, CA ACL/provisioning and assembled-daemon
  outage/cancellation.
- Actual ARM64 native auth-retention fixture passes with fresh attestation,
  restarted and stopped producers, invalid receipts, current/rollback exclusion
  and unconsumed/uncertain log preservation. The writer-fence/read-only source
  fixture, native EAP-TLS/accounting outage/replay and packaged step-ca SCEP
  suites also pass.
- Pinned `golangci-lint`: zero issues. Imported-package/test vulnerability scan:
  no vulnerabilities. Canonical both-architecture release/provenance checks and
  all eight loader scenarios pass; unsupported nonparallel configuration is
  refused before installation.
- Bounded independent final review found no remaining blocker after the
  test-reproduced renewal, inheritance, retention and peer-order fixes. Stale
  in-place Debian instructions and passive-readiness claims were corrected.

These are local component results for the application code in this cleanup
commit. GitHub CI must independently validate the pushed revision. The PR now
changes 628 files, down from 1,031 at the oversized-harness checkpoint. No new
VM controller or replacement acceptance framework was added. Broad subsystem
review does not imply line-by-line approval of every changed file.

Actual cloud IAM/KMS, full systemd lifetime, inherited production CA state and
physical client/cutover acceptance remain outside the local suite's scope. No
production deployment, traffic switch, Fleet apply, merge or release was performed.
