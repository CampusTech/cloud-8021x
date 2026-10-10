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
source directory. Production behavior is unchanged by this cleanup.

## Application audit

The core already separates device inventory, network inventory/VLAN signaling,
policy, native FreeRADIUS, CA, storage and OpenTelemetry. No production Go package
imports the removed test harness. No active Okta or Jamf adapter was found.
Keep Fleet, UniFi and Meraki behind their domain interfaces. Preserve authenticated
CA adoption, certificate freshness, pending Fleet command handoff and worker
fencing when simplifying the deployment code.

Concrete remaining simplifications identified during the source audit:

- The old executable basename selects an environment-configured webhook runtime
  in `internal/app/compatibility.go`. Its removal must also update release aliases
  and retained SCEP compatibility tests; shared protocol handlers stay.
- In-place state capture/import/export and its MySQL client are still compiled
  although the approved green deployment rejects those operations. Remove their
  public routes before pruning implementations; parallel source capture still
  needs some of the same certificate-state and writer-fencing code.
- Legacy usage import adds a baseline query to each accounting event. Once the
  in-place importer is removed, its accounting schema and baseline gate can go;
  green epoch isolation, session locking and deduplication must stay.
- Legacy display cache loading is needed only by in-place bootstrap. Remove its
  writer and loader together while retaining controller-based VLAN/AP metadata.

These are source-audit findings, not completed product changes or evidence that
production is affected. This cleanup intentionally does not redesign those
shared paths while removing the failed validation machinery.

## Recovery verification (2026-10-10)

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
