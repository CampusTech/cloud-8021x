# Historical implementation validation

These reports preserve the original implementation evidence and its original
scope. Their status, commit identifiers, package versions, commands and results
refer to that checkpoint; they do not certify the current shipping build or
replace final Debian 13 package, binary security, systemd, packet, two-node and
rollout acceptance. The report files were relocated without changing their bytes.

- [Policy, identity and hardware VLAN encoding](policy-identity.md)
- [PostgreSQL accounting and durable ledger](postgres-accounting.md)
- [Fleet inventory and certificate collection](fleet-certificates.md)
- [Network adapters and source authority](network-sources.md)
- [Historical Bookworm native packet validation](../native/bookworm-validation.md)

Current contracts live in [daemon operations](../daemon-operations.md),
[protected bootstrap](../bootstrap/README.md), and
[release building](../releasing.md). Use their current prerequisites and the
actual shipping artifact evidence for deployment decisions.

[Parallel runtime validation](parallel-runtime.md) records the Task 10 local Linux and TLS PostgreSQL fixtures. It does not establish production readiness or full systemd PID 1 acceptance; those remain separate deployment gates.

[Validation scope review](scope-review.md) records the PR39 harness reduction,
the small reproducible integration entrypoint and remaining staging gates.
