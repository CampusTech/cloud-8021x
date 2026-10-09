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
