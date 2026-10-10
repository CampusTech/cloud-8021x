# Validation guidance

[The test guide](../../tests/README.md) describes the current component suites
and their prerequisites. Use actual shipping package and binary evidence when
making deployment decisions. Mock Terraform plans and golden CA/profile
comparisons establish their own bounded contracts; they do not certify installed
services or physical clients.

- [Validation scope review](scope-review.md) records the PR39 simplifications,
  measured component results and remaining staging gates.
- [Parallel runtime validation](parallel-runtime.md) records the Task 10 local
  Linux and TLS PostgreSQL checkpoint. It does not establish production readiness
  or full systemd PID 1 acceptance.
- [Daemon operations](../daemon-operations.md), [protected bootstrap](../bootstrap/README.md)
  and [release building](../releasing.md) define current runtime contracts.

Retired implementation reports and Debian 12 build evidence remain in Git history.
Their old commit identifiers and results cannot certify the current Debian 13
build. Full systemd boot/reboot, cloud KMS/IAM, production CA adoption, two-node
cutover and physical-device renewal remain separate staging gates.
