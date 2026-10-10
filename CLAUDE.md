# Project instructions

The supported server runtime is one Go daemon, FreeRADIUS, Smallstep step-ca and Datadog Agent/DDOT on Debian 13. Policy and identity are MDM-independent; Fleet/UniFi/Meraki are adapters. No enabled server Python/Bash application, MariaDB, Okta/Jamf adapter or Datadog readback collector remains. Windows SYSTEM certificate inventory stays in `scripts/windows_certificates.ps1`.

## Deployment boundaries

- Default entrypoint/state: `terraform/green`. It owns only distinct green compute, disks, addresses, groups, firewalls, service account/scoped IAM and startup artifacts. Project/VPC/subnet/HA CloudSQL/exact CA signers/secrets/frontdoors remain read-only dependencies.
- Never apply root retirement against old production state to deploy green. Root remains only a separately reviewed fresh-install foundation configuration.
- `terraform/private-green` owns the new app DB/roles/secrets in separate private administrator state. No SQL administrator secret/grant belongs on a VM. `terraform/postgres` and `internal/provisioning` enforce private TLS, exact instance CA, budgets and existing CA ACL inventory. PUBLIC hardening is explicit and separately reviewed.
- Parallel adoption preserves CA material, server trust, provisioners, Class/challenge/broker identities and stable enrollment URLs. Empty or mismatched material fails closed. Accounting may start fresh; certificate freshness and pending external work still require authenticated handoff.
- `scripts/startup.sh` is only a mandatory-hash, authenticated, generation-pinned loader into root-private incoming paths. Never put credentials in metadata/output or introduce runtime package resolution. Go owns protected installation/rollback.
- Preparation remains passive until the authenticated activation workflow succeeds. Later NAS auth/accounting and all three EC/RSA/broker backend changes are explicitly coordinated by their existing owner. Source discovery is disabled until its exclusively green scope is ready.

## Code and validation

Use Go/Cobra, logrus structured fields, strict YAML, dry-run/debug, `goimports`, and compatible pinned `golangci-lint` before committing Go changes. Run tests relevant to actual changes. Build artifacts must carry mandatory hashes, exact provenance, correct architecture/ABI and current vulnerability evidence.

`terraform/green/tests/green.tftest.hcl` uses mock providers and synthetic state; `tests/test_green_deployment.py` checks actual serialized YAML using the Go validator. `tests/test_loader.py` executes the actual loader in an owned no-network container. `tests/infrastructure/private_postgres.py` owns its disposable TLS database fixture. Never substitute these for live acceptance or use real production state in tests.

Retired implementations and checkpoint reports remain in Git history. Independent CA/profile golden fixtures preserve compatibility checks without retaining executable legacy code. Current validation scope is documented under `docs/validation`. Follow [deployment sequencing](docs/deployment/parallel-green.md), [bootstrap](docs/bootstrap/README.md) and [daemon operations](docs/daemon-operations.md).
