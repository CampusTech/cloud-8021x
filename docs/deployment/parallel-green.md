# Parallel green deployment

The default is a separately owned Debian 13 compute pair. No production apply, secret publication, certificate issuance, worker activation or traffic switch is performed by the implementation tests. Offline fixtures prove their stated boundaries, not production readiness.

## State and dependency ownership

| State owner | Owns | Must not own or change |
|---|---|---|
| Existing foundation | Existing project, VPC/subnet, HA Cloud SQL/CA databases, CA secrets/KMS, public IPs/TLS/frontdoor routes/backends | Green compute lifecycle or new application roles |
| Private administrator (`terraform/private-green`) | `cloud8021x_<deployment>` database, runtime/native/migration roles, three DSN secrets, separate policy/peer tokens | CA schemas/data/owners/passwords, shared settings/capacity, broad application privileges |
| Green compute (`terraform/green`) | Two named VMs, non-auto-delete protected disks, private/public reservations, unique tags/SA, scoped IAM, firewall rules, groups, private artifact bucket and objects | Old VM disks/metadata/startup objects, shared network/SQL/CA resources or frontdoor backends |
| Existing foundation, later approved change | Exactly EC, RSA and broker backend group membership | URL routes, public IPs, managed TLS identities or CA trust |

Both new entrypoints require a separately configured GCS backend. Use different reviewed prefixes, for example `radius/green-20261008/private-admin` and `radius/green-20261008/compute`, in an existing protected state bucket. Never reuse the blue prefix, copy its state, import shared resources, or apply the repository-root retirement to blue. The green service account has no state-bucket grant. State containing generated credentials is accessible only to the private administrator workflow.

The green module consumes explicit project ID **and number**, VPC/subnet names, HA SQL instance/private IP, exact single instance-CA PEM/hash, exact enabled EC/RSA signer versions, secret IDs and three existing backend names. It verifies the actual read-only project/network/SQL/CA identities and the two existing `stepca`/`stepca_rsa` databases. All secret material remains outside compute inputs/metadata/outputs. The native private SQL connection uses the exact CA pin; startup does not discover or replace trust.

Secret reading uses a custom `versions.list` + `versions.access` role bound separately to each fixed secret. SQL metadata access is only `cloudsql.instances.get`, conditioned on the exact instance [using Google's documented resource type/name](https://docs.cloud.google.com/sql/docs/postgres/iam-conditions). KMS access binds exact reviewed versions. No runtime database administrator, CA version writer, Datadog application/readback key or source-network policy grant is installed.

## Ordered preparation

1. **Foundation inventory.** The existing owner supplies exact nonsecret dependency identities and the public SQL CA bytes/hash. Inventory CA ACLs, legitimate clients and current capacity through the private administrator runner. Preserve original CA material, provisioners, Class key, broker/challenge credentials and old stack recovery evidence. Account for blue and green pools together in the reserved connection budget; do not resize SQL implicitly.
2. **Private administrator prerequisite.** Build `tools/postgres-admin` on the private runner. Supply its administrator password only through `PGPASSWORD`. `check` defaults to verifying the exact existing CA ACL prerequisite. If PUBLIC permits application access, stop for separate CA grant inventory review. Only the explicit `harden-ca-acl` command may install approved required CA client grants and remove PUBLIC access; it must retain all non-PUBLIC rights and does not touch data/settings. No Terraform plan performs hardening implicitly.
3. **Private provisioning.** Initialize `terraform/private-green` with its unique backend configuration. Set `deployment_id`, exact `project_id` and the nonsecret `private_administrator` object. After its separately approved plan/apply, use `compute_secret_references`, `local_authentication_references` and `application_identity`. The module creates `cloud8021x_<id with underscores>` and matching `_runtime`, `_native`, `_migrate` identities, without server-wide role/database creation rights or CA CONNECT/TEMP. The new application uses three DSNs and two local-authentication tokens; CA/consumer identities are inherited. If the old foundation stores only `smallstep-db-password`, optionally set `inherited_ca_password` to that exact secret ID and numeric version on the private runner. This publishes two deployment-scoped DSN wrappers using the same original `stepca` password/role, fixed `stepca` and `stepca_rsa` databases, shared private endpoint and pinned CA TLS file. It never writes/rotates the source secret or CA user. Pass `inherited_ca_dsn_references` into compute `foundation.ca_dsn_secret_ids`; otherwise explicitly supply reviewed existing full DSN secret IDs. The CA password exists only in private-admin state/new protected secrets, never compute metadata/output.
4. **Artifact/configuration review.** Build and scan the actual architecture's packages using the release tooling. Supply its complete `package-manifest.json`, independent manifest SHA256, all exact archives, signed/authenticated provenance plus independent hash, application executable/version/hash and the reviewed SQL CA PEM/hash. Pin a specific Debian 13 image, not a moving family. The loader does not install curl/CA certificates or resolve packages; the tested base must already provide the bounded loader prerequisites. Supported package closure and image acceptance are release gates.
5. **Compute plan.** Start from `terraform/green/terraform.tfvars.example`, and the nonsecret YAML in `examples/cloud-8021x-green.yaml`. Supply a distinct deployment ID, both private addresses/zones, exact blue instance identities, UTC accounting epoch and independent common 64-hex transition. The module serializes both configs with `yamlencode`, forces the correct logical/physical identities and new app DB/credential refs, and leaves discovery disabled. Build a host-architecture CLI (`go build -o /private/tmp/cloud-8021x-host ./cmd/cloud-8021x`) and set `config_validator` to its absolute path. A local Terraform external check invokes its strict `config validate` on both exact serialized configs before publication; Python is only a development/private-runner adapter and is never installed on a VM. Review that the plan creates only new green resources/scoped memberships and never updates/deletes/replaces any blue/shared owner.
6. **Passive installation.** The generation-pinned loader verifies metadata project/physical identity, root ownership, every file SHA256, bounded bytes and strict configuration before invoking `bootstrap prepare --incoming`. A missing authenticated source-transfer receipt intentionally blocks installation until the required root-to-root transfer is complete; rerun the same protected incoming preparation after transfer. It keeps previous incoming directories, never writes installed CA/config files, and never resolves packages. Budget disk space for each retained bounded bundle as well as installed rollback evidence; cleanup is a separate reviewed operator action, never an implicit deletion during failed staging. Go performs manifest/ABI/OS/trust checks, exact installed-package planning and protected publication/rollback. Passive preparation is not permission for Fleet submission, shared renewal, production data export or source firewall changes. Use the runtime's [parallel adoption workflow](../parallel-adoption.md) for authenticated source keys, certificate authorization/pending-command capture, preparation, activation and reversal.

Missing/partial CA material, an expired authorization snapshot, unknown command ownership, unreviewed CA PUBLIC rights, an incomplete package closure, or an unknown prior package archive is a blocker, not a reason to initialize new CA identities or bypass checks. Green startup must not be advertised as ready before the protected runtime workflow confirms it.

## Later activation and all three frontdoors

Retain blue VMs/disks/data and exact startup object generations throughout acceptance. Establish authenticated old-node receipt public-key pins (`blue.primary_key` / `blue.secondary_key`) before source capture. Enroll both green root public keys with `bootstrap source-key --incoming` and set `destination_public_keys.primary` / `.secondary` before freezing the final common pair manifest; those authenticated pins are required for reversible handoff. Stop/fence old external submitters/readback writers and settle or preserve every uncertain external command under the runtime's authenticated handoff. Revalidate original certificate freshness; copying bytes never refreshes their authorization age. Activate one green worker authority only after both required source receipts and actual protected native/policy/CA/collector readiness pass.

At the separately approved cutover, grant `enable_server_certificate_publication = true` only if required for ongoing server certificate renewal. It adds version-adder rights to exactly the existing RADIUS Smallstep server certificate/key cache; it never grants CA material initialization/writes or activates workers.

The `backend_switch` output has exactly `ec`, `rsa`, `broker`. In the existing production foundation state owner's reviewed configuration, replace only the `backend { group = ... }` blocks of:

```hcl
# Existing owner: google_compute_backend_service.smallstep[0] (EC)
backend { group = "<green primary instance-group self-link>" }
backend { group = "<green secondary instance-group self-link>" }
# Repeat those two group replacements for smallstep_rsa[0] and scep_broker[0].
```

Preserve backend HTTPS, health checks, security policies, URL maps, addresses and managed TLS certificates. Green named ports remain exactly **stepca:8443**, **stepca-rsa:8444**, **scep-broker:9081**. The public enrollment URLs and certificate trust do not change. Verify each backend's actual healthy state and ACME/SCEP/broker interoperability, not only group creation. Green Terraform deliberately contains no backend-service resource.

Use `nas_cutover` to switch both authentication **1812/UDP** and accounting **1813/UDP** together on each NAS. Keep static/preserved source CIDRs, WiFi-only client semantics, one UniFi credential and Sacramento VLAN opt-out. Controller discovery remains disabled until an exclusively green target scope is independently ready; do not let it patch old rules or shared policy during staging.

## Accounting and rollback

Record the explicit new collection epoch. No historical accounting import is required, no pre-epoch traffic is reconstructed, and each ongoing session's first valid report establishes its baseline. Subsequent valid reports measure intervals normally. Reports spanning the cutover may have an intentional gap; do not label fresh green totals continuous with old totals.

Rollback first blocks/fences green external/background authority using the protected runtime workflow, preserves pending/uncertain submission evidence, and revalidates blue authorization. The existing foundation owner restores all three saved backend group lists; NAS auth and accounting destinations return together. Retain green ledger/outbox/cursor evidence. Restoring endpoints does not merge accounting databases or prove lossless business telemetry. The blue disks and old history were never destroyed or overwritten.

## Offline verification

```sh
terraform -chdir=terraform/green init -backend=false
terraform -chdir=terraform/green validate
terraform -chdir=terraform/private-green init -backend=false
terraform -chdir=terraform/private-green validate
python3 -m unittest discover -s tests -p test_green_deployment.py
C8021X_LOADER_FIXTURE=1 python3 -m unittest discover -s tests -p test_loader.py
python3 tests/infrastructure/private_postgres.py
```

The Terraform test uses a mock provider and owned synthetic state: initial green creations and a subsequent all-no-op plan. No production credentials/state are read. The loader fixture is a no-network Debian container and proves execution/refusal/ownership boundaries. Private PostgreSQL testing performs real TLS, scoped-role/schema migration and CA ACL/data preservation in its owned disposable fixture only. Real package/systemd/two-node/packet/renewal/cutover acceptance remains a separate gate.
