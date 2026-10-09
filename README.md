# cloud-8021x

Two-node certificate-based WiFi authentication on Google Cloud. FreeRADIUS handles EAP-TLS and native PostgreSQL accounting; one Go daemon owns policy, verified identity, inventory, collection, enrollment authorization, metadata and telemetry. Smallstep remains the EC ACME/RSA SCEP CA, and Datadog Agent/DDOT handles host monitoring and durable OTLP delivery.

The default deployment is a **new parallel Debian 13 compute stack** in [`terraform/green`](terraform/green), with its own state, two VMs/disks/IPs, service account, firewall targets and application database. It adopts the existing CA identities and enrollment frontdoors while starting a new accounting epoch. The old stack and accounting history remain intact.

**Never apply the repository-root retirement configuration to the old production state to deploy green.** That root is a separately reviewed fresh-install foundation configuration. Green consumes existing foundation resources as exact read-only dependencies and does not own their lifecycle. No default plan changes enrollment backends or activates background workers.

Start with the [ordered deployment and cutover guide](docs/deployment/parallel-green.md). The separate [private database provisioner](terraform/private-green) creates least-privilege application roles and protected credentials on an administrator runner; administrator credentials never reach the VMs. Existing CA database PUBLIC ACLs must pass the explicit inventory gate before provisioning. CA permission hardening is a separate, reviewed operation.

## Runtime contracts

- MDM-independent core identity and policy; Fleet, UniFi and Meraki are adapters. A certificate must have fresh, verified authorization evidence. Subject names and NAS-supplied location claims do not confer trust.
- WiFi-only clients, explicit static/preserved client CIDRs during preparation, one UniFi API credential, and per-location VLAN opt-out (including Sacramento).
- Preserve existing EC/RSA roots, intermediates, decrypters, exact KMS versions, CA databases, server trust, provisioners, Class key, broker/challenge credentials and stable URLs. Missing or inconsistent CA state refuses adoption.
- New accounting begins at an explicit epoch. An ongoing session's first valid report is a baseline; old traffic is not reconstructed. The history waiver does not waive certificate freshness or unresolved external-command ownership.
- Root installation consumes a bounded authenticated package closure, independently pinned application and manifest, strict YAML, and exact PostgreSQL CA PEM. The thin startup loader stages protected incoming artifacts; Go owns installed-file publication and rollback. There is no runtime package resolver, generated Python, shell application, Okta/Jamf adapter, MariaDB writer, or Datadog log-readback collector.

## Development

```sh
go test ./internal/config ./internal/provisioning
terraform -chdir=terraform/green init -backend=false
terraform -chdir=terraform/green validate
python3 -m unittest discover -s tests -p test_green_deployment.py
C8021X_LOADER_FIXTURE=1 python3 -m unittest discover -s tests -p test_loader.py
```

The loader test uses an owned Debian container without network access or published ports. [Private PostgreSQL tests](tests/infrastructure/private_postgres.py) exercise actual TLS, CA ACL preservation and Terraform role/database creation against a disposable container, without publishing host ports. They require direct access to that container's private IP (provided by OrbStack on macOS).

See [daemon operations](docs/daemon-operations.md), [protected bootstrap](docs/bootstrap/README.md), [release construction](docs/releasing.md), [profile examples](examples/README.md), and [historical validation](docs/validation/README.md). Retired server implementations are development-only fixtures under [`tests/legacy`](tests/legacy); their evidence does not certify shipping artifacts.
