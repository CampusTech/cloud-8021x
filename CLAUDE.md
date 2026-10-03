# CLAUDE.md

## Project Overview

This repo deploys primary and secondary FreeRADIUS servers on Google Cloud (GCE) via Terraform, providing RADIUS/802.1X authentication for Ubiquiti UniFi WiFi using certificate-based EAP-TLS.

## Key Concepts

- **EAP-TLS only** — attested Apple ACME or Apple/Windows SCEP from self-hosted Smallstep; legacy Okta/Jamf remains supported.
- **Client/server trust** — `radius_trust_mode` selects client trust. Smallstep/both also present an EC Smallstep-rooted server certificate; Okta mode uses the legacy RADIUS CA. Profiles pin the actual server root and name.
- **Dynamic VLANs** — normalized inventory groups map globally or per authenticated RADIUS location; site opt-out retains authorization. Never trust NAS identifiers to select a location.
- **Fingerprint authorization** — exact leaf DER observed through authenticated Fleet MDM or Windows SYSTEM scripts binds the host. Neutral SCEP challenges authorize issuance only. Do not add a CN fallback or remove the sticky downgrade guard.
- **Secrets** — Secret Manager persists credentials and CA material. Protected runtime files may remain on disk; Terraform-managed secrets also appear in state.
- **Verified logs** — device/owner fields use stable device IDs, including serial-free BYOD; signed Class binds accounting to the device, original VLAN, office and MAC.

## Tech Stack

- **Terraform** (~> 5.0 google provider) — infrastructure as code
- **GCP** — Compute Engine, Secret Manager, VPC, IAP
- **FreeRADIUS** 3.x — RADIUS server (Debian 12 package)
- **MariaDB** — RADIUS accounting (`radacct` table) via FreeRADIUS native SQL module
- **Debian 12** — VM OS
- **Ubiquiti UniFi** — WiFi access points (RADIUS clients)
- **Okta** — Identity provider (SCEP certificates via Managed Attestation)
- **Fleet or Jamf** — MDM/inventory adapters; built-in exact certificate collection supports Fleet Apple identities and Windows machine identities only
- **Smallstep + Go webhook** — EC ACME/RSA SCEP, KMS HSM signing, Cloud SQL Postgres state, loopback mTLS authorization and optional HTTPS challenge broker
- **Datadog** — Infrastructure monitoring, log shipping to SIEM, FreeRADIUS metrics via Prometheus exporter
- **[freeradius_exporter](https://github.com/bvantagelimited/freeradius_exporter)** — Prometheus exporter for FreeRADIUS status metrics

## File Layout

- `main.tf` — Provider, GCP project creation, API enablement, Secret Manager resources
- `variables.tf` — All input variables with defaults
- `network.tf` — VPC, subnet, static IP, firewall rules
- `compute.tf` — Service account, IAM bindings, GCE instance definition
- `startup-transport.tf` — Rendered byte count, metadata selection, private startup-script storage
- `outputs.tf` — Deployment outputs (IP, SSH command, RADIUS config)
- `datadog.tf` — Optional Datadog FreeRADIUS dashboard (Terraform-managed, requires `datadog_app_key`)
- `datadog-smallstep.tf` — Smallstep CA dashboard + monitors + log pipeline (requires `enable_smallstep_ca` + `datadog_app_key`)
- `datadog-dashboard.json` — Static JSON export of the FreeRADIUS dashboard (importable via Datadog UI)
- `datadog-smallstep-dashboard.json` — Static JSON export of the Smallstep CA dashboard
- `scripts/device_policy.py`, `radius_vlan.py`, `radius_identity.py`, `fleet_certificates.py`, `radius_sources.py` — policy, verified identity, collection and source discovery
- `examples/`, `docs/dynamic-vlans.md`, `docs/scep-identity-binding.md` — profile and rollout contracts
- `scripts/startup.sh` — Idempotent bootstrap: installs FreeRADIUS + MariaDB, configures EAP-TLS, manages certs via Secret Manager

## Commands

```bash
terraform init          # Initialize providers
terraform fmt           # Format .tf files
terraform validate      # Syntax/logic check
terraform plan          # Preview changes
terraform apply         # Deploy
terraform output        # Show outputs (IP, SSH command, etc.)
```

## Important Patterns

- The startup script (`scripts/startup.sh`) uses Terraform `templatefile()` for variable injection. Shell variables that should NOT be interpolated by Terraform use `$$` escaping (e.g., `$${office}`).
- The provider block intentionally does NOT set `project` — every resource sets `project = google_project.this.project_id` explicitly to avoid a circular dependency (the project is created by Terraform).
- Firewall rules use `target_tags = ["radius-server"]` which matches the GCE instance's `tags`.
- FreeRADIUS config paths: `/etc/freeradius/3.0/` (standard Debian location). Certs in `/etc/freeradius/3.0/certs/`.
- In the json_log linelog module, FreeRADIUS `%{...}` must be escaped as `%%{...}` in the Terraform template (since `%{...}` is Terraform template directive syntax).

## Key Variables

- `server_cert_cn` — RADIUS server certificate CN (must match Jamf WiFi profile)
- `server_cert_org` — Organization name used in CA and server cert subjects
- `radius_clients` — Map of offices with CIDRs and descriptions
- `datadog_app_key` — Datadog Application key (enables Terraform-managed dashboard; empty = skip)

## Datadog Dashboard

- Defined in `datadog.tf` using `datadog_dashboard_json` resource, gated by `count = local.datadog_enabled ? 1 : 0`
- Dashboard JSON is built from `local.dashboard_json` (HCL map) then encoded via `jsonencode()`
- Static exports — regenerate after editing the HCL dashboard locals (run `grep '^"'` to skip any console warnings):
  - FreeRADIUS: `echo 'jsonencode(local.dashboard_json)' | terraform console 2>/dev/null | grep '^"' | head -1 | python3 -c 'import sys,json; data=json.loads(json.loads(sys.stdin.read().strip())); print(json.dumps(data, indent=2))' > datadog-dashboard.json`
  - Smallstep CA: `echo 'jsonencode(local.smallstep_dashboard_json)' | terraform console 2>/dev/null | grep '^"' | head -1 | python3 -c 'import sys,json; data=json.loads(json.loads(sys.stdin.read().strip())); print(json.dumps(data, indent=2))' > datadog-smallstep-dashboard.json`
- Template variables: `$site` (site log facet), `$host` (metrics/logs), and `$vlan` (VLAN Assignments section only; do not globally hide rejects or opted-out sites)
- Metric queries use `{$host}` filter; FreeRADIUS counter metrics need `.count` suffix (Datadog OpenMetrics appends it automatically to Prometheus counters)
- Log queries filter with `host:$host.value @site_name:$site.value`
- Log-based widgets require facets declared in Datadog UI (see README for full list) — Terraform provider does not support facet creation
