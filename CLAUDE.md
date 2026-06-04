# CLAUDE.md

## Project Overview

This repo deploys a standalone FreeRADIUS server on Google Cloud (GCE) via Terraform, providing RADIUS/802.1X authentication for Ubiquiti UniFi WiFi using certificate-based EAP-TLS.

## Key Concepts

- **EAP-TLS only** — no passwords. MacBooks present Okta SCEP certificates (enrolled via Jamf). FreeRADIUS validates them against the Okta Intermediate CA.
- **Two CA chains**: Server cert signed by a self-signed RADIUS CA (org name from `server_cert_org` variable). Client certs signed by Okta Intermediate CA. These are independent.
- **All secrets in GCP Secret Manager** — RADIUS shared secrets, Okta CA cert, Datadog API key, and all server certificates. No secrets in instance metadata or on disk at rest.
- **Server certs persist across VM replacements** — generated on first boot, stored in Secret Manager, restored on subsequent boots.

## Tech Stack

- **Terraform** (~> 5.0 google provider) — infrastructure as code
- **GCP** — Compute Engine, Secret Manager, VPC, IAP
- **FreeRADIUS** 3.x — RADIUS server (Debian 12 package)
- **MariaDB** — RADIUS accounting (`radacct` table) via FreeRADIUS native SQL module
- **Debian 12** — VM OS
- **Ubiquiti UniFi** — WiFi access points (RADIUS clients)
- **Okta** — Identity provider (SCEP certificates via Managed Attestation)
- **Jamf** — MDM (enrolls SCEP certs, deploys WiFi profiles)
- **Datadog** — Infrastructure monitoring, log shipping to SIEM, FreeRADIUS metrics via Prometheus exporter
- **[freeradius_exporter](https://github.com/bvantagelimited/freeradius_exporter)** — Prometheus exporter for FreeRADIUS status metrics

## File Layout

- `main.tf` — Provider, GCP project creation, API enablement, Secret Manager resources
- `variables.tf` — All input variables with defaults
- `network.tf` — VPC, subnet, static IP, firewall rules
- `compute.tf` — Service account, IAM bindings, GCE instance definition
- `outputs.tf` — Deployment outputs (IP, SSH command, RADIUS config)
- `datadog.tf` — Optional Datadog FreeRADIUS dashboard (Terraform-managed, requires `datadog_app_key`)
- `datadog-smallstep.tf` — Smallstep CA dashboard + monitors + log pipeline (requires `enable_smallstep_ca` + `datadog_app_key`)
- `datadog-dashboard.json` — Static JSON export of the FreeRADIUS dashboard (importable via Datadog UI)
- `datadog-smallstep-dashboard.json` — Static JSON export of the Smallstep CA dashboard
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
- Template variables: `$site` (filters by `@site_name` log facet) and `$host` (filters metrics + logs by host)
- Metric queries use `{$host}` filter; FreeRADIUS counter metrics need `.count` suffix (Datadog OpenMetrics appends it automatically to Prometheus counters)
- Log queries filter with `host:$host.value @site_name:$site.value`
- Log-based widgets require facets declared in Datadog UI (see README for full list) — Terraform provider does not support facet creation
