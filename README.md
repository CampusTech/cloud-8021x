# cloud-8021x

Terraform deployment for cloud-hosted FreeRADIUS servers on Google Cloud, providing RADIUS/802.1X authentication for WiFi networks using certificate-based EAP-TLS. Works with any RADIUS-capable access point (Ubiquiti UniFi, Cisco Meraki, etc.). Deploys primary and secondary VMs in separate availability zones for HA failover.

## Architecture

```
MacBook (Okta SCEP cert via Jamf)
  → WiFi AP (WPA2/WPA3 Enterprise — UniFi, Meraki, etc.)
    → RADIUS (UDP 1812/1813) over internet
      → Primary:   FreeRADIUS on GCE VM (us-east4-a, static public IP)
      → Secondary: FreeRADIUS on GCE VM (us-east4-c, static public IP)
        → EAP-TLS: validates client cert against Okta Intermediate CA
        → Access-Accept → WiFi connected
```

- **Authentication**: EAP-TLS only (no passwords). Client certificates issued by Okta Managed Attestation via Jamf SCEP.
- **Trust model**: Two independent CA chains. Server cert signed by a self-signed RADIUS CA (generated on first boot). Client certs signed by Okta Intermediate CA.
- **Accounting**: FreeRADIUS native SQL module writes to local MariaDB (`radacct` table).
- **Secrets**: All managed via GCP Secret Manager (RADIUS shared secrets, server certs, Okta CA, Datadog API key).
- **Observability**: Datadog Agent for infrastructure metrics + log shipping to SIEM. FreeRADIUS Prometheus exporter for RADIUS-specific metrics. Structured JSON auth and accounting logs via FreeRADIUS `linelog`.
- **Log enrichment**: Optional Jamf and UniFi integrations add device owner, device name, model, AP name, and site name to both auth and accounting JSON logs. Jamf data is served from a local cache (no API calls on the auth path).

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- GCP account with permissions to create projects and enable billing
- `gcloud` CLI authenticated (`gcloud auth application-default login`)
- Okta Intermediate CA certificate (`okta-ca.pem`) from your Okta org
- Okta Managed Attestation configured in Jamf (SCEP profile)

## Quick Start

```bash
# 1. Copy and edit the example tfvars
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — set billing_account_id, office IPs, okta_ca_cert_pem, datadog_api_key

# 2. Initialize and deploy
terraform init
terraform plan
terraform apply

# 3. Fetch outputs (certs, shared secrets, config)
#    Wait a few minutes for VMs to finish bootstrapping first
./scripts/fetch-outputs.sh

# Outputs are saved to out/:
#   out/radius-ca.cer              — RADIUS CA cert (upload to Jamf)
#   out/radius-server.cer          — RADIUS server cert (reference)
#   out/shared-secret-<office>.txt — Per-office shared secrets
#   out/config.json                — IPs, ports, SSH commands
#   out/README.md                  — Human-readable summary with all values
```

## What Terraform Creates

| Resource | Purpose |
|----------|---------|
| GCP Project | New project with billing, APIs enabled |
| VPC + Subnet | Custom network (`10.0.1.0/24`) |
| Static IPs (x2) | Public IPs for primary and secondary RADIUS servers |
| Firewall rules | UDP 1812/1813 from office IPs, SSH from IAP |
| GCE Instances (x2) | Primary + secondary in different zones, Debian 12, `e2-medium`, FreeRADIUS + MariaDB |
| Service Account | Minimal permissions (Secret Manager read/write) |
| Secret Manager | N+7 secrets (per-office RADIUS secrets, Okta CA, Datadog API key, 5x server certs) |

## Secrets in Secret Manager

| Secret | Populated by | Purpose |
|--------|-------------|---------|
| `radius-shared-secret-<office>` | Terraform | Per-office shared secret between APs and RADIUS |
| `okta-ca-cert` | Terraform | Okta Intermediate CA for client cert validation |
| `okta-root-ca-cert` | Terraform (optional) | Okta Root CA for full chain validation |
| `radius-server-ca-key` | Startup script | Self-signed CA private key |
| `radius-server-ca-cert` | Startup script | Self-signed CA certificate (upload to Jamf) |
| `radius-server-key` | Startup script | RADIUS server private key |
| `radius-server-cert` | Startup script | RADIUS server certificate |
| `radius-dh-params` | Startup script | Diffie-Hellman parameters |
| `datadog-api-key` | Terraform | Datadog Agent API key |
| `jamf-url` | Terraform (optional) | Jamf Pro base URL for device lookup |
| `jamf-client-id` | Terraform (optional) | Jamf Pro API Client ID |
| `jamf-client-secret` | Terraform (optional) | Jamf Pro API Client Secret |
| `unifi-url` | Terraform (optional) | UniFi API URL for AP/site lookup |
| `unifi-api-key` | Terraform (optional) | UniFi API key |

Server certs are generated on first boot and stored in Secret Manager so they persist across VM replacements. You only need to upload `radius-server-ca-cert` to Jamf once.

## Configuration

### Variables

See [terraform.tfvars.example](terraform.tfvars.example) for all options. Key variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `billing_account_id` | Yes | GCP billing account to link |
| `radius_clients` | Yes | Map of offices with CIDRs (secrets auto-generated) |
| `okta_ca_cert_pem` | Yes | Okta Intermediate CA cert PEM content |
| `okta_root_ca_cert_pem` | No | Okta Root CA cert PEM (enables full chain validation) |
| `datadog_api_key` | Yes | Datadog API key for monitoring agent |
| `ssh_allowed_cidrs` | No | IPs for SSH access (default: GCP IAP) |
| `secondary_zone` | No | Zone for secondary VM (default: `us-east4-c`) |
| `machine_type` | No | VM size (default: `e2-medium`) |
| `server_cert_cn` | Yes | Server cert CN (e.g. `radius.example.com`) |
| `server_cert_org` | Yes | Organization name for CA cert subject (e.g. `Acme Corp`) |
| `datadog_site` | No | Datadog site (default: `us5.datadoghq.com`) |
| `jamf_url` | No | Jamf Pro URL — enables device lookup in auth logs |
| `jamf_client_id` | No | Jamf Pro API Client ID (requires Read Computers) |
| `jamf_client_secret` | No | Jamf Pro API Client Secret |
| `rewrite_username` | No | Set reply:User-Name to `email - serial` in Access-Accept (default: `false`) |
| `rewrite_username_separator` | No | Separator between email and serial in rewritten User-Name (default: ` - `) |
| `unifi_url` | No | UniFi API URL — enables AP/site name in auth logs |
| `unifi_api_key` | No | UniFi API key (read-only access) |
| `datadog_app_key` | No | Datadog Application key — enables Terraform-managed dashboard |

### Access Point RADIUS Setup

After deployment, run `./scripts/fetch-outputs.sh` and open `out/README.md` for all IPs, shared secrets, and certs in one place.

Configure your access points (UniFi, Meraki, or any 802.1X-capable AP) with:

- **Primary RADIUS Server IP**: from `out/README.md` or `terraform output radius_primary_ip`
- **Secondary RADIUS Server IP**: from `out/README.md` or `terraform output radius_secondary_ip`
- **Auth Port**: 1812
- **Accounting Port**: 1813
- **Shared Secret**: per-office, from `out/shared-secret-<office>.txt`
- **Interim Update Interval**: 120 seconds (recommended)
- **Security**: WPA2/WPA3 Enterprise
- Enable **RADIUS Assigned VLAN** if using dynamic VLANs

### Jamf Configuration

1. Upload the RADIUS server CA cert to Jamf:
   ```bash
   # After running ./scripts/fetch-outputs.sh
   cat out/radius-ca.cer
   ```
   Add this as a **Certificate** payload in a Jamf configuration profile.

2. Create an **SCEP** payload:
   - SCEP Subject: `CN=$SERIALNUMBER managementAttestation $UDID $PROFILE_IDENTIFIER`
   - Using `$SERIALNUMBER` as CN avoids spaces that can cause issues with RADIUS username filters

3. Create a **WiFi** payload:
   - Security: WPA2/WPA3 Enterprise
   - EAP Type: EAP-TLS
   - Protocols tab Username: `$SERIALNUMBER` (used as EAP outer identity)
   - Identity Certificate: Okta SCEP certificate
   - Trust: Add the server CA cert above
   - Trusted Server Certificate Names: `radius.example.com` (must match `server_cert_cn`)
   - Disable Private MAC Address: recommended for consistent device tracking

### Okta Root CA (Optional)

For full chain validation (client cert → Intermediate CA → Root CA), you can provide the Okta Root CA certificate via the `okta_root_ca_cert_pem` variable. Without it, FreeRADIUS trusts only the Intermediate CA directly — this works, but won't survive an Intermediate CA re-key by Okta.

To obtain the Root CA from your Okta admin console ([source](https://andrewdoering.org/blog/2023/obtaining-okta-root-ca/)):

1. Log into your Okta Admin Dashboard
2. In a new tab (same session), navigate to:
   ```
   https://<your-org>-admin.okta.com/api/v1/certificateAuthorities?type=ROOT
   ```
3. Copy the `id` value from the JSON response
4. In another tab, navigate to:
   ```
   https://<your-org>-admin.okta.com/api/v1/certificateAuthorities/<id>/cert
   ```
5. A `.cer` file will download — paste its PEM contents into `okta_root_ca_cert_pem` in your `terraform.tfvars`

### Jamf Device Lookup (Optional)

When EAP-TLS authenticates a device, the outer identity is the serial number (e.g. `H176YHQ9XV`). If you provide Jamf Pro API credentials, a background cache script bulk-fetches all Jamf inventory and stores it locally. FreeRADIUS reads from this cache (no API calls on the auth path) to resolve the serial to device details. This adds the following fields to both auth and accounting JSON logs:

- `device_owner` — assigned user's email from Jamf
- `device_name` — device name (e.g. `Robbie's MacBook Pro`)
- `device_model` — hardware model (e.g. `MacBook Pro (16-inch, 2024) M4 Max`)
- In auth: overwrites `User-Name` in the reply to `email - serial` so UniFi and accounting show the owner

The cache is built on boot and refreshed every 30 minutes via cron. Cache misses trigger a background fetch (does not block auth). If Jamf is unreachable or the device isn't found, the serial is used as-is.

**Setup:**

1. In Jamf Pro, create an **API Client** (Settings → API Roles and Clients):
   - Create an API Role with the **Read Computers** privilege
   - Create an API Client, assign the role, and note the Client ID and Client Secret

2. Add to your `terraform.tfvars`:
   ```hcl
   jamf_url           = "https://yourorg.jamfcloud.com"
   jamf_client_id     = "your-client-id"
   jamf_client_secret = "your-client-secret"
   ```

3. `terraform apply` — creates 3 new secrets in Secret Manager and updates the startup script

### UniFi AP/Site Lookup (Optional)

If you provide UniFi API credentials, FreeRADIUS will resolve the access point and site name for each authentication and accounting event. A cache script queries the UniFi API every 5 minutes and builds a local MAC-to-AP lookup table. The Python module matches the client's BSSID (from `Called-Station-Id`) to the AP's base MAC using fuzzy matching (last-byte offset 0-7). This adds to both auth and accounting JSON logs:

- `ap_name` — access point name (e.g. `Lobby`)
- `site_name` — UniFi site name (e.g. `32 Avenue of the Americas`)
- Auth logs also include `ssid` — extracted from `Called-Station-Id`

**Setup:**

1. In UniFi, create an **API Key** (Settings → Admins & Users → API Keys) with read-only access

2. Add to your `terraform.tfvars`:
   ```hcl
   unifi_url     = "https://unifi.ui.com"
   unifi_api_key = "your-api-key"
   ```

3. `terraform apply` — creates 2 new secrets in Secret Manager and enables the cache cron job

### Datadog Dashboard (Optional)

![Datadog Dashboard](docs/datadog-dashboard.png)

If you provide a Datadog Application key, Terraform creates a dashboard with authentication metrics, device analytics, location breakdowns, accounting sessions, and infrastructure health.

1. In Datadog, create an **Application Key** (Organization Settings → Application Keys) scoped to `dashboards_read` + `dashboards_write` only.

2. Add to your `terraform.tfvars`:
   ```hcl
   datadog_app_key = "your-application-key"
   ```

3. `terraform apply` — creates the dashboard, outputs the URL via `terraform output datadog_dashboard_url`.

**Without Terraform**: Import `datadog-dashboard.json` via Datadog UI → Dashboards → New Dashboard → Import Dashboard JSON.

**Required: Create Log Facets**

The dashboard's log-based widgets and the `$site` template variable filter require log facets to be declared in Datadog. These are **not** auto-created — the Datadog Terraform provider [does not support facet creation](https://github.com/DataDog/terraform-provider-datadog/issues/1644).

After your first log data arrives, go to **Datadog → Logs → Facets → Add** and create the following:

| Facet | Path | Type | Used by |
|-------|------|------|---------|
| `@event` | `@event` | String | Auth widgets (Accept/Reject filtering) |
| `@site_name` | `@site_name` | String | Site template variable, Auth by Site, Top APs |
| `@ap_name` | `@ap_name` | String | Top Access Points |
| `@ssid` | `@ssid` | String | Auth by SSID |
| `@device_name` | `@device_name` | String | Top Devices |
| `@device_owner` | `@device_owner` | String | Top Device Owners |
| `@device_model` | `@device_model` | String | Device Model Distribution |
| `@reject_reason` | `@reject_reason` | String | Reject Reasons |
| `@terminate_cause` | `@terminate_cause` | String | Session Termination Causes |
| `@session_time` | `@session_time` | Measure (seconds) | Avg Session Duration |
| `@input_bytes` | `@input_bytes` | Measure (bytes) | Bandwidth widgets |
| `@output_bytes` | `@output_bytes` | Measure (bytes) | Bandwidth widgets |

**Tip**: String facets can be added from any log entry — click the field value and select "Create facet". Measure facets (`@session_time`, `@input_bytes`, `@output_bytes`) must be created as **Measures** (not facets) to support aggregations like `avg` and `sum`.

## Post-Deployment

### SSH Access

```bash
# Via IAP tunnel (default, no public SSH needed)
$(terraform output -raw ssh_command_primary)     # Primary VM
$(terraform output -raw ssh_command_secondary)   # Secondary VM

# Check startup script progress
sudo cat /var/log/radius-bootstrap.log

# Check FreeRADIUS status
sudo systemctl status freeradius
sudo systemctl status mariadb
sudo systemctl status freeradius-exporter
sudo systemctl status datadog-agent
```

### Testing RADIUS

From a host with an allowed source IP:

```bash
# Basic connectivity test
radtest user password <radius-ip> 0 <shared-secret>

# Full EAP-TLS test (requires eapol_test from wpa_supplicant)
eapol_test -c eapol_test.conf -a <radius-ip> -s <shared-secret>
```

### Check Accounting

```bash
sudo mysql radius -e "SELECT * FROM radacct ORDER BY radacctid DESC LIMIT 5"
```

## File Structure

```
.
├── main.tf                  # Provider, project, APIs, Secret Manager
├── variables.tf             # Input variables
├── network.tf               # VPC, subnet, firewall, static IP
├── compute.tf               # Service account, IAM, GCE instance
├── outputs.tf               # IP, SSH command, RADIUS config
├── datadog.tf               # Optional Datadog dashboard (requires datadog_app_key)
├── datadog-dashboard.json   # Dashboard JSON export (importable via Datadog UI)
├── terraform.tfvars.example # Example configuration with office IPs
├── ARCHITECTURE.md          # Technical deep-dive: auth flow, startup script, log enrichment
├── scripts/
│   ├── startup.sh           # FreeRADIUS + MariaDB install, EAP-TLS config, Datadog, exporter
│   └── fetch-outputs.sh     # Post-deploy: fetch certs & secrets to out/
└── out/                     # (gitignored) Certs, shared secrets, config.json, README.md
```

For a detailed technical walkthrough of the startup script, authentication flow, log enrichment pipeline, and caching architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Future Work

- **Dynamic VLAN assignment**: Query Okta Devices API to map device → user → group → VLAN
- **Multi-region**: Deploy additional RADIUS nodes closer to west coast / new offices
