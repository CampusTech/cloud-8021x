variable "billing_account_id" {
  description = "GCP billing account ID to link to the new project"
  type        = string
}

variable "org_id" {
  description = "GCP organization ID (numeric). Leave empty to create project without an org."
  type        = string
  default     = ""
}

variable "folder_id" {
  description = "GCP folder ID to place the project in. Leave empty for org root."
  type        = string
  default     = ""
}

variable "project_id" {
  description = "GCP project ID prefix (a random suffix is appended for uniqueness)"
  type        = string
  default     = "cloud-8021x"
}

variable "project_name" {
  description = "Human-readable project name"
  type        = string
  default     = "Cloud RADIUS 802.1X"
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-east4"
}

variable "zone" {
  description = "GCP zone for the primary RADIUS VM"
  type        = string
  default     = "us-east4-a"
}

variable "secondary_zone" {
  description = "GCP zone for the secondary (failover) RADIUS VM — must be in the same region but a different zone"
  type        = string
  default     = "us-east4-c"
}

variable "machine_type" {
  description = "GCE machine type for FreeRADIUS VM"
  type        = string
  default     = "e2-medium"
}

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 50
}

variable "radius_clients" {
  description = "Map of RADIUS clients (offices). Each gets a unique shared secret auto-generated and stored in Secret Manager."
  type = map(object({
    cidrs       = list(string)
    description = optional(string, "Ubiquiti UniFi APs")
  }))
}

variable "ssh_allowed_cidrs" {
  description = "CIDR ranges allowed SSH access. Default is GCP IAP only."
  type        = list(string)
  default     = ["35.235.240.0/20"]
}

variable "server_cert_cn" {
  description = "Common Name for the RADIUS server certificate (must match Jamf WiFi profile 'Trusted Server Certificate Names')"
  type        = string
}

variable "server_cert_org" {
  description = "Organization name for the RADIUS server CA certificate subject (e.g. 'Acme Corp')"
  type        = string
}

variable "okta_ca_cert_pem" {
  description = "Okta Intermediate CA certificate in PEM format (the trust anchor for SCEP client certs)"
  type        = string
  sensitive   = true
}

variable "okta_root_ca_cert_pem" {
  description = "Okta Root CA certificate in PEM format (optional — enables full chain validation)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jamf_url" {
  description = "Jamf Pro URL (e.g. https://yourorg.jamfcloud.com) — enables device owner lookup in RADIUS auth logs"
  type        = string
  default     = ""
}

variable "jamf_client_id" {
  description = "Jamf Pro API Client ID (requires Read Computers privilege)"
  type        = string
  default     = ""
}

variable "jamf_client_secret" {
  description = "Jamf Pro API Client Secret"
  type        = string
  default     = ""
  sensitive   = true
}

variable "unifi_api_key" {
  description = "UniFi Site Manager API key — enables AP name and site name lookup in RADIUS auth logs"
  type        = string
  default     = ""
  sensitive   = true
}

variable "meraki_api_key" {
  description = "Cisco Meraki Dashboard API key — enables AP name and network (site) name lookup in RADIUS auth logs for Meraki-managed sites (the counterpart to unifi_api_key for offices on Meraki APs). Independent of and optional alongside unifi_api_key. Requires meraki_org_id."
  type        = string
  default     = ""
  sensitive   = true
}

variable "meraki_org_id" {
  description = "Cisco Meraki organization ID the AP cache reads from (whole-org BSSID→AP-name map). Required when meraki_api_key is set. Find it in the Dashboard URL or via GET /organizations."
  type        = string
  default     = ""

  validation {
    condition     = var.meraki_api_key == "" || trimspace(var.meraki_org_id) != ""
    error_message = "meraki_org_id must be set when meraki_api_key is provided (the cache builder queries a specific organization)."
  }
}

variable "rewrite_username" {
  description = "Rewrite reply:User-Name to 'email - serial' in Access-Accept (requires Jamf lookup). Shown as 802.1X Identity in UniFi."
  type        = bool
  default     = false
}

variable "rewrite_username_separator" {
  description = "Separator between email and serial in the rewritten User-Name (default: ' - ')"
  type        = string
  default     = " - "
}

variable "tls_session_cache" {
  description = "Enable TLS session caching for faster EAP-TLS re-authentication"
  type        = bool
  default     = true
}

variable "tls_session_cache_lifetime" {
  description = "TLS session cache lifetime in hours (default: 24)"
  type        = number
  default     = 24
}

variable "tls_max_version" {
  description = "Maximum TLS version for EAP-TLS (1.2 or 1.3). Use 1.2 for disk-based session cache persistence across restarts."
  type        = string
  default     = "1.2"

  validation {
    condition     = contains(["1.2", "1.3"], var.tls_max_version)
    error_message = "tls_max_version must be \"1.2\" or \"1.3\"."
  }
}

variable "datadog_api_key" {
  description = "Datadog API key for the monitoring agent"
  type        = string
  sensitive   = true
}

variable "datadog_site" {
  description = "Datadog site (e.g. us5.datadoghq.com)"
  type        = string
  default     = "us5.datadoghq.com"
}

variable "datadog_app_key" {
  description = "Datadog Application key (enables Terraform-managed dashboards + monitors). Leave empty to skip. Scope to dashboards_read/write + monitors_read/write."
  type        = string
  default     = ""
  sensitive   = true
}

variable "datadog_monitor_notify" {
  description = "Datadog notification handle(s) appended to monitor messages (e.g. \"@slack-it-alerts @pagerduty-oncall\"). Empty = monitors still trigger in-app, just no routed notification."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Optional self-hosted Smallstep step-ca (off by default)
# -----------------------------------------------------------------------------

variable "enable_smallstep_ca" {
  description = "Stand up a self-hosted Smallstep step-ca on the RADIUS VMs (KMS-backed CA, ACME + SCEP, Cloud SQL for ACME HA, GCLB front door). Off by default; existing BYO-CA deployments are unaffected."
  type        = bool
  default     = false
}

variable "radius_trust_mode" {
  description = "Which CA(s) FreeRADIUS trusts for client certs. 'okta' = existing okta-ca.pem only. 'both' = transitional dual-trust (Okta + Smallstep intermediates concatenated) so devices can migrate without a flag-day cutover. 'smallstep' = Smallstep CA only (the cutover end state). Decoupled from enable_smallstep_ca so the CA can run while RADIUS still trusts Okta during pre-stage. Requires enable_smallstep_ca=true to select 'both' or 'smallstep'."
  type        = string
  default     = "okta"
  validation {
    condition     = contains(["okta", "both", "smallstep"], var.radius_trust_mode)
    error_message = "radius_trust_mode must be one of \"okta\", \"both\", or \"smallstep\"."
  }
  validation {
    condition     = var.radius_trust_mode == "okta" || var.enable_smallstep_ca
    error_message = "radius_trust_mode \"both\" or \"smallstep\" requires enable_smallstep_ca = true (RADIUS can't trust a Smallstep CA that isn't deployed)."
  }
}

variable "smallstep_ca_dns_name" {
  description = "Public DNS name clients use to reach the step-ca ACME/SCEP endpoint (e.g. ca.example.com). Must resolve to the GCLB IP and match the managed TLS cert. Only used when enable_smallstep_ca=true."
  type        = string
  default     = ""

  validation {
    condition     = !var.enable_smallstep_ca || trimspace(var.smallstep_ca_dns_name) != ""
    error_message = "smallstep_ca_dns_name must be set when enable_smallstep_ca is true."
  }
}

variable "ca_name_prefix" {
  description = "Common-name prefix for the self-hosted CA certificates. The CA mints \"<prefix> Root CA\", \"<prefix> Intermediate CA\", and \"<prefix> SCEP Decrypter\". Change for your org; the default preserves existing issued-cert CNs."
  type        = string
  default     = "CampusGroup Wi-Fi"
}

variable "smallstep_acme_provisioner_name" {
  description = "Name of the step-ca ACME provisioner (also the URL path segment: /acme/<name>/directory). Must be globally unique across ALL provisioners (step-ca rejects duplicate names even across types), so it must differ from smallstep_scep_provisioner_name."
  type        = string
  default     = "wifi-acme"
}

variable "smallstep_scep_provisioner_name" {
  description = "Name of the step-ca SCEP provisioner (also the URL path segment: /scep/<name>). Must be globally unique across ALL provisioners (step-ca rejects duplicate names even across types), so it must differ from smallstep_acme_provisioner_name."
  type        = string
  default     = "wifi-scep"

  validation {
    condition     = var.smallstep_scep_provisioner_name != var.smallstep_acme_provisioner_name
    error_message = "smallstep_scep_provisioner_name must differ from smallstep_acme_provisioner_name (step-ca rejects duplicate provisioner names even across types)."
  }
}

variable "smallstep_ca_rsa_dns_name" {
  description = "DNS name for the RSA SCEP step-ca instance (instance #2). A record must point at smallstep_rsa_lb_ip. Required when enable_smallstep_ca is true."
  type        = string
  default     = ""

  validation {
    condition     = !var.enable_smallstep_ca || trimspace(var.smallstep_ca_rsa_dns_name) != ""
    error_message = "smallstep_ca_rsa_dns_name must be set when enable_smallstep_ca is true."
  }
}

variable "smallstep_scep_rsa_provisioner_name" {
  description = "Name of the SCEP provisioner on the RSA step-ca instance (path segment in the SCEP URL)."
  type        = string
  default     = "wifi-scep"
}

variable "acme_authorizing_webhook_url" {
  description = "URL step-ca calls per ACME order to authorize issuance (refuses to sign unless it returns allow:true). The webhook runs on the VM, so this is normally the loopback http://127.0.0.1:<webhook_port>/authorize. MUST be set and healthy (fail-closed) before enrolling real devices. Empty = ACME provisioner configured but no device should enroll yet."
  type        = string
  default     = ""
}

variable "smallstep_db_tier" {
  description = "Cloud SQL machine tier for the step-ca ACME state database. Must be a standard (non-shared-core) tier because availability_type is REGIONAL (HA); db-f1-micro/shared-core tiers do not support REGIONAL and fail at apply."
  type        = string
  default     = "db-custom-1-3840"
}

# -----------------------------------------------------------------------------
# Optional ACME authorizing webhook (on-VM localhost service) — gates ACME
# issuance to Fleet-enrolled device serials. Requires enable_smallstep_ca.
# The binary is built + released by the webhook-release GitHub Action and
# downloaded by the VM startup script.
# -----------------------------------------------------------------------------

variable "enable_acme_webhook" {
  description = "Run the ACME authorizing webhook on the RADIUS VMs (localhost systemd service) and wire it into step-ca. Requires enable_smallstep_ca=true. MANDATORY before enrolling real devices over ACME."
  type        = bool
  default     = false
}

variable "fleet_api_base_url" {
  description = "Base URL of the Fleet server (e.g. https://fleet.example.com). Used by the ACME authorizing webhook and the device-owner lookup."
  type        = string
  default     = ""

  validation {
    condition     = !(var.enable_acme_webhook || var.enable_fleet_lookup) || trimspace(var.fleet_api_base_url) != ""
    error_message = "fleet_api_base_url must be set when enable_acme_webhook or enable_fleet_lookup is true."
  }
}

variable "enable_fleet_lookup" {
  description = "Resolve serial -> assigned-user email, device name, and model from Fleet (the Jamf-lookup counterpart for Fleet-managed fleets). Requires fleet_api_base_url and the out-of-band fleet-api-token secret. Mutually exclusive with jamf_url — set one MDM source, not both."
  type        = bool
  default     = false

  validation {
    condition     = !(var.enable_fleet_lookup && var.jamf_url != "")
    error_message = "enable_fleet_lookup and jamf_url are mutually exclusive — both populate the same device-owner enrichment fields. Pick the MDM that manages this fleet."
  }
}

# NOTE: the Fleet API token is NOT a Terraform variable — it is a standing
# credential added directly to the `fleet-api-token` Secret Manager secret
# out-of-band (see webhook.tf), so it never passes through tfvars/CI/CLI. The
# device-owner lookup reuses the same secret (a read-only observer token suffices).

variable "webhook_allow_label" {
  description = "Optional Fleet label a host must carry for the webhook to allow issuance (e.g. test-pilots for a scoped pilot). Empty = any enrolled host is allowed."
  type        = string
  default     = ""
}

variable "webhook_release_version" {
  description = "Version of the ACME webhook binary to download from GitHub Releases (asset of tag webhook-v<version>, built by the webhook-release Action). Must match webhook/VERSION at the release commit."
  type        = string
  default     = "1.1.0"
}

variable "webhook_port" {
  description = "Loopback port the on-VM ACME authorizing webhook listens on (step-ca calls http://127.0.0.1:<port>/authorize)."
  type        = number
  default     = 9444
}
