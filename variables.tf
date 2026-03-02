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
  description = "Datadog Application key (enables Terraform-managed dashboard). Leave empty to skip. Scope to dashboards_read + dashboards_write only."
  type        = string
  default     = ""
  sensitive   = true
}
