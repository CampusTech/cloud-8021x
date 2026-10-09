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
  description = "RADIUS offices with unique shared secrets. Use static IPv4 CIDRs, an optional UniFi gateway/console host ID for public WAN discovery, or both."
  type = map(object({
    cidrs         = optional(list(string), [])
    unifi_host_id = optional(string)
    description   = optional(string, "Ubiquiti UniFi APs")
  }))

  validation {
    condition = alltrue([for office, client in var.radius_clients :
      can(regex("^[a-z][a-z0-9-]{0,47}$", office)) &&
      (length(client.cidrs) > 0 || try(length(trimspace(client.unifi_host_id)) > 0, false)) &&
      alltrue([for cidr in client.cidrs : can(cidrnetmask(cidr)) && try(tonumber(split("/", cidr)[1]) > 0, false)])
    ])
    error_message = "Office keys must be lowercase safe names (up to 48 characters); each office requires IPv4 CIDRs narrower than /0 or a UniFi host ID."
  }

  validation {
    condition = alltrue([for client in values(var.radius_clients) :
      client.unifi_host_id == null ? true : var.unifi_api_key != "" && client.unifi_host_id == trimspace(client.unifi_host_id)
    ])
    error_message = "UniFi host discovery requires unifi_api_key and an exact host ID with no surrounding whitespace."
  }

  validation {
    condition     = length(distinct(compact([for client in values(var.radius_clients) : client.unifi_host_id]))) == length(compact([for client in values(var.radius_clients) : client.unifi_host_id]))
    error_message = "A UniFi host ID can identify only one RADIUS office."
  }
}

variable "ssh_allowed_cidrs" {
  description = "CIDR ranges allowed SSH access. Default is GCP IAP only."
  type        = list(string)
  default     = ["35.235.240.0/20"]
}

variable "radius_vlan_name_sources" {
  description = "Display-only VLAN name API sources by RADIUS office. Choose a UniFi console (optionally pin its local site UUID) or a Meraki network ID. UniFi WAN-discovery console IDs are reused automatically unless overridden here. Requires the corresponding existing API key; no controller data changes VLAN authorization."
  type = map(object({
    unifi_host_id     = optional(string)
    unifi_site_id     = optional(string)
    meraki_network_id = optional(string)
  }))
  default = {}

  validation {
    condition     = length(setsubtract(toset(keys(var.radius_vlan_name_sources)), toset(keys(var.radius_clients)))) == 0
    error_message = "VLAN name sources must match RADIUS office keys."
  }

  validation {
    condition = alltrue([for source in values(var.radius_vlan_name_sources) :
      (source.unifi_host_id != null) != (source.meraki_network_id != null) &&
      (source.unifi_site_id == null || source.unifi_host_id != null) &&
      alltrue([for id in [source.unifi_host_id, source.unifi_site_id, source.meraki_network_id] :
        id == null ? true : length(id) > 0 && length(id) <= 255 && id == trimspace(id)
      ])
    ])
    error_message = "Each VLAN name source requires exactly one provider, nonempty IDs with no surrounding whitespace, and a console ID when pinning a UniFi site."
  }

  validation {
    condition = alltrue([for source in values(var.radius_vlan_name_sources) :
      (source.unifi_host_id == null || var.unifi_api_key != "") &&
      (source.meraki_network_id == null || var.meraki_api_key != "")
    ])
    error_message = "VLAN name sources require the corresponding unifi_api_key or meraki_api_key."
  }
}

variable "armor_trusted_cidrs" {
  description = "Office egress CIDRs exempt from the CA's Cloud Armor rate limit. Every device at a site shares one NAT IP, so enrollment bursts otherwise trip the per-IP ban. Max 10 (Cloud Armor per-rule limit)."
  type        = list(string)
  default     = []
  validation {
    condition     = length(var.armor_trusted_cidrs) <= 10
    error_message = "Cloud Armor allows at most 10 src_ip_ranges per rule."
  }
}

variable "server_cert_cn" {
  description = "Common Name for the RADIUS server certificate (must match managed WiFi Trusted Server Certificate Names)"
  type        = string
}

variable "server_cert_org" {
  description = "Organization name for the RADIUS server CA certificate subject (e.g. 'Acme Corp')"
  type        = string
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
  description = "Cisco Meraki organization ID the AP cache reads from (whole-org exact hardware-MAC/BSSID→AP-name map). Required when meraki_api_key is set. Find it in the Dashboard URL or via GET /organizations."
  type        = string
  default     = ""

  validation {
    condition     = var.meraki_api_key == "" || trimspace(var.meraki_org_id) != ""
    error_message = "meraki_org_id must be set when meraki_api_key is provided (the cache builder queries a specific organization)."
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
  validation {
    condition     = !try(var.radius_vlan_policy.attested_acme, false) || var.enable_smallstep_ca
    error_message = "Attested ACME authorization requires the built-in Smallstep CA."
  }
}

variable "enable_acme_issuance_monitor" {
  description = "Alert when step-ca signs zero wifi-acme certificates in 24h — the earliest signal that device certificate renewal has stopped. OFF by default because there is no device-side renewal mechanism yet (macOS does not re-order the com.apple.security.acme payload on its own), so issuance is near-zero and the monitor would sit permanently red. Turn on once ACME issuance is steady."
  type        = bool
  default     = false
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
  description = "Name of the step-ca ACME provisioner on the EC CA (also the URL path segment: /acme/<name>/directory). The EC CA is ACME-only; SCEP lives on the RSA instance (see smallstep_scep_rsa_provisioner_name)."
  type        = string
  default     = "wifi-acme"
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
  description = "URL step-ca calls per ACME order to authorize issuance (refuses to sign unless it returns allow:true). The webhook runs on the VM, so this is normally the loopback https://127.0.0.1:<webhook_port>/authorize. MUST be set and healthy (fail-closed) before enrolling real devices. Empty selects the managed HTTPS endpoint when enable_acme_webhook=true; otherwise no ACME authorization hook is configured."
  type        = string
  default     = ""

  validation {
    condition     = var.acme_authorizing_webhook_url == "" || startswith(var.acme_authorizing_webhook_url, "https://")
    error_message = "step-ca requires HTTPS for authorizing webhooks. Use https://127.0.0.1:<webhook_port>/authorize for the local service."
  }
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

  validation {
    condition     = !var.enable_acme_webhook || var.enable_smallstep_ca
    error_message = "enable_acme_webhook requires enable_smallstep_ca = true."
  }
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
  description = "Resolve serial -> assigned-user email, device name, and model from Fleet. Requires fleet_api_base_url and the out-of-band fleet-api-token secret."
  type        = bool
  default     = false

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

variable "webhook_port" {
  description = "Loopback port the on-VM ACME authorizing webhook listens on (step-ca calls https://127.0.0.1:<port>/authorize)."
  type        = number
  default     = 9444
}

variable "enable_fleet_certificate_inventory" {
  description = "Collect Apple managed identities through Fleet MDM and Windows machine identities through Fleet scripts. Requires permission to run CertificateList and scripts, with fleetd scripts enabled on Windows. Can be staged before fingerprint enforcement."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_fleet_certificate_inventory || var.enable_fleet_lookup
    error_message = "Certificate collection requires enable_fleet_lookup=true."
  }
}

variable "fleet_certificate_token_secret_id" {
  description = "Existing Secret Manager secret for Fleet certificate collection. Use a separate scoped maintainer credential to keep fleet-api-token observer-only. Defaults to fleet-api-token for existing deployments."
  type        = string
  default     = "fleet-api-token"
  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{1,255}$", var.fleet_certificate_token_secret_id))
    error_message = "fleet_certificate_token_secret_id must be a valid Secret Manager secret ID."
  }
}

variable "fleet_acme_profile_uuids" {
  description = "Fleet configuration profile UUIDs for hardware-attested ACME Wi-Fi. Hosts with a verified installation skip new certificate commands; Windows and unknown/pending/failed profiles still collect. Requires attested_acme authorization. These are Fleet profile UUIDs, not mobileconfig PayloadUUIDs."
  type        = set(string)
  default     = []

  validation {
    condition     = length(var.fleet_acme_profile_uuids) == 0 || (var.enable_fleet_certificate_inventory && try(var.radius_vlan_policy.attested_acme, false))
    error_message = "ACME polling exclusions require Fleet certificate inventory and radius_vlan_policy.attested_acme."
  }
}

variable "fleet_scep_profile_uuids" {
  description = "Optional Fleet Wi-Fi SCEP configuration profile UUID allowlist for polling. Null keeps all non-exempt hosts eligible; an empty set queues nothing. Any selected install (including pending/failed) remains eligible, even when an ACME profile is also installed. This affects collection only, never authorization."
  type        = set(string)
  default     = null
}

variable "scep_broker_requests_per_minute" {
  description = "Cloud Armor challenge requests per minute per source IP. Fleet shares its outbound IP across device enrollments, so size this for rollout and renewal bursts. Excess requests receive HTTP 429 without a timed ban; broker authentication remains required."
  type        = number
  default     = 1000

  validation {
    condition     = var.scep_broker_requests_per_minute >= 1 && floor(var.scep_broker_requests_per_minute) == var.scep_broker_requests_per_minute
    error_message = "scep_broker_requests_per_minute must be a positive integer."
  }
}

# Optional MDM-independent VLAN policy. Group names belong to inventory adapters,
# not to the RADIUS engine: fleet:<id>, jamf:site:<id>, or custom cache group keys.
variable "radius_vlan_policy" {
  description = "Dynamic VLAN authorization. Null disables it. locations keys match radius_clients office names; each location has its own complete group/fallback mapping or dynamic_vlans=false to retain authorization without VLAN assignment. Empty locations uses the global mapping. Unknown locations fail closed."
  type = object({
    group_vlans           = optional(map(number), {})
    vlan_names            = optional(map(string), {})
    fallback_vlan         = optional(number)
    cache_max_age         = optional(number, 3600)
    cache_file            = optional(string, "/etc/freeradius/3.0/device-policy-cache.json")
    certificate_inventory = optional(bool, false)
    attested_acme         = optional(bool, false)
    certificate_max_age   = optional(number, 86400)
    locations = optional(map(object({
      dynamic_vlans = optional(bool, true)
      group_vlans   = optional(map(number), {})
      fallback_vlan = optional(number)
      vlan_names    = optional(map(string), {})
    })), {})
  })
  default = null

  validation {
    condition = var.radius_vlan_policy == null ? true : alltrue(flatten([
      for names in concat([var.radius_vlan_policy.vlan_names], [for policy in values(var.radius_vlan_policy.locations) : policy.vlan_names]) : [
        for id, name in names :
        can(regex("^[1-9][0-9]{0,3}$", id)) && try(tonumber(id) <= 4094, false) &&
        try(length(name) > 0 && length(name) <= 128 && name == trimspace(name), false)
      ]
    ]))
    error_message = "vlan_names keys must be canonical VLAN IDs from 1 through 4094; names must be 1-128 characters with no surrounding whitespace."
  }

  validation {
    condition     = var.radius_vlan_policy == null ? true : (!var.radius_vlan_policy.attested_acme || var.radius_vlan_policy.certificate_inventory)
    error_message = "attested_acme requires certificate_inventory for all non-attested certificates."
  }

  validation {
    condition = var.radius_vlan_policy == null ? true : alltrue([
      for location, policy in var.radius_vlan_policy.locations :
      length(location) > 0 && location == trimspace(location) && alltrue([
        for vlan in concat(values(policy.group_vlans), policy.fallback_vlan == null ? [] : [policy.fallback_vlan]) :
        vlan != null && try(vlan >= 1 && vlan <= 4094 && floor(vlan) == vlan, false)
      ])
    ])
    error_message = "Location names must be nonempty with no surrounding whitespace, and location VLAN IDs must be integers from 1 through 4094."
  }

  validation {
    condition = var.radius_vlan_policy == null ? true : alltrue([
      for policy in values(var.radius_vlan_policy.locations) :
      policy.dynamic_vlans || (length(policy.group_vlans) == 0 && policy.fallback_vlan == null)
    ])
    error_message = "Locations with dynamic_vlans=false must omit group_vlans and fallback_vlan (an empty group_vlans map is allowed)."
  }

  validation {
    condition     = var.radius_vlan_policy == null ? true : length(setsubtract(toset(keys(var.radius_vlan_policy.locations)), toset(keys(var.radius_clients)))) == 0
    error_message = "Every VLAN location must match an office key in radius_clients."
  }

  validation {
    condition     = var.radius_vlan_policy == null ? true : var.radius_vlan_policy.certificate_max_age >= 7200 && floor(var.radius_vlan_policy.certificate_max_age) == var.radius_vlan_policy.certificate_max_age
    error_message = "certificate_max_age must be an integer of at least 7200 seconds to allow two hourly certificate collection cycles."
  }

  validation {
    condition = var.radius_vlan_policy == null ? true : alltrue([
      for vlan in concat(values(var.radius_vlan_policy.group_vlans), var.radius_vlan_policy.fallback_vlan == null ? [] : [var.radius_vlan_policy.fallback_vlan]) :
      vlan != null && try(vlan >= 1 && vlan <= 4094 && floor(vlan) == vlan, false)
    ])
    error_message = "VLAN IDs must be integers from 1 through 4094."
  }
  validation {
    condition     = var.radius_vlan_policy == null ? true : var.radius_vlan_policy.cache_max_age >= 60 && floor(var.radius_vlan_policy.cache_max_age) == var.radius_vlan_policy.cache_max_age
    error_message = "cache_max_age must be an integer of at least 60 seconds."
  }
  validation {
    condition = var.radius_vlan_policy == null ? true : (
      var.radius_vlan_policy.cache_file != "/etc/freeradius/3.0/device-policy-cache.json" || var.radius_vlan_policy.cache_max_age >= 600
    )
    error_message = "The built-in inventory cache refreshes every five minutes; cache_max_age must be at least 600 seconds."
  }
  validation {
    condition     = var.radius_vlan_policy == null ? true : startswith(var.radius_vlan_policy.cache_file, "/")
    error_message = "cache_file must be an absolute path to a trusted inventory snapshot."
  }
}

# Fresh-install root only. Existing production stays owned by its reviewed old
# configuration; the supported parallel deployment uses terraform/green.
variable "runtime_artifact_bucket" {
  type        = string
  description = "Reviewed private bucket containing immutable generation-pinned app/config/manifest/PEM/packages/provenance."
}
variable "runtime_artifacts" {
  type        = map(list(object({ name = string, sha256 = string, url = string })))
  description = "Complete independently pinned per-node incoming bundles. No credentials or inline application code."
  validation {
    condition     = toset(keys(var.runtime_artifacts)) == toset(["primary", "secondary"]) && alltrue([for artifacts in values(var.runtime_artifacts) : length(artifacts) >= 15 && length(artifacts) <= 69 && alltrue([for name in ["cloud-8021x", "config.yaml", "manifest.json", "postgres-ca.pem", "provenance.json"] : contains([for a in artifacts : a.name], name)]) && alltrue([for a in artifacts : can(regex("^[a-f0-9]{64}$", a.sha256)) && can(regex("^(cloud-8021x|config.yaml|manifest.json|postgres-ca.pem|provenance.json|[a-z0-9][a-z0-9+.-]*_[0-9A-Za-z.+:~-]+_(amd64|arm64|all)[.]deb)$", a.name)) && can(regex("^https://storage.googleapis.com/${var.runtime_artifact_bucket}/sha256/${a.sha256}/[^/?]+[?]generation=[0-9]+$", a.url))])])
    error_message = "Require both exact node bundles, fixed names, reviewed hashes, immutable private-bucket generations and bounded package closures."
  }
}
