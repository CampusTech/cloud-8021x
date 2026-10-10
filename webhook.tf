# Unified Go daemon owns loopback mTLS authorization and optional challenge broker.
# These resources retain the separately owned enrollment frontdoors and credentials.
locals {
  acme_webhook_enabled = var.enable_acme_webhook ? 1 : 0
  # The fleet-api-token secret is read by the webhook AND by the device-owner
  # lookup; grant the VM SA access if either consumer is enabled.
  fleet_token_needed     = (var.enable_acme_webhook || var.enable_fleet_lookup) ? 1 : 0
  scep_inventory_enabled = try(var.radius_vlan_policy.certificate_inventory, false) && var.enable_acme_webhook
}

# These preconditions protect the issuance boundary: neutral challenges must
# never be exposed while RADIUS still authorizes client-selected subject names.
resource "terraform_data" "certificate_inventory_contract" {
  lifecycle {
    precondition {
      condition     = !local.scep_inventory_enabled || (var.enable_smallstep_ca && var.enable_fleet_certificate_inventory && try(var.radius_vlan_policy.cache_file == "/etc/freeradius/3.0/device-policy-cache.json", false))
      error_message = "Dynamic SCEP requires the self-hosted CA, Smallstep RADIUS trust, Fleet certificate collection, and the built-in fingerprint policy cache."
    }
  }
}

# Separate Fleet-to-broker credential. Never distribute the signing key to Fleet
# or devices. Both nodes share these secrets for stateless challenge verification.
resource "random_password" "scep_broker_token" {
  count   = local.scep_inventory_enabled ? 1 : 0
  length  = 48
  special = false
}

resource "google_secret_manager_secret" "scep_broker_token" {
  count     = local.scep_inventory_enabled ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "scep-broker-token"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "scep_broker_token" {
  count       = local.scep_inventory_enabled ? 1 : 0
  secret      = google_secret_manager_secret.scep_broker_token[0].id
  secret_data = random_password.scep_broker_token[0].result
}

resource "google_secret_manager_secret_iam_member" "scep_broker_token_radius" {
  count     = local.scep_inventory_enabled ? 1 : 0
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.scep_broker_token[0].secret_id
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}

output "fleet_scep_challenge_url" {
  description = "Fleet Smallstep challenge_url. Authenticate as fleet using the scep-broker-token secret; never use the signing key."
  value       = local.scep_inventory_enabled ? "https://${var.smallstep_ca_rsa_dns_name}/fleet/scep-challenge" : ""
}

output "fleet_ndes_admin_url" {
  description = "Fleet Windows NDES admin_url. Authenticate as fleet using the scep-broker-token secret."
  value       = local.scep_inventory_enabled ? "https://${var.smallstep_ca_rsa_dns_name}/fleet/ndes-challenge" : ""
}

# Only the authenticated challenge routes are public. CA authorization remains on
# a separate loopback listener requiring mutual TLS. GFE-to-broker traffic also
# uses TLS; the firewall prevents clients bypassing the HTTPS load balancer.
resource "google_compute_firewall" "scep_broker" {
  count   = local.scep_inventory_enabled ? 1 : 0
  project = google_project.this.project_id
  name    = "allow-scep-broker-lb"
  network = google_compute_network.radius.id
  allow {
    protocol = "tcp"
    ports    = ["9081"]
  }
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["radius-server"]
}

resource "google_compute_health_check" "scep_broker" {
  count   = local.scep_inventory_enabled ? 1 : 0
  project = google_project.this.project_id
  name    = "scep-broker-hc"
  https_health_check {
    port         = 9081
    request_path = "/healthz"
  }
}

# Fleet requests challenges for many devices behind the same outbound IP. Keep
# its burst budget separate from device-to-CA traffic, and throttle excess
# requests without banning the shared Fleet IP for subsequent minutes.
resource "google_compute_security_policy" "scep_broker" {
  count   = local.scep_inventory_enabled ? 1 : 0
  project = google_project.this.project_id
  name    = "scep-broker-armor"

  rule {
    action   = "throttle"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.scep_broker_requests_per_minute
        interval_sec = 60
      }
    }
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default allow"
  }
}

resource "google_compute_backend_service" "scep_broker" {
  count                 = local.scep_inventory_enabled ? 1 : 0
  project               = google_project.this.project_id
  name                  = "scep-broker-backend"
  protocol              = "HTTPS"
  port_name             = "scep-broker"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 15
  health_checks         = [google_compute_health_check.scep_broker[0].id]
  security_policy       = google_compute_security_policy.scep_broker[0].id
  backend {
    group = google_compute_instance_group.smallstep_primary[0].id
  }
  backend {
    group = google_compute_instance_group.smallstep_secondary[0].id
  }
}

# Fleet API token — a standing credential created OUT-OF-BAND so it never passes
# through tfvars/CI/CLI history. Create it (container + value) yourself from an
# API-only account token, BEFORE applying with the webhook enabled. Collection
# requires maintainer access; read-only issuance lookup can use observer access:
#   ~/.fleetctl/fleetctl user create --name 'ACME Webhook' --api-only   # prints token
#   printf '%s' '<token>' | gcloud secrets create fleet-api-token \
#     --project=YOUR_PROJECT_ID --replication-policy=automatic --data-file=-
# Terraform only REFERENCES it (data source) + grants the RADIUS VM SA access.
# Also consumed by the device-owner lookup (enable_fleet_lookup), so the data
# source is present whenever either the webhook or the lookup is enabled.
data "google_secret_manager_secret" "fleet_api_token" {
  count     = local.fleet_token_needed
  project   = google_project.this.project_id
  secret_id = "fleet-api-token"
}

resource "google_secret_manager_secret_iam_member" "fleet_api_token_radius" {
  count     = local.fleet_token_needed
  project   = google_project.this.project_id
  secret_id = data.google_secret_manager_secret.fleet_api_token[0].secret_id
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Optional scoped collector credential; observer consumers keep fleet-api-token.
resource "google_secret_manager_secret_iam_member" "fleet_certificate_token_radius" {
  count     = var.enable_fleet_certificate_inventory && var.fleet_certificate_token_secret_id != "fleet-api-token" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = var.fleet_certificate_token_secret_id
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# The webhook authorize endpoint step-ca calls — always loopback now.
output "acme_webhook_url" {
  description = "URL step-ca uses to reach the on-VM authorizing webhook (loopback). Set acme_authorizing_webhook_url to this value. Empty if disabled."
  value       = var.enable_acme_webhook ? "https://127.0.0.1:${var.webhook_port}/authorize" : ""
}

# Device-bound enrollment token key. This is independent of the webhook HMAC
# and of the retired client-distributed SCEP password. Never send it to devices.
resource "random_password" "scep_challenge_signing_key" {
  count   = local.acme_webhook_enabled
  length  = 48
  special = false
}

resource "google_secret_manager_secret" "scep_challenge_signing_key" {
  count     = local.acme_webhook_enabled
  project   = google_project.this.project_id
  secret_id = "scep-challenge-signing-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "scep_challenge_signing_key" {
  count       = local.acme_webhook_enabled
  secret      = google_secret_manager_secret.scep_challenge_signing_key[0].id
  secret_data = random_password.scep_challenge_signing_key[0].result
}

resource "google_secret_manager_secret_iam_member" "scep_challenge_signing_key_radius" {
  count     = local.acme_webhook_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.scep_challenge_signing_key[0].secret_id
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}
