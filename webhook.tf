# =============================================================================
# ACME authorizing webhook — secrets + IAM.
#
# The webhook runs as a LOCALHOST systemd service on each RADIUS VM (built from
# webhook/, released via the webhook-release GitHub Action, downloaded by the VM
# startup script), NOT as a separate Cloud Run service. step-ca calls it over
# loopback (https://127.0.0.1:<port>/authorize), so there is no public hop, no
# extra TLS, and no independent outage surface. This file therefore only manages
# the secrets the webhook reads at runtime, granting access to the RADIUS VM
# service account. Gated by var.enable_acme_webhook (needs enable_smallstep_ca).
# =============================================================================

locals {
  acme_webhook_enabled = var.enable_acme_webhook ? 1 : 0
  # The fleet-api-token secret is read by the webhook AND by the device-owner
  # lookup; grant the VM SA access if either consumer is enabled.
  fleet_token_needed = (var.enable_acme_webhook || var.enable_fleet_lookup) ? 1 : 0
}

# Fleet API token — a standing credential created OUT-OF-BAND so it never passes
# through tfvars/CI/CLI history. Create it (container + value) yourself from an
# api-only observer user's token, BEFORE applying with the webhook enabled:
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
  role      = "roles/secretmanager.secretAccessor"
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
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}
