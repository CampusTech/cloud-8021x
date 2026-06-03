# =============================================================================
# ACME authorizing webhook (Cloud Run). Gated by var.enable_acme_webhook
# (which itself only makes sense with enable_smallstep_ca = true).
# =============================================================================

locals {
  acme_webhook_enabled = var.enable_acme_webhook ? 1 : 0
}

resource "google_project_service" "webhook_apis" {
  for_each = var.enable_acme_webhook ? toset([
    "run.googleapis.com",
  ]) : toset([])
  project            = google_project.this.project_id
  service            = each.value
  disable_on_destroy = false
}

# Dedicated service account for the webhook (least privilege).
resource "google_service_account" "webhook" {
  count        = local.acme_webhook_enabled
  project      = google_project.this.project_id
  account_id   = "acme-authz-webhook"
  display_name = "ACME authorizing webhook"
}

# Shared HMAC signing secret (step-ca <-> webhook). Generated here.
resource "random_password" "webhook_signing_secret" {
  count   = local.acme_webhook_enabled
  length  = 48
  special = false
}

resource "google_secret_manager_secret" "webhook_signing_secret" {
  count     = local.acme_webhook_enabled
  project   = google_project.this.project_id
  secret_id = "acme-webhook-signing-secret"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "webhook_signing_secret" {
  count       = local.acme_webhook_enabled
  secret      = google_secret_manager_secret.webhook_signing_secret[0].id
  secret_data = random_password.webhook_signing_secret[0].result
}

# Fleet API token — a standing credential created OUT-OF-BAND so it never
# passes through tfvars/CI/CLI history. Create it (container + value) yourself
# from an api-only observer user's token, BEFORE applying with the webhook
# enabled:
#   ~/.fleetctl/fleetctl user create --name 'ACME Webhook' --api-only   # prints token
#   printf '%s' '<token>' | gcloud secrets create fleet-api-token \
#     --project=campus-cloud-8021x-42e6 --replication-policy=automatic --data-file=-
# Terraform only REFERENCES it (data source) + grants the webhook SA access.
data "google_secret_manager_secret" "fleet_api_token" {
  count     = local.acme_webhook_enabled
  project   = google_project.this.project_id
  secret_id = "fleet-api-token"
}

# The webhook SA reads both secrets; the RADIUS VM SA reads the signing secret
# (step-ca needs it to sign).
resource "google_secret_manager_secret_iam_member" "webhook_signing_secret_webhook" {
  count     = local.acme_webhook_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.webhook_signing_secret[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.webhook[0].email}"
}

resource "google_secret_manager_secret_iam_member" "webhook_signing_secret_radius" {
  count     = local.acme_webhook_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.webhook_signing_secret[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "fleet_api_token_webhook" {
  count     = local.acme_webhook_enabled
  project   = google_project.this.project_id
  secret_id = data.google_secret_manager_secret.fleet_api_token[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.webhook[0].email}"
}

resource "google_cloud_run_v2_service" "webhook" {
  count    = local.acme_webhook_enabled
  project  = google_project.this.project_id
  name     = "acme-authz-webhook"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.webhook[0].email
    containers {
      image = var.webhook_image
      ports {
        container_port = 8080
      }
      env {
        name  = "FLEET_API_BASE_URL"
        value = var.fleet_api_base_url
      }
      env {
        name  = "ALLOW_LABEL"
        value = var.webhook_allow_label
      }
      env {
        name = "WEBHOOK_SIGNING_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.webhook_signing_secret[0].secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "FLEET_API_TOKEN"
        value_source {
          secret_key_ref {
            secret  = data.google_secret_manager_secret.fleet_api_token[0].secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [google_project_service.webhook_apis]
}

# step-ca calls the webhook over the public internet; the HMAC signature is the
# auth. Allow unauthenticated invocations (the signature gate is in-app).
resource "google_cloud_run_v2_service_iam_member" "webhook_public" {
  count    = local.acme_webhook_enabled
  project  = google_project.this.project_id
  location = var.region
  name     = google_cloud_run_v2_service.webhook[0].name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "acme_webhook_url" {
  description = "URL of the ACME authorizing webhook; set acme_authorizing_webhook_url to this + /authorize. Empty if disabled."
  value       = var.enable_acme_webhook ? "${google_cloud_run_v2_service.webhook[0].uri}/authorize" : ""
}
