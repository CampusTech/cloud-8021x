terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "google" {
  region = var.region
}

# -----------------------------------------------------------------------------
# Project
# -----------------------------------------------------------------------------

resource "random_id" "project_suffix" {
  byte_length = 2
}

resource "google_project" "this" {
  name                = var.project_name
  project_id          = "${var.project_id}-${random_id.project_suffix.hex}"
  org_id              = var.org_id != "" ? var.org_id : null
  folder_id           = var.folder_id != "" ? var.folder_id : null
  billing_account     = var.billing_account_id
  auto_create_network = false
}

# -----------------------------------------------------------------------------
# Enable APIs
# -----------------------------------------------------------------------------

resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "secretmanager.googleapis.com",
    "iap.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
  ])

  project = google_project.this.project_id
  service = each.key

  disable_dependent_services = false
  disable_on_destroy         = false
}

# -----------------------------------------------------------------------------
# Secret Manager — per-office RADIUS shared secrets
# Each office gets a unique auto-generated secret stored in Secret Manager.
# -----------------------------------------------------------------------------

resource "random_password" "radius_secret" {
  for_each = var.radius_clients
  length   = 48
  special  = false
}

resource "google_secret_manager_secret" "radius_secret" {
  for_each  = var.radius_clients
  project   = google_project.this.project_id
  secret_id = "radius-shared-secret-${each.key}"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "radius_secret" {
  for_each    = var.radius_clients
  secret      = google_secret_manager_secret.radius_secret[each.key].id
  secret_data = random_password.radius_secret[each.key].result
}

# -----------------------------------------------------------------------------
# Secret Manager — RADIUS server certificates
# These are empty shells; the startup script generates certs on first boot
# and stores them here so they persist across VM replacements.
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "radius_server_ca_key" {
  project   = google_project.this.project_id
  secret_id = "radius-server-ca-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret" "radius_server_ca_cert" {
  project   = google_project.this.project_id
  secret_id = "radius-server-ca-cert"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret" "radius_server_key" {
  project   = google_project.this.project_id
  secret_id = "radius-server-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret" "radius_server_cert" {
  project   = google_project.this.project_id
  secret_id = "radius-server-cert"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret" "radius_dh_params" {
  project   = google_project.this.project_id
  secret_id = "radius-dh-params"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

# -----------------------------------------------------------------------------
# Secret Manager — Okta CA certificate
# The Okta Intermediate CA that signs SCEP client certs.
# This is a public cert (not secret), but stored here for consistency.
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "okta_ca_cert" {
  project   = google_project.this.project_id
  secret_id = "okta-ca-cert"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "okta_ca_cert" {
  secret      = google_secret_manager_secret.okta_ca_cert.id
  secret_data = var.okta_ca_cert_pem
}

# -----------------------------------------------------------------------------
# Secret Manager — Okta Root CA certificate (optional)
# Enables full chain validation: client cert → Intermediate → Root.
# Without this, FreeRADIUS trusts only the Intermediate CA directly.
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "okta_root_ca_cert" {
  count     = var.okta_root_ca_cert_pem != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "okta-root-ca-cert"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "okta_root_ca_cert" {
  count       = var.okta_root_ca_cert_pem != "" ? 1 : 0
  secret      = google_secret_manager_secret.okta_root_ca_cert[0].id
  secret_data = var.okta_root_ca_cert_pem
}

# -----------------------------------------------------------------------------
# Secret Manager — Datadog API key
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "datadog_api_key" {
  project   = google_project.this.project_id
  secret_id = "datadog-api-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "datadog_api_key" {
  secret      = google_secret_manager_secret.datadog_api_key.id
  secret_data = var.datadog_api_key
}
