terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 5.45.2"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.7.2"
    }
    datadog = {
      source  = "DataDog/datadog"
      version = "= 4.25.0"
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
    "storage.googleapis.com",
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

resource "google_secret_manager_secret" "radius_smallstep_server_cert" {
  count     = var.enable_smallstep_ca ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "radius-smallstep-server-cert"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret" "radius_smallstep_server_key" {
  count     = var.enable_smallstep_ca ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "radius-smallstep-server-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

# -----------------------------------------------------------------------------
# Secret Manager — UniFi API key (optional)
# Enables AP name and site name lookup in RADIUS auth logs.
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "unifi_api_key" {
  count     = var.unifi_api_key != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "unifi-api-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "unifi_api_key" {
  count       = var.unifi_api_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.unifi_api_key[0].id
  secret_data = var.unifi_api_key
}

# -----------------------------------------------------------------------------
# Secret Manager — Meraki Dashboard API key (optional)
# Enables AP name and network (site) name lookup in RADIUS auth logs for
# Meraki-managed sites. Independent of the UniFi key.
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "meraki_api_key" {
  count     = var.meraki_api_key != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "meraki-api-key"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "meraki_api_key" {
  count       = var.meraki_api_key != "" ? 1 : 0
  secret      = google_secret_manager_secret.meraki_api_key[0].id
  secret_data = var.meraki_api_key
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
