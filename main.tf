terraform {
  required_version = ">= 1.9" # cross-variable validation (radius_trust_mode vs enable_smallstep_ca)

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    datadog = {
      source  = "DataDog/datadog"
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

# Smallstep-issued RADIUS server cert + key (server-trust direction). Separate
# from radius-server-cert/-key (the legacy self-signed pair) so the two never
# clobber each other and radius_trust_mode=okta rolls back cleanly. Only created
# when the Smallstep CA is enabled.
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
# Secret Manager — Jamf Pro API credentials (optional)
# Enables device owner lookup: serial → email in RADIUS post-auth logs.
# -----------------------------------------------------------------------------

resource "google_secret_manager_secret" "jamf_url" {
  count     = var.jamf_url != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "jamf-url"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "jamf_url" {
  count       = var.jamf_url != "" ? 1 : 0
  secret      = google_secret_manager_secret.jamf_url[0].id
  secret_data = var.jamf_url
}

resource "google_secret_manager_secret" "jamf_client_id" {
  count     = var.jamf_url != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "jamf-client-id"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "jamf_client_id" {
  count       = var.jamf_url != "" ? 1 : 0
  secret      = google_secret_manager_secret.jamf_client_id[0].id
  secret_data = var.jamf_client_id
}

resource "google_secret_manager_secret" "jamf_client_secret" {
  count     = var.jamf_url != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "jamf-client-secret"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis["secretmanager.googleapis.com"]]
}

resource "google_secret_manager_secret_version" "jamf_client_secret" {
  count       = var.jamf_url != "" ? 1 : 0
  secret      = google_secret_manager_secret.jamf_client_secret[0].id
  secret_data = var.jamf_client_secret
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
