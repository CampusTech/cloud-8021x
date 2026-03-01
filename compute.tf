# -----------------------------------------------------------------------------
# Service account
# -----------------------------------------------------------------------------

resource "google_service_account" "radius" {
  project      = google_project.this.project_id
  account_id   = "radius-vm"
  display_name = "RADIUS VM Service Account"

  depends_on = [google_project_service.apis["compute.googleapis.com"]]
}

# Secret Manager access for per-office RADIUS shared secrets
resource "google_secret_manager_secret_iam_member" "radius_secret_access" {
  for_each  = var.radius_clients
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.radius_secret[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager access for Datadog API key
resource "google_secret_manager_secret_iam_member" "datadog_api_key_access" {
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.datadog_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager access for Okta CA certificate
resource "google_secret_manager_secret_iam_member" "okta_ca_access" {
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.okta_ca_cert.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager access for Okta Root CA certificate (optional)
resource "google_secret_manager_secret_iam_member" "okta_root_ca_access" {
  count     = var.okta_root_ca_cert_pem != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.okta_root_ca_cert[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager read+write for RADIUS server certificates
# The VM generates certs on first boot and stores them in Secret Manager
# so they persist across VM replacements.
locals {
  cert_secret_ids = [
    google_secret_manager_secret.radius_server_ca_key.secret_id,
    google_secret_manager_secret.radius_server_ca_cert.secret_id,
    google_secret_manager_secret.radius_server_key.secret_id,
    google_secret_manager_secret.radius_server_cert.secret_id,
    google_secret_manager_secret.radius_dh_params.secret_id,
  ]
}

resource "google_secret_manager_secret_iam_member" "cert_secrets_read" {
  for_each  = toset(local.cert_secret_ids)
  project   = google_project.this.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "cert_secrets_write" {
  for_each  = toset(local.cert_secret_ids)
  project   = google_project.this.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretVersionAdder"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# -----------------------------------------------------------------------------
# GCE instances (primary + secondary for HA)
# -----------------------------------------------------------------------------

locals {
  startup_script = templatefile("${path.module}/scripts/startup.sh", {
    project_id      = google_project.this.project_id
    server_cert_cn  = var.server_cert_cn
    server_cert_org = var.server_cert_org
    has_root_ca     = var.okta_root_ca_cert_pem != ""
    datadog_site    = var.datadog_site
    radius_clients_json = jsonencode({
      for k, v in var.radius_clients : k => {
        cidrs       = v.cidrs
        description = v.description
        secret_id   = "radius-shared-secret-${k}"
      }
    })
  })
}

resource "google_compute_instance" "radius" {
  project      = google_project.this.project_id
  name         = "radius-primary"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["radius-server"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.radius.id

    access_config {
      nat_ip = google_compute_address.radius.address
    }
  }

  service_account {
    email  = google_service_account.radius.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    startup-script = local.startup_script
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  depends_on = [
    google_project_service.apis["compute.googleapis.com"],
    google_secret_manager_secret_version.okta_ca_cert,
    google_secret_manager_secret_version.radius_secret,
    google_secret_manager_secret_version.datadog_api_key,
  ]
}

resource "google_compute_instance" "radius_secondary" {
  project      = google_project.this.project_id
  name         = "radius-secondary"
  machine_type = var.machine_type
  zone         = var.secondary_zone
  tags         = ["radius-server"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.radius.id

    access_config {
      nat_ip = google_compute_address.radius_secondary.address
    }
  }

  service_account {
    email  = google_service_account.radius.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    startup-script = local.startup_script
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  depends_on = [
    google_project_service.apis["compute.googleapis.com"],
    google_secret_manager_secret_version.okta_ca_cert,
    google_secret_manager_secret_version.radius_secret,
    google_secret_manager_secret_version.datadog_api_key,
  ]
}
