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
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager access for Datadog API key
resource "google_secret_manager_secret_iam_member" "datadog_api_key_access" {
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.datadog_api_key.secret_id
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager access for UniFi API key (optional)
resource "google_secret_manager_secret_iam_member" "unifi_api_key_access" {
  count     = var.unifi_api_key != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.unifi_api_key[0].secret_id
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager access for Meraki API key (optional)
resource "google_secret_manager_secret_iam_member" "meraki_api_key_access" {
  count     = var.meraki_api_key != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.meraki_api_key[0].secret_id
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager read+write for RADIUS server certificates
# The VM generates certs on first boot and stores them in Secret Manager
# so they persist across VM replacements.
locals {
  cert_secret_ids = var.enable_smallstep_ca ? [
    google_secret_manager_secret.radius_smallstep_server_cert[0].secret_id,
    google_secret_manager_secret.radius_smallstep_server_key[0].secret_id,
  ] : []
}

resource "google_secret_manager_secret_iam_member" "cert_secrets_read" {
  for_each  = toset(local.cert_secret_ids)
  project   = google_project.this.project_id
  secret_id = each.value
  role      = google_project_iam_custom_role.runtime_secret_reader.name
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
  startup_scripts = { for role in ["primary", "secondary"] : role => templatefile("${path.module}/scripts/startup.sh", {
    project_number = google_project.this.number
    parallel       = false
    instance_name  = "radius-${role}"
    artifacts      = var.runtime_artifacts[role]
  }) }
}

resource "google_compute_instance" "radius" {
  # Existing disks require a separately approved staged in-place OS upgrade.
  # An image-family edit must never recreate both stateful RADIUS nodes.
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [boot_disk[0].initialize_params[0].image]
  }

  project      = google_project.this.project_id
  name         = "radius-primary"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["radius-server", "radius-primary"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-13"
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

  metadata = local.startup_metadata["primary"]

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  depends_on = [
    google_project_service.apis["compute.googleapis.com"],
    google_storage_bucket_iam_member.startup_script_reader,
    google_storage_bucket_iam_member.runtime_artifact_reader,
    google_project_iam_member.runtime_sql_trust,
    google_secret_manager_secret_iam_member.runtime_credentials,
    google_secret_manager_secret_version.radius_secret,
    google_secret_manager_secret_version.datadog_api_key,
    # Smallstep bootstrap prerequisites (no-op when enable_smallstep_ca=false:
    # these count-gated resources resolve to an empty set). Unindexed refs depend
    # on all instances of each resource so the VM waits for the CA's secrets, KMS
    # IAM, and Cloud SQL before the startup script consumes them on first boot.
    google_secret_manager_secret_version.smallstep_db_password,
    google_secret_manager_secret_version.scep_challenge_signing_key,
    google_secret_manager_secret_iam_member.scep_challenge_signing_key_radius,
    google_secret_manager_secret_version.scep_broker_token,
    google_secret_manager_secret_iam_member.scep_broker_token_radius,
    google_secret_manager_secret_iam_member.fleet_certificate_token_radius,
    terraform_data.certificate_inventory_contract,
    google_project_iam_member.radius_source_discovery,
    google_project_iam_member.radius_source_network_policy,
    google_compute_firewall.radius_discovered,
    google_secret_manager_secret_iam_member.unifi_api_key_access,
    google_secret_manager_secret_version.radius_accounting_key,
    google_secret_manager_secret_iam_member.radius_accounting_key,
    google_secret_manager_secret_iam_member.smallstep_ca_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_ca_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_intermediate_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_intermediate_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_scep_decrypter_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_scep_decrypter_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_scep_decrypter_key_version_manager,
    google_secret_manager_secret_iam_member.smallstep_scep_decrypter_key_accessor,
    google_kms_crypto_key_iam_member.smallstep_signing_use,
    google_kms_crypto_key_iam_member.smallstep_signing_viewer,
    google_sql_database.smallstep,
    google_sql_user.smallstep,
    # RSA step-ca (instance #2) bootstrap prerequisites — the startup script's
    # standalone RSA CA block needs the RSA KMS signing grant, the RSA secret
    # IAM (root/intermediate/decrypter cert + key), and the RSA DB before first
    # boot. (Self-contained RSA root; no dependency on the EC chain.)
    google_kms_crypto_key_iam_member.smallstep_signing_rsa_use,
    google_kms_crypto_key_iam_member.smallstep_signing_rsa_viewer,
    google_secret_manager_secret_iam_member.smallstep_rsa_root_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_rsa_root_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_rsa_intermediate_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_rsa_intermediate_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_rsa_scep_decrypter_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_rsa_scep_decrypter_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_rsa_scep_decrypter_key_version_manager,
    google_secret_manager_secret_iam_member.smallstep_rsa_scep_decrypter_key_accessor,
    google_sql_database.smallstep_rsa,
  ]
}

resource "google_compute_instance" "radius_secondary" {
  # Existing disks require a separately approved staged in-place OS upgrade.
  # An image-family edit must never recreate both stateful RADIUS nodes.
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [boot_disk[0].initialize_params[0].image]
  }

  project      = google_project.this.project_id
  name         = "radius-secondary"
  machine_type = var.machine_type
  zone         = var.secondary_zone
  tags         = ["radius-server", "radius-secondary"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-13"
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

  metadata = local.startup_metadata["secondary"]

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  depends_on = [
    google_project_service.apis["compute.googleapis.com"],
    google_storage_bucket_iam_member.startup_script_reader,
    google_storage_bucket_iam_member.runtime_artifact_reader,
    google_project_iam_member.runtime_sql_trust,
    google_secret_manager_secret_iam_member.runtime_credentials,
    google_secret_manager_secret_version.radius_secret,
    google_secret_manager_secret_version.datadog_api_key,
    # Smallstep bootstrap prerequisites (no-op when enable_smallstep_ca=false).
    google_secret_manager_secret_version.smallstep_db_password,
    google_secret_manager_secret_version.scep_challenge_signing_key,
    google_secret_manager_secret_iam_member.scep_challenge_signing_key_radius,
    google_secret_manager_secret_version.scep_broker_token,
    google_secret_manager_secret_iam_member.scep_broker_token_radius,
    google_secret_manager_secret_iam_member.fleet_certificate_token_radius,
    terraform_data.certificate_inventory_contract,
    google_project_iam_member.radius_source_discovery,
    google_project_iam_member.radius_source_network_policy,
    google_compute_firewall.radius_discovered,
    google_secret_manager_secret_iam_member.unifi_api_key_access,
    google_secret_manager_secret_version.radius_accounting_key,
    google_secret_manager_secret_iam_member.radius_accounting_key,
    google_secret_manager_secret_iam_member.smallstep_ca_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_ca_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_intermediate_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_intermediate_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_scep_decrypter_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_scep_decrypter_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_scep_decrypter_key_version_manager,
    google_secret_manager_secret_iam_member.smallstep_scep_decrypter_key_accessor,
    google_kms_crypto_key_iam_member.smallstep_signing_use,
    google_kms_crypto_key_iam_member.smallstep_signing_viewer,
    google_sql_database.smallstep,
    google_sql_user.smallstep,
    # RSA step-ca (instance #2) bootstrap prerequisites (see primary VM).
    google_kms_crypto_key_iam_member.smallstep_signing_rsa_use,
    google_kms_crypto_key_iam_member.smallstep_signing_rsa_viewer,
    google_secret_manager_secret_iam_member.smallstep_rsa_root_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_rsa_root_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_rsa_intermediate_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_rsa_intermediate_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_rsa_scep_decrypter_cert_version_manager,
    google_secret_manager_secret_iam_member.smallstep_rsa_scep_decrypter_cert_accessor,
    google_secret_manager_secret_iam_member.smallstep_rsa_scep_decrypter_key_version_manager,
    google_secret_manager_secret_iam_member.smallstep_rsa_scep_decrypter_key_accessor,
    google_sql_database.smallstep_rsa,
  ]
}

# Go pins enabled versions before access; accessor alone cannot list versions.
resource "google_project_iam_custom_role" "runtime_secret_reader" {
  project     = google_project.this.project_id
  role_id     = "radiusRuntimeSecretReader"
  title       = "RADIUS exact enabled version reader"
  permissions = ["secretmanager.versions.list", "secretmanager.versions.access"]
}
variable "runtime_secret_ids" {
  type        = set(string)
  default     = []
  description = "Additional exact private-provisioned app/CA-DSN credential IDs for fresh root installations; never administrator credentials."
}
resource "google_secret_manager_secret_iam_member" "runtime_credentials" {
  for_each  = var.runtime_secret_ids
  project   = google_project.this.project_id
  secret_id = each.value
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}
resource "google_project_iam_custom_role" "runtime_sql_trust" {
  project     = google_project.this.project_id
  role_id     = "radiusRuntimeSQLTrust"
  title       = "RADIUS exact SQL instance trust read"
  permissions = ["cloudsql.instances.get"]
}
resource "google_project_iam_member" "runtime_sql_trust" {
  count   = var.enable_smallstep_ca ? 1 : 0
  project = google_project.this.project_id
  role    = google_project_iam_custom_role.runtime_sql_trust.name
  member  = "serviceAccount:${google_service_account.radius.email}"
  condition {
    title      = "ExactSQLTrust"
    expression = "resource.type == 'sqladmin.googleapis.com/Instance' && resource.name == 'projects/${google_project.this.project_id}/instances/${google_sql_database_instance.smallstep[0].name}'"
  }
}
