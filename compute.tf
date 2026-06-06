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

# Secret Manager access for Jamf Pro API credentials (optional)
locals {
  jamf_secret_ids = var.jamf_url != "" ? [
    google_secret_manager_secret.jamf_url[0].secret_id,
    google_secret_manager_secret.jamf_client_id[0].secret_id,
    google_secret_manager_secret.jamf_client_secret[0].secret_id,
  ] : []
}

resource "google_secret_manager_secret_iam_member" "jamf_secrets_access" {
  for_each  = toset(local.jamf_secret_ids)
  project   = google_project.this.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager access for UniFi API key (optional)
resource "google_secret_manager_secret_iam_member" "unifi_api_key_access" {
  count     = var.unifi_api_key != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.unifi_api_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager access for Meraki API key (optional)
resource "google_secret_manager_secret_iam_member" "meraki_api_key_access" {
  count     = var.meraki_api_key != "" ? 1 : 0
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.meraki_api_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# Secret Manager read+write for RADIUS server certificates
# The VM generates certs on first boot and stores them in Secret Manager
# so they persist across VM replacements.
locals {
  cert_secret_ids = concat(
    [
      google_secret_manager_secret.radius_server_ca_key.secret_id,
      google_secret_manager_secret.radius_server_ca_cert.secret_id,
      google_secret_manager_secret.radius_server_key.secret_id,
      google_secret_manager_secret.radius_server_cert.secret_id,
      google_secret_manager_secret.radius_dh_params.secret_id,
    ],
    # Smallstep server cert/key — only present when the Smallstep CA is enabled.
    var.enable_smallstep_ca ? [
      google_secret_manager_secret.radius_smallstep_server_cert[0].secret_id,
      google_secret_manager_secret.radius_smallstep_server_key[0].secret_id,
    ] : [],
  )
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
    project_id                 = google_project.this.project_id
    server_cert_cn             = var.server_cert_cn
    server_cert_org            = var.server_cert_org
    has_root_ca                = var.okta_root_ca_cert_pem != ""
    has_jamf_lookup            = var.jamf_url != ""
    has_fleet_lookup           = var.enable_fleet_lookup
    has_unifi_lookup           = var.unifi_api_key != ""
    has_meraki_lookup          = var.meraki_api_key != ""
    meraki_org_id              = var.meraki_org_id
    rewrite_username           = var.rewrite_username && (var.jamf_url != "" || var.enable_fleet_lookup)
    rewrite_username_separator = var.rewrite_username_separator
    tls_session_cache          = var.tls_session_cache
    tls_session_cache_lifetime = var.tls_session_cache_lifetime
    tls_max_version            = var.tls_max_version
    datadog_site               = var.datadog_site
    radius_clients_json = jsonencode({
      for k, v in var.radius_clients : k => {
        cidrs       = v.cidrs
        description = v.description
        secret_id   = "radius-shared-secret-${k}"
      }
    })

    # --- Smallstep step-ca ---
    smallstep_enabled     = var.enable_smallstep_ca
    radius_trust_mode     = var.radius_trust_mode
    ca_name_prefix        = var.ca_name_prefix
    smallstep_ca_dns_name = var.smallstep_ca_dns_name
    smallstep_acme_name   = var.smallstep_acme_provisioner_name
    smallstep_scep_name   = var.smallstep_scep_provisioner_name
    acme_webhook_url      = var.acme_authorizing_webhook_url
    # On-VM ACME authorizing webhook (localhost systemd service).
    acme_webhook_enabled          = var.enable_acme_webhook
    webhook_release_version       = var.webhook_release_version
    webhook_port                  = var.webhook_port
    webhook_allow_label           = var.webhook_allow_label
    fleet_api_base_url            = var.fleet_api_base_url
    webhook_repo                  = "CampusTech/cloud-8021x"
    smallstep_signing_key_uri     = var.enable_smallstep_ca ? "cloudkms:projects/${google_project.this.project_id}/locations/${var.region}/keyRings/smallstep-ca/cryptoKeys/ca-signing/cryptoKeyVersions/1" : ""
    smallstep_ca_rsa_dns_name     = var.smallstep_ca_rsa_dns_name
    smallstep_scep_rsa_name       = var.smallstep_scep_rsa_provisioner_name
    smallstep_rsa_signing_key_uri = var.enable_smallstep_ca ? "cloudkms:projects/${google_project.this.project_id}/locations/${var.region}/keyRings/smallstep-ca/cryptoKeys/ca-signing-rsa/cryptoKeyVersions/1" : ""
    # SCEP decrypter is a shared software RSA key in Secret Manager, not KMS
    # (Cloud KMS keys are single-purpose; step-ca's SCEP decrypter must both
    # decrypt and sign). No KMS URI needed for it.
    smallstep_db_host = var.enable_smallstep_ca ? google_sql_database_instance.smallstep[0].private_ip_address : ""
    smallstep_db_name = "stepca"
    smallstep_db_user = "stepca"
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
    # Smallstep bootstrap prerequisites (no-op when enable_smallstep_ca=false:
    # these count-gated resources resolve to an empty set). Unindexed refs depend
    # on all instances of each resource so the VM waits for the CA's secrets, KMS
    # IAM, and Cloud SQL before the startup script consumes them on first boot.
    google_secret_manager_secret_version.smallstep_db_password,
    google_secret_manager_secret_version.smallstep_scep_challenge,
    google_secret_manager_secret_iam_member.smallstep_scep_challenge,
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
    # Smallstep bootstrap prerequisites (no-op when enable_smallstep_ca=false).
    google_secret_manager_secret_version.smallstep_db_password,
    google_secret_manager_secret_version.smallstep_scep_challenge,
    google_secret_manager_secret_iam_member.smallstep_scep_challenge,
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
