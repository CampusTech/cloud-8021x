# =============================================================================
# Optional self-hosted Smallstep step-ca
# Gated by var.enable_smallstep_ca. All resources use count = ... ? 1 : 0.
# =============================================================================

locals {
  smallstep_enabled = var.enable_smallstep_ca ? 1 : 0
}

# --- Cloud KMS: keyring + CA signing key (HSM) + SCEP decrypter (RSA) --------

resource "google_project_service" "smallstep_apis" {
  for_each = var.enable_smallstep_ca ? toset([
    "cloudkms.googleapis.com",
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
  ]) : toset([])
  project            = google_project.this.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_kms_key_ring" "smallstep" {
  count    = local.smallstep_enabled
  project  = google_project.this.project_id
  name     = "smallstep-ca"
  location = var.region

  depends_on = [google_project_service.smallstep_apis]
}

# CA signing key — HSM protection level for FIPS 140-2 L3 posture.
resource "google_kms_crypto_key" "smallstep_signing" {
  count    = local.smallstep_enabled
  name     = "ca-signing"
  key_ring = google_kms_key_ring.smallstep[0].id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# SCEP decrypter — RSA key.
#
# DEPRECATED / UNUSED as of the move to a software decrypter key: step-ca's SCEP
# provisioner needs the decrypter key to BOTH decrypt and sign, but Cloud KMS
# keys are single-purpose (ASYMMETRIC_DECRYPT can't sign), so this key cannot
# back the SCEP decrypter — see smallstep-scep-decrypter-key (a shared software
# RSA key in Secret Manager) and the SCEP provisioner block in startup.sh.
# Retained (prevent_destroy, HSM) so no destroy is required; the VM no longer
# references it. Safe to remove in a future cleanup once confirmed unused.
resource "google_kms_crypto_key" "smallstep_scep_decrypter" {
  count    = local.smallstep_enabled
  name     = "scep-decrypter"
  key_ring = google_kms_key_ring.smallstep[0].id
  purpose  = "ASYMMETRIC_DECRYPT"

  version_template {
    algorithm        = "RSA_DECRYPT_OAEP_2048_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Grant the RADIUS VM service account use of the SIGNING key (the live CA
# signer). The scep-decrypter KMS key is deprecated/unused — the SCEP decrypter
# is now a software RSA key in Secret Manager — so it gets NO IAM grants here.
resource "google_kms_crypto_key_iam_member" "smallstep_signing_use" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing[0].id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

# Viewer on the signing key's public key (fetched for ca.json / CSR signing).
resource "google_kms_crypto_key_iam_member" "smallstep_signing_viewer" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

# RSA CA signing key — backs the SECOND step-ca instance's intermediate, which
# issues SCEP leaves for Windows + non-ADE/DEP Macs. Windows native SCEP and
# Apple SCEP both require an RSA-signed leaf; the EC key (above) cannot serve
# them. ASYMMETRIC_SIGN purpose (issuing only — distinct from the single-purpose
# ASYMMETRIC_DECRYPT scep-decrypter key). HSM for FIPS posture, matching ca-signing.
resource "google_kms_crypto_key" "smallstep_signing_rsa" {
  count    = local.smallstep_enabled
  name     = "ca-signing-rsa"
  key_ring = google_kms_key_ring.smallstep[0].id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "RSA_SIGN_PKCS1_2048_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "smallstep_signing_rsa_use" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing_rsa[0].id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_kms_crypto_key_iam_member" "smallstep_signing_rsa_viewer" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing_rsa[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

# --- Cloud SQL Postgres for ACME state (shared by both step-ca instances) ----

resource "random_password" "smallstep_db" {
  count   = local.smallstep_enabled
  length  = 32
  special = false
}

resource "google_secret_manager_secret" "smallstep_db_password" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-db-password"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "smallstep_db_password" {
  count       = local.smallstep_enabled
  secret      = google_secret_manager_secret.smallstep_db_password[0].id
  secret_data = random_password.smallstep_db[0].result
}

resource "google_secret_manager_secret_iam_member" "smallstep_db_password" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_db_password[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_sql_database_instance" "smallstep" {
  count               = local.smallstep_enabled
  project             = google_project.this.project_id
  name                = "smallstep-ca"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  settings {
    tier              = var.smallstep_db_tier
    availability_type = "REGIONAL"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.radius.id
    }
    backup_configuration {
      enabled = true
    }
  }

  depends_on = [
    google_project_service.smallstep_apis,
    google_service_networking_connection.smallstep[0],
  ]
}

resource "google_sql_database" "smallstep" {
  count    = local.smallstep_enabled
  project  = google_project.this.project_id
  name     = "stepca"
  instance = google_sql_database_instance.smallstep[0].name
}

resource "google_sql_database" "smallstep_rsa" {
  count    = local.smallstep_enabled
  project  = google_project.this.project_id
  name     = "stepca_rsa"
  instance = google_sql_database_instance.smallstep[0].name
}

resource "google_sql_user" "smallstep" {
  count    = local.smallstep_enabled
  project  = google_project.this.project_id
  name     = "stepca"
  instance = google_sql_database_instance.smallstep[0].name
  password = random_password.smallstep_db[0].result
}

# Private Services Access — required for Cloud SQL private IP in this VPC.
resource "google_compute_global_address" "smallstep_psa" {
  count         = local.smallstep_enabled
  project       = google_project.this.project_id
  name          = "smallstep-psa-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.radius.id
}

resource "google_service_networking_connection" "smallstep" {
  count                   = local.smallstep_enabled
  network                 = google_compute_network.radius.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.smallstep_psa[0].name]
}

# --- SCEP static challenge (Fleet proxies a per-host challenge in front; this
#     is the upstream secret step-ca itself checks). ---------------------------
resource "random_password" "smallstep_scep_challenge" {
  count   = local.smallstep_enabled
  length  = 40
  special = false
}

resource "google_secret_manager_secret" "smallstep_scep_challenge" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-scep-challenge"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "smallstep_scep_challenge" {
  count       = local.smallstep_enabled
  secret      = google_secret_manager_secret.smallstep_scep_challenge[0].id
  secret_data = random_password.smallstep_scep_challenge[0].result
}

# --- CA root cert: created empty, populated by the VM on first init, read back
#     out for distribution (RADIUS trust bundle, MDM profiles). ----------------
resource "google_secret_manager_secret" "smallstep_ca_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-ca-cert"
  replication {
    auto {}
  }
}

# --- Secret IAM: VM SA can read challenge + read/write the CA cert. -----------
resource "google_secret_manager_secret_iam_member" "smallstep_scep_challenge" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_scep_challenge[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_ca_cert_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_ca_cert[0].secret_id
  # Lets the VM add a new version when it first initializes the CA.
  role   = "roles/secretmanager.secretVersionManager"
  member = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_ca_cert_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_ca_cert[0].secret_id
  # Lets the VM (and Terraform via data source) read the CA cert back.
  role   = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.radius.email}"
}

# --- CA intermediate cert: created empty, populated by the first VM alongside
#     the root cert. step-ca 0.30.2 can't init against a pre-created KMS key, so
#     a local root key signs a KMS-backed intermediate; the intermediate's
#     public key is byte-identical to the KMS signing key. Both certs must be
#     persisted so the 2nd VM / any reboot restores a chain that matches the
#     live KMS signer (the only private key that stays alive). -----------------
resource "google_secret_manager_secret" "smallstep_intermediate_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-intermediate-cert"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "smallstep_intermediate_cert_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_intermediate_cert[0].secret_id
  # Lets the VM add a new version when it first initializes the CA.
  role   = "roles/secretmanager.secretVersionManager"
  member = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_intermediate_cert_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_intermediate_cert[0].secret_id
  # Lets the VM (and Terraform via data source) read the intermediate cert back.
  role   = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.radius.email}"
}

# --- SCEP decrypter cert: an X.509 leaf whose public key is the Cloud KMS
#     scep-decrypter RSA key. step-ca's SCEP provisioner requires BOTH a
#     decrypterCertificate AND a decrypterKeyURI; clients encrypt SCEP requests
#     to this cert and step-ca decrypts with the KMS private key. Created empty,
#     populated by the first VM at CA init (signed by the root before the local
#     root key is discarded), and restored by the 2nd VM / any reboot. ----------
resource "google_secret_manager_secret" "smallstep_scep_decrypter_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-scep-decrypter-cert"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "smallstep_scep_decrypter_cert_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_scep_decrypter_cert[0].secret_id
  # Lets the VM add a new version when it first initializes the CA.
  role   = "roles/secretmanager.secretVersionManager"
  member = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_scep_decrypter_cert_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_scep_decrypter_cert[0].secret_id
  # Lets the VM (and Terraform via data source) read the decrypter cert back.
  role   = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.radius.email}"
}

# SCEP decrypter PRIVATE key (shared software RSA key).
#
# step-ca's SCEP provisioner needs the decrypter key to BOTH decrypt SCEP
# envelopes and sign SCEP responses. Cloud KMS keys are single-purpose
# (ASYMMETRIC_DECRYPT can't sign), so the SCEP decrypter cannot be KMS-backed —
# a KMS decrypter fails init ("does not have decrypter") and every PKIOperation
# 500s. Instead the VM generates a dual-purpose RSA key at CA init and persists
# it here so both HA nodes + rebuilds share ONE decrypter identity (required
# behind the round-robin LB). The CA SIGNING key stays in Cloud KMS/HSM; this
# key only handles SCEP message crypto and never issues certificates.
resource "google_secret_manager_secret" "smallstep_scep_decrypter_key" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-scep-decrypter-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "smallstep_scep_decrypter_key_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_scep_decrypter_key[0].secret_id
  # Lets the VM add the key version when it first initializes the CA.
  role   = "roles/secretmanager.secretVersionManager"
  member = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_scep_decrypter_key_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_scep_decrypter_key[0].secret_id
  # Lets both HA nodes read the shared decrypter key back at boot.
  role   = "roles/secretmanager.secretAccessor"
  member = "serviceAccount:${google_service_account.radius.email}"
}

# --- RSA CA (instance #2) persisted artifacts. Same model as instance #1:
#     created empty here, populated by the first VM at RSA-CA init, restored by
#     the 2nd VM / any reboot. smallstep-rsa-intermediate-cert is the readiness
#     marker (published LAST). -------------------------------------------------
# RSA CA self-signed ROOT cert. The RSA instance has its OWN root (not the EC
# root): the EC root's private key is discarded after EC init and is not
# persisted, and the EC intermediate is pathlen:0 (can't sign a sub-CA), so the
# RSA intermediate cannot chain under the existing EC chain. The RSA root is
# self-signed at RSA init and persisted here for HA restore; RADIUS trusts BOTH
# roots (EC for ACME Macs, RSA for SCEP Windows/non-ADE Macs).
resource "google_secret_manager_secret" "smallstep_rsa_root_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-rsa-root-cert"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_root_cert_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_root_cert[0].secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_root_cert_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_root_cert[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret" "smallstep_rsa_intermediate_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-rsa-intermediate-cert"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_intermediate_cert_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_intermediate_cert[0].secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_intermediate_cert_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_intermediate_cert[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret" "smallstep_rsa_scep_decrypter_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-rsa-scep-decrypter-cert"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_scep_decrypter_cert_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_scep_decrypter_cert[0].secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_scep_decrypter_cert_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_scep_decrypter_cert[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret" "smallstep_rsa_scep_decrypter_key" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-rsa-scep-decrypter-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_scep_decrypter_key_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_scep_decrypter_key[0].secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_scep_decrypter_key_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_scep_decrypter_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

# --- Firewall: step-ca HTTPS listener reachable by the GCP load-balancer +
#     health-check ranges (the public front door is the GCLB in Task 5). ------
resource "google_compute_firewall" "allow_stepca_lb" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "allow-stepca-lb"
  network = google_compute_network.radius.id

  allow {
    protocol = "tcp"
    ports    = ["8443"]
  }

  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["radius-server"]
}

# --- External HTTPS load balancer fronting both VMs' step-ca listeners --------

resource "google_compute_global_address" "smallstep_lb" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-lb-ip"
}

resource "google_compute_managed_ssl_certificate" "smallstep" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-cert"
  managed {
    domains = [var.smallstep_ca_dns_name]
  }
}

# Unmanaged instance group per VM zone, each holding its RADIUS VM.
resource "google_compute_instance_group" "smallstep_primary" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  name      = "smallstep-ig-primary"
  zone      = var.zone
  instances = [google_compute_instance.radius.self_link]
  named_port {
    name = "stepca"
    port = 8443
  }
  # RSA step-ca (instance #2) is served from the SAME instance group on a second
  # named port — GCP forbids a VM being in two load-balanced instance groups, so
  # the RSA backend reuses this group rather than its own.
  named_port {
    name = "stepca-rsa"
    port = 8444
  }
}

resource "google_compute_instance_group" "smallstep_secondary" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  name      = "smallstep-ig-secondary"
  zone      = var.secondary_zone
  instances = [google_compute_instance.radius_secondary.self_link]
  named_port {
    name = "stepca"
    port = 8443
  }
  # RSA step-ca (instance #2) — second named port on the shared group (see primary).
  named_port {
    name = "stepca-rsa"
    port = 8444
  }
}

resource "google_compute_health_check" "smallstep" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-hc"
  https_health_check {
    port         = 8443
    request_path = "/health"
  }
}

resource "google_compute_security_policy" "smallstep" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-armor"

  rule {
    action   = "rate_based_ban"
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
        count        = 100
        interval_sec = 60
      }
      ban_duration_sec = 300
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

resource "google_compute_backend_service" "smallstep" {
  count                 = local.smallstep_enabled
  project               = google_project.this.project_id
  name                  = "smallstep-ca-backend"
  protocol              = "HTTPS"
  port_name             = "stepca"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  health_checks         = [google_compute_health_check.smallstep[0].id]
  security_policy       = google_compute_security_policy.smallstep[0].id

  backend {
    group = google_compute_instance_group.smallstep_primary[0].id
  }
  backend {
    group = google_compute_instance_group.smallstep_secondary[0].id
  }
}

resource "google_compute_url_map" "smallstep" {
  count           = local.smallstep_enabled
  project         = google_project.this.project_id
  name            = "smallstep-ca-urlmap"
  default_service = google_compute_backend_service.smallstep[0].id
}

resource "google_compute_target_https_proxy" "smallstep" {
  count            = local.smallstep_enabled
  project          = google_project.this.project_id
  name             = "smallstep-ca-https-proxy"
  url_map          = google_compute_url_map.smallstep[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.smallstep[0].id]
}

resource "google_compute_global_forwarding_rule" "smallstep" {
  count                 = local.smallstep_enabled
  project               = google_project.this.project_id
  name                  = "smallstep-ca-fr"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.smallstep_lb[0].address
  port_range            = "443"
  target                = google_compute_target_https_proxy.smallstep[0].id
}

# --- RSA step-ca (instance #2): firewall + external HTTPS LB on :8444 ----------
resource "google_compute_firewall" "allow_stepca_rsa_lb" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "allow-stepca-rsa-lb"
  network = google_compute_network.radius.id
  allow {
    protocol = "tcp"
    ports    = ["8444"]
  }
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["radius-server"]
}

resource "google_compute_global_address" "smallstep_rsa_lb" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-rsa-lb-ip"
}

resource "google_compute_managed_ssl_certificate" "smallstep_rsa" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-rsa-cert"
  managed {
    domains = [var.smallstep_ca_rsa_dns_name]
  }
}

# NOTE: the RSA backend reuses the EXISTING smallstep_primary/secondary instance
# groups (via their second "stepca-rsa" named port on 8444). GCP forbids a VM in
# two load-balanced instance groups, so there are intentionally no dedicated RSA
# instance groups.

resource "google_compute_health_check" "smallstep_rsa" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-rsa-hc"
  https_health_check {
    port         = 8444
    request_path = "/health"
  }
}

resource "google_compute_backend_service" "smallstep_rsa" {
  count                 = local.smallstep_enabled
  project               = google_project.this.project_id
  name                  = "smallstep-ca-rsa-backend"
  protocol              = "HTTPS"
  port_name             = "stepca-rsa"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  health_checks         = [google_compute_health_check.smallstep_rsa[0].id]
  security_policy       = google_compute_security_policy.smallstep[0].id

  backend {
    group = google_compute_instance_group.smallstep_primary[0].id
  }
  backend {
    group = google_compute_instance_group.smallstep_secondary[0].id
  }
}

resource "google_compute_url_map" "smallstep_rsa" {
  count           = local.smallstep_enabled
  project         = google_project.this.project_id
  name            = "smallstep-ca-rsa-urlmap"
  default_service = google_compute_backend_service.smallstep_rsa[0].id
}

resource "google_compute_target_https_proxy" "smallstep_rsa" {
  count            = local.smallstep_enabled
  project          = google_project.this.project_id
  name             = "smallstep-ca-rsa-https-proxy"
  url_map          = google_compute_url_map.smallstep_rsa[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.smallstep_rsa[0].id]
}

resource "google_compute_global_forwarding_rule" "smallstep_rsa" {
  count                 = local.smallstep_enabled
  project               = google_project.this.project_id
  name                  = "smallstep-ca-rsa-fr"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.smallstep_rsa_lb[0].address
  port_range            = "443"
  target                = google_compute_target_https_proxy.smallstep_rsa[0].id
}
