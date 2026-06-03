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

# SCEP decrypter — RSA decryption key. SCEP CMS uses RSA; PKCS#1 v1.5 decrypt.
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

# Grant the RADIUS VM service account use of both keys.
resource "google_kms_crypto_key_iam_member" "smallstep_signing_use" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing[0].id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_kms_crypto_key_iam_member" "smallstep_scep_decrypt" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_scep_decrypter[0].id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

# Also need viewer on the public keys to fetch them for ca.json / CSR signing.
resource "google_kms_crypto_key_iam_member" "smallstep_signing_viewer" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_kms_crypto_key_iam_member" "smallstep_scep_viewer" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_scep_decrypter[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.radius.email}"
}
