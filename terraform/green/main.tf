resource "google_service_account" "green" {
  account_id   = "${local.name}-vm"
  display_name = "${local.name} isolated RADIUS runtime"
}
resource "google_secret_manager_secret_iam_member" "read" {
  for_each  = var.foundation.secret_ids
  secret_id = data.google_secret_manager_secret.existing[each.key].secret_id
  role      = google_project_iam_custom_role.secret_read.name
  member    = "serviceAccount:${google_service_account.green.email}"
}
# Sign and public-key reads only; no key/secret creation or secretVersionAdder.
resource "google_kms_crypto_key_iam_member" "sign" {
  for_each      = toset([var.foundation.ec_kms_version, var.foundation.rsa_kms_version])
  crypto_key_id = join("/", slice(split("/", each.value), 0, 8))
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.green.email}"
  condition {
    title      = "ExactReviewedSignerVersion"
    expression = "resource.name == '${each.value}'"

  }
}
resource "google_project_iam_member" "logs" {
  role    = "roles/logging.logWriter"
  project = var.foundation.project_id
  member  = "serviceAccount:${google_service_account.green.email}"
}
resource "google_storage_bucket" "artifacts" {
  name                        = "${var.foundation.project_id}-${local.name}-artifacts"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  versioning { enabled = true }
}
resource "google_storage_bucket_iam_member" "reader" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.green.email}"
}
resource "google_storage_bucket_object" "artifact" {
  for_each       = local.uploads
  bucket         = google_storage_bucket.artifacts.name
  name           = "sha256/${each.value.sha256}/${each.key}"
  source         = each.value.path
  detect_md5hash = filemd5(each.value.path)
  lifecycle {
    create_before_destroy = true
  }
}
resource "google_storage_bucket_object" "config" {
  for_each = var.nodes
  bucket   = google_storage_bucket.artifacts.name
  name     = "sha256/${sha256(local.config[each.key])}/config.yaml"
  content  = local.config[each.key]
  lifecycle {
    create_before_destroy = true
  }
}
resource "google_storage_bucket_object" "manifest" {
  for_each = var.nodes
  bucket   = google_storage_bucket.artifacts.name
  name     = "sha256/${sha256(local.manifest[each.key])}/manifest.json"
  content  = local.manifest[each.key]
  lifecycle {
    create_before_destroy = true
  }
}
resource "google_compute_address" "external" {
  for_each = var.nodes
  name     = "${local.name}-${each.key}"
  region   = var.region
}
resource "google_compute_address" "internal" {
  for_each     = var.nodes
  name         = "${local.name}-${each.key}-internal"
  region       = var.region
  subnetwork   = data.google_compute_subnetwork.existing.self_link
  address_type = "INTERNAL"
  address      = each.value.address
}
resource "google_compute_disk" "boot" {
  for_each = var.nodes
  name     = "${local.name}-${each.key}-boot"
  zone     = each.value.zone
  type     = "pd-balanced"
  size     = var.disk_size_gb
  image    = var.image
  lifecycle {
    prevent_destroy = true
  }
}
locals {
  loaders = { for role in keys(var.nodes) : role => templatefile("${path.module}/../../scripts/startup.sh", {
    project_number = var.foundation.project_number
    parallel       = true
    instance_name  = "${local.name}-${role}"
    artifacts = concat([for name, a in local.uploads : {
      name = name, sha256 = a.sha256,
      url  = "https://storage.googleapis.com/${google_storage_bucket.artifacts.name}/${google_storage_bucket_object.artifact[name].name}?generation=${google_storage_bucket_object.artifact[name].generation}"
      }], [
      { name = "config.yaml", sha256 = sha256(local.config[role]), url = "https://storage.googleapis.com/${google_storage_bucket.artifacts.name}/${google_storage_bucket_object.config[role].name}?generation=${google_storage_bucket_object.config[role].generation}" },
      { name = "manifest.json", sha256 = sha256(local.manifest[role]), url = "https://storage.googleapis.com/${google_storage_bucket.artifacts.name}/${google_storage_bucket_object.manifest[role].name}?generation=${google_storage_bucket_object.manifest[role].generation}" }
    ])
  }) }
}
resource "google_compute_instance" "green" {
  for_each                  = var.nodes
  name                      = "${local.name}-${each.key}"
  zone                      = each.value.zone
  machine_type              = var.machine_type
  allow_stopping_for_update = true
  deletion_protection       = true
  tags                      = [local.name, "${local.name}-${each.key}"]
  boot_disk {
    source      = google_compute_disk.boot[each.key].self_link
    auto_delete = false

  }
  network_interface {
    subnetwork = data.google_compute_subnetwork.existing.self_link
    network_ip = google_compute_address.internal[each.key].address
    access_config { nat_ip = google_compute_address.external[each.key].address }

  }
  service_account {
    email  = google_service_account.green.email
    scopes = ["cloud-platform"]

  }
  metadata = { startup-script = local.loaders[each.key], enable-oslogin = "TRUE", block-project-ssh-keys = "TRUE" }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = length(base64encode(local.loaders[each.key])) * 3 / 4 <= 262144
      error_message = "Thin loader exceeds metadata capacity."

    }

  }
  depends_on = [terraform_data.dependencies, terraform_data.configuration, google_secret_manager_secret_iam_member.read, google_kms_crypto_key_iam_member.sign, google_storage_bucket_iam_member.reader, google_project_iam_member.sql_trust]
}
resource "google_compute_firewall" "radius" {
  name                    = "${local.name}-radius-static"
  network                 = data.google_compute_network.existing.self_link
  target_service_accounts = [google_service_account.green.email]
  source_ranges           = length(local.clients) > 0 ? local.clients : ["192.0.2.1/32"]
  disabled                = length(local.clients) == 0
  allow {
    protocol = "udp"
    ports    = ["1812", "1813"]
  }
}
resource "google_compute_firewall" "iap" {
  name                    = "${local.name}-iap"
  network                 = data.google_compute_network.existing.self_link
  target_service_accounts = [google_service_account.green.email]
  source_ranges           = ["35.235.240.0/20"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
resource "google_compute_firewall" "peer" {
  name                    = "${local.name}-peer-health"
  network                 = data.google_compute_network.existing.self_link
  target_service_accounts = [google_service_account.green.email]
  source_service_accounts = [google_service_account.green.email]
  allow {
    protocol = "tcp"
    ports    = ["18122"]
  }
}
resource "google_compute_firewall" "enrollment" {
  name                    = "${local.name}-enrollment-lb"
  network                 = data.google_compute_network.existing.self_link
  target_service_accounts = [google_service_account.green.email]
  source_ranges           = ["35.191.0.0/16", "130.211.0.0/22"]
  allow {
    protocol = "tcp"
    ports    = ["8443", "8444", "9081"]
  }
}
resource "google_compute_instance_group" "green" {
  for_each  = var.nodes
  name      = "${local.name}-${each.key}"
  zone      = each.value.zone
  instances = [google_compute_instance.green[each.key].self_link]
  named_port {
    name = "stepca"
    port = 8443
  }
  named_port {
    name = "stepca-rsa"
    port = 8444
  }
  named_port {
    name = "scep-broker"
    port = 9081
  }
}

resource "google_project_iam_custom_role" "secret_read" {
  role_id     = "${replace(local.name, "-", "_")}_secretRead"
  title       = "${local.name} exact enabled secret version reader"
  permissions = ["secretmanager.versions.list", "secretmanager.versions.access"]
}
resource "google_project_iam_custom_role" "sql_trust" {
  role_id     = "${replace(local.name, "-", "_")}_sqlTrust"
  title       = "${local.name} pinned SQL instance trust read"
  permissions = ["cloudsql.instances.get"]
}
resource "google_project_iam_member" "sql_trust" {
  project = var.foundation.project_id
  role    = google_project_iam_custom_role.sql_trust.name
  member  = "serviceAccount:${google_service_account.green.email}"
  condition {
    title      = "ExactExistingSQLTrust"
    expression = "resource.type == 'sqladmin.googleapis.com/Instance' && resource.name == 'projects/${var.foundation.project_id}/instances/${var.foundation.sql_instance}'"
  }
}

# Later approved activation grant only; default preparation cannot publish secrets.
# This does not activate workers or change any enrollment/backend endpoint.
variable "enable_server_certificate_publication" {
  type        = bool
  default     = false
  description = "Separately approved cutover prerequisite for renewal of only the existing server leaf/key cache. Never CA material."
}
resource "google_secret_manager_secret_iam_member" "server_certificate_publication" {
  for_each  = var.enable_server_certificate_publication ? toset(["radius-smallstep-server-cert", "radius-smallstep-server-key"]) : toset([])
  secret_id = each.value
  role      = "roles/secretmanager.secretVersionAdder"
  member    = "serviceAccount:${google_service_account.green.email}"
}
