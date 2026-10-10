data "google_project" "existing" { project_id = var.foundation.project_id }
data "google_compute_network" "existing" { name = var.foundation.network }
data "google_compute_subnetwork" "existing" {
  name   = var.foundation.subnet
  region = var.region
}
data "google_sql_database_instance" "existing" { name = var.foundation.sql_instance }
data "google_kms_crypto_key_version" "existing" {
  for_each   = toset([var.foundation.ec_kms_version, var.foundation.rsa_kms_version])
  crypto_key = join("/", slice(split("/", each.value), 0, 8))
  version    = element(reverse(split("/", each.value)), 0)
}
data "google_secret_manager_secret" "existing" {
  for_each  = var.foundation.secret_ids
  secret_id = each.value
}
data "google_compute_backend_service" "existing" {
  for_each = var.foundation.frontdoors
  name     = each.value
}
resource "terraform_data" "dependencies" {
  input = {
    project    = data.google_project.existing.project_id
    sql        = data.google_sql_database_instance.existing.connection_name
    frontdoors = { for k, v in data.google_compute_backend_service.existing : k => v.self_link }

  }
  lifecycle {
    precondition {
      condition     = length(distinct(values(var.foundation.frontdoors))) == 3 && alltrue([for name, backend in data.google_compute_backend_service.existing : backend.protocol == "HTTPS" && backend.port_name == { ec = "stepca", rsa = "stepca-rsa", broker = "scep-broker" }[name]])
      error_message = "Pin three distinct existing HTTPS frontdoors with preserved EC/RSA/broker named ports."
    }
    precondition {
      condition     = alltrue([for version in data.google_kms_crypto_key_version.existing : version.state == "ENABLED"])
      error_message = "A pinned CA signer is not enabled; no replacement signer may be generated."
    }
    precondition {
      condition     = tostring(data.google_project.existing.number) == var.foundation.project_number
      error_message = "Project number does not match the reviewed dependency manifest."

    }
    precondition {
      condition     = data.google_compute_subnetwork.existing.network == data.google_compute_network.existing.self_link && data.google_sql_database_instance.existing.private_ip_address == var.foundation.sql_private_ip && data.google_sql_database_instance.existing.settings[0].availability_type == "REGIONAL"
      error_message = "Existing VPC/subnet/private HA PostgreSQL identity differs from reviewed inputs."

    }
    precondition {
      condition     = data.google_sql_database_instance.existing.settings[0].ip_configuration[0].private_network == data.google_compute_network.existing.self_link && sha256(data.google_sql_database_instance.existing.server_ca_cert[0].cert) == var.foundation.postgres_ca_sha256
      error_message = "Existing SQL network or exact instance CA PEM pin differs."

    }

  }
}

data "google_sql_database" "ca" {
  for_each = toset(["stepca", "stepca_rsa"])
  name     = each.value
  instance = var.foundation.sql_instance
}
