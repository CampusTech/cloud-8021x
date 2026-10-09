# Shared across both RADIUS nodes so NAS accounting keeps its authenticated
# device association after failover. This key signs logging context only.
resource "random_password" "radius_accounting_key" {
  count   = try(var.radius_vlan_policy.certificate_inventory, false) ? 1 : 0
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "radius_accounting_key" {
  count     = try(var.radius_vlan_policy.certificate_inventory, false) ? 1 : 0
  project   = google_project.this.project_id
  secret_id = "radius-accounting-key"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "radius_accounting_key" {
  count       = try(var.radius_vlan_policy.certificate_inventory, false) ? 1 : 0
  secret      = google_secret_manager_secret.radius_accounting_key[0].id
  secret_data = random_password.radius_accounting_key[0].result
}

resource "google_secret_manager_secret_iam_member" "radius_accounting_key" {
  count     = try(var.radius_vlan_policy.certificate_inventory, false) ? 1 : 0
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.radius_accounting_key[0].secret_id
  role      = google_project_iam_custom_role.runtime_secret_reader.name
  member    = "serviceAccount:${google_service_account.radius.email}"
}
