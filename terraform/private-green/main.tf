terraform {
  backend "gcs" {}
  required_version = ">= 1.9, < 2.0"
  required_providers {
    postgresql = { source = "cyrilgdn/postgresql", version = "= 1.27.0" }
    external   = { source = "hashicorp/external", version = "= 2.3.5" }
    google     = { source = "hashicorp/google", version = "= 5.45.2" }
    random     = { source = "hashicorp/random", version = "= 3.7.2" }
  }
}
provider "google" { project = var.project_id }
variable "project_id" { type = string }
variable "deployment_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,24}[a-z0-9]$", var.deployment_id)) && var.deployment_id != "stepca"
    error_message = "Private green state requires an explicit isolated deployment ID."
  }
}
variable "private_administrator" {
  description = "Nonsecret reviewed private-runner connection/CA/ACL inventory. Password comes only from PGPASSWORD. No VM uses this input or this state."
  type = object({
    host                    = string, port = number, administrator = string, admin_tool = string,
    ca_file                 = string, ca_pem_sha256 = string, cloud_sql_instance = string,
    reserved_ca_connections = number,
    expected_ca_acl         = map(object({ owner = string, grants = list(object({ grantor = string, role = string, privilege = string, grantable = bool })) })),
    approved_ca_access      = map(list(object({ role = string, connect = bool, temporary = bool })))
  })
}
resource "random_password" "application" {
  for_each = toset(["runtime", "native", "migration"])
  length   = 48
  special  = false
  lifecycle { prevent_destroy = true }
}
module "database" {
  source                  = "../postgres"
  deployment_id           = var.deployment_id
  host                    = var.private_administrator.host
  port                    = var.private_administrator.port
  administrator           = var.private_administrator.administrator
  admin_tool              = var.private_administrator.admin_tool
  ca_file                 = var.private_administrator.ca_file
  ca_pem_sha256           = var.private_administrator.ca_pem_sha256
  tls_mode                = "cloudsql-instance-ca"
  cloud_sql_instance      = var.private_administrator.cloud_sql_instance
  reserved_ca_connections = var.private_administrator.reserved_ca_connections
  expected_ca_acl         = var.private_administrator.expected_ca_acl
  approved_ca_access      = var.private_administrator.approved_ca_access
  passwords               = { for k, p in random_password.application : k => p.result }
}
resource "google_secret_manager_secret" "application" {
  for_each  = toset(["runtime", "native", "migration"])
  secret_id = "${var.deployment_id}-postgres-${each.key}-dsn"
  replication {
    auto {}
  }
  lifecycle { prevent_destroy = true }
}
resource "google_secret_manager_secret_version" "application" {
  for_each    = toset(["runtime", "native", "migration"])
  secret      = google_secret_manager_secret.application[each.key].id
  secret_data = module.database.application_dsns[each.key]
  lifecycle { prevent_destroy = true }
}
output "compute_secret_references" {
  value       = { for role, secret in google_secret_manager_secret.application : role => secret.id }
  depends_on  = [google_secret_manager_secret_version.application]
  description = "Only these nonsecret references cross into green compute's fixed credential map; no IAM grants or administrator credential are emitted."
}
output "application_identity" { value = module.database.application_identity }
output "ca_acl_review_input" { value = module.database.prerequisite_configuration }

resource "random_password" "local_authentication" {
  for_each = toset(["policy-token", "peer-health"])
  length   = 64
  special  = false
  lifecycle { prevent_destroy = true }
}
resource "google_secret_manager_secret" "local_authentication" {
  for_each  = toset(["policy-token", "peer-health"])
  secret_id = "${var.deployment_id}-${each.key}"
  replication {
    auto {}
  }
  lifecycle { prevent_destroy = true }
}
resource "google_secret_manager_secret_version" "local_authentication" {
  for_each    = toset(["policy-token", "peer-health"])
  secret      = google_secret_manager_secret.local_authentication[each.key].id
  secret_data = random_password.local_authentication[each.key].result
  lifecycle { prevent_destroy = true }
}
output "local_authentication_references" {
  value      = { for role, secret in google_secret_manager_secret.local_authentication : role => secret.id }
  depends_on = [google_secret_manager_secret_version.local_authentication]
}

variable "inherited_ca_password" {
  description = "Optional exact existing stepca password secret VERSION for a private-runner-only DSN wrapper. Never the SQL administrator password. Null means reviewed existing EC/RSA DSN secrets are supplied separately. No source secret is modified."
  type        = object({ secret_id = string, version = string })
  default     = null
  validation {
    condition     = var.inherited_ca_password == null ? true : (can(regex("^[A-Za-z0-9_-]+$", var.inherited_ca_password.secret_id)) && can(regex("^[1-9][0-9]*$", var.inherited_ca_password.version)))
    error_message = "Pin a concrete existing CA password version; latest is forbidden."
  }
}
data "google_secret_manager_secret_version" "inherited_ca_password" {
  count   = var.inherited_ca_password == null ? 0 : 1
  secret  = var.inherited_ca_password.secret_id
  version = var.inherited_ca_password.version
}
resource "google_secret_manager_secret" "ca_dsn" {
  for_each  = var.inherited_ca_password == null ? toset([]) : toset(["stepca", "stepca_rsa"])
  secret_id = "${var.deployment_id}-${replace(each.value, "_", "-")}-dsn"
  replication {
    auto {}
  }
  lifecycle { prevent_destroy = true }
}
resource "google_secret_manager_secret_version" "ca_dsn" {
  for_each    = google_secret_manager_secret.ca_dsn
  secret      = each.value.id
  secret_data = "postgres://stepca:${replace(urlencode(data.google_secret_manager_secret_version.inherited_ca_password[0].secret_data), "+", "%20")}@${var.private_administrator.host}:${var.private_administrator.port}/${each.key}?sslmode=verify-ca&sslrootcert=/etc/cloud-8021x/postgres-ca.pem"
  # Do not deliver a usable credential before the CA ACL/capacity/TLS prerequisite.
  depends_on = [module.database]
  lifecycle { prevent_destroy = true }
}
output "inherited_ca_dsn_references" {
  value       = { for database, secret in google_secret_manager_secret.ca_dsn : database => secret.id }
  depends_on  = [google_secret_manager_secret_version.ca_dsn]
  description = "New wrappers around the exact preserved original CA password. Same stepca role, fixed original databases and shared private instance; no CA credential rotation."
}
