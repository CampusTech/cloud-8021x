variable "host" { type = string }
variable "port" {
  type    = number
  default = 5432
}
variable "administrator" { type = string }
variable "admin_tool" {
  type        = string
  description = "Absolute path to the reviewed locally built private administrator helper; never installed on RADIUS VMs."
}
variable "ca_file" { type = string }
variable "ca_pem_sha256" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.ca_pem_sha256)) && filesha256(var.ca_file) == var.ca_pem_sha256 && length(regexall("-----BEGIN CERTIFICATE-----", file(var.ca_file))) == 1
    error_message = "The exact single instance CA PEM file and SHA256 are required."
  }
}
variable "tls_mode" {
  type    = string
  default = "verify-full"
  validation {
    condition     = contains(["verify-full", "cloudsql-instance-ca"], var.tls_mode)
    error_message = "Unverified TLS and plaintext modes are forbidden."
  }
}
variable "cloud_sql_instance" {
  type    = string
  default = ""
}
variable "runtime_connections_per_node" {
  type    = number
  default = 8
  validation {
    condition     = var.runtime_connections_per_node >= 1 && var.runtime_connections_per_node <= 64
    error_message = "Runtime pool capacity must match both daemon configurations."
  }
}
variable "reserved_ca_connections" {
  type        = number
  description = "Reviewed combined existing CA/client/headroom reservation; never inferred from idle test load."
  validation {
    condition     = var.reserved_ca_connections >= 20
    error_message = "Reserve at least twenty connections for existing CA services and administrator headroom."
  }
}
variable "passwords" {
  type      = object({ runtime = string, native = string, migration = string })
  sensitive = true
  validation {
    condition     = alltrue([for value in values(var.passwords) : length(value) >= 32]) && length(distinct(values(var.passwords))) == 3
    error_message = "Three distinct application credentials of at least 32 characters are required."
  }
}
variable "expected_ca_acl" {
  description = "Separately reviewed exact original ACL/owner inventory of stepca and stepca_rsa; unknown clients must not be inferred from PUBLIC."
  type = map(object({
    owner  = string
    grants = list(object({ grantor = string, role = string, privilege = string, grantable = bool }))
  }))
}
variable "approved_ca_access" {
  description = "Explicit existing legitimate CA clients requiring CONNECT/TEMP after PUBLIC hardening."
  type        = map(list(object({ role = string, connect = bool, temporary = bool })))
}
