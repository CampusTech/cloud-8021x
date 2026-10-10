terraform {
  required_version = ">= 1.9"
  required_providers {
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "= 1.27.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "= 2.3.5"
    }
  }
}

# PGPASSWORD is read only from this private administrator runner's environment.
# No administrator password is an input, data-source query, output or VM secret.
provider "postgresql" {
  host             = var.host
  port             = var.port
  database         = "postgres"
  username         = var.administrator
  superuser        = false
  sslmode          = var.tls_mode == "cloudsql-instance-ca" ? "verify-ca" : "verify-full"
  sslrootcert      = var.ca_file
  connect_timeout  = 5
  max_connections  = 4
  expected_version = "16.0.0"
}
