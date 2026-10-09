locals {
  application_database = var.deployment_id == "" ? "cloud8021x" : "cloud8021x_${replace(var.deployment_id, "-", "_")}"
  # The daemon partitions this aggregate budget; observations are included.
  runtime_limit = 2 * var.runtime_connections_per_node
  # The reviewed native SQL template has two connections per node.
  native_limit = 4
  # Protected migration uses the same configured pool maximum on each node.
  migration_limit = local.runtime_limit
  prerequisite = {
    deployment_id        = var.deployment_id
    host                 = var.host
    port                 = var.port
    administrator        = var.administrator
    ca_file              = var.ca_file
    tls_mode             = var.tls_mode
    instance             = var.cloud_sql_instance
    ca_pin               = var.ca_pem_sha256
    runtime_limit        = local.runtime_limit
    native_limit         = local.native_limit
    migration_limit      = local.migration_limit
    reserved_connections = var.reserved_ca_connections
    expected_ca          = var.expected_ca_acl
    approved_ca_access   = var.approved_ca_access
  }
  identities = {
    runtime   = { name = "${local.application_database}_runtime", connections = local.runtime_limit }
    native    = { name = "${local.application_database}_native", connections = local.native_limit }
    migration = { name = "${local.application_database}_migrate", connections = local.migration_limit }
  }
}

# A failed CA ACL, role, durability, TLS or capacity check prevents even the
# initial role creation. Hardening is never performed implicitly by Terraform.
data "external" "prerequisite" {
  program = [var.admin_tool, "check", "--terraform"]
  query   = { config = jsonencode(local.prerequisite) }
}

resource "postgresql_role" "application" {
  for_each                  = local.identities
  name                      = each.value.name
  login                     = true
  password                  = var.passwords[each.key]
  superuser                 = false
  create_database           = false
  create_role               = false
  replication               = false
  bypass_row_level_security = false
  inherit                   = false
  roles                     = []
  connection_limit          = each.value.connections
  search_path               = ["pg_catalog"]
  skip_drop_role            = true
  skip_reassign_owned       = true
  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = data.external.prerequisite.result.verified == "true"
      error_message = "Private database prerequisites did not pass."
    }
  }
}

resource "postgresql_database" "application" {
  name              = local.application_database
  owner             = postgresql_role.application["migration"].name
  template          = "template0"
  encoding          = "UTF8"
  allow_connections = true
  lifecycle { prevent_destroy = true }
}

resource "postgresql_grant" "public_database" {
  database    = postgresql_database.application.name
  role        = "public"
  object_type = "database"
  privileges  = []
}
resource "postgresql_grant" "public_schema" {
  database    = postgresql_database.application.name
  schema      = "public"
  role        = "public"
  object_type = "schema"
  privileges  = []
}
resource "postgresql_grant" "application_connect" {
  for_each    = toset(["runtime", "native"])
  database    = postgresql_database.application.name
  role        = postgresql_role.application[each.key].name
  object_type = "database"
  privileges  = ["CONNECT"]
  depends_on  = [postgresql_grant.public_database, postgresql_grant.public_schema]
}
