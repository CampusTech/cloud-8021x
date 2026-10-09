locals {
  green_credentials = {
    "/run/cloud-8021x-root/stepca-dsn"                  = "projects/${var.foundation.project_id}/secrets/${var.foundation.ca_dsn_secret_ids.ec}"
    "/run/cloud-8021x-root/stepca-rsa-dsn"              = "projects/${var.foundation.project_id}/secrets/${var.foundation.ca_dsn_secret_ids.rsa}"
    "/run/cloud-8021x/credentials/postgres-runtime-dsn" = "projects/${var.foundation.project_id}/secrets/${var.deployment_id}-postgres-runtime-dsn"
    "/run/cloud-8021x-root/postgres-native-dsn"         = "projects/${var.foundation.project_id}/secrets/${var.deployment_id}-postgres-native-dsn"
    "/run/cloud-8021x-root/postgres-migration-dsn"      = "projects/${var.foundation.project_id}/secrets/${var.deployment_id}-postgres-migration-dsn"
    "/run/cloud-8021x/credentials/policy-token"         = "projects/${var.foundation.project_id}/secrets/${var.deployment_id}-policy-token"
    "/run/cloud-8021x/credentials/peer-health"          = "projects/${var.foundation.project_id}/secrets/${var.deployment_id}-peer-health"
  }
  base             = yamldecode(file(var.base_config_file))
  package_manifest = jsondecode(file(var.package_manifest_file))
  name             = var.deployment_id
  config = { for role, node in var.nodes : role => yamlencode(merge(local.base, {
    instance_id      = "radius-${role}"
    state_transition = var.state_transition
    hostname         = "${local.name}-${role}"
    deployment = {
      mode                      = "parallel", id = local.name, instance = "${local.name}-${role}", source_id = var.blue.id,
      source_primary            = var.blue.primary, source_secondary = var.blue.secondary,
      source_primary_key        = var.blue.primary_key
      source_secondary_key      = var.blue.secondary_key
      destination_primary_key   = var.destination_public_keys.primary
      destination_secondary_key = var.destination_public_keys.secondary
      collection_epoch          = var.collection_epoch

    }
    database = merge(local.base.database, {
      name                   = "cloud8021x_${replace(local.name, "-", "_")}"
      ca_file                = "/etc/cloud-8021x/postgres-ca.pem"
      tls_mode               = "cloudsql-instance-ca"
      cloud_sql_instance     = "${var.foundation.project_id}:${var.region}:${var.foundation.sql_instance}"
      instance_ca_pem_sha256 = var.foundation.postgres_ca_sha256
    })
    network = merge(local.base.network, { discovery = merge(local.base.network.discovery, { enabled = false }) })
    bootstrap = merge(local.base.bootstrap, {
      secrets = [for secret in local.base.bootstrap.secrets : merge(secret, {
        resource = lookup(local.green_credentials, secret.file, secret.resource)
      })]
      project       = var.foundation.project_id, project_number = var.foundation.project_number,
      ec_kms        = "cloudkms:${var.foundation.ec_kms_version}", rsa_kms = "cloudkms:${var.foundation.rsa_kms_version}",
      runtime_role  = "cloud8021x_${replace(local.name, "-", "_")}_runtime",
      native_role   = "cloud8021x_${replace(local.name, "-", "_")}_native",
      local_address = node.address, peer_address = var.nodes[role == "primary" ? "secondary" : "primary"].address,
      peer_dns      = node.peer_dns
    })
  })) }
  manifest = { for role in keys(var.nodes) : role => jsonencode(merge(local.package_manifest, {
    config_sha256       = sha256(local.config[role]), postgres_ca_sha256 = var.foundation.postgres_ca_sha256,
    application_sha256  = var.application_sha256
    application_version = var.application_version
  })) }
  archives = { for a in local.package_manifest.artifacts : "${a.name}_${a.version}_${a.architecture}.deb" => {
    path = "${var.package_directory}/${a.name}_${a.version}_${a.architecture}.deb", sha256 = a.sha256
  } }
  uploads = merge(local.archives, {
    "cloud-8021x"     = { path = var.application_file, sha256 = var.application_sha256 }
    "postgres-ca.pem" = { path = var.foundation.postgres_ca_file, sha256 = var.foundation.postgres_ca_sha256 }
    "provenance.json" = { path = var.provenance_file, sha256 = var.provenance_sha256 }
  })
  adopted_ca_secrets = toset(["smallstep-ca-cert", "smallstep-intermediate-cert", "smallstep-scep-decrypter-cert", "smallstep-scep-decrypter-key", "smallstep-rsa-root-cert", "smallstep-rsa-intermediate-cert", "smallstep-rsa-scep-decrypter-cert", "smallstep-rsa-scep-decrypter-key", "radius-smallstep-server-cert", "radius-smallstep-server-key"])
  clients            = distinct(flatten([for client in local.base.radius_clients : client.cidrs]))
}
resource "terraform_data" "configuration" {
  input = { for role in keys(var.nodes) : role => sha256(local.config[role]) }
  lifecycle {
    precondition {
      condition     = alltrue([for validation in data.external.strict_config : validation.result.validated == "true"])
      error_message = "Both serialized configurations must pass the strict Go validator before any compute publication."
    }
    precondition {
      condition     = length(setsubtract(local.adopted_ca_secrets, var.foundation.secret_ids)) == 0
      error_message = "Every existing EC/RSA/decrypter/server certificate/key secret must be explicitly inherited read-only."
    }
    precondition {
      condition     = length(local.archives) >= 10 && length(local.archives) <= 64 && alltrue([for name, a in local.archives : can(regex("^[a-z0-9][a-z0-9+.-]*_[0-9A-Za-z.+:~-]+_(amd64|arm64|all)\\.deb$", name)) && filesha256(a.path) == a.sha256])
      error_message = "Supply the complete reviewed bounded package closure with exact hashes."

    }
    precondition {
      condition     = alltrue([for s in local.base.bootstrap.secrets : contains(var.foundation.secret_ids, trimprefix(lookup(local.green_credentials, s.file, s.resource), "projects/${var.foundation.project_id}/secrets/"))]) && alltrue([for c in local.base.radius_clients : c.medium == "wifi"]) && length([for p in local.base.network.providers : p if p.kind == "unifi"]) <= 1
      error_message = "Every fixed credential must have scoped access; only WiFi clients and one UniFi credential source are permitted."

    }
    precondition {
      condition     = alltrue([for s in var.foundation.secret_ids : !can(regex("(?i)(admin|root-password|datadog.*app|okta|jamf)", s))])
      error_message = "No administrator, retired adapter or Datadog readback credential is allowed on green VMs."

    }

  }
}

data "external" "strict_config" {
  for_each = local.config
  program  = ["python3", "${path.module}/validate-config.py", var.config_validator]
  query    = { config = each.value }
}
