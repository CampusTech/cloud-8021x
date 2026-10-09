variable "deployment_id" {
  type = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,24}[a-z0-9]$", var.deployment_id))
    error_message = "Use a distinct 2-26 character deployment ID (also fits the dedicated service account)."

  }
}
variable "blue" {
  type = object({ id = string, primary = string, secondary = string, primary_key = optional(string, ""), secondary_key = optional(string, "") })
  validation {
    condition     = var.blue.id != var.deployment_id && var.blue.primary != "${var.deployment_id}-primary" && var.blue.secondary != "${var.deployment_id}-secondary"
    error_message = "Green and retained blue physical identities must differ."

  }
}
variable "collection_epoch" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", var.collection_epoch)) && can(timeadd(var.collection_epoch, "0s"))
    error_message = "Use an explicit UTC whole-second epoch; no historical accounting is imported."

  }
}
variable "region" {
  type = string
}
variable "nodes" {
  type = map(object({ zone = string, address = string, peer_dns = string }))
  validation {
    condition     = toset(keys(var.nodes)) == toset(["primary", "secondary"]) && length(distinct([for n in values(var.nodes) : n.zone])) == 2 && length(distinct([for n in values(var.nodes) : n.address])) == 2
    error_message = "Exactly primary and secondary in distinct zones with distinct reserved private addresses are required."

  }
}
variable "foundation" {
  description = "Exact reviewed existing dependencies; this state never owns shared project, network, SQL, CA data, signers or enrollment frontdoors. No secret values."
  type = object({
    project_id        = string, project_number = string, network = string, subnet = string,
    sql_instance      = string, sql_private_ip = string, postgres_ca_file = string, postgres_ca_sha256 = string,
    ec_kms_version    = string, rsa_kms_version = string,
    secret_ids        = set(string),
    ca_dsn_secret_ids = object({ ec = string, rsa = string })
    frontdoors        = object({ ec = string, rsa = string, broker = string })
  })
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.foundation.postgres_ca_sha256)) && filesha256(var.foundation.postgres_ca_file) == var.foundation.postgres_ca_sha256
    error_message = "The public instance CA PEM must match its independently reviewed SHA256."

  }
  validation {
    condition     = alltrue([for v in [var.foundation.ec_kms_version, var.foundation.rsa_kms_version] : can(regex("^projects/${var.foundation.project_id}/locations/[a-z0-9-]+/keyRings/[^/]+/cryptoKeys/[^/]+/cryptoKeyVersions/[1-9][0-9]*$", v))])
    error_message = "Pin exact EC and RSA signer versions in the existing project."

  }
}
variable "base_config_file" {
  type        = string
  description = "Strict nonsecret YAML; validated by the built Go config validate command before plan and again on the VM."
}
variable "package_directory" {
  type = string
}
variable "package_manifest_file" {
  type = string
}
variable "package_manifest_sha256" {
  type = string
  validation {
    condition     = filesha256(var.package_manifest_file) == var.package_manifest_sha256 && can(regex("^[0-9a-f]{64}$", var.package_manifest_sha256))
    error_message = "Pin the reviewed build manifest independently of the uploaded files."

  }
}
variable "application_file" {
  type = string
}
variable "application_sha256" {
  type = string
  validation {
    condition     = filesha256(var.application_file) == var.application_sha256 && can(regex("^[0-9a-f]{64}$", var.application_sha256))
    error_message = "The executable requires an independent deployment pin."

  }
}
variable "provenance_file" {
  type = string
}
variable "provenance_sha256" {
  type = string
  validation {
    condition     = filesha256(var.provenance_file) == var.provenance_sha256 && can(regex("^[0-9a-f]{64}$", var.provenance_sha256))
    error_message = "Pin the retained authenticated build provenance."

  }
}
variable "machine_type" {
  type    = string
  default = "e2-standard-2"
}
variable "image" {
  type        = string
  description = "Exact reviewed Debian13 image self-link, never a moving family. Architecture must match the manifest."
  validation {
    condition     = can(regex("^projects/debian-cloud/global/images/debian-13-[a-z0-9-]+$", var.image))
    error_message = "Select a pinned Debian13 image after package/image acceptance."

  }
}
variable "disk_size_gb" {
  type    = number
  default = 50
}

variable "state_transition" {
  type        = string
  description = "Independent 32-byte random transition identity, hex encoded; binds both green nodes and the authenticated handoff. Not a credential."
  validation {
    condition     = can(regex("^[0-9a-f]{64}$", var.state_transition))
    error_message = "An explicit common protected transition is required."
  }
}
variable "application_version" {
  type        = string
  description = "Exact reviewed application build version in its independently pinned executable."
}

variable "config_validator" {
  type        = string
  description = "Absolute path to the reviewed locally built Go CLI for this workstation architecture; strict validation runs on the Terraform runner, never on cloud metadata."
}

variable "destination_public_keys" {
  type        = object({ primary = string, secondary = string })
  default     = { primary = "", secondary = "" }
  description = "Authenticated green root receipt public-key pins; enroll before freezing the final pair manifest. Required by reversible handoff, not credentials."
}

variable "application_capacity" {
  description = "Exact reviewed application_capacity output from the separate private-green state owner; never read administrator state remotely."
  type        = object({ deployment_id = string, runtime_connections_per_node = number, runtime_role_limit = number, native_role_limit = number, migration_role_limit = number })
  validation {
    condition     = var.application_capacity.deployment_id == var.deployment_id && var.application_capacity.runtime_connections_per_node >= 8 && var.application_capacity.runtime_connections_per_node <= 64 && floor(var.application_capacity.runtime_connections_per_node) == var.application_capacity.runtime_connections_per_node && var.application_capacity.runtime_role_limit == 2 * var.application_capacity.runtime_connections_per_node && var.application_capacity.native_role_limit == 4 && var.application_capacity.migration_role_limit == 2 * var.application_capacity.runtime_connections_per_node
    error_message = "The aggregate runtime budget must belong to this deployment and match the pair-wide runtime/native/migration role limits."
  }
}
