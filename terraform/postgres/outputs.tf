output "prerequisite_configuration" {
  value       = local.prerequisite
  description = "Nonsecret exact input for the separately approved CA ACL hardening command."
}
output "application_dsns" {
  sensitive = true
  value = {
    for key, identity in local.identities : key => "postgres://${identity.name}:${replace(urlencode(var.passwords[key]), "+", "%20")}@${var.host}:${var.port}/${local.application_database}"
  }
  depends_on  = [postgresql_grant.application_connect]
  description = "Publish to only the fixed runtime/native/migration Secret Manager secret versions after successful provisioning; never include administrator credentials."
}
output "capacity" {
  value = data.external.prerequisite.result
}

output "application_identity" {
  value = { database = local.application_database, roles = local.identities }
}
