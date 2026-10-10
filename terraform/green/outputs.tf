output "rendered_config" {
  description = "Nonsecret exact YAML for strict Go config validation; never DSN/password contents."
  value       = local.config
}
output "nas_cutover" {
  value       = { for role, a in google_compute_address.external : role => { address = a.address, auth_port = 1812, accounting_port = 1813 } }
  description = "Switch authentication AND accounting together only after approved worker/authorization handoff."
}
output "backend_switch" {
  value = { for kind, backend in data.google_compute_backend_service.existing : kind => {
    existing_backend = backend.self_link
    groups           = [for group in google_compute_instance_group.green : group.self_link]
    port_name        = { ec = "stepca", rsa = "stepca-rsa", broker = "scep-broker" }[kind]
  } }
  description = "Exactly EC/RSA/broker group replacements for the separately approved existing foundation state owner; no switch occurs here."
}
output "ownership" {
  value = { deployment = local.name, source = var.blue, collection_epoch = var.collection_epoch, service_account = google_service_account.green.email, application_database = "cloud8021x_${replace(local.name, "-", "_")}" }
}

output "observability_handoff" {
  description = "Exact green physical host admission input for the separately approved Datadog-only owner. Does not alter blue dashboards or traffic."
  value       = { deployment_id = local.name, datadog_observability_hosts = sort([for yaml in values(local.config) : yamldecode(yaml).hostname]) }
}
