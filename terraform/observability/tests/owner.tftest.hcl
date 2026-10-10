mock_provider "datadog" {}
variables {
  project_id                      = "campus-example"
  datadog_site                    = "datadoghq.com"
  datadog_monitor_notify          = ""
  enable_smallstep_ca             = true
  enable_acme_issuance_monitor    = false
  smallstep_ca_dns_name           = "ca.example.test"
  smallstep_acme_provisioner_name = "wifi-acme"
  radius_vlan_policy              = { certificate_inventory = true }
  datadog_observability_hosts     = ["green-test-primary", "green-test-secondary"]
}
run "green_owner" {
  command = plan
  assert {
    condition     = toset([for variable in jsondecode(datadog_dashboard_json.radius[0].dashboard).template_variables : variable.available_values if variable.name == "host"][0]) == toset(["green-test-primary", "green-test-secondary"])
    error_message = "The actual JSON owner must admit the explicit green physical pair."
  }
  assert {
    condition     = strcontains(datadog_monitor.radius_server_cert_expiry[0].query, "host:green-test-primary") && strcontains(datadog_monitor.radius_server_cert_expiry[0].query, "host:green-test-secondary") && !strcontains(datadog_monitor.radius_server_cert_expiry[0].query, "host:radius-primary")
    error_message = "Safety monitoring must use only the reviewed physical host scope."
  }
}
run "refuse_wildcard" {
  command = plan
  variables { datadog_observability_hosts = ["*", "green-test-secondary"] }
  expect_failures = [var.datadog_observability_hosts]
}
run "refuse_single_host" {
  command = plan
  variables { datadog_observability_hosts = ["green-test-primary"] }
  expect_failures = [var.datadog_observability_hosts]
}

# Only Terraform's owned in-memory mock state; never an imported remote state.
run "seed_existing_owner" {
  command = apply
  variables { datadog_observability_hosts = ["radius-primary", "radius-secondary"] }
}
run "existing_owner_plan" {
  command = plan
  assert {
    condition     = length([for widget in jsondecode(datadog_dashboard_json.smallstep[0].dashboard).widgets[0].definition.widgets : widget if widget.definition.type == "check_status"]) == 6
    error_message = "Both admitted hosts need separately scoped EC/RSA/process health cards."
  }
  assert {
    condition     = alltrue([for widget in jsondecode(datadog_dashboard_json.smallstep[0].dashboard).widgets[0].definition.widgets : length([for tag in widget.definition.tags : tag if contains(["host:green-test-primary", "host:green-test-secondary"], tag)]) == 1 && !contains(widget.definition.tags, "host:radius-primary") && !contains(widget.definition.tags, "host:radius-secondary") && widget.definition.group_by == ["host"] if widget.definition.type == "check_status"])
    error_message = "Every health card must retain one exact admitted physical host and per-host results."
  }
  assert {
    condition     = strcontains(datadog_monitor.stepca_health[0].query, "service:smallstep-ca") && strcontains(datadog_monitor.stepca_health[0].query, "ca_instance:ec") && strcontains(datadog_monitor.stepca_health[0].query, "instance:stepca_health") && strcontains(datadog_monitor.stepca_rsa_health[0].query, "ca_instance:rsa")
    error_message = "Retained per-host service-check monitor identities must match actual fresh-node producer tags."
  }
}
