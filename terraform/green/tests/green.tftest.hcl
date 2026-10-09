mock_provider "external" {
 mock_data "external" { defaults = { result = { validated = "true" } } }
}
mock_provider "google" {
  mock_data "google_kms_crypto_key_version" { defaults = { state = "ENABLED" } }
  mock_data "google_project" { defaults = { number = "123456789012" } }
  mock_data "google_compute_network" { defaults = { self_link = "https://www.googleapis.com/compute/v1/projects/campus-example/global/networks/radius-network" } }
  mock_data "google_compute_subnetwork" { defaults = { network = "https://www.googleapis.com/compute/v1/projects/campus-example/global/networks/radius-network", self_link = "https://www.googleapis.com/compute/v1/projects/campus-example/regions/us-central1/subnetworks/radius-subnet" } }
  mock_data "google_sql_database_instance" {
    defaults = {
      private_ip_address = "10.0.2.2"
      connection_name = "campus-example:us-central1:smallstep-ca"
      server_ca_cert = [{ cert = "synthetic public instance CA; never connected\n" }]
      settings = [{ availability_type = "REGIONAL", ip_configuration = [{ private_network = "https://www.googleapis.com/compute/v1/projects/campus-example/global/networks/radius-network" }] }]
    }
  }
  mock_resource "google_storage_bucket_object" { defaults = { generation = 1 } }
}
override_data {
 target = data.google_compute_backend_service.existing["ec"]
 values = { self_link = "https://www.googleapis.com/compute/v1/projects/campus-example/global/backendServices/smallstep-ca-backend", protocol = "HTTPS", port_name = "stepca" }
}
override_data {
 target = data.google_compute_backend_service.existing["rsa"]
 values = { self_link = "https://www.googleapis.com/compute/v1/projects/campus-example/global/backendServices/smallstep-rsa-backend", protocol = "HTTPS", port_name = "stepca-rsa" }
}
override_data {
 target = data.google_compute_backend_service.existing["broker"]
 values = { self_link = "https://www.googleapis.com/compute/v1/projects/campus-example/global/backendServices/scep-broker", protocol = "HTTPS", port_name = "scep-broker" }
}
run "new_green_plan" {
  assert {
    condition = length(google_secret_manager_secret_iam_member.server_certificate_publication) == 0 && alltrue([for group in google_compute_instance_group.green : toset([for p in group.named_port : "${p.name}:${p.port}"]) == toset(["stepca:8443", "stepca-rsa:8444", "scep-broker:9081"])])
    error_message = "Passive compute must preserve all enrollment ports and cannot publish CA/server cache secrets."
  }
  assert {
    condition = alltrue([for role, yaml in output.rendered_config : alltrue([for secret in yamldecode(yaml).bootstrap.secrets : !contains(["postgres-runtime-dsn", "postgres-native-dsn", "postgres-migration-dsn", "policy-token", "peer-health"], element(reverse(split("/",secret.resource)),0))])])
    error_message = "Green must never inherit old application DSNs/policy/peer authority."
  }

  command = plan
  assert {
    condition = length(google_compute_instance.green) == 2 && length(google_compute_disk.boot) == 2 && alltrue([for vm in google_compute_instance.green : startswith(vm.name,"green-test-") && vm.deletion_protection && !vm.boot_disk[0].auto_delete])
    error_message = "Green must create two distinct protected VMs and retained disks."
  }
  assert {
    condition = toset(keys(output.backend_switch)) == toset(["ec","rsa","broker"])
    error_message = "All three existing frontdoor backend replacements must be explicit outputs only."
  }
  assert {
    condition = alltrue([for role, yaml in output.rendered_config : yamldecode(yaml).deployment.instance == "green-test-${role}" && yamldecode(yaml).database.name == "cloud8021x_green_test" && yamldecode(yaml).network.discovery.enabled == false])
    error_message = "Physical identity, isolated DB and passive static-source config are mandatory."
  }
}

# Terraform test's mock provider creates only disposable in-memory state.
run "seed_synthetic_green_state" {
 command = apply
}
run "existing_green_state_plan" {
 command = plan
 assert {
  condition = alltrue([for vm in google_compute_instance.green : startswith(vm.name, "green-test-")])
  error_message = "Only synthetic green instances belong to this state."
 }
}
