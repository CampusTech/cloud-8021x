mock_provider "google" {
  mock_data "google_secret_manager_secret_version" {
    defaults = { secret_data = "original-ca-password+/@" }
  }
}
mock_provider "random" {}
mock_provider "postgresql" {}
mock_provider "external" {
  mock_data "external" { defaults = { result = { verified = "true" } } }
}
variables {
  project_id = "campus-example"
  deployment_id = "green-test"
  inherited_ca_password = { secret_id = "smallstep-db-password", version = "17" }
  private_administrator = {
    host = "10.0.2.2", port = 5432, administrator = "private-admin", admin_tool = "/bin/false",
    ca_file = "tests/fixtures/ca.pem", ca_pem_sha256 = filesha256("tests/fixtures/ca.pem"),
    cloud_sql_instance = "campus-example:us-central1:smallstep-ca", reserved_ca_connections = 60,
    expected_ca_acl = { stepca = { owner = "postgres", grants = [] }, stepca_rsa = { owner = "postgres", grants = [] } },
    approved_ca_access = { stepca = [{ role = "stepca", connect = true, temporary = true }], stepca_rsa = [{ role = "stepca", connect = true, temporary = true }] }
  }
}
run "private_owners_and_preserved_ca_password" {
  command = plan
  assert {
    condition = toset(keys(google_secret_manager_secret.ca_dsn)) == toset(["stepca", "stepca_rsa"]) && alltrue([for name, secret in google_secret_manager_secret.ca_dsn : startswith(secret.secret_id, "green-test-")])
    error_message = "Only new deployment-scoped CA DSN wrappers may be created."
  }
  assert {
    condition = google_secret_manager_secret_version.ca_dsn["stepca"].secret_data == "postgres://stepca:original-ca-password%2B%2F%40@10.0.2.2:5432/stepca?sslmode=verify-ca&sslrootcert=/etc/cloud-8021x/postgres-ca.pem" && google_secret_manager_secret_version.ca_dsn["stepca_rsa"].secret_data == "postgres://stepca:original-ca-password%2B%2F%40@10.0.2.2:5432/stepca_rsa?sslmode=verify-ca&sslrootcert=/etc/cloud-8021x/postgres-ca.pem"
    error_message = "Wrapping must preserve exact credential bytes, fixed role/database identities and pinned TLS."
  }
  assert {
    condition = output.application_identity.database == "cloud8021x_green_test" && output.application_identity.roles.runtime.name == "cloud8021x_green_test_runtime" && output.application_identity.roles.native.name == "cloud8021x_green_test_native"
    error_message = "New application roles/database must be disjoint from original authority."
  }
}
