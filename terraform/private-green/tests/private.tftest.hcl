mock_provider "google" {
  mock_data "google_secret_manager_secret_version" {
    defaults = { secret_data = "OriginalCAPassword0123456789" }
  }
}
mock_provider "random" {}
mock_provider "postgresql" {}
mock_provider "external" {
  mock_data "external" { defaults = { result = { verified = "true" } } }
}
variables {
  runtime_connections_per_node = 8
  project_id                   = "campus-example"
  deployment_id                = "green-test"
  inherited_ca_password        = { secret_id = "smallstep-db-password", version = "17" }
  private_administrator = {
    host               = "10.0.2.2", port = 5432, administrator = "private-admin", admin_tool = "/bin/false",
    ca_file            = "tests/fixtures/ca.pem", ca_pem_sha256 = filesha256("tests/fixtures/ca.pem"),
    cloud_sql_instance = "campus-example:us-central1:smallstep-ca", reserved_ca_connections = 60,
    expected_ca_acl    = { stepca = { owner = "postgres", grants = [] }, stepca_rsa = { owner = "postgres", grants = [] } },
    approved_ca_access = { stepca = [{ role = "stepca", connect = true, temporary = true }], stepca_rsa = [{ role = "stepca", connect = true, temporary = true }] }
  }
}
run "private_owners_and_preserved_ca_password" {
  command = plan
  assert {
    condition     = toset(keys(google_secret_manager_secret.ca_dsn)) == toset(["stepca", "stepca_rsa"]) && alltrue([for name, secret in google_secret_manager_secret.ca_dsn : startswith(secret.secret_id, "green-test-")])
    error_message = "Only new deployment-scoped CA DSN wrappers may be created."
  }
  assert {
    condition     = output.application_identity.database == "cloud8021x_green_test" && output.application_identity.roles.runtime.name == "cloud8021x_green_test_runtime" && output.application_identity.roles.native.name == "cloud8021x_green_test_native"
    error_message = "New application roles/database must be disjoint from original authority."
  }
}

run "refuse_nonlegacy_password_bytes" {
  command = plan
  override_data {
    target = data.google_secret_manager_secret_version.inherited_ca_password[0]
    values = { secret_data = "original-ca-password+/@" }
  }
  expect_failures = [google_secret_manager_secret_version.ca_dsn]
}

run "refuse_nonlegacy_database_port" {
  command = plan
  variables {
    private_administrator = {
      host               = "10.0.2.2", port = 5433, administrator = "private-admin", admin_tool = "/bin/false",
      ca_file            = "tests/fixtures/ca.pem", ca_pem_sha256 = filesha256("tests/fixtures/ca.pem"),
      cloud_sql_instance = "campus-example:us-central1:smallstep-ca", reserved_ca_connections = 60,
      expected_ca_acl    = { stepca = { owner = "postgres", grants = [] }, stepca_rsa = { owner = "postgres", grants = [] } },
      approved_ca_access = { stepca = [{ role = "stepca", connect = true, temporary = true }], stepca_rsa = [{ role = "stepca", connect = true, temporary = true }] }
    }
  }
  expect_failures = [google_secret_manager_secret_version.ca_dsn]
}

run "nondefault_aggregate_runtime_capacity" {
  command = plan
  variables { runtime_connections_per_node = 12 }
  assert {
    condition     = output.application_identity.roles.runtime.connections == 24 && output.application_identity.roles.native.connections == 4 && output.application_identity.roles.migration.connections == 24
    error_message = "The exact per-node aggregate runtime budget must reach the pair role and capacity prerequisite while retaining native/migration reservations."
  }
}
