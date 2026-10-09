terraform {
  required_version = ">= 1.9, < 2.0"
  required_providers { datadog = { source = "DataDog/datadog", version = "= 4.25.0" } }
  backend "gcs" {}
}
# DD_API_KEY and DD_APP_KEY are supplied through the private operator environment.
provider "datadog" { api_url = "https://api.${var.datadog_site}/" }
