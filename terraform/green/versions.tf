terraform {
  backend "gcs" {}
  required_version = ">= 1.9, < 2.0"
  required_providers {
    external = { source = "hashicorp/external", version = "= 2.3.5" }
    google   = { source = "hashicorp/google", version = "= 5.45.2" }

  }
}
provider "google" {
  project = var.foundation.project_id
  region  = var.region
}
