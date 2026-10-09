# GCE metadata values are limited to 256 KiB. Measure the fully rendered UTF-8
# script, including embedded modules and policy, rather than its source template.
# Terraform length() counts characters; base64 is ASCII and exposes the byte size.
# BEGIN METADATA SELECTION
locals {
  startup_script_base64 = base64encode(local.startup_script)
  startup_script_size_bytes = length(local.startup_script_base64) * 3 / 4 - (
    endswith(local.startup_script_base64, "==") ? 2 : endswith(local.startup_script_base64, "=") ? 1 : 0
  )
  startup_script_uses_gcs = local.startup_script_size_bytes > 262144
  startup_metadata = local.startup_script_uses_gcs ? {
    startup-script-url = "gs://${google_storage_bucket_object.startup_script.bucket}/${google_storage_bucket_object.startup_script.name}"
    } : {
    startup-script = local.startup_script
  }
}
# END METADATA SELECTION

# Always create the transport resources: the rendered script contains project
# and database addresses that may be unknown during a first plan, so its size
# cannot safely drive resource count or for_each. The VM selects one metadata key.
resource "google_storage_bucket" "startup_scripts" {
  project                     = google_project.this.project_id
  name                        = "${google_project.this.project_id}-startup-scripts"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  depends_on = [google_project_service.apis["storage.googleapis.com"]]
}

resource "google_storage_bucket_object" "startup_script" {
  bucket        = google_storage_bucket.startup_scripts.name
  name          = "startup-${sha256(local.startup_script)}.sh"
  content       = local.startup_script
  content_type  = "text/x-shellscript; charset=utf-8"
  cache_control = "no-store"

  lifecycle {
    create_before_destroy = true
  }
}

# The runtime account can download startup code, but cannot replace it.
resource "google_storage_bucket_iam_member" "startup_script_reader" {
  bucket = google_storage_bucket.startup_scripts.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.radius.email}"
}
