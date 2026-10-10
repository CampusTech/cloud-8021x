# Root fresh-install transport only. Never apply this root retirement to blue.
# Parallel green uses its own distinct bucket, objects, identity and metadata.
locals {
  startup_script_size_bytes = { for role, script in local.startup_scripts : role => length(base64encode(script)) * 3 / 4 }
  startup_metadata = { for role, script in local.startup_scripts : role => {
    startup-script-url = "gs://${google_storage_bucket_object.go_loader[role].bucket}/${google_storage_bucket_object.go_loader[role].name}"
  } }
}
resource "google_storage_bucket" "startup_scripts" {
  project                     = google_project.this.project_id
  name                        = "${google_project.this.project_id}-startup-scripts"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  depends_on                  = [google_project_service.apis["storage.googleapis.com"]]
}
removed {
  from = google_storage_bucket_object.startup_script
  lifecycle { destroy = false }
}
resource "google_storage_bucket_object" "go_loader" {
  for_each      = local.startup_scripts
  bucket        = google_storage_bucket.startup_scripts.name
  name          = "go-loader-${each.key}-${sha256(each.value)}.sh"
  content       = each.value
  content_type  = "text/x-shellscript; charset=utf-8"
  cache_control = "no-store"
  lifecycle { create_before_destroy = true }
}
resource "google_storage_bucket_iam_member" "startup_script_reader" {
  bucket = google_storage_bucket.startup_scripts.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.radius.email}"
}
resource "google_storage_bucket_iam_member" "runtime_artifact_reader" {
  bucket = var.runtime_artifact_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.radius.email}"
}
