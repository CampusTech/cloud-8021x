# One collector queries both RADIUS nodes. Credentials remain outside Terraform.
variable "enable_radius_usage_collector" {
  description = "Install the checkpointed usage collector only on the primary VM."
  type        = bool
  default     = false
}

variable "radius_usage_credentials_secret_id" {
  description = "Existing Secret Manager secret in this project containing JSON api_key and a logs_read_data-only app_key."
  type        = string
  default     = ""
  validation {
    condition     = var.radius_usage_credentials_secret_id == "" || can(regex("^[A-Za-z0-9_-]+$", var.radius_usage_credentials_secret_id))
    error_message = "Provide a Secret Manager secret ID, not credential material or a URL."
  }
}

variable "radius_usage_preview_id" {
  description = "Optional stable tag for existing preview checkpoints; retain it when migrating a preview to the permanent collector."
  type        = string
  default     = ""
  validation {
    condition     = var.radius_usage_preview_id == "" || can(regex("^[A-Za-z0-9_.-]{1,128}$", var.radius_usage_preview_id))
    error_message = "Preview ID must be empty or a stable single label."
  }
}

resource "google_secret_manager_secret_iam_member" "radius_usage_credentials" {
  count     = var.enable_radius_usage_collector ? 1 : 0
  project   = google_project.this.project_id
  secret_id = var.radius_usage_credentials_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
  lifecycle {
    precondition {
      condition     = var.radius_usage_credentials_secret_id != ""
      error_message = "An existing collector credentials secret is required when usage collection is enabled."
    }
  }
}

resource "datadog_monitor" "radius_usage_stale" {
  count   = local.datadog_enabled && var.enable_radius_usage_collector ? 1 : 0
  name    = "RADIUS observed usage collector stopped — ${google_project.this.project_id}"
  type    = "log alert"
  query   = "logs(\"service:radius-usage-collector @event:Collection-Heartbeat @collector_id:${local.datadog_radius_hosts[google_compute_instance.radius.name]}\").index(\"*\").rollup(\"count\").last(\"10m\") < 1"
  message = "No successful usage collection heartbeat in 10 minutes. Traffic totals may be stale even if raw accounting is arriving. Quiet successful collections also emit a heartbeat. Inspect radius-usage-collector.service on the primary; preserve /var/lib/radius-usage/checkpoint.json. An uncertain intake batch requires reconciliation before restarting collection. This monitor does not indicate an authentication outage.${local.dd_notify}"
  monitor_thresholds {
    critical = 1
  }
  include_tags        = true
  require_full_window = false
  on_missing_data     = "default"
  tags                = ["service:radius-usage-collector", "project:${google_project.this.project_id}"]
}
