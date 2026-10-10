# New projects receive a distinct monitoring identity even when their GCE VM
# names match another deployment. Existing installations may explicitly set ""
# to retain their historical Datadog hostnames. A named canary can use its own
# stable suffix (for example, "canary-bb45").
variable "datadog_hostname_suffix" {
  description = "Datadog hostname suffix. Null uses the unique GCP project ID; an empty string retains legacy production names. Set a distinct explicit suffix for canaries."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.datadog_hostname_suffix == null ? true : (
      var.datadog_hostname_suffix == "" || (
        length(var.datadog_hostname_suffix) <= 46 &&
        can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.datadog_hostname_suffix))
      )
    )
    error_message = "Datadog hostname suffix must be null, empty, or a lowercase DNS label of at most 46 characters (no leading or trailing hyphen)."
  }
}

locals {
  # Bootstrap consumes only the resolved suffix, avoiding a dependency cycle
  # between the rendered VM metadata and the VM resource names.
  datadog_hostname_suffix = var.datadog_hostname_suffix == null ? google_project.this.project_id : var.datadog_hostname_suffix
  datadog_radius_hosts = var.datadog_observability_hosts != null ? { for host in var.datadog_observability_hosts : host => host } : {
    for instance_name in [google_compute_instance.radius.name, google_compute_instance.radius_secondary.name] :
    instance_name => local.datadog_hostname_suffix == "" ? instance_name : "${instance_name}-${local.datadog_hostname_suffix}"
  }
}

variable "datadog_observability_hosts" {
  description = "Reviewed exact physical hosts admitted by the observability owner. Null preserves the legacy pair; explicitly list two green hosts or four blue+green hosts for deliberate staging."
  type        = set(string)
  default     = null
  validation {
    condition     = var.datadog_observability_hosts == null ? true : (contains([2, 4], length(var.datadog_observability_hosts)) && alltrue([for host in var.datadog_observability_hosts : length(host) <= 253 && can(regex("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", host))]))
    error_message = "Admit exactly two or four reviewed physical DNS hostnames; no wildcard, query syntax or implicit deployments."
  }
}
