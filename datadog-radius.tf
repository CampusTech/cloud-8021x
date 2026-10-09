# Ingestion defaults also cover existing RADIUS versions during a staged rollout.
# This is display metadata only: device_id and identity_verified stay unchanged.
resource "datadog_logs_custom_pipeline" "radius_owner" {
  count      = local.datadog_enabled ? 1 : 0
  name       = "RADIUS log display defaults"
  is_enabled = true

  filter {
    query = "service:(radius-auth OR radius-acct OR radius-usage)"
  }

  processor {
    category_processor {
      name       = "Use N/A for missing owners"
      is_enabled = true
      target     = "device_owner"

      category {
        name = "N/A"
        filter {
          query = "(-@device_owner:* OR @device_owner:\"\")"
        }
      }
    }
  }

  processor {
    category_processor {
      name       = "Label rejects without a recorded reason"
      is_enabled = true
      target     = "reject_reason"

      category {
        name = "Unknown / reason not recorded"
        filter {
          query = "service:radius-auth @event:Access-Reject (-@reject_reason:* OR @reject_reason:\"\")"
        }
      }
    }
  }

  processor {
    category_processor {
      name       = "Label session stops without a recorded cause"
      is_enabled = true
      target     = "terminate_cause"

      category {
        name = "Unknown / cause not recorded"
        filter {
          query = "service:radius-acct @event:Acct-Stop (-@terminate_cause:* OR @terminate_cause:\"\")"
        }
      }
    }
  }
}
