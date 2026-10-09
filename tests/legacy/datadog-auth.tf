# Auth diagnostics use existing indexed logs, without requiring a RADIUS restart.
# A client is scoped by RADIUS source + station address, never claimed identity.
locals {
  auth_diagnostics_filter = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value"
  auth_reject_filter      = "${local.auth_diagnostics_filter} @event:Access-Reject"
  auth_identified_rejects = "${local.auth_reject_filter} @src_ip:* -@src_ip:\"\" @calling_station:* -@calling_station:\"\""
  auth_site_groups = [
    for facet in ["@src_ip", "@site_name"] : {
      facet                  = facet
      should_exclude_missing = false
      limit                  = 20
      sort                   = { aggregation = "count", order = "desc" }
    }
  ]
  auth_client_groups = [
    # The product of limits stays within Datadog's 5000-bucket limit.
    for group in [
      { facet = "@src_ip", limit = 10 },
      { facet = "@calling_station", limit = 50 },
      { facet = "@site_name", limit = 10 }
      ] : {
      facet                  = group.facet
      should_exclude_missing = false
      limit                  = group.limit
      sort                   = { aggregation = "count", order = "desc" }
    }
  ]

  datadog_auth_content = {
    definition = {
      title       = "Auth Diagnostics"
      type        = "group"
      layout_type = "ordered"
      widgets = [
        {
          definition = {
            type             = "note"
            content          = "Reject attempts include retries; affected clients count station addresses per source/site, excluding missing addresses. Private addresses may change, and blank site labels can split buckets. Open an affected-client row’s ‘View latest successful authentication’ link for successes, newest first; widen the Logs window for older events. Claimed identity is unverified. Owner/device details require verified enrichment."
            background_color = "white"
            font_size        = "14"
            text_align       = "left"
            show_tick        = false
          }
        },
        {
          definition = {
            title          = "Reject attempts vs affected clients by RADIUS source / site"
            type           = "query_table"
            has_search_bar = "always"
            requests = [{
              queries = [
                {
                  data_source = "logs"
                  name        = "rejects"
                  indexes     = ["*"]
                  search      = { query = local.auth_reject_filter }
                  compute     = { aggregation = "count" }
                  group_by    = local.auth_site_groups
                },
                {
                  data_source = "logs"
                  name        = "clients"
                  indexes     = ["*"]
                  search      = { query = local.auth_identified_rejects }
                  compute     = { aggregation = "cardinality", metric = "@calling_station" }
                  group_by    = local.auth_site_groups
                }
              ]
              response_format = "scalar"
              formulas = [
                { formula = "rejects", alias = "Reject attempts", cell_display_mode = "number" },
                { formula = "clients", alias = "Distinct affected clients", cell_display_mode = "number" }
              ]
              sort = { count = 100, order_by = [{ type = "formula", index = 0, order = "desc" }] }
            }]
          }
        },
        {
          definition = {
            title          = "Affected clients — reject attempts (open row for latest successful auth)"
            type           = "query_table"
            has_search_bar = "always"
            custom_links = [{
              label = "View latest successful authentication"
              # Query variables include the facet key and Datadog URL-encodes them.
              # Do not constrain site_name: rejects can lack the successful label.
              link = "/logs?query=service:radius-auth (${join(" OR ", [for host in values(local.datadog_radius_hosts) : "host:${host}"])}) @event:Access-Accept {{@src_ip}} {{@calling_station}}&stream_sort=time%2Cdesc&viz=stream&from_ts={{timestamp_start}}&to_ts={{timestamp_end}}&live=false"
            }]
            requests = [{
              queries = [{
                data_source = "logs"
                name        = "rejects"
                indexes     = ["*"]
                search      = { query = local.auth_identified_rejects }
                compute     = { aggregation = "count" }
                group_by    = local.auth_client_groups
              }]
              response_format = "scalar"
              formulas        = [{ formula = "rejects", alias = "Reject attempts", cell_display_mode = "number" }]
              sort            = { count = 100, order_by = [{ type = "formula", index = 0, order = "desc" }] }
            }]
          }
        },
        {
          definition = {
            title           = "Recent rejected clients — claimed identity is unverified"
            type            = "log_stream"
            indexes         = ["*"]
            query           = local.auth_reject_filter
            columns         = ["timestamp", "@src_ip", "@calling_station", "@site_name", "@ap_name", "@reject_reason", "@raw_identity"]
            sort            = { column = "timestamp", order = "desc" }
            message_display = "inline"
          }
        },
        {
          definition = {
            title           = "Successful authentications — newest first (verified details when available)"
            type            = "log_stream"
            indexes         = ["*"]
            query           = "${local.auth_diagnostics_filter} @event:Access-Accept"
            columns         = ["timestamp", "@src_ip", "@calling_station", "@site_name", "@ap_name", "@identity_verified", "@device_owner", "@device_name", "@device_id"]
            sort            = { column = "timestamp", order = "desc" }
            message_display = "inline"
          }
        }
      ]
    }
  }
  auth_diagnostics_layouts = [
    { x = 0, y = 0, width = 12, height = 1 },
    { x = 0, y = 1, width = 6, height = 3 },
    { x = 6, y = 1, width = 6, height = 3 },
    { x = 0, y = 4, width = 6, height = 3 },
    { x = 6, y = 4, width = 6, height = 3 }
  ]
  datadog_auth_group = merge(local.datadog_auth_content, {
    definition = merge(local.datadog_auth_content.definition, {
      widgets = [for i, widget in local.datadog_auth_content.definition.widgets : merge(widget, { layout = local.auth_diagnostics_layouts[i] })]
    })
  })
}
