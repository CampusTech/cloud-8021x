variable "datadog_usage_sites" {
  description = "Per-site accounting/usage counter tiles: display label => exact site_name in logs. Empty shows all sites together."
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for label, site in var.datadog_usage_sites : trimspace(label) != "" && trimspace(site) != ""])
    error_message = "Site labels and log site names must be nonempty."
  }
}

# Raw counters are cumulative; only the checkpointed collector emits additive deltas.
locals {
  usage_counter_sites   = length(var.datadog_usage_sites) == 0 ? { "All sites" = "*" } : var.datadog_usage_sites
  usage_counter_columns = min(4, length(local.usage_counter_sites))
  usage_counter_rows    = ceil(length(local.usage_counter_sites) / local.usage_counter_columns)
  accounting_filter     = "service:radius-acct ${local.radius_log_hosts_filter} @site_name:$site.value"
  usage_preview_filter  = var.radius_usage_preview_id == "" ? "" : " @preview_id:${var.radius_usage_preview_id}"
  usage_filter          = "service:radius-usage ${local.radius_log_hosts_filter} @site_name:$site.value${local.usage_preview_filter}"
  usage_queries = [
    for direction, metric in { upload = "@input_bytes", download = "@output_bytes" } : {
      data_source                     = "logs"
      name                            = direction
      indexes                         = ["*"]
      search                          = { query = "${local.usage_filter} @event:Acct-Usage" }
      compute                         = { aggregation = "sum", metric = metric }
    }
  ]
  usage_formulas = [
    { formula = "upload / 1073741824", alias = "Upload (GiB)" },
    { formula = "download / 1073741824", alias = "Download (GiB)" },
    { formula = "(upload + download) / 1073741824", alias = "Total (GiB)" }
  ]
  usage_session_groups = [
    # NAS + session + client distinguishes sessions across offices/APs. Include
    # WAN source for overlapping private NAS ranges. Limits multiply to 5000.
    for facet, limit in {
      "@src_ip" = 5, "@nas_ip" = 10, "@calling_station" = 10, "@session_id" = 10
      } : {
      facet = facet
      limit = limit
      sort  = { aggregation = "max", metric = "@output_bytes", order = "desc" }
    }
  ]
  usage_session_queries = concat([
    for query in local.usage_queries : merge(query, {
      search   = { query = "${local.accounting_filter} @event:Acct-Update -@session_id:\"\" -@calling_station:\"\"" }
      compute  = merge(query.compute, { aggregation = "max" })
      group_by = local.usage_session_groups
    })
    ], [{
      data_source = "logs"
      name        = "duration"
      indexes     = ["*"]
      search      = { query = "${local.accounting_filter} @event:Acct-Update -@session_id:\"\" -@calling_station:\"\"" }
      compute     = { aggregation = "max", metric = "@session_time" }
      group_by    = local.usage_session_groups
  }])

  datadog_usage_content = {
    definition = {
      title       = "Network Data Usage"
      type        = "group"
      layout_type = "ordered"
      widgets = concat([
        {
          definition = {
            type             = "note"
            content          = "**Usage:** Upload/download are from the device’s perspective. Totals include ongoing sessions and deduplicate reports. Totals follow the network’s accounting report cadence; throughput is an interval average. Missing baselines or counter resets leave gaps. N/A measured-client coverage means no measured interval.\n\nEarlier usage is not reconstructed. ${var.enable_radius_usage_collector ? "Collection runs every two minutes, with an alert after ten minutes without a successful pass." : "Usage requires an enabled collector."}"
            background_color = "white"
            font_size        = "14"
            text_align       = "left"
            show_tick        = false
          }
        }
        ], [
        for formula in local.usage_formulas : {
          definition = {
            title       = "Observed traffic — ${formula.alias}"
            type        = "query_value"
            autoscale   = false
            precision   = 2
            custom_unit = "GiB"
            requests = [{
              queries         = local.usage_queries
              response_format = "scalar"
              formulas        = [formula]
            }]
          }
        }
        ], [
        # Count received accounting events separately from measured intervals.
        # Fixed windows keep these health counters independent of the time picker.
        for counter in flatten([
          for source in [
            { title = "Accounting events", filter = local.accounting_filter },
            { title = "Usage intervals", filter = "${local.usage_filter} @event:Acct-Usage" }
            ] : [for label, site in local.usage_counter_sites : {
              title  = "${label} — ${source.title} (1h)"
              filter = site == "*" ? source.filter : "${source.filter} @site_name:${jsonencode(site)}"
          }]
          ]) : {
          definition = {
            title     = counter.title
            type      = "query_value"
            time      = { live_span = "1h" }
            autoscale = false
            precision = 0
            requests = [{
              queries = [{
                data_source = "logs"
                name        = "events"
                indexes     = ["*"]
                search      = { query = counter.filter }
                compute     = { aggregation = "count" }
              }]
              response_format = "scalar"
              formulas        = [{ formula = "default_zero(events)" }]
            }]
          }
        }
        ], [
        {
          definition = {
            title = "Measured client coverage — last 30m"
            type  = "query_table"
            time  = { live_span = "30m" }
            requests = [{
              queries = [for source in [
                { name = "reporting", filter = "${local.accounting_filter} (@event:Acct-Update OR @event:Acct-Stop) -@calling_station:\"\"" },
                { name = "measured", filter = "${local.usage_filter} @event:Acct-Usage -@calling_station:\"\"" }
                ] : {
                data_source = "logs"
                name        = source.name
                indexes     = ["*"]
                search      = { query = source.filter }
                compute     = { aggregation = "cardinality", metric = "@calling_station" }
                group_by    = [{ facet = "@site_name", limit = 20, sort = { aggregation = "cardinality", metric = "@calling_station", order = "desc" }, should_exclude_missing = false }]
              }]
              response_format = "scalar"
              formulas = [
                { formula = "reporting", alias = "Reporting clients", cell_display_mode = "number" },
                { formula = "measured", alias = "Measured clients", cell_display_mode = "number" },
                { formula = "measured / reporting * 100", alias = "Coverage (%)", cell_display_mode = "bar" }
              ]
              sort = { count = 20, order_by = [{ type = "formula", index = 0, order = "desc" }] }
            }]
          }
        },
        {
          definition = {
            title       = "Observed traffic increments by report time (GiB)"
            type        = "timeseries"
            show_legend = true
            yaxis       = { min = "0", include_zero = true }
            requests = [{
              queries         = local.usage_queries
              response_format = "timeseries"
              display_type    = "bars"
              formulas        = slice(local.usage_formulas, 0, 2)
            }]
          }
        },
        {
          definition = {
            title = "Observed usage by site (GiB)"
            type  = "query_table"
            requests = [{
              queries = [for query in local.usage_queries : merge(query, {
                group_by = [{ facet = "@site_name", limit = 10, sort = { aggregation = "sum", metric = "@output_bytes", order = "desc" } }]
              })]
              response_format = "scalar"
              formulas        = [for formula in local.usage_formulas : merge(formula, { cell_display_mode = "bar" })]
              sort            = { count = 10, order_by = [{ type = "formula", index = 2, order = "desc" }] }
            }]
          }
        },
        {
          definition = {
            title = "Observed usage by verified owner / device (GiB)"
            type  = "query_table"
            requests = [{
              queries = [for query in local.usage_queries : merge(query, {
                search = { query = "${query.search.query} @identity_verified:true -@device_id:\"\"" }
                group_by = [for facet in ["@device_owner", "@device_name", "@device_id"] : {
                  facet = facet, limit = 15, sort = { aggregation = "sum", metric = "@output_bytes", order = "desc" }, should_exclude_missing = false
                }]
              })]
              response_format = "scalar"
              formulas        = [for formula in local.usage_formulas : merge(formula, { cell_display_mode = "bar" })]
              sort            = { count = 30, order_by = [{ type = "formula", index = 2, order = "desc" }] }
            }]
          }
        },
        {
          definition = {
            title = "Cumulative session counters — reported in last 30m (GiB)"
            type  = "query_table"
            time  = { live_span = "30m" }
            requests = [{
              queries         = local.usage_session_queries
              response_format = "scalar"
              formulas = concat(
                [for formula in local.usage_formulas : merge(formula, { cell_display_mode = "bar" })],
                [{ formula = "duration / 3600", alias = "Session age (hours)", cell_display_mode = "number", number_format = { unit = { type = "custom_unit_label", label = "hours" } } }]
              )
              sort = { count = 50, order_by = [{ type = "formula", index = 2, order = "desc" }] }
            }]
          }
        },
        {
          definition = {
            title = "Reported interval throughput by client — last 30m (Mbps)"
            type  = "query_table"
            time  = { live_span = "30m" }
            requests = [{
              queries = concat([for query in local.usage_queries : merge(query, {
                group_by = [for facet, limit in { "@site_name" = 10, "@calling_station" = 100 } : {
                  facet = facet, limit = limit, sort = { aggregation = "sum", metric = "@output_bytes", order = "desc" }
                }]
                })], [{
                data_source = "logs"
                name        = "elapsed"
                indexes     = ["*"]
                search      = { query = "${local.usage_filter} @event:Acct-Usage" }
                compute     = { aggregation = "sum", metric = "@session_time" }
                group_by = [for facet, limit in { "@site_name" = 10, "@calling_station" = 100 } : {
                  facet = facet, limit = limit, sort = { aggregation = "sum", metric = "@output_bytes", order = "desc" }
                }]
              }])
              response_format = "scalar"
              formulas = [
                { formula = "upload * 8 / elapsed / 1000000", alias = "Upload (Mbps)", cell_display_mode = "bar" },
                { formula = "download * 8 / elapsed / 1000000", alias = "Download (Mbps)", cell_display_mode = "bar" }
              ]
              sort = { count = 30, order_by = [{ type = "formula", index = 1, order = "desc" }] }
            }]
          }
        },
        {
          definition = {
            title = "Interim accounting updates by site"
            type  = "timeseries"
            requests = [{
              queries = [{
                data_source = "logs"
                name        = "updates"
                search      = { query = "${local.accounting_filter} @event:Acct-Update" }
                indexes     = ["*"]
                compute     = { aggregation = "count" }
                group_by    = [{ facet = "@site_name", limit = 10, sort = { aggregation = "count", order = "desc" } }]
              }]
              response_format = "timeseries"
              display_type    = "bars"
              formulas        = [{ formula = "updates", alias = "Updates received" }]
            }]
          }
        },
        {
          definition = {
            title   = "Recent session counters and device details"
            type    = "log_stream"
            query   = "${local.accounting_filter} (@event:Acct-Update OR @event:Acct-Stop)"
            indexes = ["*"]
            columns = ["timestamp", "@event", "@site_name", "@ap_name", "@ssid", "@device_owner", "@device_name", "@calling_station", "@session_id", "@input_bytes", "@output_bytes", "@session_time", "@identity_verified"]
            sort    = { column = "timestamp", order = "desc" }
          }
        }
      ])
    }
  }

  # Compact per-site counters occupy one row per source (more for >4 sites).
  # Coverage and traffic panels keep the four-column grid underneath.
  datadog_usage_group = merge(local.datadog_usage_content, {
    definition = merge(local.datadog_usage_content.definition, {
      widgets = [for index, widget in local.datadog_usage_content.definition.widgets : merge(widget, {
        layout = index < 4 ? {
          x = index * 3, y = 0, width = 3, height = 2
          } : index < 4 + 2 * length(local.usage_counter_sites) ? {
          x     = ((index - 4) % length(local.usage_counter_sites) % local.usage_counter_columns) * (12 / local.usage_counter_columns)
          y     = 2 + floor((index - 4) / length(local.usage_counter_sites)) * local.usage_counter_rows + floor(((index - 4) % length(local.usage_counter_sites)) / local.usage_counter_columns)
          width = 12 / local.usage_counter_columns, height = 1
          } : {
          x     = ((index - 4 - 2 * length(local.usage_counter_sites)) % 4) * 3
          y     = 2 + 2 * local.usage_counter_rows + floor((index - 4 - 2 * length(local.usage_counter_sites)) / 4) * 2
          width = 3, height = 2
        }
      })]
    })
  })

  freeradius_uptime_widget = {
    definition = {
      title = "FreeRADIUS process uptime by server (hours)"
      type  = "query_table"
      time  = { live_span = "5m" }
      requests = [{
        queries = [{
          data_source = "metrics"
          name        = "uptime"
          query       = "min:system.processes.run_time.max{${local.radius_hosts_filter} AND process_name:freeradius} by {host}"
          aggregator  = "last"
        }]
        response_format = "scalar"
        formulas        = [{ formula = "uptime / 3600", alias = "FreeRADIUS uptime (hours)", cell_display_mode = "number", number_format = { unit = { type = "custom_unit_label", label = "hours" } } }]
      }]
    }
  }
}
