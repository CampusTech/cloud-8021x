# -----------------------------------------------------------------------------
# Datadog — Optional dashboard
# Set datadog_app_key to enable. Scope the Application Key to
# dashboards_read + dashboards_write only.
# -----------------------------------------------------------------------------

provider "datadog" {
  api_key  = var.datadog_api_key
  app_key  = var.datadog_app_key
  api_url  = "https://api.${var.datadog_site}/"
  validate = var.datadog_app_key != ""
}

locals {
  datadog_enabled = var.datadog_app_key != ""

  dashboard_json = {
    title       = "FreeRADIUS 802.1X"
    description = "RADIUS authentication, devices, accounting, and infrastructure"
    layout_type = "ordered"
    template_variables = [
      {
        name             = "site"
        prefix           = "@site_name"
        available_values = []
        defaults         = ["*"]
      },
      {
        name   = "host"
        prefix = "host"
        available_values = [
          "${google_compute_instance.radius.name}.${var.zone}.c.${google_project.this.project_id}.internal",
          "${google_compute_instance.radius_secondary.name}.${var.secondary_zone}.c.${google_project.this.project_id}.internal"
        ]
        defaults = ["*"]
      }
    ]
    widgets = concat(
      # -----------------------------------------------------------------------
      # Overview
      # -----------------------------------------------------------------------
      [
        {
          definition = {
            title       = "Overview"
            type        = "group"
            layout_type = "ordered"
            widgets = [
              {
                definition = {
                  title     = "Server Status"
                  type      = "query_value"
                  autoscale = false
                  precision = 0
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "a", query = "min:freeradius.up{$host}", aggregator = "last" },
                        { data_source = "metrics", name = "b", query = "min:freeradius.freeradius_up{$host}", aggregator = "last" }
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "default_zero(a) + default_zero(b)" }
                      ]
                      conditional_formats = [
                        { comparator = ">=", value = 1, palette = "white_on_green" }
                      ]
                    }
                  ]
                }
              },
              {
                definition = {
                  title     = "Auth Requests / min"
                  type      = "query_value"
                  autoscale = true
                  precision = 1
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "a", query = "sum:freeradius.total_access_requests.count{$host}.as_rate()", aggregator = "avg" },
                        { data_source = "metrics", name = "b", query = "sum:freeradius.freeradius_total_access_requests.count{$host}.as_rate()", aggregator = "avg" }
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "(default_zero(a) + default_zero(b)) * 60" }
                      ]
                    }
                  ]
                }
              },
              # Accepts/Rejects come from the radius-auth LOG (one line per event),
              # NOT the freeradius.total_access_* counters — those stay 0 under
              # EAP-TLS (FreeRADIUS counts total_access_requests but not
              # accepts/rejects for EAP). See the radius_no_accepts monitor note.
              {
                definition = {
                  title     = "Accepts / min"
                  type      = "query_value"
                  autoscale = true
                  precision = 1
                  requests = [
                    {
                      queries = [
                        { data_source = "logs", name = "a", search = { query = "service:radius-auth @event:Access-Accept $host" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "default_zero(a) / 30" }
                      ]
                      conditional_formats = [
                        { comparator = ">", value = 0, palette = "white_on_green" }
                      ]
                    }
                  ]
                }
              },
              {
                definition = {
                  title     = "Rejects / min"
                  type      = "query_value"
                  autoscale = true
                  precision = 1
                  requests = [
                    {
                      queries = [
                        { data_source = "logs", name = "a", search = { query = "service:radius-auth @event:Access-Reject $host" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "default_zero(a) / 30" }
                      ]
                      conditional_formats = [
                        { comparator = ">", value = 0, palette = "white_on_yellow" }
                      ]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "Auth Success Rate"
                  type        = "query_value"
                  autoscale   = false
                  precision   = 1
                  custom_unit = "%"
                  requests = [
                    {
                      queries = [
                        { data_source = "logs", name = "a", search = { query = "service:radius-auth @event:Access-Accept $host" }, compute = { aggregation = "count" } },
                        { data_source = "logs", name = "c", search = { query = "service:radius-auth @event:Access-Reject $host" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "scalar"
                      formulas = [
                        {
                          formula = "(default_zero(a) / (default_zero(a) + default_zero(c))) * 100"
                        }
                      ]
                      conditional_formats = [
                        { comparator = ">=", value = 99, palette = "white_on_green" },
                        { comparator = ">=", value = 95, palette = "white_on_yellow" },
                        { comparator = "<", value = 95, palette = "white_on_red" }
                      ]
                    }
                  ]
                }
              }
            ]
          }
        },

        # ---------------------------------------------------------------------
        # Authentication
        # ---------------------------------------------------------------------
        {
          definition = {
            title       = "Authentication"
            type        = "group"
            layout_type = "ordered"
            widgets = [
              {
                definition = {
                  title       = "Accepts vs Rejects"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        { data_source = "logs", name = "a", search = { query = "service:radius-auth @event:Access-Accept $host" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "green" }
                      formulas        = [{ formula = "a", alias = "Accepts" }]
                    },
                    {
                      queries = [
                        { data_source = "logs", name = "c", search = { query = "service:radius-auth @event:Access-Reject $host" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "red" }
                      formulas        = [{ formula = "c", alias = "Rejects" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "e", query = "sum:freeradius.total_access_challenges.count{$host}.as_rate()" },
                        { data_source = "metrics", name = "f", query = "sum:freeradius.freeradius_total_access_challenges.count{$host}.as_rate()" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "orange" }
                      formulas        = [{ formula = "default_zero(e) + default_zero(f)", alias = "Challenges" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title   = "Recent Auth Events"
                  type    = "log_stream"
                  indexes = ["*"]
                  query   = "service:radius-auth host:$host.value @site_name:$site.value"
                  columns = ["@timestamp", "@event", "@serial", "@device_owner", "@device_name", "@ssid", "@site_name", "@ap_name"]
                  sort = {
                    column = "@timestamp"
                    order  = "desc"
                  }
                  message_display = "inline"
                }
              },
              {
                definition = {
                  title = "Reject Reasons"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-auth host:$host.value @site_name:$site.value @event:Access-Reject" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@reject_reason"
                              limit = 10
                              sort  = { aggregation = "count", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "count" }
                        }
                      ]
                      response_format = "scalar"
                      formulas        = [{ formula = "query1" }]
                    }
                  ]
                }
              }
            ]
          }
        },

        # ---------------------------------------------------------------------
        # Devices
        # ---------------------------------------------------------------------
        {
          definition = {
            title       = "Devices"
            type        = "group"
            layout_type = "ordered"
            widgets = [
              {
                definition = {
                  title = "Top Devices by Auth Count"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-auth host:$host.value @site_name:$site.value @event:Access-Accept" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@device_name"
                              limit = 20
                              sort  = { aggregation = "count", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "count" }
                        }
                      ]
                      response_format = "scalar"
                      formulas        = [{ formula = "query1" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title = "Device Model Distribution"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-auth host:$host.value @site_name:$site.value @event:Access-Accept" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@device_model"
                              limit = 10
                              sort  = { aggregation = "count", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "count" }
                        }
                      ]
                      response_format = "scalar"
                      formulas        = [{ formula = "query1" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title = "Device Owners by Auth Count"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-auth host:$host.value @site_name:$site.value @event:Access-Accept" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@device_owner"
                              limit = 20
                              sort  = { aggregation = "count", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "count" }
                        }
                      ]
                      response_format = "scalar"
                      formulas        = [{ formula = "query1" }]
                    }
                  ]
                }
              }
            ]
          }
        },

        # ---------------------------------------------------------------------
        # Network / Location
        # ---------------------------------------------------------------------
        {
          definition = {
            title       = "Network / Location"
            type        = "group"
            layout_type = "ordered"
            widgets = [
              {
                definition = {
                  title       = "Auth Events by Site"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-auth host:$host.value @site_name:$site.value @event:Access-Accept" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@site_name"
                              limit = 10
                              sort  = { aggregation = "count", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "count" }
                        }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      formulas        = [{ formula = "query1" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title = "Top Access Points"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-auth host:$host.value @site_name:$site.value @event:Access-Accept" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@site_name"
                              limit = 10
                              sort  = { aggregation = "count", order = "desc" }
                            },
                            {
                              facet = "@ap_name"
                              limit = 20
                              sort  = { aggregation = "count", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "count" }
                        }
                      ]
                      response_format = "scalar"
                      formulas        = [{ formula = "query1" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title = "Auth by SSID"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-auth host:$host.value @site_name:$site.value @event:Access-Accept" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@site_name"
                              limit = 10
                              sort  = { aggregation = "count", order = "desc" }
                            },
                            {
                              facet = "@ssid"
                              limit = 10
                              sort  = { aggregation = "count", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "count" }
                        }
                      ]
                      response_format = "scalar"
                      formulas        = [{ formula = "query1" }]
                    }
                  ]
                }
              }
            ]
          }
        },

        # ---------------------------------------------------------------------
        # Accounting
        # ---------------------------------------------------------------------
        {
          definition = {
            title       = "Accounting"
            type        = "group"
            layout_type = "ordered"
            widgets = [
              {
                definition = {
                  title       = "Accounting Requests"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "a", query = "sum:freeradius.total_acct_requests.count{$host}.as_rate()" },
                        { data_source = "metrics", name = "b", query = "sum:freeradius.freeradius_total_acct_requests.count{$host}.as_rate()" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "blue" }
                      formulas        = [{ formula = "default_zero(a) + default_zero(b)", alias = "Requests" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "c", query = "sum:freeradius.total_acct_responses.count{$host}.as_rate()" },
                        { data_source = "metrics", name = "d", query = "sum:freeradius.freeradius_total_acct_responses.count{$host}.as_rate()" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "green" }
                      formulas        = [{ formula = "default_zero(c) + default_zero(d)", alias = "Responses" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "Session Events"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "starts"
                          search      = { query = "service:radius-acct host:$host.value @site_name:$site.value @event:Acct-Start" }
                          indexes     = ["*"]
                          compute     = { aggregation = "count" }
                        }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "green" }
                      formulas        = [{ formula = "starts", alias = "Session Starts" }]
                    },
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "stops"
                          search      = { query = "service:radius-acct host:$host.value @site_name:$site.value @event:Acct-Stop" }
                          indexes     = ["*"]
                          compute     = { aggregation = "count" }
                        }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "red" }
                      formulas        = [{ formula = "stops", alias = "Session Stops" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title = "Avg Session Duration by User (min)"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-acct host:$host.value @site_name:$site.value @event:Acct-Stop" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@device_owner"
                              limit = 20
                              sort  = { aggregation = "avg", metric = "@session_time", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "avg", metric = "@session_time" }
                        }
                      ]
                      response_format = "scalar"
                      formulas        = [{ formula = "query1 / 60" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title = "Session Termination Causes"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-acct host:$host.value @site_name:$site.value @event:Acct-Stop" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet = "@terminate_cause"
                              limit = 10
                              sort  = { aggregation = "count", order = "desc" }
                            }
                          ]
                          compute = { aggregation = "count" }
                        }
                      ]
                      response_format = "scalar"
                      formulas        = [{ formula = "query1" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "Bandwidth (Acct-Stop)"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "input"
                          search      = { query = "service:radius-acct host:$host.value @site_name:$site.value @event:Acct-Stop" }
                          indexes     = ["*"]
                          compute     = { aggregation = "sum", metric = "@input_bytes" }
                        }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "cool" }
                      formulas        = [{ formula = "input", alias = "Input Bytes" }]
                    },
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "output"
                          search      = { query = "service:radius-acct host:$host.value @site_name:$site.value @event:Acct-Stop" }
                          indexes     = ["*"]
                          compute     = { aggregation = "sum", metric = "@output_bytes" }
                        }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "warm" }
                      formulas        = [{ formula = "output", alias = "Output Bytes" }]
                    }
                  ]
                }
              }
            ]
          }
        },

        # ---------------------------------------------------------------------
        # Infrastructure
        # ---------------------------------------------------------------------
        {
          definition = {
            title       = "Infrastructure"
            type        = "group"
            layout_type = "ordered"
            widgets = [
              {
                definition = {
                  title       = "Queue Depths"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "a", query = "avg:freeradius.queue_len_auth{$host}" },
                        { data_source = "metrics", name = "b", query = "avg:freeradius.freeradius_queue_len_auth{$host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      formulas        = [{ formula = "default_zero(a) + default_zero(b)", alias = "Auth" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "c", query = "avg:freeradius.queue_len_acct{$host}" },
                        { data_source = "metrics", name = "d", query = "avg:freeradius.freeradius_queue_len_acct{$host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      formulas        = [{ formula = "default_zero(c) + default_zero(d)", alias = "Acct" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "e", query = "avg:freeradius.queue_len_internal{$host}" },
                        { data_source = "metrics", name = "f", query = "avg:freeradius.freeradius_queue_len_internal{$host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      formulas        = [{ formula = "default_zero(e) + default_zero(f)", alias = "Internal" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "Packets Per Second"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "a", query = "avg:freeradius.queue_pps_in{$host}" },
                        { data_source = "metrics", name = "b", query = "avg:freeradius.freeradius_queue_pps_in{$host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "blue" }
                      formulas        = [{ formula = "default_zero(a) + default_zero(b)", alias = "PPS In" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "c", query = "avg:freeradius.queue_pps_out{$host}" },
                        { data_source = "metrics", name = "d", query = "avg:freeradius.freeradius_queue_pps_out{$host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "green" }
                      formulas        = [{ formula = "default_zero(c) + default_zero(d)", alias = "PPS Out" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "Auth Errors"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "a", query = "sum:freeradius.total_auth_malformed_requests.count{$host}.as_rate()" },
                        { data_source = "metrics", name = "b", query = "sum:freeradius.freeradius_total_auth_malformed_requests.count{$host}.as_rate()" }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "red" }
                      formulas        = [{ formula = "default_zero(a) + default_zero(b)", alias = "Malformed" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "c", query = "sum:freeradius.total_auth_invalid_requests.count{$host}.as_rate()" },
                        { data_source = "metrics", name = "d", query = "sum:freeradius.freeradius_total_auth_invalid_requests.count{$host}.as_rate()" }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "orange" }
                      formulas        = [{ formula = "default_zero(c) + default_zero(d)", alias = "Invalid" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "e", query = "sum:freeradius.total_auth_dropped_requests.count{$host}.as_rate()" },
                        { data_source = "metrics", name = "f", query = "sum:freeradius.freeradius_total_auth_dropped_requests.count{$host}.as_rate()" }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "yellow" }
                      formulas        = [{ formula = "default_zero(e) + default_zero(f)", alias = "Dropped" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "g", query = "sum:freeradius.total_auth_duplicate_requests.count{$host}.as_rate()" },
                        { data_source = "metrics", name = "h", query = "sum:freeradius.freeradius_total_auth_duplicate_requests.count{$host}.as_rate()" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "grey" }
                      formulas        = [{ formula = "default_zero(g) + default_zero(h)", alias = "Duplicate" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "CPU Usage"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "cpu", query = "avg:system.cpu.user{$host} by {host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      formulas        = [{ formula = "cpu" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "Memory Usage (%)"
                  type        = "timeseries"
                  show_legend = true
                  yaxis       = { min = "0", max = "100" }
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "used", query = "avg:system.mem.used{$host} by {host}" },
                        { data_source = "metrics", name = "total", query = "avg:system.mem.total{$host} by {host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      formulas        = [{ formula = "(used / total) * 100" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "System Uptime (days)"
                  type        = "query_value"
                  autoscale   = false
                  precision   = 1
                  custom_unit = "days"
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "a", query = "min:system.uptime{$host}", aggregator = "last" }
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "a / 86400" }
                      ]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "Network I/O"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "rx", query = "avg:system.net.bytes_rcvd{$host} by {host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "blue" }
                      formulas = [
                        { formula = "rx" }
                      ]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "tx", query = "avg:system.net.bytes_sent{$host} by {host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "green" }
                      formulas = [
                        { formula = "tx" }
                      ]
                    }
                  ]
                }
              },
              {
                definition = {
                  title       = "Disk Usage (%)"
                  type        = "timeseries"
                  show_legend = true
                  yaxis       = { min = "0", max = "100" }
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "disk", query = "max:system.disk.in_use{$host} by {host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      formulas        = [{ formula = "disk * 100" }]
                    }
                  ]
                }
              }
            ]
          }
        }
      ]
    )
  }
}

resource "datadog_dashboard_json" "radius" {
  count     = local.datadog_enabled ? 1 : 0
  dashboard = jsonencode(local.dashboard_json)
}
