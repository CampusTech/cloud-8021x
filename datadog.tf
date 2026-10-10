# -----------------------------------------------------------------------------
# Datadog — Optional dashboard
# Set datadog_app_key to enable. Scope the Application Key to
# dashboards_read + dashboards_write; the owner-default pipeline also requires
# logs_read_pipelines + logs_write_pipelines.
# -----------------------------------------------------------------------------

provider "datadog" {
  api_key  = var.datadog_api_key
  app_key  = var.datadog_app_key
  api_url  = "https://api.${var.datadog_site}/"
  validate = var.datadog_app_key != ""
}

locals {
  monitor_hosts_filter     = "(${join(" OR ", [for host in values(local.datadog_radius_hosts) : "host:${host}"])})"
  monitor_log_hosts_filter = local.monitor_hosts_filter
  datadog_enabled          = var.datadog_app_key != ""
  radius_hosts_filter      = "$host AND (${join(" OR ", [for host in values(local.datadog_radius_hosts) : "host:${host}"])})"
  radius_log_hosts_filter  = "host:$host.value (${join(" OR ", [for host in values(local.datadog_radius_hosts) : "host:${host}"])})"
  dashboard_content = {
    title       = "FreeRADIUS 802.1X"
    description = "RADIUS authentication, assigned VLANs, devices, accounting, and infrastructure. The VLAN filter applies to the VLAN Assignments section; other sections retain unassigned and rejected events."
    layout_type = "ordered"
    template_variables = [
      {
        name   = "vlan"
        prefix = "@vlan_id"
        available_values = [
        ]
        defaults = [
          "*",
        ]
      },
      {
        name             = "site"
        prefix           = "@site_name"
        available_values = []
        defaults         = ["*"]
      },
      {
        name             = "host"
        prefix           = "host"
        available_values = sort(values(local.datadog_radius_hosts))
        defaults         = ["*"]
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
                layout = { x = 0, y = 0, width = 2, height = 1 }
                definition = {
                  title     = "RADIUS servers online"
                  type      = "query_value"
                  autoscale = false
                  precision = 0
                  time      = { live_span = "5m" }
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "online", query = "max:cloud8021x.backend.up{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius} by {host}.fill(last,60)", aggregator = "last" }
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "count_nonzero(online)" }
                      ]
                      conditional_formats = [
                        { comparator = "<", value = 1, palette = "white_on_red" },
                        { comparator = "=", value = 1, palette = "white_on_yellow" },
                        { comparator = ">=", value = 2, palette = "white_on_green" }
                      ]
                    }
                  ]
                }
              },
              {
                layout = { x = 2, y = 0, width = 3, height = 1 }
                definition = {
                  title     = "Auth Requests / min"
                  type      = "query_value"
                  autoscale = true
                  precision = 1
                  requests = [
                    {
                      queries = [
                        { data_source = "metrics", name = "a", query = "sum:cloud8021x.radius.total_access_requests{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius}.as_rate()", aggregator = "avg" },
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "(a) * 60" }
                      ]
                    }
                  ]
                }
              },
              # Accepts/Rejects come from the radius-auth LOG (one line per event),
              # NOT the freeradius.total_access_* counters — those stay 0 under
              # EAP-TLS (FreeRADIUS counts total_access_requests but not
              # accepts/rejects for EAP). See the radius_no_accepts monitor note.
              # Raw counts over the dashboard's selected window (not a per-minute
              # rate): a count widget can't know the global time selector, so a
              # fixed divisor would be wrong whenever the window changes. The
              # title reflects "over the selected time range".
              {
                layout = { x = 5, y = 0, width = 2, height = 1 }
                definition = {
                  title     = "Accepts"
                  type      = "query_value"
                  autoscale = true
                  precision = 0
                  requests = [
                    {
                      queries = [
                        { data_source = "logs", name = "a", search = { query = "service:radius-auth @event:Access-Accept ${local.radius_log_hosts_filter} @site_name:$site.value" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "default_zero(a)" }
                      ]
                      conditional_formats = [
                        { comparator = ">", value = 0, palette = "white_on_green" }
                      ]
                    }
                  ]
                }
              },
              {
                layout = { x = 7, y = 0, width = 2, height = 1 }
                definition = {
                  title     = "Rejects"
                  type      = "query_value"
                  autoscale = true
                  precision = 0
                  requests = [
                    {
                      queries = [
                        { data_source = "logs", name = "a", search = { query = "service:radius-auth @event:Access-Reject ${local.radius_log_hosts_filter} @site_name:$site.value" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "scalar"
                      formulas = [
                        { formula = "default_zero(a)" }
                      ]
                      conditional_formats = [
                        { comparator = ">", value = 0, palette = "white_on_yellow" }
                      ]
                    }
                  ]
                }
              },
              {
                layout = { x = 9, y = 0, width = 3, height = 1 }
                definition = {
                  title       = "Auth Success Rate"
                  type        = "query_value"
                  autoscale   = false
                  precision   = 1
                  custom_unit = "%"
                  requests = [
                    {
                      queries = [
                        { data_source = "logs", name = "a", search = { query = "service:radius-auth @event:Access-Accept ${local.radius_log_hosts_filter} @site_name:$site.value" }, compute = { aggregation = "count" } },
                        { data_source = "logs", name = "c", search = { query = "service:radius-auth @event:Access-Reject ${local.radius_log_hosts_filter} @site_name:$site.value" }, compute = { aggregation = "count" } }
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
                        { data_source = "logs", name = "a", search = { query = "service:radius-auth @event:Access-Accept ${local.radius_log_hosts_filter} @site_name:$site.value" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "green" }
                      formulas        = [{ formula = "a", alias = "Accepts" }]
                    },
                    {
                      queries = [
                        { data_source = "logs", name = "c", search = { query = "service:radius-auth @event:Access-Reject ${local.radius_log_hosts_filter} @site_name:$site.value" }, compute = { aggregation = "count" } }
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "red" }
                      formulas        = [{ formula = "c", alias = "Rejects" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "e", query = "sum:cloud8021x.radius.total_access_challenges{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius}.as_rate()" },
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "orange" }
                      formulas        = [{ formula = "e", alias = "Challenges" }]
                    }
                  ]
                }
              },
              {
                definition = {
                  title   = "Recent Auth Events"
                  type    = "log_stream"
                  indexes = ["*"]
                  query   = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value"
                  columns = ["timestamp", "@event", "@device_id", "@serial", "@certificate_fingerprint", "@vlan_id", "@vlan_name", "@device_owner", "@device_name", "@ssid", "@site_name", "@ap_name"]
                  sort = {
                    column = "timestamp"
                    order  = "desc"
                  }
                  message_display = "inline"
                }
              },
              {
                definition = {
                  title = "Reject Reasons (blank = reason not recorded)"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value @event:Access-Reject" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet                  = "@reject_reason"
                              should_exclude_missing = false
                              limit                  = 10
                              sort                   = { aggregation = "count", order = "desc" }
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

        local.datadog_auth_group,

        # Assigned VLANs (filter scoped here to preserve unassigned/rejected events).
        {
          definition = {
            title       = "VLAN Assignments"
            type        = "group"
            layout_type = "ordered"
            widgets = [
              {
                definition = {
                  type             = "note"
                  content          = "The VLAN filter applies only to this section. Counts cover the selected time range, not currently connected sessions. VLAN IDs are local to each location: use the site filter or RADIUS source IP to distinguish sites. A blank VLAN means no dynamic assignment was recorded; this is expected for opted-out sites and does not identify the AP or switch default VLAN. Rejected events remain visible in Overview. VLAN labels use the name recorded on each event. Older unnamed events are retained; the same device can appear in named and unnamed buckets, so device counts across VLAN/name buckets are not additive."
                  background_color = "white"
                  font_size        = "14"
                  text_align       = "left"
                  show_tick        = false
                }
              },
              {
                definition = {
                  title = "Accepted Authentications by VLAN"
                  type  = "timeseries"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search = {
                            query = "service:radius-auth @event:Access-Accept ${local.radius_log_hosts_filter} @site_name:$site.value @vlan_id:$vlan.value -@vlan_id:\"\""
                          }
                          indexes = [
                            "*",
                          ]
                          compute = {
                            aggregation = "count"
                          }
                          group_by = [
                            {
                              facet = "@vlan_id"
                              limit = 20
                              sort = {
                                aggregation = "count"
                                order       = "desc"
                              }
                            },
                            {
                              facet                  = "@vlan_name"
                              limit                  = 20
                              should_exclude_missing = false
                              sort = {
                                aggregation = "count"
                                order       = "desc"
                              }
                            },
                          ]
                        },
                      ]
                      response_format = "timeseries"
                      formulas = [
                        {
                          formula = "query1"
                        },
                      ]
                      display_type = "bars"
                    },
                  ]
                }
              },
              {
                definition = {
                  title = "Verified Devices Seen by VLAN"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search = {
                            query = "service:(radius-auth OR radius-acct) ${local.radius_log_hosts_filter} @site_name:$site.value @vlan_id:$vlan.value -@vlan_id:\"\" @identity_verified:true"
                          }
                          indexes = [
                            "*",
                          ]
                          compute = {
                            aggregation = "cardinality"
                            metric      = "@device_id"
                          }
                          group_by = [
                            {
                              facet = "@vlan_id"
                              limit = 20
                              sort = {
                                aggregation = "cardinality"
                                order       = "desc"
                                metric      = "@device_id"
                              }
                            },
                            {
                              facet                  = "@vlan_name"
                              limit                  = 20
                              should_exclude_missing = false
                              sort = {
                                aggregation = "cardinality"
                                metric      = "@device_id"
                                order       = "desc"
                              }
                            },
                          ]
                        },
                      ]
                      response_format = "scalar"
                      formulas = [
                        {
                          formula = "query1"
                        },
                      ]
                    },
                  ]
                }
              },
              {
                definition = {
                  title = "Assignments by RADIUS Source / VLAN"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search = {
                            query = "service:radius-auth @event:Access-Accept ${local.radius_log_hosts_filter} @site_name:$site.value @vlan_id:$vlan.value -@vlan_id:\"\""
                          }
                          indexes = [
                            "*",
                          ]
                          compute = {
                            aggregation = "count"
                          }
                          group_by = [
                            {
                              facet = "@src_ip"
                              limit = 20
                              sort = {
                                aggregation = "count"
                                order       = "desc"
                              }
                            },
                            {
                              facet = "@vlan_id"
                              limit = 20
                              sort = {
                                aggregation = "count"
                                order       = "desc"
                              }
                            },
                            {
                              facet                  = "@vlan_name"
                              limit                  = 20
                              should_exclude_missing = false
                              sort = {
                                aggregation = "count"
                                order       = "desc"
                              }
                            },
                          ]
                        },
                      ]
                      response_format = "scalar"
                      formulas = [
                        {
                          formula = "query1"
                        },
                      ]
                    },
                  ]
                }
              },
              {
                definition = {
                  title = "Recent VLAN Authentication and Accounting"
                  type  = "log_stream"
                  indexes = [
                    "*",
                  ]
                  query = "service:(radius-auth OR radius-acct) ${local.radius_log_hosts_filter} @site_name:$site.value @vlan_id:$vlan.value -@vlan_id:\"\""
                  columns = [
                    "timestamp",
                    "@event",
                    "@vlan_id",
                    "@vlan_name",
                    "@site_name",
                    "@src_ip",
                    "@nas_ip",
                    "@device_id",
                    "@device_name",
                    "@device_owner",
                    "@identity_verified",
                    "@session_id",
                  ]
                  sort = {
                    column = "timestamp"
                    order  = "desc"
                  }
                  message_display = "inline"
                }
              },
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
                          search      = { query = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value @event:Access-Accept" }
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
                          search      = { query = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value @event:Access-Accept" }
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
                          search      = { query = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value @event:Access-Accept" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet                  = "@device_owner"
                              should_exclude_missing = false
                              limit                  = 20
                              sort                   = { aggregation = "count", order = "desc" }
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
                          search      = { query = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value @event:Access-Accept" }
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
                          search      = { query = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value @event:Access-Accept" }
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
                          search      = { query = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value @event:Access-Accept" }
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
              },
              {
                layout = { x = 0, y = 2, width = 12, height = 3 }
                definition = {
                  title       = "Top authenticators — successful auth"
                  description = "Successful authentications, not unique clients, grouped by site and AP name. Missing site or AP names are unresolved events; they remain visible in the chart."
                  type        = "sunburst"
                  hide_total  = false
                  legend      = { type = "table" }
                  requests = [{
                    queries = [{
                      data_source = "logs"
                      name        = "authenticators"
                      indexes     = ["*"]
                      search      = { query = "service:radius-auth ${local.radius_log_hosts_filter} @site_name:$site.value @event:Access-Accept" }
                      compute     = { aggregation = "count" }
                      group_by = [
                        { facet = "@site_name", limit = 10, should_exclude_missing = false, sort = { aggregation = "count", order = "desc" } },
                        { facet = "@ap_name", limit = 20, should_exclude_missing = false, sort = { aggregation = "count", order = "desc" } }
                      ]
                    }]
                    formulas = [{ formula = "authenticators" }]

                    response_format = "scalar"

                  }]
                }

              }
            ]
          }
        },

        local.datadog_usage_group,

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
                        { data_source = "metrics", name = "a", query = "sum:cloud8021x.radius.total_acct_requests{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius}.as_rate()" },
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "blue" }
                      formulas        = [{ formula = "a", alias = "Requests" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "c", query = "sum:cloud8021x.radius.total_acct_responses{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius}.as_rate()" },
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "green" }
                      formulas        = [{ formula = "c", alias = "Responses" }]
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
                          search      = { query = "service:radius-acct ${local.radius_log_hosts_filter} @site_name:$site.value @event:Acct-Start" }
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
                          search      = { query = "service:radius-acct ${local.radius_log_hosts_filter} @site_name:$site.value @event:Acct-Stop" }
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
                          search      = { query = "service:radius-acct ${local.radius_log_hosts_filter} @site_name:$site.value @event:Acct-Stop" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet                  = "@device_owner"
                              should_exclude_missing = false
                              limit                  = 20
                              sort                   = { aggregation = "avg", metric = "@session_time", order = "desc" }
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
                  title = "Session Termination Causes (blank = cause not recorded)"
                  type  = "toplist"
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "query1"
                          search      = { query = "service:radius-acct ${local.radius_log_hosts_filter} @site_name:$site.value @event:Acct-Stop" }
                          indexes     = ["*"]
                          group_by = [
                            {
                              facet                  = "@terminate_cause"
                              should_exclude_missing = false
                              limit                  = 10
                              sort                   = { aggregation = "count", order = "desc" }
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
                  title       = "Completed session counters (bytes, at stop)"
                  type        = "timeseries"
                  show_legend = true
                  requests = [
                    {
                      queries = [
                        {
                          data_source = "logs"
                          name        = "input"
                          search      = { query = "service:radius-acct ${local.radius_log_hosts_filter} @site_name:$site.value @event:Acct-Stop" }
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
                          search      = { query = "service:radius-acct ${local.radius_log_hosts_filter} @site_name:$site.value @event:Acct-Stop" }
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
                  requests = [for queue, label in { auth = "Auth", acct = "Acct", internal = "Internal" } : {
                    queries         = [{ data_source = "metrics", name = "depth", query = "max:cloud8021x.radius.queue_len_${queue}{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius} by {host}" }]
                    response_format = "timeseries"
                    display_type    = "line"
                    formulas        = [{ formula = "depth", alias = label }]
                  }]
                }
              },
              {
                definition = {
                  title       = "Incoming RADIUS requests / sec"
                  type        = "timeseries"
                  show_legend = true
                  requests = [for metric, label in { total_access_requests = "Access requests / sec", total_acct_requests = "Accounting requests / sec" } : {
                    queries         = [{ data_source = "metrics", name = "requests", query = "sum:cloud8021x.radius.${metric}{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius} by {host}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "line"
                    formulas        = [{ formula = "requests", alias = label }]
                  }]
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
                        { data_source = "metrics", name = "a", query = "sum:cloud8021x.radius.total_auth_malformed_requests{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius}.as_rate()" },
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "red" }
                      formulas        = [{ formula = "a", alias = "Malformed" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "c", query = "sum:cloud8021x.radius.total_auth_invalid_requests{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius}.as_rate()" },
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "orange" }
                      formulas        = [{ formula = "c", alias = "Invalid" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "e", query = "sum:cloud8021x.radius.total_auth_dropped_requests{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius}.as_rate()" },
                      ]
                      response_format = "timeseries"
                      display_type    = "bars"
                      style           = { palette = "yellow" }
                      formulas        = [{ formula = "e", alias = "Dropped" }]
                    },
                    {
                      queries = [
                        { data_source = "metrics", name = "g", query = "sum:cloud8021x.radius.total_auth_duplicate_requests{${local.radius_hosts_filter} AND service:cloud-8021x AND component:freeradius}.as_rate()" },
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      style           = { palette = "grey" }
                      formulas        = [{ formula = "g", alias = "Duplicate" }]
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
                        { data_source = "metrics", name = "cpu", query = "avg:system.cpu.user{${local.radius_hosts_filter}} by {host}" }
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
                        { data_source = "metrics", name = "used", query = "avg:system.mem.used{${local.radius_hosts_filter}} by {host}" },
                        { data_source = "metrics", name = "total", query = "avg:system.mem.total{${local.radius_hosts_filter}} by {host}" }
                      ]
                      response_format = "timeseries"
                      display_type    = "line"
                      formulas        = [{ formula = "(used / total) * 100" }]
                    }
                  ]
                }
              },
              local.freeradius_uptime_widget,
              {
                definition = {
                  title = "VM uptime by server (hours)"
                  type  = "query_table"
                  time  = { live_span = "5m" }
                  requests = [{
                    queries         = [{ data_source = "metrics", name = "uptime", query = "min:system.uptime{${local.radius_hosts_filter}} by {host}", aggregator = "last" }]
                    response_format = "scalar"
                    formulas        = [{ formula = "uptime / 3600", alias = "VM uptime (hours)", cell_display_mode = "number", number_format = { unit = { type = "custom_unit_label", label = "hours" } } }]
                  }]
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
                        { data_source = "metrics", name = "rx", query = "avg:system.net.bytes_rcvd{${local.radius_hosts_filter}} by {host}" }
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
                        { data_source = "metrics", name = "tx", query = "avg:system.net.bytes_sent{${local.radius_hosts_filter}} by {host}" }
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
                        { data_source = "metrics", name = "disk", query = "max:system.disk.in_use{${local.radius_hosts_filter}} by {host}" }
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

  # Explicit grid dimensions keep Overview compact; other groups retain the
  # preview's four-column arrangement. Include each group's header spacing.
  dashboard_group_heights = [
    for group in local.dashboard_content.widgets :
    group.definition.title == "Overview" ? 1 : group.definition.title == "Auth Diagnostics" ? 7 : contains(["Network Data Usage", "Network / Location"], group.definition.title) ? max([for widget in group.definition.widgets : try(widget.layout.y + widget.layout.height, 2)]...) : ceil(length(group.definition.widgets) / 4) * 2
  ]
  dashboard_json = merge(local.dashboard_content, {
    reflow_type = "fixed"
    widgets = [for index, group in local.dashboard_content.widgets : merge(group, {
      layout = {
        x      = 0
        y      = index + sum(concat([0], slice(local.dashboard_group_heights, 0, index)))
        width  = 12
        height = local.dashboard_group_heights[index]
      }
      definition = merge(group.definition, {
        widgets = [for position, widget in group.definition.widgets : merge(widget, {
          layout = try(widget.layout, {
            x      = (position % 4) * 3
            y      = floor(position / 4) * 2
            width  = 3
            height = 2
          })
        })]
      })
    })]
  })
}

resource "datadog_dashboard_json" "radius" {
  count     = local.datadog_enabled ? 1 : 0
  dashboard = jsonencode(local.dashboard_json)
}
