locals {
  monitor_hosts_filter     = "(${join(" OR ", [for host in values(local.datadog_radius_hosts) : "host:${host}"])})"
  monitor_log_hosts_filter = local.monitor_hosts_filter
  datadog_enabled          = "explicit-observability-owner" != ""
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
  datadog_hostname_suffix = var.datadog_hostname_suffix == null ? var.project_id : var.datadog_hostname_suffix
  datadog_radius_hosts = var.datadog_observability_hosts != null ? { for host in var.datadog_observability_hosts : host => host } : {
    for instance_name in ["radius-primary", "radius-secondary"] :
    instance_name => local.datadog_hostname_suffix == "" ? instance_name : "${instance_name}-${local.datadog_hostname_suffix}"
  }
}
variable "datadog_observability_hosts" {
  description = "Reviewed exact physical hosts admitted by the observability owner. Null preserves the legacy pair; explicitly list two green hosts or four blue+green hosts for deliberate staging."
  type        = set(string)
  validation {
    condition     = var.datadog_observability_hosts == null ? true : (contains([2, 4], length(var.datadog_observability_hosts)) && alltrue([for host in var.datadog_observability_hosts : length(host) <= 253 && can(regex("^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", host))]))
    error_message = "Admit exactly two or four reviewed physical DNS hostnames; no wildcard, query syntax or implicit deployments."
  }
  nullable = false
}
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
locals {
  smallstep_datadog_enabled = local.datadog_enabled && var.enable_smallstep_ca

  # One explicitly scoped card per physical host: never let a blue healthy
  # instance conceal an absent/failing green peer at the default * selection.
  stepca_health_widgets = flatten([for host in sort(values(local.datadog_radius_hosts)) : [
    { definition = { title = "${host}: EC CA Health", type = "check_status", check = "http.can_connect", grouping = "cluster", group_by = ["host"], tags = ["service:smallstep-ca", "instance:stepca_health", "ca_instance:ec", "host:${host}", "$host"] } },
    { definition = { title = "${host}: RSA CA Health", type = "check_status", check = "http.can_connect", grouping = "cluster", group_by = ["host"], tags = ["service:smallstep-ca", "instance:stepca_rsa_health", "ca_instance:rsa", "host:${host}", "$host"] } },
    { definition = { title = "${host}: step-ca Processes", type = "check_status", check = "process.up", grouping = "cluster", group_by = ["host"], tags = ["service:smallstep-ca", "process:step-ca", "host:${host}", "$host"] } }
  ]])

  smallstep_dashboard_json = {
    title       = "Smallstep step-ca (Wi-Fi CA)"
    description = "Self-hosted step-ca: issuance by provisioner (ACME/SCEP), KMS, health, cert expiry, and logs."
    layout_type = "ordered"
    template_variables = [
      {
        name             = "host"
        prefix           = "host"
        available_values = sort(values(local.datadog_radius_hosts))
        defaults         = ["*"]
      },
      {
        # Break the two CA instances apart: EC (ACME, :8443/:9090) vs RSA
        # (SCEP-only, :8444/:9091). Both carry service:smallstep-ca, so the
        # issuance/KMS/expiry widgets aggregate both by default ($ca_instance=*);
        # select ec or rsa to isolate one.
        name             = "ca_instance"
        prefix           = "ca_instance"
        available_values = ["ec", "rsa"]
        defaults         = ["*"]
      }
    ]
    widgets = [
      # -----------------------------------------------------------------------
      # Overview
      # -----------------------------------------------------------------------
      {
        definition = {
          title       = "Overview"
          type        = "group"
          layout_type = "ordered"
          widgets = concat(local.stepca_health_widgets, [
            {
              definition = {
                title     = "SCEP Decrypter Ready"
                type      = "query_value"
                autoscale = false
                precision = 0
                requests = [
                  {
                    queries = [
                      { data_source = "metrics", name = "a", query = "min:cloud8021x.scep.decrypter_ready{${local.radius_hosts_filter} AND service:cloud-8021x AND component:step-ca AND ca_instance:rsa AND $ca_instance}", aggregator = "last" }
                    ]
                    response_format = "scalar"
                    formulas        = [{ formula = "a" }]
                    conditional_formats = [
                      { comparator = "<", value = 1, palette = "white_on_red" },
                      { comparator = ">=", value = 1, palette = "white_on_green" }
                    ]
                  }
                ]
              }
            },
            {
              definition = {
                title       = "CA Uptime (days)"
                type        = "query_value"
                autoscale   = false
                precision   = 1
                custom_unit = "days"
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "max:smallstep.uptime{${local.radius_hosts_filter} AND service:smallstep-ca AND $ca_instance}", aggregator = "last" }]
                    response_format = "scalar"
                    formulas        = [{ formula = "a / 86400" }]
                  }
                ]
              }
            },
            {
              definition = {
                title     = "Certs Signed / min (all provisioners)"
                type      = "query_value"
                autoscale = true
                precision = 1
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.x509.signed.count{${local.radius_hosts_filter} AND service:smallstep-ca AND $ca_instance}.as_rate()", aggregator = "avg" }]
                    response_format = "scalar"
                    formulas        = [{ formula = "a * 60" }]
                  }
                ]
              }
            }
          ])
        }
      },

      # -----------------------------------------------------------------------
      # Issuance by provisioner (ACME vs SCEP)
      # -----------------------------------------------------------------------
      {
        definition = {
          # EC (ACME wifi-acme + SCEP wifi-scep) and RSA (SCEP wifi-scep only)
          # are combined here; filter with $ca_instance or read the
          # by {ca_instance} breakdown on the signed-by-provisioner widgets.
          title       = "Issuance"
          type        = "group"
          layout_type = "ordered"
          widgets = [
            {
              definition = {
                title       = "Certificates Signed by Provisioner"
                type        = "timeseries"
                show_legend = true
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.x509.signed.count{${local.radius_hosts_filter} AND service:smallstep-ca AND $ca_instance} by {provisioner,ca_instance}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "bars"
                    formulas        = [{ formula = "a", alias = "signed" }]
                  }
                ]
              }
            },
            {
              definition = {
                # Was "Renewed + Rekeyed by Provisioner", built on
                # smallstep.provisioner.renewed / .rekeyed. Neither metric
                # exists — step-ca has no renewed/rekeyed counter in this
                # build — so the widget was blank from the day it shipped. The
                # signal the x509 counters DO carry is the success label: a
                # rising success:false series is issuance failing at the CA,
                # which the signed-rate widget above cannot show.
                title       = "Issuance Outcome by Provisioner"
                type        = "timeseries"
                show_legend = true
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.x509.signed.count{${local.radius_hosts_filter} AND service:smallstep-ca AND $ca_instance} by {provisioner,success}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "line"
                    style           = { palette = "cool" }
                    formulas        = [{ formula = "a" }]
                  }
                ]
              }
            },
            {
              definition = {
                title = "Total Signed by Provisioner (window)"
                type  = "toplist"
                requests = [
                  {
                    queries = [
                      { data_source = "metrics", name = "a", query = "sum:smallstep.x509.signed.count{${local.radius_hosts_filter} AND service:smallstep-ca AND $ca_instance} by {provisioner,ca_instance}.as_count()", aggregator = "sum" }
                    ]
                    response_format = "scalar"
                    formulas        = [{ formula = "a" }]
                  }
                ]
              }
            }
          ]
        }
      },

      # -----------------------------------------------------------------------
      # ACME authorizing webhook + KMS
      # -----------------------------------------------------------------------
      {
        definition = {
          title       = "Webhook & KMS"
          type        = "group"
          layout_type = "ordered"
          widgets = [
            {
              definition = {
                title       = "ACME Authorizing Webhook Calls"
                type        = "timeseries"
                show_legend = true
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.x509.webhook_authorized.count{${local.radius_hosts_filter} AND service:smallstep-ca AND $ca_instance} by {provisioner}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "bars"
                    formulas        = [{ formula = "a", alias = "authorized" }]
                  }
                ]
              }
            },
            {
              definition = {
                title       = "KMS Signatures vs Errors"
                type        = "timeseries"
                show_legend = true
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.kms.signed.count{${local.radius_hosts_filter} AND service:smallstep-ca AND $ca_instance}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "line"
                    style           = { palette = "green" }
                    formulas        = [{ formula = "a", alias = "signed" }]
                  },
                  {
                    queries         = [{ data_source = "metrics", name = "b", query = "sum:smallstep.kms.errors.count{${local.radius_hosts_filter} AND service:smallstep-ca AND $ca_instance}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "bars"
                    style           = { palette = "red" }
                    formulas        = [{ formula = "b", alias = "errors" }]
                  }
                ]
              }
            }
          ]
        }
      },

      # -----------------------------------------------------------------------
      # Certificate expiry
      # -----------------------------------------------------------------------
      {
        definition = {
          # Both CA instances emit cloud8021x.certificate.days_until_expiry; EC and RSA
          # are combined (min across both) unless $ca_instance is set. The trend
          # widget breaks them out by {cert,ca_instance}.
          title       = "Certificate Expiry"
          type        = "group"
          layout_type = "ordered"
          widgets = [
            {
              definition = {
                title       = "Intermediate CA — days until expiry"
                type        = "query_value"
                autoscale   = false
                precision   = 0
                custom_unit = "days"
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "min:cloud8021x.certificate.days_until_expiry{${local.radius_hosts_filter} AND service:cloud-8021x AND component:step-ca AND cert:intermediate AND $ca_instance}", aggregator = "last" }]
                    response_format = "scalar"
                    formulas        = [{ formula = "a" }]
                    conditional_formats = [
                      { comparator = "<", value = 30, palette = "white_on_red" },
                      { comparator = "<", value = 90, palette = "white_on_yellow" },
                      { comparator = ">=", value = 90, palette = "white_on_green" }
                    ]
                  }
                ]
              }
            },
            {
              definition = {
                title       = "SCEP Decrypter — days until expiry"
                type        = "query_value"
                autoscale   = false
                precision   = 0
                custom_unit = "days"
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "min:cloud8021x.certificate.days_until_expiry{${local.radius_hosts_filter} AND service:cloud-8021x AND component:step-ca AND cert:decrypter AND $ca_instance}", aggregator = "last" }]
                    response_format = "scalar"
                    formulas        = [{ formula = "a" }]
                    conditional_formats = [
                      { comparator = "<", value = 30, palette = "white_on_red" },
                      { comparator = "<", value = 90, palette = "white_on_yellow" },
                      { comparator = ">=", value = 90, palette = "white_on_green" }
                    ]
                  }
                ]
              }
            },
            {
              definition = {
                title       = "Cert expiry trend"
                type        = "timeseries"
                show_legend = true
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "min:cloud8021x.certificate.days_until_expiry{${local.radius_hosts_filter} AND service:cloud-8021x AND component:step-ca AND $ca_instance} by {cert,ca_instance}" }]
                    response_format = "timeseries"
                    display_type    = "line"
                    formulas        = [{ formula = "a" }]
                  }
                ]
              }
            }
          ]
        }
      },

      # -----------------------------------------------------------------------
      # Logs
      # -----------------------------------------------------------------------
      {
        definition = {
          title       = "Logs"
          type        = "group"
          layout_type = "ordered"
          widgets = [
            {
              definition = {
                title           = "step-ca request log"
                type            = "log_stream"
                indexes         = ["*"]
                query           = "service:smallstep-ca ${local.radius_log_hosts_filter}"
                columns         = ["timestamp", "host", "@status", "@method", "@path", "@request-id"]
                sort            = { column = "timestamp", order = "desc" }
                message_display = "inline"
              }
            },
            {
              definition = {
                title           = "Errors / warnings"
                type            = "log_stream"
                indexes         = ["*"]
                query           = "service:smallstep-ca ${local.radius_log_hosts_filter} (status:error OR status:warn OR @level:error OR @level:warn)"
                columns         = ["timestamp", "host", "@level", "@msg", "@error"]
                sort            = { column = "timestamp", order = "desc" }
                message_display = "expanded-md"
              }
            }
          ]
        }
      }
    ]
  }
}
resource "datadog_dashboard_json" "smallstep" {
  count     = local.smallstep_datadog_enabled ? 1 : 0
  dashboard = jsonencode(local.smallstep_dashboard_json)
}
locals {
  dd_notify = var.datadog_monitor_notify != "" ? "\n\n${var.datadog_monitor_notify}" : ""
}
resource "datadog_monitor" "stepca_health" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep step-ca /health failing"
  type    = "service check"
  query   = "\"http.can_connect\".over(\"instance:stepca_health\",\"service:smallstep-ca\",\"ca_instance:ec\").by(\"host\").last(3).count_by_status()"
  message = "step-ca /health is failing on {{host.name}} — the Wi-Fi CA is unreachable on this node. EAP-TLS issuance (ACME + SCEP) may be degraded; check `systemctl status step-ca`.${local.dd_notify}"
  monitor_thresholds {
    critical = 2
    warning  = 1
    ok       = 1
  }
  notify_no_data    = true
  no_data_timeframe = 10
  tags              = ["service:smallstep-ca", "ca_instance:ec", "managed-by:terraform"]
}
resource "datadog_monitor" "stepca_rsa_health" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep step-ca-rsa /health failing"
  type    = "service check"
  query   = "\"http.can_connect\".over(\"instance:stepca_rsa_health\",\"service:smallstep-ca\",\"ca_instance:rsa\").by(\"host\").last(3).count_by_status()"
  message = "step-ca-rsa /health is failing on {{host.name}} — the RSA SCEP CA (Windows + non-ADE Mac Wi-Fi certs) is unreachable on this node. SCEP issuance may be degraded; check `systemctl status step-ca-rsa`.${local.dd_notify}"
  monitor_thresholds {
    critical = 2
    warning  = 1
    ok       = 1
  }
  notify_no_data    = true
  no_data_timeframe = 10
  tags              = ["service:smallstep-ca", "ca_instance:rsa", "managed-by:terraform"]
}
resource "datadog_monitor" "stepca_process" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep step-ca process down"
  type    = "service check"
  query   = "\"process.up\".over(\"process:step-ca\",\"service:smallstep-ca\").by(\"host\").last(3).count_by_status()"
  message = "The step-ca process is not running on {{host.name}}. Restart with `systemctl restart step-ca`.${local.dd_notify}"
  monitor_thresholds {
    critical = 2
    warning  = 1
    ok       = 1
  }
  notify_no_data    = true
  no_data_timeframe = 10
  tags              = ["service:smallstep-ca", "managed-by:terraform"]
}
resource "datadog_monitor" "stepca_decrypter" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep SCEP decrypter not initialized"
  type    = "metric alert"
  query   = "min(last_10m):min:cloud8021x.scep.decrypter_ready{${local.monitor_hosts_filter} AND service:cloud-8021x AND component:step-ca AND ca_instance:rsa} by {host,ca_instance} < 1"
  message = "step-ca on {{host.name}} is running but its SCEP decrypter failed to initialize — every Windows SCEP PKIOperation will return HTTP 500 and no Wi-Fi certs will issue. Inspect the protected doctor output and step-ca-rsa logs; verify the preserved decrypterKeyPEM/decrypterCertificate pair and trust before a guarded repair.${local.dd_notify}"
  monitor_thresholds {
    critical = 1
  }
  notify_no_data = false
  tags           = ["service:smallstep-ca", "managed-by:terraform"]
}
resource "datadog_monitor" "stepca_cert_expiry" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep CA certificate nearing expiry"
  type    = "metric alert"
  query   = "min(last_1h):min:cloud8021x.certificate.days_until_expiry{${local.monitor_hosts_filter} AND service:cloud-8021x AND component:step-ca} by {host,cert,ca_instance} < 14"
  message = "The {{ca_instance.name}} {{cert.name}} certificate on {{host.name}} is nearing expiry (warning <30 days, critical <14 days). Re-issue it (intermediate is KMS-backed; the SCEP decrypter is the shared software RSA key) before EAP-TLS breaks.${local.dd_notify}"
  monitor_thresholds {
    critical = 14
    warning  = 30
  }
  notify_no_data = false
  tags           = ["service:smallstep-ca", "managed-by:terraform"]
}
resource "datadog_monitor" "stepca_kms_errors" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep CA KMS errors"
  type    = "metric alert"
  query   = "sum(last_15m):sum:smallstep.kms.errors.count{${local.monitor_hosts_filter} AND service:smallstep-ca}.as_count() > 5"
  message = "step-ca is hitting Cloud KMS errors (>5 in 15m) — the HSM-backed signing key may be unavailable or rate-limited, which blocks all certificate issuance.${local.dd_notify}"
  monitor_thresholds {
    critical = 5
    warning  = 1
  }
  notify_no_data = false
  tags           = ["service:smallstep-ca", "managed-by:terraform"]
}
resource "datadog_monitor" "radius_down" {
  count   = local.datadog_enabled ? 1 : 0
  name    = "FreeRADIUS down (no server reporting up)"
  type    = "metric alert"
  query   = "max(last_5m):max:cloud8021x.backend.up{${local.monitor_hosts_filter} AND service:cloud-8021x AND component:freeradius} < 1"
  message = "No FreeRADIUS server is reporting healthy — 802.1X Wi-Fi authentication is down network-wide. Check the reviewed physical hosts: ${join(", ", values(local.datadog_radius_hosts))}.${local.dd_notify}"
  monitor_thresholds {
    critical = 1
  }
  notify_no_data    = true
  no_data_timeframe = 15
  tags              = ["service:radius", "managed-by:terraform"]
}
resource "datadog_monitor" "radius_no_accepts" {
  count   = local.datadog_enabled ? 1 : 0
  name    = "FreeRADIUS no Access-Accepts"
  type    = "log alert"
  query   = "logs(\"service:radius-auth ${local.monitor_log_hosts_filter} @event:Access-Accept\").index(\"*\").rollup(\"count\").last(\"4h\") <= 0"
  message = "FreeRADIUS has logged zero Access-Accept events in the last 4 hours. During business hours this points to a broken auth path (cert trust, RADIUS config) with the daemon still up; overnight it can be normal (PMK caching means few full re-auths). Cross-check `radius_down`. (Source: the radius-auth log, NOT freeradius.total_access_accepts — that counter is always 0 under EAP-TLS.)${local.dd_notify}"
  monitor_thresholds {
    critical = 0
  }
  notify_no_data = false
  tags           = ["service:radius", "managed-by:terraform"]
}
resource "datadog_monitor" "radius_server_cert_expiry" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "FreeRADIUS server certificate nearing expiry"
  type    = "metric alert"
  query   = "min(last_4h):min:cloud8021x.certificate.days_until_expiry{${local.monitor_hosts_filter} AND service:cloud-8021x AND component:freeradius AND cert:server AND ca_instance:ec} by {host} < 14"
  message = "The RADIUS EAP-TLS server certificate on {{host.name}} has {{value}} days remaining (warning <25, critical <14). Inspect `cloud-8021x --config /etc/cloud-8021x/config.yaml doctor`, then use the protected `cloud-8021x --config /etc/cloud-8021x/config.yaml certificates renew` workflow after resolving peer, CA and authority failures. Inspect `journalctl -u cloud-8021x`. An expired leaf can break Wi-Fi while the process remains healthy. NO DATA means certificate observation or telemetry is unavailable; do not infer a valid certificate.${local.dd_notify}"
  monitor_thresholds {
    critical = 14
    warning  = 25
  }
  notify_no_data    = true
  no_data_timeframe = 720

  # Periodic observations may be sparse during recovery; keep evaluation
  # independent of a densely populated four-hour window.
  require_full_window = false

  tags = ["service:radius", "managed-by:terraform"]
}
resource "datadog_monitor" "radius_client_cert_expiring" {
  count = local.smallstep_datadog_enabled ? 1 : 0
  name  = "EAP-TLS client certificates nearing expiry"
  type  = "metric alert"

  # Both nodes read the shared verified observations of recently authenticated clients.
  # This is not full issued/offline CA inventory; no CA database grant is required.
  # Max across replicas, never sum; unknown provenance emits no guessed zero.
  query   = "max(last_4h):max:cloud8021x.client_certificate.expiring_soon{${local.monitor_hosts_filter} AND service:cloud-8021x AND component:freeradius AND window:48h AND scope:shared} > 10"
  message = "{{value}} recently authenticated client certificate(s) expire within 48 hours (warning >0, critical >10). Nothing renews these automatically — an expired client cert is a per-device Wi-Fi lockout that FreeRADIUS reports only as `eap_tls: (TLS) OpenSSL says error 10 : certificate has expired`. Force a re-issue by re-pushing the Campus Wi-Fi ACME profile to the affected hosts from fleet-gitops; inspect verified recent authentication observations and the 48h renewal window. This count does not cover all issued certificates or offline clients. NO DATA means verified recent-client observations or telemetry are unavailable; inspect `cloud-8021x --config /etc/cloud-8021x/config.yaml doctor` and `journalctl -u cloud-8021x`.${local.dd_notify}"

  monitor_thresholds {
    critical = 10
    warning  = 0
  }

  notify_no_data    = true
  no_data_timeframe = 720

  # Periodic observations need not fill every point in the four-hour window;
  # retain the original sparse/no-data evaluation behavior.
  require_full_window = false

  tags = ["service:radius", "managed-by:terraform"]
}
resource "datadog_monitor" "radius_client_cert_expired" {
  count = local.datadog_enabled ? 1 : 0
  name  = "EAP-TLS client certificate expired (device locked out)"
  type  = "log alert"

  # Expired TLS certificates cannot establish a verified device identity. In
  # inventory mode count rejection events instead of silently dropping devices
  # without serials; this measures retries, not unique affected devices.
  query   = try(var.radius_vlan_policy.certificate_inventory, false) ? "logs(\"service:radius-auth ${local.monitor_log_hosts_filter} @event:Access-Reject @reject_reason:\\\"*certificate has expired*\\\"\").index(\"*\").rollup(\"count\").last(\"1h\") > 5" : "logs(\"service:radius-auth ${local.monitor_log_hosts_filter} @event:Access-Reject @reject_reason:\\\"*certificate has expired*\\\"\").index(\"*\").rollup(\"cardinality\", \"@serial\").last(\"1h\") > 5"
  message = try(var.radius_vlan_policy.certificate_inventory, false) ? "{{value}} RADIUS rejection event(s) in the last hour presented an EXPIRED client certificate (warning >0, critical >5). This counts retries, not unique devices: expired TLS cannot establish a verified device identity. Inspect the matching logs by calling_station, src_ip and site_name; raw_identity and cert_cn are unverified diagnostic claims. Correlate with Fleet certificate inventory and re-deliver the affected Wi-Fi profile. Cross-check radius_client_cert_expiring for a renewal wave.${local.dd_notify}" : "{{value}} device(s) were rejected by RADIUS in the last hour for presenting an EXPIRED client certificate — they have no Wi-Fi (warning >0, critical >5). Identify them with `@reject_reason:\"*certificate has expired*\"` grouped by `@serial`, then re-push the Campus Wi-Fi ACME profile from fleet-gitops to force a fresh cert. If this fires in numbers, cross-check `radius_client_cert_expiring` — a wave means the renewal path is broken fleet-wide, not that one device drifted.${local.dd_notify}"

  monitor_thresholds {
    critical = 5
    warning  = 0
  }

  notify_no_data = false
  tags           = ["service:radius", "managed-by:terraform"]
}
resource "datadog_monitor" "stepca_no_issuance" {
  count = local.smallstep_datadog_enabled && var.enable_acme_issuance_monitor ? 1 : 0
  name  = "Smallstep CA issuing no ACME certificates"
  type  = "metric alert"

  query   = "sum(last_24h):sum:smallstep.x509.signed.count{${local.monitor_hosts_filter} AND service:smallstep-ca AND ca_instance:ec AND provisioner:${var.smallstep_acme_provisioner_name}}.as_count() <= 0"
  message = "step-ca has signed zero wifi-acme certificates in 24 hours. With device renewal working this metric is never flat — a zero means devices have stopped ordering, and every EAP-TLS client cert in the fleet is now counting down to a lockout wave with no replacement coming. Check the ACME directory is reachable (`curl https://${var.smallstep_ca_dns_name}/acme/${var.smallstep_acme_provisioner_name}/directory`), then the authorizing webhook (`journalctl -u cloud-8021x`) for deny decisions.${local.dd_notify}"

  monitor_thresholds {
    critical = 0
  }

  notify_no_data      = true
  no_data_timeframe   = 1440
  require_full_window = false

  tags = ["service:smallstep-ca", "managed-by:terraform"]
}
resource "datadog_logs_custom_pipeline" "stepca" {
  count      = local.smallstep_datadog_enabled ? 1 : 0
  name       = "Smallstep step-ca"
  is_enabled = true

  filter {
    query = "source:stepca"
  }

  # 1. Parse JSON request lines into attributes, and text lines into date+msg.
  processor {
    grok_parser {
      name       = "step-ca grok"
      is_enabled = true
      source     = "message"
      # %%{ escapes Terraform template interpolation so the literal grok
      # token %{...} reaches Datadog. First matching rule wins: JSON lines
      # merge their keys to the event root; text lines yield text_date + text_msg.
      grok {
        support_rules = ""
        match_rules   = <<-GROK
          stepca_json %%{data::json}
          stepca_text %%{date("yyyy/MM/dd HH:mm:ss"):text_date}\s+%%{data:text_msg}
        GROK
      }
    }
  }

  # 1b. Explode the nested "response" attribute. step-ca's ACME/SCEP request
  #     logs carry the API response body as a JSON *string* in "response", which
  #     Datadog otherwise stores as one opaque string. %%{data:response:json}
  #     parses the WHOLE object recursively, so every key across all response
  #     shapes is surfaced under response.* automatically:
  #       - order:     id, status, expires, identifiers[].{type,value}, notBefore,
  #                    notAfter, authorizations[], finalize, certificate
  #       - authz:     identifier.{type,value}, status, challenges[].{type,status,
  #                    token,url}, wildcard, expires
  #       - challenge: type, status, token, validated, url
  #       - account:   status, orders
  #       - directory: newNonce, newAccount, newOrder, revokeCert, keyChange
  #     Non-JSON responses (some errors) simply don't match and pass through.
  processor {
    grok_parser {
      name       = "Parse nested response JSON"
      is_enabled = true
      source     = "response"
      grok {
        support_rules = ""
        # Named target ":response:json" nests the parsed keys under "response.*"
        # (response.status, response.identifier.value, response.expires, ...).
        # An UNNAMED %%{data::json} would merge to the event root and collide
        # with the top-level "status" (HTTP status) field.
        match_rules = <<-GROK
          stepca_response %%{data:response:json}
        GROK
      }
    }
  }

  # 1c. Unify the attested device serial into a single facetable attribute.
  #     The permanent-identifier (device serial) appears in TWO shapes depending
  #     on the ACME endpoint:
  #       - order responses:  response.identifiers[0].value  (array, plural)
  #       - authz responses:  response.identifier.value      (object, singular)
  #     Remap both into response.serial so you can facet/group on one field.
  #     attribute_remapper takes the first source present, so a given log line
  #     (only ever one shape) maps cleanly.
  processor {
    attribute_remapper {
      name                 = "Unify response serial"
      is_enabled           = true
      sources              = ["response.identifier.value", "response.identifiers.0.value"]
      source_type          = "attribute"
      target               = "response.serial"
      target_type          = "attribute"
      preserve_source      = true
      override_on_conflict = false
    }
  }

  # 2. Official timestamp: prefer the JSON "time" field, else the text date.
  processor {
    date_remapper {
      name       = "Define event timestamp"
      is_enabled = true
      sources    = ["time", "text_date"]
    }
  }

  # 3. Clean message: for text lines use the stripped message; JSON lines keep
  #    their "msg" (often empty for request logs — the attributes carry signal).
  processor {
    message_remapper {
      name       = "Define message"
      is_enabled = true
      sources    = ["text_msg", "msg"]
    }
  }

  # 4. Log status from step-ca's level (info/warn/error).
  processor {
    status_remapper {
      name       = "Define status from level"
      is_enabled = true
      sources    = ["level"]
    }
  }

  # 5. Map HTTP status to a standard attribute for faceting/coloring.
  processor {
    attribute_remapper {
      name                 = "Map status -> http.status_code"
      is_enabled           = true
      sources              = ["status"]
      source_type          = "attribute"
      target               = "http.status_code"
      target_type          = "attribute"
      preserve_source      = true
      override_on_conflict = false
    }
  }
}
variable "datadog_usage_sites" {
  description = "Per-site accounting/usage counter tiles: display label => exact site_name in logs. Empty shows all sites together."
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for label, site in var.datadog_usage_sites : trimspace(label) != "" && trimspace(site) != ""])
    error_message = "Site labels and log site names must be nonempty."
  }
}
locals {
  usage_counter_sites   = length(var.datadog_usage_sites) == 0 ? { "All sites" = "*" } : var.datadog_usage_sites
  usage_counter_columns = min(4, length(local.usage_counter_sites))
  usage_counter_rows    = ceil(length(local.usage_counter_sites) / local.usage_counter_columns)
  accounting_filter     = "service:radius-acct ${local.radius_log_hosts_filter} @site_name:$site.value"
  usage_preview_filter  = ""
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
            content          = "**Usage:** Upload/download are from the device’s perspective. The shared PostgreSQL ledger deduplicates accounting reports and is authoritative for exact totals. These dashboard totals are observed telemetry: downstream at-least-once delivery can duplicate intervals, and stable IDs do not deduplicate sums. Totals follow the network’s accounting report cadence; throughput is an interval average. Missing baselines or counter resets leave gaps. N/A measured-client coverage means no measured interval.\n\nEarlier usage is not reconstructed. The Go daemon emits committed PostgreSQL intervals through the local durable OTLP collector."
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

variable "project_id" { type = string }
variable "datadog_site" { type = string }
variable "datadog_monitor_notify" { type = string }
variable "enable_smallstep_ca" { type = bool }
variable "enable_acme_issuance_monitor" { type = bool }
variable "smallstep_ca_dns_name" { type = string }
variable "smallstep_acme_provisioner_name" { type = string }
variable "radius_vlan_policy" { type = object({ certificate_inventory = bool }) }
