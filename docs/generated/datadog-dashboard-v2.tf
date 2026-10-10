# GENERATED FILE: regenerate with tools/dashboard sync; do not edit.
# DO NOT APPLY: this is a native HCL companion, not a roundtrip-equivalent dashboard.
# The root module intentionally retains datadog_dashboard_json.radius.
# This resource is disabled (count = 0); released provider 4.25.0 loses the options below.
# Native migration depends on https://github.com/DataDog/terraform-provider-datadog/pull/4225 being released and verified.
# Unsupported: $.widgets[1].definition.widgets[2].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[2].definition.widgets[1].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[2].definition.widgets[1].definition.requests[0].queries[0].group_by[1].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[2].definition.widgets[1].definition.requests[0].queries[1].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[2].definition.widgets[1].definition.requests[0].queries[1].group_by[1].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[2].definition.widgets[2].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[2].definition.widgets[2].definition.requests[0].queries[0].group_by[1].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[2].definition.widgets[2].definition.requests[0].queries[0].group_by[2].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[3].definition.widgets[1].definition.requests[0].queries[0].group_by[1].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[3].definition.widgets[2].definition.requests[0].queries[0].group_by[1].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[3].definition.widgets[3].definition.requests[0].queries[0].group_by[2].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[4].definition.widgets[2].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[5].definition.widgets[3].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[5].definition.widgets[3].definition.requests[0].queries[0].group_by[1].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[6].definition.widgets[6].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[6].definition.widgets[6].definition.requests[0].queries[1].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[6].definition.widgets[9].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[6].definition.widgets[9].definition.requests[0].queries[0].group_by[1].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[6].definition.widgets[9].definition.requests[0].queries[0].group_by[2].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[6].definition.widgets[9].definition.requests[0].queries[1].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[6].definition.widgets[9].definition.requests[0].queries[1].group_by[1].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[6].definition.widgets[9].definition.requests[0].queries[1].group_by[2].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[7].definition.widgets[2].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Unsupported: $.widgets[7].definition.widgets[3].definition.requests[0].queries[0].group_by[0].should_exclude_missing = false (native logs group_by schema cannot express missing-bucket inclusion)
# Provider serialization: $.template_variables[0].available_values (empty variable choices are retained in HCL but omitted by provider JSON serialization)
# Provider serialization: $.template_variables[1].available_values (empty variable choices are retained in HCL but omitted by provider JSON serialization)
# Provider serialization: $.widgets[5].definition.widgets[3].definition.hide_total (modeled false is retained in HCL but omitted by provider JSON serialization)

resource "datadog_dashboard_v2" "radius_native_companion" {
  count       = 0
  description = "RADIUS authentication, assigned VLANs, devices, accounting, and infrastructure. The VLAN filter applies to the VLAN Assignments section; other sections retain unassigned and rejected events."
  layout_type = "ordered"
  reflow_type = "fixed"
  template_variable {
    available_values = []
    defaults         = ["*"]
    name             = "vlan"
    prefix           = "@vlan_id"
  }
  template_variable {
    available_values = []
    defaults         = ["*"]
    name             = "site"
    prefix           = "@site_name"
  }
  template_variable {
    available_values = ["radius-primary", "radius-secondary"]
    defaults         = ["*"]
    name             = "host"
    prefix           = "host"
  }
  title = "FreeRADIUS 802.1X"
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "Overview"
      widget {
        query_value_definition {
          autoscale = false
          live_span = "5m"
          precision = 0
          request {
            conditional_formats {
              comparator = "<"
              palette    = "white_on_red"
              value      = 1
            }
            conditional_formats {
              comparator = "="
              palette    = "white_on_yellow"
              value      = 1
            }
            conditional_formats {
              comparator = ">="
              palette    = "white_on_green"
              value      = 2
            }
            formula {
              formula_expression = "count_nonzero(online)"
            }
            query {
              metric_query {
                aggregator  = "last"
                data_source = "metrics"
                name        = "online"
                query       = "max:cloud8021x.backend.up{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius} by {host}.fill(last,60)"
              }
            }
          }
          title = "RADIUS servers online"
        }
        widget_layout {
          height = 1
          width  = 2
          x      = 0
          y      = 0
        }
      }
      widget {
        query_value_definition {
          autoscale = true
          precision = 1
          request {
            formula {
              formula_expression = "(a) * 60"
            }
            query {
              metric_query {
                aggregator  = "avg"
                data_source = "metrics"
                name        = "a"
                query       = "sum:cloud8021x.radius.total_access_requests{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius}.as_rate()"
              }
            }
          }
          title = "Auth Requests / min"
        }
        widget_layout {
          height = 1
          width  = 3
          x      = 2
          y      = 0
        }
      }
      widget {
        query_value_definition {
          autoscale = true
          precision = 0
          request {
            conditional_formats {
              comparator = ">"
              palette    = "white_on_green"
              value      = 0
            }
            formula {
              formula_expression = "default_zero(a)"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                name        = "a"
                search {
                  query = "service:radius-auth @event:Access-Accept host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value"
                }
              }
            }
          }
          title = "Accepts"
        }
        widget_layout {
          height = 1
          width  = 2
          x      = 5
          y      = 0
        }
      }
      widget {
        query_value_definition {
          autoscale = true
          precision = 0
          request {
            conditional_formats {
              comparator = ">"
              palette    = "white_on_yellow"
              value      = 0
            }
            formula {
              formula_expression = "default_zero(a)"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                name        = "a"
                search {
                  query = "service:radius-auth @event:Access-Reject host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value"
                }
              }
            }
          }
          title = "Rejects"
        }
        widget_layout {
          height = 1
          width  = 2
          x      = 7
          y      = 0
        }
      }
      widget {
        query_value_definition {
          autoscale   = false
          custom_unit = "%"
          precision   = 1
          request {
            conditional_formats {
              comparator = ">="
              palette    = "white_on_green"
              value      = 99
            }
            conditional_formats {
              comparator = ">="
              palette    = "white_on_yellow"
              value      = 95
            }
            conditional_formats {
              comparator = "<"
              palette    = "white_on_red"
              value      = 95
            }
            formula {
              formula_expression = "(default_zero(a) / (default_zero(a) + default_zero(c))) * 100"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                name        = "a"
                search {
                  query = "service:radius-auth @event:Access-Accept host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                name        = "c"
                search {
                  query = "service:radius-auth @event:Access-Reject host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value"
                }
              }
            }
          }
          title = "Auth Success Rate"
        }
        widget_layout {
          height = 1
          width  = 3
          x      = 9
          y      = 0
        }
      }
    }
    widget_layout {
      height = 1
      width  = 12
      x      = 0
      y      = 0
    }
  }
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "Authentication"
      widget {
        timeseries_definition {
          request {
            display_type = "bars"
            formula {
              alias              = "Accepts"
              formula_expression = "a"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                name        = "a"
                search {
                  query = "service:radius-auth @event:Access-Accept host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value"
                }
              }
            }
            style {
              palette = "green"
            }
          }
          request {
            display_type = "bars"
            formula {
              alias              = "Rejects"
              formula_expression = "c"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                name        = "c"
                search {
                  query = "service:radius-auth @event:Access-Reject host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value"
                }
              }
            }
            style {
              palette = "red"
            }
          }
          request {
            display_type = "line"
            formula {
              alias              = "Challenges"
              formula_expression = "e"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "e"
                query       = "sum:cloud8021x.radius.total_access_challenges{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius}.as_rate()"
              }
            }
            style {
              palette = "orange"
            }
          }
          show_legend = true
          title       = "Accepts vs Rejects"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 0
        }
      }
      widget {
        log_stream_definition {
          columns         = ["timestamp", "@event", "@device_id", "@serial", "@certificate_fingerprint", "@vlan_id", "@vlan_name", "@device_owner", "@device_name", "@ssid", "@site_name", "@ap_name"]
          indexes         = ["*"]
          message_display = "inline"
          query           = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value"
          sort {
            column = "timestamp"
            order  = "desc"
          }
          title = "Recent Auth Events"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@reject_reason"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Reject"
                }
              }
            }
          }
          title = "Reject Reasons (blank = reason not recorded)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 0
        }
      }
    }
    widget_layout {
      height = 2
      width  = 12
      x      = 0
      y      = 2
    }
  }
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "Auth Diagnostics"
      widget {
        note_definition {
          background_color = "white"
          content          = "Reject attempts include retries; affected clients count station addresses per source/site, excluding missing addresses. Private addresses may change, and blank site labels can split buckets. Open an affected-client row’s ‘View latest successful authentication’ link for successes, newest first; widen the Logs window for older events. Claimed identity is unverified. Owner/device details require verified enrichment."
          font_size        = "14"
          show_tick        = false
          text_align       = "left"
        }
        widget_layout {
          height = 1
          width  = 12
          x      = 0
          y      = 0
        }
      }
      widget {
        query_table_definition {
          has_search_bar = "always"
          request {
            formula {
              alias              = "Reject attempts"
              cell_display_mode  = "number"
              formula_expression = "rejects"
            }
            formula {
              alias              = "Distinct affected clients"
              cell_display_mode  = "number"
              formula_expression = "clients"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@src_ip"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@site_name"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "rejects"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Reject"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "cardinality"
                  metric      = "@calling_station"
                }
                data_source = "logs"
                group_by {
                  facet = "@src_ip"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@site_name"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "clients"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Reject @src_ip:* -@src_ip:\"\" @calling_station:* -@calling_station:\"\""
                }
              }
            }
            sort {
              count = 100
              order_by {
                formula_sort {
                  index = 0
                  order = "desc"
                }
              }
            }
          }
          title = "Reject attempts vs affected clients by RADIUS source / site"
        }
        widget_layout {
          height = 3
          width  = 6
          x      = 0
          y      = 1
        }
      }
      widget {
        query_table_definition {
          custom_link {
            label = "View latest successful authentication"
            link  = "/logs?query=service:radius-auth (host:radius-primary OR host:radius-secondary) @event:Access-Accept {{@src_ip}} {{@calling_station}}&stream_sort=time%2Cdesc&viz=stream&from_ts={{timestamp_start}}&to_ts={{timestamp_end}}&live=false"
          }
          has_search_bar = "always"
          request {
            formula {
              alias              = "Reject attempts"
              cell_display_mode  = "number"
              formula_expression = "rejects"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@src_ip"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@calling_station"
                  limit = 50
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "rejects"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Reject @src_ip:* -@src_ip:\"\" @calling_station:* -@calling_station:\"\""
                }
              }
            }
            sort {
              count = 100
              order_by {
                formula_sort {
                  index = 0
                  order = "desc"
                }
              }
            }
          }
          title = "Affected clients — reject attempts (open row for latest successful auth)"
        }
        widget_layout {
          height = 3
          width  = 6
          x      = 6
          y      = 1
        }
      }
      widget {
        log_stream_definition {
          columns         = ["timestamp", "@src_ip", "@calling_station", "@site_name", "@ap_name", "@reject_reason", "@raw_identity"]
          indexes         = ["*"]
          message_display = "inline"
          query           = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Reject"
          sort {
            column = "timestamp"
            order  = "desc"
          }
          title = "Recent rejected clients — claimed identity is unverified"
        }
        widget_layout {
          height = 3
          width  = 6
          x      = 0
          y      = 4
        }
      }
      widget {
        log_stream_definition {
          columns         = ["timestamp", "@src_ip", "@calling_station", "@site_name", "@ap_name", "@identity_verified", "@device_owner", "@device_name", "@device_id"]
          indexes         = ["*"]
          message_display = "inline"
          query           = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Accept"
          sort {
            column = "timestamp"
            order  = "desc"
          }
          title = "Successful authentications — newest first (verified details when available)"
        }
        widget_layout {
          height = 3
          width  = 6
          x      = 6
          y      = 4
        }
      }
    }
    widget_layout {
      height = 7
      width  = 12
      x      = 0
      y      = 5
    }
  }
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "VLAN Assignments"
      widget {
        note_definition {
          background_color = "white"
          content          = "The VLAN filter applies only to this section. Counts cover the selected time range, not currently connected sessions. VLAN IDs are local to each location: use the site filter or RADIUS source IP to distinguish sites. A blank VLAN means no dynamic assignment was recorded; this is expected for opted-out sites and does not identify the AP or switch default VLAN. Rejected events remain visible in Overview. VLAN labels use the name recorded on each event. Older unnamed events are retained; the same device can appear in named and unnamed buckets, so device counts across VLAN/name buckets are not additive."
          font_size        = "14"
          show_tick        = false
          text_align       = "left"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 0
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "bars"
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@vlan_id"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@vlan_name"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth @event:Access-Accept host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @vlan_id:$vlan.value -@vlan_id:\"\""
                }
              }
            }
          }
          title = "Accepted Authentications by VLAN"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "cardinality"
                  metric      = "@device_id"
                }
                data_source = "logs"
                group_by {
                  facet = "@vlan_id"
                  limit = 20
                  sort {
                    aggregation = "cardinality"
                    metric      = "@device_id"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@vlan_name"
                  limit = 20
                  sort {
                    aggregation = "cardinality"
                    metric      = "@device_id"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:(radius-auth OR radius-acct) host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @vlan_id:$vlan.value -@vlan_id:\"\" @identity_verified:true"
                }
              }
            }
          }
          title = "Verified Devices Seen by VLAN"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@src_ip"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@vlan_id"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@vlan_name"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth @event:Access-Accept host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @vlan_id:$vlan.value -@vlan_id:\"\""
                }
              }
            }
          }
          title = "Assignments by RADIUS Source / VLAN"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 9
          y      = 0
        }
      }
      widget {
        log_stream_definition {
          columns         = ["timestamp", "@event", "@vlan_id", "@vlan_name", "@site_name", "@src_ip", "@nas_ip", "@device_id", "@device_name", "@device_owner", "@identity_verified", "@session_id"]
          indexes         = ["*"]
          message_display = "inline"
          query           = "service:(radius-auth OR radius-acct) host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @vlan_id:$vlan.value -@vlan_id:\"\""
          sort {
            column = "timestamp"
            order  = "desc"
          }
          title = "Recent VLAN Authentication and Accounting"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 2
        }
      }
    }
    widget_layout {
      height = 4
      width  = 12
      x      = 0
      y      = 13
    }
  }
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "Devices"
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@device_name"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Accept"
                }
              }
            }
          }
          title = "Top Devices by Auth Count"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@device_model"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Accept"
                }
              }
            }
          }
          title = "Device Model Distribution"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@device_owner"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Accept"
                }
              }
            }
          }
          title = "Device Owners by Auth Count"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 0
        }
      }
    }
    widget_layout {
      height = 2
      width  = 12
      x      = 0
      y      = 18
    }
  }
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "Network / Location"
      widget {
        timeseries_definition {
          request {
            display_type = "bars"
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Accept"
                }
              }
            }
          }
          show_legend = true
          title       = "Auth Events by Site"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@ap_name"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Accept"
                }
              }
            }
          }
          title = "Top Access Points"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@ssid"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Accept"
                }
              }
            }
          }
          title = "Auth by SSID"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 0
        }
      }
      widget {
        sunburst_definition {
          description = "Successful authentications, not unique clients, grouped by site and AP name. Missing site or AP names are unresolved events; they remain visible in the chart."
          hide_total  = false
          legend_table {
            type = "table"
          }
          request {
            formula {
              formula_expression = "authenticators"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@ap_name"
                  limit = 20
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "authenticators"
                search {
                  query = "service:radius-auth host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Access-Accept"
                }
              }
            }
          }
          title = "Top authenticators — successful auth"
        }
        widget_layout {
          height = 3
          width  = 12
          x      = 0
          y      = 2
        }
      }
    }
    widget_layout {
      height = 5
      width  = 12
      x      = 0
      y      = 21
    }
  }
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "Network Data Usage"
      widget {
        note_definition {
          background_color = "white"
          content          = "**Usage:** Upload/download are from the device’s perspective. The shared PostgreSQL ledger deduplicates accounting reports and is authoritative for exact totals. These dashboard totals are observed telemetry: downstream at-least-once delivery can duplicate intervals, and stable IDs do not deduplicate sums. Totals follow the network’s accounting report cadence; throughput is an interval average. Missing baselines or counter resets leave gaps. N/A measured-client coverage means no measured interval.\n\nEarlier usage is not reconstructed. The Go daemon emits committed PostgreSQL intervals through the local durable OTLP collector."
          font_size        = "14"
          show_tick        = false
          text_align       = "left"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 0
        }
      }
      widget {
        query_value_definition {
          autoscale   = false
          custom_unit = "GiB"
          precision   = 2
          request {
            formula {
              alias              = "Upload (GiB)"
              formula_expression = "upload / 1073741824"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "download"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "upload"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
          }
          title = "Observed traffic — Upload (GiB)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 0
        }
      }
      widget {
        query_value_definition {
          autoscale   = false
          custom_unit = "GiB"
          precision   = 2
          request {
            formula {
              alias              = "Download (GiB)"
              formula_expression = "download / 1073741824"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "download"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "upload"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
          }
          title = "Observed traffic — Download (GiB)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 0
        }
      }
      widget {
        query_value_definition {
          autoscale   = false
          custom_unit = "GiB"
          precision   = 2
          request {
            formula {
              alias              = "Total (GiB)"
              formula_expression = "(upload + download) / 1073741824"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "download"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "upload"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
          }
          title = "Observed traffic — Total (GiB)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 9
          y      = 0
        }
      }
      widget {
        query_value_definition {
          autoscale = false
          live_span = "1h"
          precision = 0
          request {
            formula {
              formula_expression = "default_zero(events)"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "events"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value"
                }
              }
            }
          }
          title = "All sites — Accounting events (1h)"
        }
        widget_layout {
          height = 1
          width  = 12
          x      = 0
          y      = 2
        }
      }
      widget {
        query_value_definition {
          autoscale = false
          live_span = "1h"
          precision = 0
          request {
            formula {
              formula_expression = "default_zero(events)"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "events"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
          }
          title = "All sites — Usage intervals (1h)"
        }
        widget_layout {
          height = 1
          width  = 12
          x      = 0
          y      = 3
        }
      }
      widget {
        query_table_definition {
          live_span = "30m"
          request {
            formula {
              alias              = "Reporting clients"
              cell_display_mode  = "number"
              formula_expression = "reporting"
            }
            formula {
              alias              = "Measured clients"
              cell_display_mode  = "number"
              formula_expression = "measured"
            }
            formula {
              alias              = "Coverage (%)"
              cell_display_mode  = "bar"
              formula_expression = "measured / reporting * 100"
            }
            query {
              event_query {
                compute {
                  aggregation = "cardinality"
                  metric      = "@calling_station"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 20
                  sort {
                    aggregation = "cardinality"
                    metric      = "@calling_station"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "reporting"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value (@event:Acct-Update OR @event:Acct-Stop) -@calling_station:\"\""
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "cardinality"
                  metric      = "@calling_station"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 20
                  sort {
                    aggregation = "cardinality"
                    metric      = "@calling_station"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "measured"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage -@calling_station:\"\""
                }
              }
            }
            sort {
              count = 20
              order_by {
                formula_sort {
                  index = 0
                  order = "desc"
                }
              }
            }
          }
          title = "Measured client coverage — last 30m"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 4
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "bars"
            formula {
              alias              = "Upload (GiB)"
              formula_expression = "upload / 1073741824"
            }
            formula {
              alias              = "Download (GiB)"
              formula_expression = "download / 1073741824"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "download"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "upload"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
          }
          show_legend = true
          title       = "Observed traffic increments by report time (GiB)"
          yaxis {
            include_zero = true
            min          = "0"
          }
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 4
        }
      }
      widget {
        query_table_definition {
          request {
            formula {
              alias              = "Upload (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "upload / 1073741824"
            }
            formula {
              alias              = "Download (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "download / 1073741824"
            }
            formula {
              alias              = "Total (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "(upload + download) / 1073741824"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "download"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "upload"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            sort {
              count = 10
              order_by {
                formula_sort {
                  index = 2
                  order = "desc"
                }
              }
            }
          }
          title = "Observed usage by site (GiB)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 4
        }
      }
      widget {
        query_table_definition {
          request {
            formula {
              alias              = "Upload (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "upload / 1073741824"
            }
            formula {
              alias              = "Download (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "download / 1073741824"
            }
            formula {
              alias              = "Total (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "(upload + download) / 1073741824"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                group_by {
                  facet = "@device_owner"
                  limit = 15
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@device_name"
                  limit = 15
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@device_id"
                  limit = 15
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "download"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage @identity_verified:true -@device_id:\"\""
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                group_by {
                  facet = "@device_owner"
                  limit = 15
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@device_name"
                  limit = 15
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@device_id"
                  limit = 15
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "upload"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage @identity_verified:true -@device_id:\"\""
                }
              }
            }
            sort {
              count = 30
              order_by {
                formula_sort {
                  index = 2
                  order = "desc"
                }
              }
            }
          }
          title = "Observed usage by verified owner / device (GiB)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 9
          y      = 4
        }
      }
      widget {
        query_table_definition {
          live_span = "30m"
          request {
            formula {
              alias              = "Upload (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "upload / 1073741824"
            }
            formula {
              alias              = "Download (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "download / 1073741824"
            }
            formula {
              alias              = "Total (GiB)"
              cell_display_mode  = "bar"
              formula_expression = "(upload + download) / 1073741824"
            }
            formula {
              alias              = "Session age (hours)"
              cell_display_mode  = "number"
              formula_expression = "duration / 3600"
              number_format {
                unit {
                  custom {
                    label = "hours"
                  }
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "max"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                group_by {
                  facet = "@calling_station"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@nas_ip"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@session_id"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@src_ip"
                  limit = 5
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "download"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Update -@session_id:\"\" -@calling_station:\"\""
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "max"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                group_by {
                  facet = "@calling_station"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@nas_ip"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@session_id"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@src_ip"
                  limit = 5
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "upload"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Update -@session_id:\"\" -@calling_station:\"\""
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "max"
                  metric      = "@session_time"
                }
                data_source = "logs"
                group_by {
                  facet = "@calling_station"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@nas_ip"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@session_id"
                  limit = 10
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@src_ip"
                  limit = 5
                  sort {
                    aggregation = "max"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "duration"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Update -@session_id:\"\" -@calling_station:\"\""
                }
              }
            }
            sort {
              count = 50
              order_by {
                formula_sort {
                  index = 2
                  order = "desc"
                }
              }
            }
          }
          title = "Cumulative session counters — reported in last 30m (GiB)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 6
        }
      }
      widget {
        query_table_definition {
          live_span = "30m"
          request {
            formula {
              alias              = "Upload (Mbps)"
              cell_display_mode  = "bar"
              formula_expression = "upload * 8 / elapsed / 1000000"
            }
            formula {
              alias              = "Download (Mbps)"
              cell_display_mode  = "bar"
              formula_expression = "download * 8 / elapsed / 1000000"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                group_by {
                  facet = "@calling_station"
                  limit = 100
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "download"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                group_by {
                  facet = "@calling_station"
                  limit = 100
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "upload"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@session_time"
                }
                data_source = "logs"
                group_by {
                  facet = "@calling_station"
                  limit = 100
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "sum"
                    metric      = "@output_bytes"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "elapsed"
                search {
                  query = "service:radius-usage host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Usage"
                }
              }
            }
            sort {
              count = 30
              order_by {
                formula_sort {
                  index = 1
                  order = "desc"
                }
              }
            }
          }
          title = "Reported interval throughput by client — last 30m (Mbps)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 6
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "bars"
            formula {
              alias              = "Updates received"
              formula_expression = "updates"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@site_name"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "updates"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Update"
                }
              }
            }
          }
          title = "Interim accounting updates by site"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 6
        }
      }
      widget {
        log_stream_definition {
          columns = ["timestamp", "@event", "@site_name", "@ap_name", "@ssid", "@device_owner", "@device_name", "@calling_station", "@session_id", "@input_bytes", "@output_bytes", "@session_time", "@identity_verified"]
          indexes = ["*"]
          query   = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value (@event:Acct-Update OR @event:Acct-Stop)"
          sort {
            column = "timestamp"
            order  = "desc"
          }
          title = "Recent session counters and device details"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 9
          y      = 6
        }
      }
    }
    widget_layout {
      height = 8
      width  = 12
      x      = 0
      y      = 27
    }
  }
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "Accounting"
      widget {
        timeseries_definition {
          request {
            display_type = "line"
            formula {
              alias              = "Requests"
              formula_expression = "a"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "a"
                query       = "sum:cloud8021x.radius.total_acct_requests{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius}.as_rate()"
              }
            }
            style {
              palette = "blue"
            }
          }
          request {
            display_type = "line"
            formula {
              alias              = "Responses"
              formula_expression = "c"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "c"
                query       = "sum:cloud8021x.radius.total_acct_responses{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius}.as_rate()"
              }
            }
            style {
              palette = "green"
            }
          }
          show_legend = true
          title       = "Accounting Requests"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 0
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "bars"
            formula {
              alias              = "Session Starts"
              formula_expression = "starts"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "starts"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Start"
                }
              }
            }
            style {
              palette = "green"
            }
          }
          request {
            display_type = "bars"
            formula {
              alias              = "Session Stops"
              formula_expression = "stops"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "stops"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Stop"
                }
              }
            }
            style {
              palette = "red"
            }
          }
          show_legend = true
          title       = "Session Events"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1 / 60"
            }
            query {
              event_query {
                compute {
                  aggregation = "avg"
                  metric      = "@session_time"
                }
                data_source = "logs"
                group_by {
                  facet = "@device_owner"
                  limit = 20
                  sort {
                    aggregation = "avg"
                    metric      = "@session_time"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Stop"
                }
              }
            }
          }
          title = "Avg Session Duration by User (min)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 0
        }
      }
      widget {
        toplist_definition {
          request {
            formula {
              formula_expression = "query1"
            }
            query {
              event_query {
                compute {
                  aggregation = "count"
                }
                data_source = "logs"
                group_by {
                  facet = "@terminate_cause"
                  limit = 10
                  sort {
                    aggregation = "count"
                    order       = "desc"
                  }
                }
                indexes = ["*"]
                name    = "query1"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Stop"
                }
              }
            }
          }
          title = "Session Termination Causes (blank = cause not recorded)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 9
          y      = 0
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "bars"
            formula {
              alias              = "Input Bytes"
              formula_expression = "input"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@input_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "input"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Stop"
                }
              }
            }
            style {
              palette = "cool"
            }
          }
          request {
            display_type = "bars"
            formula {
              alias              = "Output Bytes"
              formula_expression = "output"
            }
            query {
              event_query {
                compute {
                  aggregation = "sum"
                  metric      = "@output_bytes"
                }
                data_source = "logs"
                indexes     = ["*"]
                name        = "output"
                search {
                  query = "service:radius-acct host:$host.value (host:radius-primary OR host:radius-secondary) @site_name:$site.value @event:Acct-Stop"
                }
              }
            }
            style {
              palette = "warm"
            }
          }
          show_legend = true
          title       = "Completed session counters (bytes, at stop)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 2
        }
      }
    }
    widget_layout {
      height = 4
      width  = 12
      x      = 0
      y      = 36
    }
  }
  widget {
    group_definition {
      layout_type = "ordered"
      title       = "Infrastructure"
      widget {
        timeseries_definition {
          request {
            display_type = "line"
            formula {
              alias              = "Acct"
              formula_expression = "depth"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "depth"
                query       = "max:cloud8021x.radius.queue_len_acct{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius} by {host}"
              }
            }
          }
          request {
            display_type = "line"
            formula {
              alias              = "Auth"
              formula_expression = "depth"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "depth"
                query       = "max:cloud8021x.radius.queue_len_auth{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius} by {host}"
              }
            }
          }
          request {
            display_type = "line"
            formula {
              alias              = "Internal"
              formula_expression = "depth"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "depth"
                query       = "max:cloud8021x.radius.queue_len_internal{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius} by {host}"
              }
            }
          }
          show_legend = true
          title       = "Queue Depths"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 0
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "line"
            formula {
              alias              = "Access requests / sec"
              formula_expression = "requests"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "requests"
                query       = "sum:cloud8021x.radius.total_access_requests{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius} by {host}.as_rate()"
              }
            }
          }
          request {
            display_type = "line"
            formula {
              alias              = "Accounting requests / sec"
              formula_expression = "requests"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "requests"
                query       = "sum:cloud8021x.radius.total_acct_requests{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius} by {host}.as_rate()"
              }
            }
          }
          show_legend = true
          title       = "Incoming RADIUS requests / sec"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 0
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "bars"
            formula {
              alias              = "Malformed"
              formula_expression = "a"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "a"
                query       = "sum:cloud8021x.radius.total_auth_malformed_requests{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius}.as_rate()"
              }
            }
            style {
              palette = "red"
            }
          }
          request {
            display_type = "bars"
            formula {
              alias              = "Invalid"
              formula_expression = "c"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "c"
                query       = "sum:cloud8021x.radius.total_auth_invalid_requests{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius}.as_rate()"
              }
            }
            style {
              palette = "orange"
            }
          }
          request {
            display_type = "bars"
            formula {
              alias              = "Dropped"
              formula_expression = "e"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "e"
                query       = "sum:cloud8021x.radius.total_auth_dropped_requests{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius}.as_rate()"
              }
            }
            style {
              palette = "yellow"
            }
          }
          request {
            display_type = "line"
            formula {
              alias              = "Duplicate"
              formula_expression = "g"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "g"
                query       = "sum:cloud8021x.radius.total_auth_duplicate_requests{$host AND (host:radius-primary OR host:radius-secondary) AND service:cloud-8021x AND component:freeradius}.as_rate()"
              }
            }
            style {
              palette = "grey"
            }
          }
          show_legend = true
          title       = "Auth Errors"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 0
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "line"
            formula {
              formula_expression = "cpu"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "cpu"
                query       = "avg:system.cpu.user{$host AND (host:radius-primary OR host:radius-secondary)} by {host}"
              }
            }
          }
          show_legend = true
          title       = "CPU Usage"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 9
          y      = 0
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "line"
            formula {
              formula_expression = "(used / total) * 100"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "used"
                query       = "avg:system.mem.used{$host AND (host:radius-primary OR host:radius-secondary)} by {host}"
              }
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "total"
                query       = "avg:system.mem.total{$host AND (host:radius-primary OR host:radius-secondary)} by {host}"
              }
            }
          }
          show_legend = true
          title       = "Memory Usage (%)"
          yaxis {
            max = "100"
            min = "0"
          }
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 2
        }
      }
      widget {
        query_table_definition {
          live_span = "5m"
          request {
            formula {
              alias              = "FreeRADIUS uptime (hours)"
              cell_display_mode  = "number"
              formula_expression = "uptime / 3600"
              number_format {
                unit {
                  custom {
                    label = "hours"
                  }
                }
              }
            }
            query {
              metric_query {
                aggregator  = "last"
                data_source = "metrics"
                name        = "uptime"
                query       = "min:system.processes.run_time.max{$host AND (host:radius-primary OR host:radius-secondary) AND process_name:freeradius} by {host}"
              }
            }
          }
          title = "FreeRADIUS process uptime by server (hours)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 3
          y      = 2
        }
      }
      widget {
        query_table_definition {
          live_span = "5m"
          request {
            formula {
              alias              = "VM uptime (hours)"
              cell_display_mode  = "number"
              formula_expression = "uptime / 3600"
              number_format {
                unit {
                  custom {
                    label = "hours"
                  }
                }
              }
            }
            query {
              metric_query {
                aggregator  = "last"
                data_source = "metrics"
                name        = "uptime"
                query       = "min:system.uptime{$host AND (host:radius-primary OR host:radius-secondary)} by {host}"
              }
            }
          }
          title = "VM uptime by server (hours)"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 6
          y      = 2
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "line"
            formula {
              formula_expression = "rx"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "rx"
                query       = "avg:system.net.bytes_rcvd{$host AND (host:radius-primary OR host:radius-secondary)} by {host}"
              }
            }
            style {
              palette = "blue"
            }
          }
          request {
            display_type = "line"
            formula {
              formula_expression = "tx"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "tx"
                query       = "avg:system.net.bytes_sent{$host AND (host:radius-primary OR host:radius-secondary)} by {host}"
              }
            }
            style {
              palette = "green"
            }
          }
          show_legend = true
          title       = "Network I/O"
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 9
          y      = 2
        }
      }
      widget {
        timeseries_definition {
          request {
            display_type = "line"
            formula {
              formula_expression = "disk * 100"
            }
            query {
              metric_query {
                data_source = "metrics"
                name        = "disk"
                query       = "max:system.disk.in_use{$host AND (host:radius-primary OR host:radius-secondary)} by {host}"
              }
            }
          }
          show_legend = true
          title       = "Disk Usage (%)"
          yaxis {
            max = "100"
            min = "0"
          }
        }
        widget_layout {
          height = 2
          width  = 3
          x      = 0
          y      = 4
        }
      }
    }
    widget_layout {
      height = 6
      width  = 12
      x      = 0
      y      = 41
    }
  }
}
