# -----------------------------------------------------------------------------
# Datadog — Smallstep step-ca dashboard + monitors
#
# Gated on BOTH enable_smallstep_ca (the CA exists) and datadog_app_key (TF can
# manage Datadog). Metrics come from step-ca's native Prometheus endpoint
# (metricsAddress in ca.json, namespace step_ca) scraped via the agent's
# OpenMetrics check (namespace "smallstep" — see scripts/startup.sh), plus the
# custom DogStatsD gauges (smallstep.cert.days_until_expiry,
# smallstep.scep.decrypter_ready) and the file-tailed logs (source:stepca,
# service:smallstep-ca) parsed by the pipeline at the bottom of this file.
#
# OpenMetrics maps counters to "<name>.count"; gauges keep their name.
# -----------------------------------------------------------------------------

locals {
  smallstep_datadog_enabled = local.datadog_enabled && var.enable_smallstep_ca

  # Tag selector limiting all queries to this project's two CA hosts.
  stepca_hosts = "{service:smallstep-ca}"

  smallstep_dashboard_json = {
    title       = "Smallstep step-ca (Wi-Fi CA)"
    description = "Self-hosted step-ca: issuance by provisioner (ACME/SCEP), KMS, health, cert expiry, and logs."
    layout_type = "ordered"
    template_variables = [
      {
        name   = "host"
        prefix = "host"
        available_values = [
          "radius-primary",
          "radius-secondary"
        ]
        defaults = ["*"]
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
          widgets = [
            {
              definition = {
                title    = "CA Health (/health)"
                type     = "check_status"
                check    = "http.can_connect"
                grouping = "cluster"
                tags     = ["instance:stepca-health"]
              }
            },
            {
              definition = {
                title    = "step-ca Process Up"
                type     = "check_status"
                check    = "process.up"
                grouping = "cluster"
                tags     = ["process:step-ca"]
              }
            },
            {
              definition = {
                title     = "SCEP Decrypter Ready"
                type      = "query_value"
                autoscale = false
                precision = 0
                requests = [
                  {
                    queries = [
                      { data_source = "metrics", name = "a", query = "min:smallstep.scep.decrypter_ready{$host}", aggregator = "last" }
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
                    queries         = [{ data_source = "metrics", name = "a", query = "max:smallstep.uptime{$host}", aggregator = "last" }]
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
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.provisioner.signed.count{$host}.as_rate()", aggregator = "avg" }]
                    response_format = "scalar"
                    formulas        = [{ formula = "a * 60" }]
                  }
                ]
              }
            }
          ]
        }
      },

      # -----------------------------------------------------------------------
      # Issuance by provisioner (ACME vs SCEP)
      # -----------------------------------------------------------------------
      {
        definition = {
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
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.provisioner.signed.count{$host} by {provisioner}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "bars"
                    formulas        = [{ formula = "a", alias = "signed" }]
                  }
                ]
              }
            },
            {
              definition = {
                title       = "Renewed + Rekeyed by Provisioner"
                type        = "timeseries"
                show_legend = true
                requests = [
                  {
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.provisioner.renewed.count{$host} by {provisioner}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "line"
                    style           = { palette = "cool" }
                    formulas        = [{ formula = "a", alias = "renewed" }]
                  },
                  {
                    queries         = [{ data_source = "metrics", name = "b", query = "sum:smallstep.provisioner.rekeyed.count{$host} by {provisioner}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "line"
                    style           = { palette = "warm" }
                    formulas        = [{ formula = "b", alias = "rekeyed" }]
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
                      { data_source = "metrics", name = "a", query = "sum:smallstep.provisioner.signed.count{$host} by {provisioner}.as_count()", aggregator = "sum" }
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
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.provisioner.webhook_authorized.count{$host} by {provisioner}.as_rate()" }]
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
                    queries         = [{ data_source = "metrics", name = "a", query = "sum:smallstep.kms.signed.count{$host}.as_rate()" }]
                    response_format = "timeseries"
                    display_type    = "line"
                    style           = { palette = "green" }
                    formulas        = [{ formula = "a", alias = "signed" }]
                  },
                  {
                    queries         = [{ data_source = "metrics", name = "b", query = "sum:smallstep.kms.errors.count{$host}.as_rate()" }]
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
                    queries         = [{ data_source = "metrics", name = "a", query = "min:smallstep.cert.days_until_expiry{cert:intermediate,$host}", aggregator = "last" }]
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
                    queries         = [{ data_source = "metrics", name = "a", query = "min:smallstep.cert.days_until_expiry{cert:decrypter,$host}", aggregator = "last" }]
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
                    queries         = [{ data_source = "metrics", name = "a", query = "min:smallstep.cert.days_until_expiry{$host} by {cert}" }]
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
                query           = "service:smallstep-ca $host"
                columns         = ["@timestamp", "host", "@status", "@method", "@path", "@request-id"]
                sort            = { column = "@timestamp", order = "desc" }
                message_display = "inline"
              }
            },
            {
              definition = {
                title           = "Errors / warnings"
                type            = "log_stream"
                indexes         = ["*"]
                query           = "service:smallstep-ca $host (status:error OR status:warn OR @level:error OR @level:warn)"
                columns         = ["@timestamp", "host", "@level", "@msg", "@error"]
                sort            = { column = "@timestamp", order = "desc" }
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

# -----------------------------------------------------------------------------
# Monitors (alerting)
#
# No monitors existed before this; these are the first. The notification handle
# (var.datadog_monitor_notify) is appended to each message — empty is fine, the
# monitor still triggers and shows in the Datadog UI, it just isn't routed.
# -----------------------------------------------------------------------------

locals {
  dd_notify = var.datadog_monitor_notify != "" ? "\n\n${var.datadog_monitor_notify}" : ""
}

# step-ca /health unreachable (the CA is down on a node).
resource "datadog_monitor" "stepca_health" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep step-ca /health failing"
  type    = "service check"
  query   = "\"http.can_connect\".over(\"instance:stepca-health\").by(\"host\").last(3).count_by_status()"
  message = "step-ca /health is failing on {{host.name}} — the Wi-Fi CA is unreachable on this node. EAP-TLS issuance (ACME + SCEP) may be degraded; check `systemctl status step-ca`.${local.dd_notify}"
  monitor_thresholds {
    critical = 2
    warning  = 1
    ok       = 1
  }
  notify_no_data    = true
  no_data_timeframe = 10
  tags              = ["service:smallstep-ca", "managed-by:terraform"]
}

# step-ca process gone.
resource "datadog_monitor" "stepca_process" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep step-ca process down"
  type    = "service check"
  query   = "\"process.up\".over(\"process:step-ca\").by(\"host\").last(3).count_by_status()"
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

# SCEP decrypter degraded — the exact failure mode that broke Windows SCEP:
# step-ca came up but the decrypter didn't initialize, so every PKIOperation
# 500s. Caught by the smallstep.scep.decrypter_ready gauge.
resource "datadog_monitor" "stepca_decrypter" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep SCEP decrypter not initialized"
  type    = "metric alert"
  query   = "min(last_10m):min:smallstep.scep.decrypter_ready{service:smallstep-ca} by {host} < 1"
  message = "step-ca on {{host.name}} is running but its SCEP decrypter failed to initialize — every Windows SCEP PKIOperation will return HTTP 500 and no Wi-Fi certs will issue. Restart step-ca (the ExecStartPost probe should self-heal a transient KMS blip); if it persists, verify the decrypterKeyPEM/decrypterCertificate pair.${local.dd_notify}"
  monitor_thresholds {
    critical = 1
  }
  notify_no_data = false
  tags           = ["service:smallstep-ca", "managed-by:terraform"]
}

# Certificate expiry — intermediate or SCEP decrypter nearing end of life.
resource "datadog_monitor" "stepca_cert_expiry" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep CA certificate nearing expiry"
  type    = "metric alert"
  query   = "min(last_1h):min:smallstep.cert.days_until_expiry{service:smallstep-ca} by {host,cert} < 30"
  message = "The {{cert.name}} certificate on {{host.name}} expires in under 30 days. Re-issue it (intermediate is KMS-backed; the SCEP decrypter is the shared software RSA key) before EAP-TLS breaks.${local.dd_notify}"
  monitor_thresholds {
    critical = 14
    warning  = 30
  }
  notify_no_data = false
  tags           = ["service:smallstep-ca", "managed-by:terraform"]
}

# KMS errors — the HSM signing path is failing.
resource "datadog_monitor" "stepca_kms_errors" {
  count   = local.smallstep_datadog_enabled ? 1 : 0
  name    = "Smallstep CA KMS errors"
  type    = "metric alert"
  query   = "sum(last_15m):sum:smallstep.kms.errors.count{service:smallstep-ca}.as_count() > 5"
  message = "step-ca is hitting Cloud KMS errors (>5 in 15m) — the HSM-backed signing key may be unavailable or rate-limited, which blocks all certificate issuance.${local.dd_notify}"
  monitor_thresholds {
    critical = 5
    warning  = 1
  }
  notify_no_data = false
  tags           = ["service:smallstep-ca", "managed-by:terraform"]
}

# -----------------------------------------------------------------------------
# RADIUS monitors (the FreeRADIUS dashboard had none either)
# -----------------------------------------------------------------------------

# Both RADIUS servers down = total Wi-Fi auth outage.
resource "datadog_monitor" "radius_down" {
  count   = local.datadog_enabled ? 1 : 0
  name    = "FreeRADIUS down (no server reporting up)"
  type    = "metric alert"
  query   = "max(last_5m):max:freeradius.up{*} + max:freeradius.freeradius_up{*} < 1"
  message = "No FreeRADIUS server is reporting healthy — 802.1X Wi-Fi authentication is down campus-wide. Check radius-primary and radius-secondary.${local.dd_notify}"
  monitor_thresholds {
    critical = 1
  }
  notify_no_data    = true
  no_data_timeframe = 15
  tags              = ["service:radius", "managed-by:terraform"]
}

# Sustained zero accepts during the day often means a broken auth path.
resource "datadog_monitor" "radius_no_accepts" {
  count   = local.datadog_enabled ? 1 : 0
  name    = "FreeRADIUS no Access-Accepts"
  type    = "metric alert"
  query   = "sum(last_30m):sum:freeradius.total_access_accepts.count{*}.as_count() + sum:freeradius.freeradius_total_access_accepts.count{*}.as_count() <= 0"
  message = "FreeRADIUS has issued zero Access-Accepts in the last 30 minutes. If this is during business hours it likely indicates a broken auth path (cert trust, RADIUS config). Off-hours this can be normal.${local.dd_notify}"
  monitor_thresholds {
    critical = 0
  }
  notify_no_data = false
  tags           = ["service:radius", "managed-by:terraform"]
}

# -----------------------------------------------------------------------------
# Log pipeline for step-ca (source:stepca)
#
# step-ca writes TWO line formats to the tee'd file:
#   - JSON request log:  {"time":"2026-06-04T01:07:39Z","level":"info",
#                         "method":"GET","path":"/scep/...","status":200,...}
#   - plain-text ops log: 2026/06/04 01:04:58 Serving HTTPS on :8443 ...
#
# This pipeline parses both: extracts the real event time (so Datadog uses it
# instead of ingestion time), pulls structured attributes from JSON, strips the
# leading timestamp from text lines, and maps level -> log status.
# -----------------------------------------------------------------------------

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
