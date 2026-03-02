# Architecture

Technical deep-dive into how cloud-8021x works. Read this if you need to modify the startup script, change the authentication flow, add new log fields, or debug issues.

## Table of Contents

- [Architecture](#architecture)
  - [Table of Contents](#table-of-contents)
  - [System Overview](#system-overview)
  - [Startup Script Walkthrough](#startup-script-walkthrough)
    - [Execution order](#execution-order)
    - [Re-running the startup script](#re-running-the-startup-script)
  - [Certificate Architecture](#certificate-architecture)
  - [Authentication Flow](#authentication-flow)
    - [Key details](#key-details)
  - [Log Enrichment Pipeline](#log-enrichment-pipeline)
    - [Why external scripts?](#why-external-scripts)
    - [BSSID fuzzy matching](#bssid-fuzzy-matching)
    - [Cache miss handling](#cache-miss-handling)
  - [JSON Log Schemas](#json-log-schemas)
    - [Auth log (`/var/log/freeradius/radius-auth.json`)](#auth-log-varlogfreeradiusradius-authjson)
    - [Accounting log (`/var/log/freeradius/radius-acct.json`)](#accounting-log-varlogfreeradiusradius-acctjson)
  - [Reply Attribute Mapping](#reply-attribute-mapping)
  - [FreeRADIUS Virtual Server](#freeradius-virtual-server)
  - [Observability Stack](#observability-stack)
    - [Datadog Agent](#datadog-agent)
    - [FreeRADIUS Prometheus Exporter](#freeradius-prometheus-exporter)
    - [Log files on disk](#log-files-on-disk)
  - [Terraform templatefile() Escaping](#terraform-templatefile-escaping)
  - [Common Operations](#common-operations)
    - [Deploy changes to a running VM](#deploy-changes-to-a-running-vm)
    - [Check FreeRADIUS config without restarting](#check-freeradius-config-without-restarting)
    - [Manually refresh Jamf cache](#manually-refresh-jamf-cache)
    - [Manually refresh UniFi cache](#manually-refresh-unifi-cache)
    - [View live auth events](#view-live-auth-events)
    - [View live accounting events](#view-live-accounting-events)
    - [Query accounting database](#query-accounting-database)
    - [Debug a specific device](#debug-a-specific-device)
    - [Add a new field to auth/accounting logs](#add-a-new-field-to-authaccounting-logs)

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│ GCE VM (Debian 12)                                          │
│                                                             │
│  ┌────────────┐ ┌────────┐ ┌─────────────┐ ┌────────────┐   │
│  │ FreeRADIUS │ │MariaDB │ │Datadog Agent│ │ freeradius │   │
│  │:1812/:1813 │ │:3306   │ │(logs+metrics│ │ _exporter  │   │
│  │            │ │        │ └─────────────┘ │ :9812      │   │
│  │┌──────────┐│ │radacct │                 └────────────┘   │
│  ││rlm_python││ │radpost │                                  │
│  ││ 3 module ││ │auth    │ ┌─────────────────────────────┐  │
│  │└──────────┘│ └────────┘ │Cron jobs                    │  │
│  └────────────┘            │ */5  unifi-ap-cache.sh      │  │
│                            │ */30 jamf-device-cache.sh   │  │
│  ┌──────────────────┐      └─────────────────────────────┘  │
│  │Log files          │                                      │
│  │ radius-auth.json  │     ┌─────────────────────────────┐  │
│  │ radius-acct.json  │     │Cache files                  │  │
│  └──────────────────┘      │ /etc/freeradius/3.0/        │  │
│                            │  jamf-device-cache.json     │  │
│                            │  unifi-ap-cache.json        │  │
│                            └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

Key processes:
- **FreeRADIUS** — handles all RADIUS auth and accounting
- **MariaDB** — stores RADIUS accounting records (`radacct` table)
- **rlm_python3 module** — runs inside FreeRADIUS, reads local cache files to enrich auth/accounting with device and AP info
- **Cron scripts** — run outside FreeRADIUS, call external APIs (Jamf, UniFi) and write cache files
- **Datadog Agent** — ships logs and metrics
- **freeradius_exporter** — Prometheus exporter, scraped by Datadog

## Startup Script Walkthrough

`scripts/startup.sh` is an idempotent bootstrap script that runs as root via GCE metadata `startup-script`. It is rendered through Terraform's `templatefile()` with variables injected at apply time.

### Execution order

| Step | Section | What it does |
|------|---------|-------------|
| 0 | Idempotency check | If FreeRADIUS is already running, exit immediately |
| 1 | System prerequisites | `apt-get update`, install `curl`, `jq`, `python3` |
| 2 | Install packages | `freeradius`, `freeradius-utils`, `freeradius-mysql`, `freeradius-python3`, `mariadb-server` |
| 3 | Okta CA | Retrieve Okta Intermediate CA (and optionally Root CA) from Secret Manager → `/etc/freeradius/3.0/certs/okta-ca.pem` |
| 4 | Server certificates | Restore from Secret Manager if they exist, otherwise generate self-signed CA + server cert and store them back |
| 5 | EAP-TLS config | Write `mods-available/eap` with certificate paths, TLS settings |
| 6 | RADIUS clients | Generate `clients.conf` from `radius_clients` variable — one client block per office with per-office shared secrets from Secret Manager |
| 7 | MariaDB setup | Create `radius` database, load FreeRADIUS SQL schema, configure `mods-available/sql` |
| 8 | Whitespace filter patch | Disable whitespace rejection in `policy.d/filter` (SCEP CNs contain spaces) |
| 9 | Jamf credentials + cache | Write credentials JSON, deploy `jamf-device-cache.sh` (bulk) and `jamf-device-fetch.sh` (single), run initial cache build, set up cron |
| 10 | UniFi cache | Write credentials, deploy `unifi-ap-cache.sh`, run initial cache build, set up cron |
| 10a | Python module | Write `radius_lookups.py` and FreeRADIUS module config, enable module |
| 11 | JSON logging | Configure `json_log` (auth) and `acct_log` (accounting) linelog modules |
| 12 | Virtual server | Write `sites-available/default` with authorize → authenticate → accounting → post-auth pipeline |
| 13 | Status server | Configure status virtual server on `127.0.0.1:18121` for Prometheus exporter |
| 14 | Start FreeRADIUS | `freeradius -XC` (config check) then `systemctl start` |
| 15 | Datadog Agent | Install and configure with API key from Secret Manager |
| 16 | Prometheus exporter | Install `freeradius_exporter` binary, create systemd service |
| 17 | Datadog OpenMetrics | Configure Datadog to scrape the exporter |

### Re-running the startup script

The idempotency check means you must stop FreeRADIUS before re-running:

```bash
sudo systemctl stop freeradius
sudo bash -c 'curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script" | bash'
```

A `gcloud compute instances reset` also works (full VM reboot).

## Certificate Architecture

Two completely independent CA chains:

```
Server chain (RADIUS server identity):
  Self-signed RADIUS CA (CN=<server_cert_org> RADIUS CA)
    └── Server cert (CN=<server_cert_cn>)

Client chain (device identity):
  Okta Root CA (optional)
    └── Okta Intermediate Authority
          └── Client SCEP cert (CN=<serial> managementAttestation <udid> <profile>)
```

- **Server CA + cert**: Generated on first boot by the startup script using `openssl`. Stored in Secret Manager so they persist across VM replacements. The CA cert must be uploaded to Jamf once (trusted server certificate in WiFi profile).
- **Client CA**: Okta Intermediate CA cert provided via `okta_ca_cert_pem` Terraform variable, stored in Secret Manager, written to `/etc/freeradius/3.0/certs/okta-ca.pem`. FreeRADIUS validates client certificates against this CA.
- **EAP-TLS config**: `ca_file` points to the Okta CA (client validation), while `certificate_file`/`private_key_file` point to the server cert/key.

## Authentication Flow

```
MacBook              WiFi AP              FreeRADIUS
  │                    │                     │
  │── 802.1X Start ──> │                      │
  │                    │── Access-Request ─> │
  │                    │  (User-Name=serial) │
  │                    │                     │
  │                    │   authorize:        │
  │                    │    filter_username  │
  │                    │    eap → ok=return  │
  │                    │                     │
  │<══════ EAP-TLS handshake (multi) ═════>  │
  │  Client presents SCEP cert               │
  │  Server presents RADIUS cert             │
  │  Validates client cert vs Okta CA        │
  │                    │                     │
  │                    │   authenticate:     │
  │                    │    eap              │
  │                    │                     │
  │                    │   post-auth:        │
  │                    │    radius_lookups   │
  │                    │     Jamf cache read │
  │                    │     UniFi cache     │
  │                    │     SSID extract    │
  │                    │     Set reply attrs │
  │                    │    json_log         │
  │                    │     Write auth JSON │
  │                    │                     │
  │                    │<── Access-Accept ──-│
  │<── WiFi Connected─ │                     │
  │                    │                     │
  │                    │── Acct-Start ─────> │
  │                    │                     │
  │                    │   accounting:       │
  │                    │    radius_lookups   │
  │                    │     Jamf + UniFi    │
  │                    │    sql → MariaDB    │
  │                    │    acct_log → JSON  │
```

### Key details

- **EAP outer identity**: The WiFi profile sets `$SERIALNUMBER` as the EAP outer identity. This appears as `User-Name` in the RADIUS request and is used to look up the device in Jamf.
- **User-Name rewrite**: In post-auth, if Jamf returns an email, the Python module rewrites `User-Name` to `email - serial` (e.g. `robbie@campus.edu - H176YHQ9XV`). This is what the AP sees and caches.
- **Accounting enrichment**: Accounting packets arrive with `User-Name` set to either the raw serial or the rewritten `email - serial`. The Python module extracts the serial (splitting on ` - ` if needed) and does the same cache lookup.

## Log Enrichment Pipeline

The enrichment pipeline has two layers: **external cache scripts** (call APIs, write files) and the **FreeRADIUS Python module** (reads files, sets RADIUS attributes).

```
External (cron / boot)                    Inside FreeRADIUS (per-request)
┌───────────────────────┐                 ┌─────────────────────────────┐
│ jamf-device-cache.sh  │                 │ radius_lookups.py           │
│   Bulk Jamf inventory │──writes──>      │   _get_cached_jamf(serial)  │
│   Every 30 min + boot │          │      │     Read jamf cache file    │
│                       │          │      │     Return device info      │
│ jamf-device-fetch.sh  │          │      │                             │
│   Single device fetch │──writes──┤      │   _unifi_lookup(bssid)      │
│   On cache miss       │          │      │     Read UniFi cache file   │
│                       │          ▼      │     Fuzzy BSSID matching    │
│ unifi-ap-cache.sh     │      Cache      │     Return AP + site name   │
│   UniFi hosts+devices │──writes──>files │                             │
│   Every 5 min + boot  │                 │   Sets reply attributes     │
└───────────────────────┘                 │   for linelog to read       │
                                          └─────────────────────────────┘
```

### Why external scripts?

FreeRADIUS runs with `PrivateTmp=yes` in its systemd unit file, which creates a private `/tmp` namespace. More critically, making HTTPS requests from within the FreeRADIUS process (via `rlm_python3`) conflicts with FreeRADIUS's own OpenSSL context used for EAP-TLS. External scripts run in a clean process with system SSL, avoiding both issues.

### BSSID fuzzy matching

WiFi APs expose multiple BSSIDs (one per radio/SSID), which are the AP's base MAC address + a small offset (0-7) on the last byte. `Called-Station-Id` in RADIUS contains the BSSID, not the base MAC. The Python module tries an exact match first, then decrements the last byte by 1-7 to find the base MAC in the UniFi cache.

Example: BSSID `84-78-48-16-DD-73` → base MAC `84784816DD70` (offset 3) → AP "Lobby"

### Cache miss handling

If a serial isn't in the Jamf cache (new device enrolled after last cache build), the Python module spawns a background thread that calls `jamf-device-fetch.sh` via `subprocess`. This does not block the current auth — the device gets empty Jamf fields this time, but the cache is updated for the next auth. The fetch script reads the existing cache file, adds the new entry, and writes it back atomically.

## JSON Log Schemas

### Auth log (`/var/log/freeradius/radius-auth.json`)

One JSON line per Access-Accept or Access-Reject.

| Field | Source | Example |
|-------|--------|---------|
| `timestamp` | FreeRADIUS `%S` | `2026-03-02 16:19:16` |
| `event` | Packet type | `Access-Accept` or `Access-Reject` |
| `serial` | `User-Name` request attr | `H176YHQ9XV` |
| `device_owner` | Jamf cache (via `Reply-Message`) | `robbie@campus.edu` |
| `device_name` | Jamf cache (via `Filter-Id`) | `Robbie's MacBook Pro` |
| `device_model` | Jamf cache (via `Login-LAT-Node`) | `MacBook Pro (16-inch, 2024) M4 Max` |
| `src_ip` | `Packet-Src-IP-Address` | `216.200.20.23` |
| `nas_ip` | `NAS-IP-Address` | `192.168.1.143` |
| `nas_port` | `NAS-Port` | `5` |
| `calling_station` | `Calling-Station-Id` (client MAC) | `70-8C-F2-C4-D2-B5` |
| `ssid` | Extracted from `Called-Station-Id` (via `Login-LAT-Port`) | `Campus` |
| `site_name` | UniFi cache (via `Connect-Info`) | `32 Avenue of the Americas` |
| `ap_name` | UniFi cache (via `Callback-Id`) | `Engineering` |
| `session_id` | `Acct-Session-Id` | `76427984EAE9D8CB` |
| `multi_session_id` | `Acct-Multi-Session-Id` | `5D1A082740598EE7` |
| `cert_cn` | `TLS-Client-Cert-Common-Name` | `H176YHQ9XV managementAttestation ...` |
| `cert_issuer` | `TLS-Client-Cert-Issuer` | `/DC=com/DC=okta/.../CN=Organization Intermediate Authority` |
| `cert_expiration` | `TLS-Client-Cert-Expiration` | `270301202503Z` |
| `reject_reason` | `Module-Failure-Message` (Reject only) | `eap: No mutually acceptable types found` |

### Accounting log (`/var/log/freeradius/radius-acct.json`)

One JSON line per Acct-Start, Acct-Stop, or Interim-Update.

| Field | Source | Events |
|-------|--------|--------|
| `timestamp` | FreeRADIUS `%S` | All |
| `event` | `Acct-Status-Type` | `Acct-Start`, `Acct-Stop`, `Acct-Update` |
| `username` | `User-Name` (may be `email - serial`) | All |
| `device_owner` | Jamf cache (via `Reply-Message`) | All |
| `device_name` | Jamf cache (via `Filter-Id`) | All |
| `device_model` | Jamf cache (via `Login-LAT-Node`) | All |
| `src_ip` | `Packet-Src-IP-Address` | All |
| `nas_ip` | `NAS-IP-Address` | All |
| `calling_station` | `Calling-Station-Id` (client MAC) | All |
| `called_station` | `Called-Station-Id` (AP BSSID:SSID) | All |
| `site_name` | UniFi cache (via `Connect-Info`) | All |
| `ap_name` | UniFi cache (via `Callback-Id`) | All |
| `session_id` | `Acct-Session-Id` | All |
| `multi_session_id` | `Acct-Multi-Session-Id` | All |
| `session_time` | `Acct-Session-Time` (seconds) | Stop, Update |
| `input_bytes` | `Acct-Input-Octets` | Stop, Update |
| `output_bytes` | `Acct-Output-Octets` | Stop, Update |
| `terminate_cause` | `Acct-Terminate-Cause` | Stop |

## Reply Attribute Mapping

FreeRADIUS `linelog` can only read RADIUS attributes, not arbitrary Python variables. The Python module sets enrichment data as reply attributes, which `linelog` then reads via `%{reply:Attribute-Name}`. We repurpose unused RADIUS attributes as carriers:

| Reply Attribute | Carries | Why this attribute |
|----------------|---------|-------------------|
| `Filter-Id` | `device_name` | String type, common in RADIUS, not used by EAP-TLS |
| `Login-LAT-Node` | `device_model` | String type, LAT attributes are obsolete |
| `Reply-Message` | `device_owner` (email) | String type, standard reply attribute |
| `Login-LAT-Port` | `ssid` | String type (unlike `Class` which is octets → renders as hex) |
| `Callback-Id` | `ap_name` | String type, not used in modern WiFi |
| `Connect-Info` | `site_name` | String type |
| `User-Name` | `email - serial` (rewritten) | Standard — AP caches this as the client identity |

**Important**: These reply attributes are set by `radius_lookups.py` and consumed by `json_log`/`acct_log` linelog modules. They are also sent back to the AP in the Access-Accept, but the AP ignores attributes it doesn't understand.

## FreeRADIUS Virtual Server

The default virtual server (`sites-available/default`) has a minimal pipeline:

```
authorize {
    filter_username        # Reject invalid characters (spaces allowed)
    eap { ok = return }    # Start EAP negotiation
}

authenticate {
    eap                    # Complete EAP-TLS handshake
}

preacct {
    acct_unique            # Generate unique accounting session ID
}

accounting {
    radius_lookups         # Jamf + UniFi enrichment (if enabled)
    sql                    # Write to MariaDB radacct table
    acct_log               # Write JSON accounting log
}

post-auth {
    radius_lookups         # Jamf + UniFi enrichment (if enabled)
    json_log               # Write JSON auth log

    Post-Auth-Type REJECT {
        json_log           # Also log rejections
    }
}
```

The `radius_lookups` module is only included if Jamf or UniFi integrations are enabled (`HAS_JAMF_LOOKUP` or `HAS_UNIFI_LOOKUP`).

## Observability Stack

### Datadog Agent

- Ships `/var/log/freeradius/radius-auth.json` and `radius-acct.json` to Datadog as logs
- Source tag: `freeradius`
- Infrastructure metrics (CPU, memory, disk, network)

### FreeRADIUS Prometheus Exporter

- [`freeradius_exporter`](https://github.com/bvantagelimited/freeradius_exporter) binary on `:9812`
- Scrapes FreeRADIUS status virtual server on `127.0.0.1:18121`
- Datadog OpenMetrics integration scrapes the exporter
- Metrics: `freeradius_total_access_accepts`, `freeradius_total_access_rejects`, `freeradius_total_accounting_requests`, etc.

### Log files on disk

| File | Content | Rotation |
|------|---------|----------|
| `/var/log/radius-bootstrap.log` | Startup script output | Appended on each boot |
| `/var/log/freeradius/radius-auth.json` | JSON auth events (Accept/Reject) | Datadog ships, no rotation configured |
| `/var/log/freeradius/radius-acct.json` | JSON accounting events (Start/Stop/Update) | Datadog ships, no rotation configured |
| `/var/log/freeradius/radius.log` | FreeRADIUS default log | Standard FreeRADIUS logrotate |

## Terraform templatefile() Escaping

The startup script uses `templatefile()` which has its own interpolation syntax that conflicts with shell, FreeRADIUS config, and Python. Rules:

| You want in output | Write in template | Why |
|-------------------|-------------------|-----|
| `${shell_var}` | `$${shell_var}` | `$$` escapes Terraform `${}` interpolation |
| `%{User-Name}` (FreeRADIUS) | `%%{User-Name}` | `%%` escapes Terraform `%{}` directive syntax |
| `%S` (FreeRADIUS timestamp) | `%%S` | Same `%%` escape |
| `${.module}` (FreeRADIUS config) | `$${.module}` | Same `$$` escape |
| `${project_id}` (Terraform var) | `${project_id}` | Normal interpolation |

**Heredoc quoting doesn't help** — Terraform processes `templatefile()` before the shell sees the script, so `<< 'EOF'` (which prevents shell expansion) has no effect on Terraform interpolation.

## Common Operations

### Deploy changes to a running VM

```bash
terraform apply
# Then on each VM:
sudo systemctl stop freeradius
sudo bash -c 'curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script" | bash'
```

### Check FreeRADIUS config without restarting

```bash
sudo freeradius -XC    # Config check (parses all config, loads modules, exits)
```

### Manually refresh Jamf cache

```bash
sudo /usr/local/bin/jamf-device-cache.sh
# Check result:
python3 -c 'import json; d=json.load(open("/etc/freeradius/3.0/jamf-device-cache.json")); print(f"{len(d)} devices")'
```

### Manually refresh UniFi cache

```bash
sudo /usr/local/bin/unifi-ap-cache.sh
cat /etc/freeradius/3.0/unifi-ap-cache.json | python3 -m json.tool | head -20
```

### View live auth events

```bash
sudo tail -f /var/log/freeradius/radius-auth.json | python3 -m json.tool
```

### View live accounting events

```bash
sudo tail -f /var/log/freeradius/radius-acct.json | python3 -m json.tool
```

### Query accounting database

```bash
sudo mysql radius -e "SELECT radacctid, username, acctstarttime, acctstoptime, \
  acctinputoctets, acctoutputoctets FROM radacct ORDER BY radacctid DESC LIMIT 10"
```

### Debug a specific device

```bash
SERIAL="H176YHQ9XV"
# Check Jamf cache
python3 -c "import json; d=json.load(open('/etc/freeradius/3.0/jamf-device-cache.json')); print(json.dumps(d.get('$SERIAL', 'NOT FOUND'), indent=2))"
# Check auth log
sudo grep "$SERIAL" /var/log/freeradius/radius-auth.json | tail -5 | python3 -m json.tool
# Check accounting
sudo grep "$SERIAL" /var/log/freeradius/radius-acct.json | tail -5 | python3 -m json.tool
```

### Add a new field to auth/accounting logs

1. If the field comes from a RADIUS request attribute (e.g. `Acct-Session-Id`), add it directly to the linelog format in `scripts/startup.sh` using `%%{Attribute-Name}`.
2. If the field comes from an external source (API, cache), add it to `radius_lookups.py`:
   - Choose an unused string-type reply attribute as a carrier (see [Reply Attribute Mapping](#reply-attribute-mapping))
   - Set it in `post_auth()` and/or `accounting()` via `reply_attrs.append(("Attribute-Name", value))`
   - Reference it in the linelog format as `%%{reply:Attribute-Name}`
3. Redeploy: `terraform apply` + re-run startup script on both VMs.
