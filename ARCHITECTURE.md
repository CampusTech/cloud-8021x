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

Terraform deploys **two** RADIUS VMs in separate zones. The diagram below shows
one node's base services; each also hosts optional EC/RSA step-ca services, the
loopback authorization webhook, and (in inventory mode) the Fleet challenge
broker. CA state uses shared Cloud SQL Postgres; RADIUS accounting remains in
**local MariaDB on each node**.

Fleet or Jamf bulk inventory runs every five minutes with VLAN policy enabled,
or every 30 minutes otherwise. Fleet certificate commands/scripts run hourly,
with results polled during inventory refresh. UniFi AP enrichment runs every
five minutes; separate source discovery runs every minute with up to 15 seconds
jitter. See [VLAN policy](docs/dynamic-vlans.md) and
[SCEP/inventory staging](docs/scep-identity-binding.md).

The compact diagram depicts the legacy Jamf enrichment path; Fleet replaces
that adapter and adds certificate inventory when configured.

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
│  ┌───────────────────┐     └─────────────────────────────┘  │
│  │Log files          │                                      │
│  │ radius-auth.json  │     ┌─────────────────────────────┐  │
│  │ radius-acct.json  │     │Cache files                  │  │
│  └───────────────────┘     │ /etc/freeradius/3.0/        │  │
│                            │  jamf-device-cache.json     │  │
│                            │  unifi-ap-cache.json        │  │
│                            └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

Key processes:
- **FreeRADIUS** — handles all RADIUS auth and accounting
- **MariaDB** — stores RADIUS accounting records (`radacct` table)
- **rlm_python3 modules** — enforce source/VLAN policy and read local caches for device/AP enrichment; exact certificate capture and signed accounting bindings support serial-free devices
- **Cron scripts** — run outside FreeRADIUS, call external APIs (Fleet or Jamf, plus AP integrations) and write cache files
- **Datadog Agent** — ships logs and metrics
- **freeradius_exporter** — Prometheus exporter, scraped by Datadog

## Startup Script Walkthrough

`scripts/startup.sh` is an idempotent bootstrap script that runs as root through the GCE startup-script runner. Terraform renders it with `templatefile()` and measures the complete UTF-8 byte count, including embedded modules and configuration. Values up to 262,144 bytes use inline `startup-script` metadata; larger scripts use `startup-script-url` pointing to a private Cloud Storage object. Both VMs use the same selection.

The bucket blocks public access and grants the VM service account read-only object access. Script objects have content-hashed names, so a changed script updates the metadata URL. Terraform always manages the bucket and object because the final script size can be unknown during the first plan. Inspect `terraform output startup_script_size_bytes` and `terraform output startup_script_transport` after applying.

### Execution order

| Step | Section | What it does |
|------|---------|-------------|
| 0 | Downgrade/idempotency guards | Refuse unsafe fingerprint downgrade; skip only if FreeRADIUS is running and the rendered script hash matches the completed bootstrap stamp |
| 1 | System prerequisites | `apt-get update`, install `curl`, `jq`, `python3` |
| 2 | Install packages | `freeradius`, `freeradius-utils`, `freeradius-mysql`, `freeradius-python3`, `mariadb-server` |
| 3 | Okta CA | Retrieve Okta Intermediate CA (and optionally Root CA) from Secret Manager → `/etc/freeradius/3.0/certs/okta-ca.pem` |
| 4 | Server certificates | Restore from Secret Manager if they exist, otherwise generate self-signed CA + server cert and store them back |
| 4a | Optional CA/webhook | Restore or initialize EC/RSA CAs, start step-ca and mTLS webhook, configure broker when enabled, select Smallstep server certificate and renewal timers |
| 5 | EAP-TLS config | Write `mods-available/eap` with certificate paths, TLS settings |
| 6 | RADIUS clients | Generate static clients from office CIDRs and shared secrets; optional UniFi discovery maintains dynamic client includes and firewall sources |
| 7 | MariaDB setup | Create `radius` database, load FreeRADIUS SQL schema, configure `mods-available/sql` |
| 8 | Whitespace filter patch | Disable whitespace rejection in `policy.d/filter` (SCEP CNs contain spaces) |
| 9 | Inventory + cache | Deploy Fleet or Jamf bulk/single-host adapters; optional Fleet certificate collection, policy snapshot and readiness report |
| 10 | UniFi cache | Write credentials, deploy `unifi-ap-cache.sh`, run initial cache build, set up cron |
| 10a | Python modules | Install policy, source-discovery, certificate and identity helpers; render `radius_lookups.py` and module configuration |
| 11 | JSON logging | Configure `json_log` (auth) and `acct_log` (accounting) linelog modules |
| 12 | Virtual server | Write `sites-available/default` with authorize → authenticate → accounting → post-auth pipeline |
| 13 | Status server | Configure status virtual server on `127.0.0.1:18121` for Prometheus exporter |
| 14 | Start FreeRADIUS | `freeradius -XC` (config check) then `systemctl start` |
| 15 | Datadog Agent | Install and configure with API key from Secret Manager |
| 16 | Prometheus exporter | Install `freeradius_exporter` binary, create systemd service |
| 17 | Datadog OpenMetrics | Configure Datadog to scrape the exporter |

### Re-running the startup script

A changed rendered script runs on the next bootstrap even if FreeRADIUS is active.
An unchanged completed script is skipped while the service is running. To force
a full run, stop FreeRADIUS first (do one node at a time after verifying failover):

```bash
sudo systemctl stop freeradius
sudo google_metadata_script_runner startup
```

The runner supports both inline metadata and Cloud Storage URLs. A `gcloud compute instances reset` also works (full VM reboot).

## Certificate Architecture

Client trust and server trust have distinct roles:

| Mode | Client validation bundle | Standard presented RADIUS server chain |
| --- | --- | --- |
| `okta` | Configured Okta intermediate/root | Legacy self-signed RADIUS CA → server leaf |
| `smallstep` | EC ACME and RSA SCEP CA chains | Smallstep EC root → EC intermediate → server leaf |
| `both` | Combined Okta and Smallstep bundle | Same Smallstep server chain |

The RSA SCEP root is not normally the server trust anchor. MDM Wi-Fi profiles
must trust the actual server root **and pin `server_cert_cn`** independently of
the client issuer. See [profile trust-root selection](examples/README.md#choose-the-correct-trust-root).

The bootstrap persists CA/server material in Secret Manager and restores it
on replacement VMs. Runtime private keys and credentials use protected local
files; they are not universally memory-only. EC/RSA intermediate signing uses
Cloud KMS HSM; the SCEP message decrypter is a shared software RSA key.
`radius-cert-renew.timer` renews the Smallstep server leaf before
expiry; devices/MDM separately renew their client certificates.

Attested ACME checks the Apple-signed permanent identifier against Fleet.
Inventory-mode SCEP deliberately issues the neutral CN `cloud-8021x-inventory`:
its challenge permits issuance, but cannot select a host or VLAN. RADIUS then
requires the exact leaf fingerprint reported through authenticated Fleet MDM
(Apple) or SYSTEM script results (Windows). Legacy identity-bound SCEP is
retained for other integrations. Never use the neutral CN as network identity.

## Authentication Flow

```text
Device → AP → authenticated RADIUS client (office shared secret)
  authorize: source guard (if discovery enabled), EAP negotiation
  authenticate: EAP-TLS chain validation and proof of private-key possession
    check-device-vlan: exact leaf fingerprint (inventory mode) or secure CN (legacy)
      → fresh inventory + current enrollment + office group mapping
      → reject unknown/ambiguous/stale/unmapped identities
  post-auth: current VLAN policy, verified identity, AP enrichment, JSON auth log
      → Access-Accept with VLAN attributes and signed Class (inventory mode)
  accounting: source guard, verify echoed Class, enrich, local SQL + JSON log
```

### Key details

- `User-Name`, CSR subjects, NAS identifiers, and client MACs are not trusted
  inventory identities. Fingerprint mode captures the actual TLS leaf and
  disables session resumption. Legacy CN mode rechecks policy on resumed sessions.
- The authenticated client's configured `shortname` selects the location.
  Its mapping is evaluated on authentication. `dynamic_vlans = false` omits
  all tunnel VLAN attributes while retaining device authorization.
- In inventory mode, accepted requests mint a signed RADIUS `Class` binding
  device ID, leaf fingerprint, and original VLAN to the office and client MAC.
  Accounting must echo it. Wrong/missing/expired bindings leave device/owner
  attribution empty and `identity_verified: false`. The shared signing key is
  restored before FreeRADIUS starts on both nodes; bindings last 30 days.
- Legacy log enrichment can resolve a serial from `User-Name`; those fields
  are diagnostic and do not have fingerprint-mode verification guarantees.
- `rewrite_username` defaults to false. When enabled, legacy mode returns
  `email - serial`; fingerprint mode uses `email - device_id`. It is only a
  display feature and does not change authorization.
- Changing groups/VLANs does not terminate active sessions. No CoA is sent.

## Log Enrichment Pipeline

The legacy enrichment diagram below shows Jamf. Fleet uses the same separation
of API work from authentication; fingerprint mode resolves verified device IDs
through `radius_identity.py` rather than trusting the outer username.

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

This describes legacy enrichment only. Policy snapshots are replaced only by a
complete successful bulk refresh; background lookups cannot authorize an unknown
device or extend policy/certificate freshness.

If a serial isn't in the Jamf cache (new device enrolled after last cache build), the Python module spawns a background thread that calls `jamf-device-fetch.sh` via `subprocess`. This does not block the current auth — the device gets empty Jamf fields this time, but the cache is updated for the next auth. The fetch script reads the existing cache file, adds the new entry, and writes it back atomically.

## JSON Log Schemas

### Auth log (`/var/log/freeradius/radius-auth.json`)

One JSON line per Access-Accept or Access-Reject. In fingerprint mode,
`radius_log.py`, called by `radius_lookups.py`, serializes JSON into `reply:Tmp-String-4`; linelog emits that
value, preserving proper escaping. Identity-related fields are:

| Field | Meaning in fingerprint mode |
| --- | --- |
| `identity_verified` | Whether this event has a valid signed device binding |
| `device_id` | Stable inventory ID, including serial-free BYOD |
| `certificate_fingerprint` | SHA-256 of the exact leaf DER |
| `serial` | Actual inventory serial, empty if unavailable |
| `raw_identity` / `cert_cn` | Diagnostic claims, never ownership lookup keys |
| `vlan_id` | Assigned VLAN as a string; empty at opted-out locations |
| `device_owner`, `device_name`, `device_model` | Metadata from fresh inventory for the verified device |

Rejected handshakes cannot assert verified ownership from their subjects. The
remaining transport/AP fields are shared with legacy mode. This table describes
the legacy attribute carriers as well:

| Field | Source | Example |
|-------|--------|---------|
| `timestamp` | FreeRADIUS `%S` | `2026-03-02 16:19:16` |
| `event` | Packet type | `Access-Accept` or `Access-Reject` |
| `serial` | Inventory serial in fingerprint mode; normalized identity in legacy mode | `H176YHQ9XV` |
| `device_owner` | Fleet/Jamf cache (via `Reply-Message`) | `robbie@campus.edu` |
| `device_name` | Fleet/Jamf cache (via `Filter-Id`) | `Robbie's MacBook Pro` |
| `device_model` | Fleet/Jamf cache (via `Login-LAT-Node`) | `MacBook Pro (16-inch, 2024) M4 Max` |
| `src_ip` | `Packet-Src-IP-Address` | `203.0.113.10` |
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

One JSON line per Acct-Start, Acct-Stop, or Interim-Update. Fingerprint mode also
includes `identity_verified`, `device_id`, `certificate_fingerprint`, `serial`,
and the original `vlan_id` from the verified Class binding, with the same rules
as auth logs. These are historical session assignments, not a new policy decision.

| Field | Source | Events |
|-------|--------|--------|
| `timestamp` | FreeRADIUS `%S` | All |
| `event` | `Acct-Status-Type` | `Acct-Start`, `Acct-Stop`, `Acct-Update` |
| `username` | `User-Name` (may be `email - serial`) | All |
| `device_owner` | Fleet/Jamf cache (via `Reply-Message`) | All |
| `device_name` | Fleet/Jamf cache (via `Filter-Id`) | All |
| `device_model` | Fleet/Jamf cache (via `Login-LAT-Node`) | All |
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
| `User-Name` | Optional `email - serial` or verified `email - device_id` | Standard — AP caches this as the client identity |

**Important**: These reply attributes are set by `radius_lookups.py` and consumed by `json_log`/`acct_log` linelog modules. They are also sent back to the AP in the Access-Accept, but the AP ignores attributes it doesn't understand.

## FreeRADIUS Virtual Server

The bootstrap renders `sites-available/default` plus `check-device-vlan` when
policy is enabled. EAP-TLS uses that policy virtual server during certificate
validation; post-auth reevaluates policy before sending the final acceptance.
`radius_source_check` guards both authentication and accounting when UniFi WAN
discovery is enabled. A rejection after TLS success removes acceptance-only
attributes and replaces EAP-Success with the rejection response.

`radius_lookups` runs for enabled Fleet/Jamf/AP integrations or policy/identity
features. It precedes auth/accounting JSON logging, including on the reject path.
Accounting also writes through `sql` to local MariaDB. The exact generated
configuration is in `scripts/startup.sh`; the packet tests in
[tests/README.md](tests/README.md) exercise this rendered configuration.

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

**Missing metrics**: The exporter defines several metrics that are always zero in this deployment: `outstanding_requests`, `queue_use_percentage`, `state`, `ema_window`, `last_packet_recv`, `last_packet_sent`. These map to FreeRADIUS vendor-specific attributes (Vendor ID 11344, attribute types 172-185) that are **home server statistics** — they are only populated when FreeRADIUS is acting as a proxy forwarding requests to other RADIUS servers. Since this is a standalone (non-proxying) deployment, FreeRADIUS never includes them in the status response. The exporter reports `freeradius_stats_error{error=""} 1` as a result. The Datadog dashboard intentionally omits widgets for these metrics.

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
| `%S` (FreeRADIUS timestamp) | `%S` | No Terraform directive brace; no escape needed |
| `${.module}` (FreeRADIUS config) | `$${.module}` | Same `$$` escape |
| `${project_id}` (Terraform var) | `${project_id}` | Normal interpolation |

**Heredoc quoting doesn't help** — Terraform processes `templatefile()` before the shell sees the script, so `<< 'EOF'` (which prevents shell expansion) has no effect on Terraform interpolation.

## Common Operations

### Deploy changes to a running VM

```bash
terraform apply
# Then on each VM:
sudo systemctl stop freeradius
sudo google_metadata_script_runner startup
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
sudo tail -f /var/log/freeradius/radius-auth.json | jq --unbuffered .
```

### View live accounting events

```bash
sudo tail -f /var/log/freeradius/radius-acct.json | jq --unbuffered .
```

### Query accounting database

```bash
sudo mysql radius -e "SELECT radacctid, username, acctstarttime, acctstoptime, \
  acctinputoctets, acctoutputoctets FROM radacct ORDER BY radacctid DESC LIMIT 10"
```

### Debug a specific device

For fingerprint mode, filter by verified stable device ID rather than assuming
a serial exists:

```sh
sudo jq -c 'select(.identity_verified == true and .device_id == "fleet:752")' \
  /var/log/freeradius/radius-auth.json
sudo cat /var/lib/cloud-8021x/certificate-readiness.json
```

Use the actual ID from inventory/logs. For legacy serial-based enrichment:

```bash
SERIAL="H176YHQ9XV"
# Check Jamf cache
python3 -c "import json; d=json.load(open('/etc/freeradius/3.0/jamf-device-cache.json')); print(json.dumps(d.get('$SERIAL', 'NOT FOUND'), indent=2))"
# Check auth log
sudo grep "$SERIAL" /var/log/freeradius/radius-auth.json | tail -5 | jq .
# Check accounting
sudo grep "$SERIAL" /var/log/freeradius/radius-acct.json | tail -5 | jq .
```

### Add a new field to auth/accounting logs

For fingerprint mode, update the JSON serializer in
`scripts/radius_log.py` and its regression tests as well as the dashboard/facets.
For legacy linelog formats:

1. If the field comes from a RADIUS request attribute (e.g. `Acct-Session-Id`), add it directly to the linelog format in `scripts/startup.sh` using `%%{Attribute-Name}`.
2. If the field comes from an external source (API, cache), add it to `radius_lookups.py`:
   - Choose an unused string-type reply attribute as a carrier (see [Reply Attribute Mapping](#reply-attribute-mapping))
   - Set it in `post_auth()` and/or `accounting()` via `reply_attrs.append(("Attribute-Name", value))`
   - Reference it in the linelog format as `%%{reply:Attribute-Name}`
3. Redeploy: `terraform apply` + re-run startup script on both VMs.
