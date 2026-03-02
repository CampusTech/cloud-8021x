#!/bin/bash
# FreeRADIUS bootstrap script for GCE
# Runs as root via GCE metadata startup-script.
# Idempotent — safe to re-run on reboot.
set -euo pipefail

LOG="/var/log/radius-bootstrap.log"
exec > >(tee -a "$LOG") 2>&1
echo "=== FreeRADIUS bootstrap started at $(date) ==="

# ---------------------------------------------------------------------------
# Template variables (injected by Terraform templatefile)
# ---------------------------------------------------------------------------
PROJECT_ID="${project_id}"
SERVER_CERT_CN="${server_cert_cn}"
SERVER_CERT_ORG="${server_cert_org}"
HAS_ROOT_CA="${has_root_ca}"
HAS_JAMF_LOOKUP="${has_jamf_lookup}"
HAS_UNIFI_LOOKUP="${has_unifi_lookup}"
REWRITE_USERNAME="${rewrite_username}"
REWRITE_USERNAME_SEPARATOR="${rewrite_username_separator}"
RADIUS_CLIENTS_JSON='${radius_clients_json}'
DATADOG_SITE="${datadog_site}"

# ---------------------------------------------------------------------------
# Idempotency — skip if FreeRADIUS is already running
# ---------------------------------------------------------------------------
if systemctl is-active --quiet freeradius 2>/dev/null; then
    echo "FreeRADIUS already running, skipping bootstrap."
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. System prerequisites
# ---------------------------------------------------------------------------
echo "=== Installing prerequisites ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y gnupg2 curl apt-transport-https ca-certificates \
    lsb-release jq openssl python3

# Install gcloud CLI if not already present (for Secret Manager)
if ! command -v gcloud &>/dev/null; then
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
        > /etc/apt/sources.list.d/google-cloud-sdk.list
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
        | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
    apt-get update
    apt-get install -y google-cloud-cli
fi

# ---------------------------------------------------------------------------
# 2. Install FreeRADIUS + MariaDB
# ---------------------------------------------------------------------------
echo "=== Installing FreeRADIUS and MariaDB ==="
apt-get install -y freeradius freeradius-utils freeradius-mysql freeradius-python3 mariadb-server

# Stop services while we configure them
systemctl stop freeradius 2>/dev/null || true

RADDB="/etc/freeradius/3.0"
CERT_DIR="$RADDB/certs"

# ---------------------------------------------------------------------------
# 3. Retrieve Okta CA certificate from Secret Manager
# ---------------------------------------------------------------------------
echo "=== Retrieving Okta CA certificate(s) ==="

gcloud secrets versions access latest \
    --secret=okta-ca-cert \
    --project="$PROJECT_ID" > "$CERT_DIR/okta-ca.pem"

# If the Root CA is provided, append it to build the full trust chain
if [ "$HAS_ROOT_CA" = "true" ]; then
    echo "Fetching Okta Root CA certificate..."
    gcloud secrets versions access latest \
        --secret=okta-root-ca-cert \
        --project="$PROJECT_ID" >> "$CERT_DIR/okta-ca.pem"
    echo "Full CA chain: Intermediate + Root"
fi

# ---------------------------------------------------------------------------
# 4. RADIUS server certificates
#    Try to restore from Secret Manager first (persists across VM replacements).
#    If not found, generate fresh certs and store them back.
# ---------------------------------------------------------------------------
echo "=== Setting up RADIUS server certificates ==="

# Helper: fetch a secret, return 1 if it doesn't have a version yet
fetch_secret() {
    gcloud secrets versions access latest \
        --secret="$1" --project="$PROJECT_ID" 2>/dev/null
}

CERTS_FROM_SM=false

if fetch_secret "radius-server-cert" > /dev/null 2>&1; then
    echo "Restoring certificates from Secret Manager..."
    fetch_secret "radius-server-ca-key"  > "$CERT_DIR/server-ca-key.pem"
    fetch_secret "radius-server-ca-cert" > "$CERT_DIR/server-ca.pem"
    fetch_secret "radius-server-key"     > "$CERT_DIR/server-key.pem"
    fetch_secret "radius-server-cert"    > "$CERT_DIR/server-cert.pem"
    fetch_secret "radius-dh-params"      > "$CERT_DIR/dh.pem"
    CERTS_FROM_SM=true
    echo "Certificates restored from Secret Manager."
fi

if [ "$CERTS_FROM_SM" = false ] && [ ! -f "$CERT_DIR/server-cert.pem" ]; then
    echo "Generating new RADIUS server certificates..."
    CA_DAYS=3650          # CA valid for 10 years
    SERVER_DAYS=825       # Server cert valid for ~2.25 years (Apple max)
    KEY_SIZE=2048
    CA_CN="$SERVER_CERT_ORG RADIUS CA"

    # Generate CA key + cert
    openssl genrsa -out "$CERT_DIR/server-ca-key.pem" $KEY_SIZE
    openssl req -new -x509 \
        -key "$CERT_DIR/server-ca-key.pem" \
        -out "$CERT_DIR/server-ca.pem" \
        -days $CA_DAYS \
        -subj "/O=$SERVER_CERT_ORG/CN=$CA_CN"

    # Generate server key + CSR
    openssl genrsa -out "$CERT_DIR/server-key.pem" $KEY_SIZE
    openssl req -new \
        -key "$CERT_DIR/server-key.pem" \
        -out /tmp/server.csr \
        -subj "/O=$SERVER_CERT_ORG/CN=$SERVER_CERT_CN"

    # Extensions (SAN, key usage)
    cat > /tmp/server-ext.cnf << EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$SERVER_CERT_CN
EXTEOF

    # Sign server cert with CA
    openssl x509 -req -in /tmp/server.csr \
        -CA "$CERT_DIR/server-ca.pem" \
        -CAkey "$CERT_DIR/server-ca-key.pem" \
        -CAcreateserial \
        -out "$CERT_DIR/server-cert.pem" \
        -days $SERVER_DAYS \
        -extfile /tmp/server-ext.cnf -extensions v3_req

    # DH parameters (FreeRADIUS requires this)
    openssl dhparam -out "$CERT_DIR/dh.pem" 2048

    rm -f /tmp/server.csr /tmp/server-ext.cnf "$CERT_DIR/server-ca.srl"

    # Store certs in Secret Manager so they survive VM replacement
    echo "Storing certificates in Secret Manager..."
    gcloud secrets versions add radius-server-ca-key  --data-file="$CERT_DIR/server-ca-key.pem" --project="$PROJECT_ID"
    gcloud secrets versions add radius-server-ca-cert --data-file="$CERT_DIR/server-ca.pem"     --project="$PROJECT_ID"
    gcloud secrets versions add radius-server-key     --data-file="$CERT_DIR/server-key.pem"    --project="$PROJECT_ID"
    gcloud secrets versions add radius-server-cert    --data-file="$CERT_DIR/server-cert.pem"   --project="$PROJECT_ID"
    gcloud secrets versions add radius-dh-params      --data-file="$CERT_DIR/dh.pem"            --project="$PROJECT_ID"

    echo "Server certificate generated for CN=$SERVER_CERT_CN and stored in Secret Manager."
    echo "IMPORTANT: Upload $CERT_DIR/server-ca.pem to Jamf as a trusted cert."
else
    echo "Server certificate already exists on disk, skipping generation."
fi

chown freerad:freerad "$CERT_DIR"/server-*.pem "$CERT_DIR"/dh.pem "$CERT_DIR"/okta-ca.pem
chmod 600 "$CERT_DIR/server-key.pem" "$CERT_DIR/server-ca-key.pem"
chmod 644 "$CERT_DIR/server-cert.pem" "$CERT_DIR/server-ca.pem" \
          "$CERT_DIR/dh.pem" "$CERT_DIR/okta-ca.pem"

# ---------------------------------------------------------------------------
# 5. Configure EAP-TLS (native FreeRADIUS format)
#    ca_file points directly to the Okta Intermediate CA for client cert
#    validation — no post-start PEM file patching needed.
# ---------------------------------------------------------------------------
echo "=== Configuring EAP-TLS ==="

cat > "$RADDB/mods-available/eap" << 'EAPEOF'
eap {
    default_eap_type = tls
    timer_expire = 60
    ignore_unknown_eap_types = no
    max_sessions = 4096

    tls-config tls-common {
        private_key_file = $${certdir}/server-key.pem
        certificate_file = $${certdir}/server-cert.pem
        ca_file = $${certdir}/okta-ca.pem
        dh_file = $${certdir}/dh.pem
        ca_path = $${cadir}

        cipher_list = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256"
        ecdh_curve = "prime256v1"

        tls_min_version = "1.2"
        tls_max_version = "1.3"

        verify {
        }
    }

    tls {
        tls = tls-common
    }
}
EAPEOF

# ---------------------------------------------------------------------------
# 6. Configure RADIUS clients — per-office UniFi APs
#    Each office has its own RADIUS shared secret stored in Secret Manager.
# ---------------------------------------------------------------------------
echo "=== Configuring RADIUS clients (per-office secrets) ==="

# Start with localhost client (needed for status virtual server / exporter)
cat > "$RADDB/clients.conf" << 'CLIENTSHEADER'
client localhost {
    ipaddr = 127.0.0.1
    secret = testing123
    require_message_authenticator = no
    nastype = other
}

client localhost_ipv6 {
    ipaddr = ::1
    secret = testing123
    require_message_authenticator = no
    nastype = other
}
CLIENTSHEADER

CLIENT_INDEX=0
for office in $(echo "$RADIUS_CLIENTS_JSON" | jq -r 'keys[]'); do
    secret_id=$(echo "$RADIUS_CLIENTS_JSON" | jq -r --arg k "$office" '.[$k].secret_id')
    description=$(echo "$RADIUS_CLIENTS_JSON" | jq -r --arg k "$office" '.[$k].description')

    echo "  Fetching secret for office: $office ($secret_id)"
    OFFICE_SECRET=$(gcloud secrets versions access latest \
        --secret="$secret_id" --project="$PROJECT_ID")

    for cidr in $(echo "$RADIUS_CLIENTS_JSON" | jq -r --arg k "$office" '.[$k].cidrs[]'); do
        cat >> "$RADDB/clients.conf" << CLIENTEOF

client $${office}-$${CLIENT_INDEX} {
    ipaddr = $cidr
    secret = $OFFICE_SECRET
    shortname = $office
    nastype = other
}
CLIENTEOF
        CLIENT_INDEX=$((CLIENT_INDEX + 1))
    done
done

# ---------------------------------------------------------------------------
# 7. Configure MariaDB for RADIUS accounting
#    FreeRADIUS native sql module for RADIUS accounting.
# ---------------------------------------------------------------------------
echo "=== Setting up MariaDB for RADIUS accounting ==="

# Ensure MariaDB is running
systemctl start mariadb

# Wait for MariaDB to be ready
for i in $(seq 1 30); do
    if mysqladmin ping 2>/dev/null; then
        echo "MariaDB is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: MariaDB did not start within 60 seconds"
        exit 1
    fi
    sleep 2
done

# Create radius database and user if they don't exist
mysql -u root << 'SQLEOF'
CREATE DATABASE IF NOT EXISTS radius;
GRANT ALL ON radius.* TO 'radius'@'localhost' IDENTIFIED BY 'radpass';
FLUSH PRIVILEGES;
SQLEOF

# Import FreeRADIUS schema (creates radacct, radpostauth, etc.)
SCHEMA_FILE="$RADDB/mods-config/sql/main/mysql/schema.sql"
if ! mysql -u root radius -e "SELECT 1 FROM radacct LIMIT 1" 2>/dev/null; then
    mysql -u root radius < "$SCHEMA_FILE"
    echo "RADIUS schema imported."
fi

# Configure FreeRADIUS sql module
cat > "$RADDB/mods-available/sql" << 'SQLEOF'
sql {
    driver = "rlm_sql_mysql"
    dialect = "mysql"

    server = "localhost"
    port = 3306
    login = "radius"
    password = "radpass"
    radius_db = "radius"

    acct_table1 = "radacct"
    acct_table2 = "radacct"
    postauth_table = "radpostauth"
    authcheck_table = "radcheck"
    authreply_table = "radreply"
    groupcheck_table = "radgroupcheck"
    groupreply_table = "radgroupreply"
    usergroup_table = "radusergroup"
    client_table = "nas"
    group_attribute = "SQL-Group"

    read_clients = no
    delete_stale_sessions = yes

    sql_user_name = "%%{User-Name}"

    $INCLUDE $${modconfdir}/$${.:instance}/main/$${dialect}/queries.conf

    pool {
        start = 5
        min = 3
        max = 10
        spare = 3
        uses = 0
        lifetime = 0
        idle_timeout = 60
    }
}
SQLEOF

ln -sf "$RADDB/mods-available/sql" "$RADDB/mods-enabled/sql"

# ---------------------------------------------------------------------------
# 8. Disable whitespace rejection in filter_username policy
#    EAP-TLS uses certificates for auth — the User-Name (EAP outer identity)
#    may contain spaces (e.g. from SCEP subject CNs) and should not be rejected.
# ---------------------------------------------------------------------------
echo "=== Patching filter_username policy ==="

python3 - "$RADDB/policy.d/filter" << 'FILTERPYEOF'
import sys
path = sys.argv[1]
with open(path, "r") as f:
    lines = f.readlines()

i = 0
while i < len(lines):
    if "&User-Name =~ / /" in lines[i] and "if" in lines[i]:
        # Found the whitespace check. Comment this line and everything
        # until the matching closing brace (brace-counting).
        brace_depth = 0
        for j in range(i, len(lines)):
            stripped = lines[j].rstrip()
            brace_depth += stripped.count("{") - stripped.count("}")
            indent = len(lines[j]) - len(lines[j].lstrip())
            lines[j] = lines[j][:indent] + "#" + lines[j][indent:]
            if brace_depth <= 0:
                break
        print("Whitespace filter disabled")
        break
    i += 1
else:
    print("Whitespace filter block not found (may already be disabled)")

with open(path, "w") as f:
    f.writelines(lines)
FILTERPYEOF

# ---------------------------------------------------------------------------
# 9. Jamf device owner lookup (optional)
#    Resolves serial number → assigned user email, device name, model via
#    Jamf Pro API. Credentials stored as JSON for Python module consumption.
# ---------------------------------------------------------------------------
if [ "$HAS_JAMF_LOOKUP" = "true" ]; then
    echo "=== Configuring Jamf device owner lookup ==="

    # Fetch Jamf API credentials from Secret Manager
    JAMF_URL=$(gcloud secrets versions access latest \
        --secret=jamf-url --project="$PROJECT_ID")
    JAMF_CLIENT_ID=$(gcloud secrets versions access latest \
        --secret=jamf-client-id --project="$PROJECT_ID")
    JAMF_CLIENT_SECRET=$(gcloud secrets versions access latest \
        --secret=jamf-client-secret --project="$PROJECT_ID")

    # Write JSON credentials file for the Python lookup module
    cat > "$RADDB/jamf-credentials.json" << JAMFCREDEOF
{"url": "$JAMF_URL", "client_id": "$JAMF_CLIENT_ID", "client_secret": "$JAMF_CLIENT_SECRET"}
JAMFCREDEOF
    chown freerad:freerad "$RADDB/jamf-credentials.json"
    chmod 640 "$RADDB/jamf-credentials.json"

    # Create token cache directory
    mkdir -p /tmp/jamf-token
    chown freerad:freerad /tmp/jamf-token

    # Deploy the Jamf device cache script (bulk inventory pull)
    cat > /usr/local/bin/jamf-device-cache.sh << 'JAMFCACHEEOF'
#!/bin/bash
# Fetches all Jamf inventory, builds serial -> device info cache.
# Called on boot and every 30 minutes via cron.
set -uo pipefail

CRED_FILE="/etc/freeradius/3.0/jamf-credentials.json"
CACHE_FILE="/etc/freeradius/3.0/jamf-device-cache.json"
TOKEN_CACHE="/tmp/jamf-token/token.json"

[ -f "$CRED_FILE" ] || exit 0

JAMF_URL=$(python3 -c "import json; print(json.load(open('$CRED_FILE'))['url'])")
CLIENT_ID=$(python3 -c "import json; print(json.load(open('$CRED_FILE'))['client_id'])")
CLIENT_SECRET=$(python3 -c "import json; print(json.load(open('$CRED_FILE'))['client_secret'])")

# Get OAuth2 token (check cache first)
get_token() {
    if [ -f "$TOKEN_CACHE" ]; then
        EXPIRES=$(python3 -c "import json; print(json.load(open('$TOKEN_CACHE')).get('expires_at',0))" 2>/dev/null || echo 0)
        NOW=$(date +%s)
        if [ "$NOW" -lt "$EXPIRES" ]; then
            python3 -c "import json; print(json.load(open('$TOKEN_CACHE'))['access_token'])"
            return
        fi
    fi
    RESP=$(curl -sf --connect-timeout 5 --max-time 10 \
        -X POST "$JAMF_URL/api/v1/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET") || return 1
    TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
    EXPIRES_IN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_in',300))")
    NOW=$(date +%s)
    echo "{\"access_token\":\"$TOKEN\",\"expires_at\":$((NOW + EXPIRES_IN - 30))}" > "$TOKEN_CACHE"
    echo "$TOKEN"
}

TOKEN=$(get_token) || exit 0
[ -n "$TOKEN" ] || exit 0

# Paginate through all inventory
python3 << PYEOF
import json, urllib.request, sys

token = "$TOKEN"
url = "$JAMF_URL"
cache = {}
page = 0
page_size = 100
import time
now = int(time.time())

while True:
    api_url = (
        f"{url}/api/v3/computers-inventory"
        f"?section=GENERAL&section=HARDWARE&section=USER_AND_LOCATION"
        f"&page={page}&page-size={page_size}"
    )
    req = urllib.request.Request(api_url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    try:
        resp = urllib.request.urlopen(req, timeout=30)
    except Exception as e:
        print(f"API error on page {page}: {e}", file=sys.stderr)
        break
    data = json.loads(resp.read())
    results = data.get("results", [])
    if not results:
        break
    for device in results:
        serial = (device.get("hardware") or {}).get("serialNumber") or ""
        if not serial:
            continue
        cache[serial] = {
            "email": (device.get("userAndLocation") or {}).get("email") or "",
            "device_name": (device.get("general") or {}).get("name") or "",
            "device_model": (device.get("hardware") or {}).get("model") or "",
            "ts": now,
        }
    total_count = data.get("totalCount", 0)
    if (page + 1) * page_size >= total_count:
        break
    page += 1

with open("$${CACHE_FILE}.tmp", "w") as f:
    json.dump(cache, f)
import os
os.replace("$${CACHE_FILE}.tmp", "$CACHE_FILE")
print(f"Jamf cache: {len(cache)} devices")
PYEOF
JAMFCACHEEOF
    chmod 755 /usr/local/bin/jamf-device-cache.sh

    # Run initial cache build
    /usr/local/bin/jamf-device-cache.sh || true

    # Set up cron to refresh cache every 30 minutes
    echo "*/30 * * * * root /usr/local/bin/jamf-device-cache.sh" > /etc/cron.d/jamf-device-cache
    chmod 644 /etc/cron.d/jamf-device-cache

    # Deploy single-device fetch script (for cache misses)
    cat > /usr/local/bin/jamf-device-fetch.sh << 'JAMFFETCHEOF'
#!/bin/bash
# Fetches a single device from Jamf by serial, updates the cache file.
# Called from FreeRADIUS Python module via subprocess on cache miss.
set -uo pipefail

SERIAL="$1"
CRED_FILE="/etc/freeradius/3.0/jamf-credentials.json"
CACHE_FILE="/etc/freeradius/3.0/jamf-device-cache.json"
TOKEN_CACHE="/tmp/jamf-token/token.json"

[ -n "$SERIAL" ] || exit 1
[ -f "$CRED_FILE" ] || exit 0

JAMF_URL=$(python3 -c "import json; print(json.load(open('$CRED_FILE'))['url'])")
CLIENT_ID=$(python3 -c "import json; print(json.load(open('$CRED_FILE'))['client_id'])")
CLIENT_SECRET=$(python3 -c "import json; print(json.load(open('$CRED_FILE'))['client_secret'])")

# Get OAuth2 token (check cache first)
if [ -f "$TOKEN_CACHE" ]; then
    EXPIRES=$(python3 -c "import json; print(json.load(open('$TOKEN_CACHE')).get('expires_at',0))" 2>/dev/null || echo 0)
    NOW=$(date +%s)
    if [ "$NOW" -lt "$EXPIRES" ]; then
        TOKEN=$(python3 -c "import json; print(json.load(open('$TOKEN_CACHE'))['access_token'])")
    fi
fi
if [ -z "$${TOKEN:-}" ]; then
    RESP=$(curl -sf --connect-timeout 5 --max-time 10 \
        -X POST "$JAMF_URL/api/v1/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET") || exit 0
    TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
    EXPIRES_IN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_in',300))")
    NOW=$(date +%s)
    echo "{\"access_token\":\"$TOKEN\",\"expires_at\":$((NOW + EXPIRES_IN - 30))}" > "$TOKEN_CACHE"
fi

# Fetch single device
ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SERIAL'))")
RESP=$(curl -sf --connect-timeout 5 --max-time 10 \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/json" \
    "$JAMF_URL/api/v3/computers-inventory?section=GENERAL&section=HARDWARE&section=USER_AND_LOCATION&filter=hardware.serialNumber%3D%3D%22$${ENCODED}%22&page-size=1") || exit 0

# Update cache file
python3 << PYEOF
import json, os, time, sys

serial = "$SERIAL"
data = json.loads('''$RESP''')
results = data.get("results", [])
if not results:
    sys.exit(0)

device = results[0]
entry = {
    "email": (device.get("userAndLocation") or {}).get("email") or "",
    "device_name": (device.get("general") or {}).get("name") or "",
    "device_model": (device.get("hardware") or {}).get("model") or "",
    "ts": int(time.time()),
}

cache = {}
if os.path.isfile("$CACHE_FILE"):
    with open("$CACHE_FILE") as f:
        cache = json.load(f)

cache[serial] = entry
tmp = "$${CACHE_FILE}.tmp"
with open(tmp, "w") as f:
    json.dump(cache, f)
os.replace(tmp, "$CACHE_FILE")
PYEOF
JAMFFETCHEOF
    chmod 755 /usr/local/bin/jamf-device-fetch.sh

    echo "Jamf credentials and cache configured."
fi

# ---------------------------------------------------------------------------
# 10. UniFi AP name + site name lookup (optional)
#     Caches device list from UniFi cloud API, resolves NAS-IP to AP name.
#     Uses Packet-Src-IP-Address (public gateway IP) to disambiguate sites.
# ---------------------------------------------------------------------------
if [ "$HAS_UNIFI_LOOKUP" = "true" ]; then
    echo "=== Configuring UniFi AP name lookup ==="

    # Fetch UniFi API key from Secret Manager
    UNIFI_API_KEY=$(gcloud secrets versions access latest \
        --secret=unifi-api-key --project="$PROJECT_ID")

    # Write credentials file for the cache/lookup scripts
    cat > "$RADDB/unifi-credentials.conf" << UNIFICREDEOF
UNIFI_API_KEY=$UNIFI_API_KEY
UNIFICREDEOF
    chown freerad:freerad "$RADDB/unifi-credentials.conf"
    chmod 640 "$RADDB/unifi-credentials.conf"

    # Deploy the cache refresh script
    cat > /usr/local/bin/unifi-ap-cache.sh << 'UNIFICACHEEOF'
#!/bin/bash
# Fetches UniFi hosts + devices, builds AP name + site name cache.
# Called on boot and every 5 minutes via cron.
set -uo pipefail

CRED_FILE="/etc/freeradius/3.0/unifi-credentials.conf"
CACHE_FILE="/etc/freeradius/3.0/unifi-ap-cache.json"

[ -f "$CRED_FILE" ] || exit 0
source "$CRED_FILE"

API="https://api.ui.com/v1"

HOSTS=$(curl -sf --connect-timeout 5 --max-time 15 \
    -H "X-API-Key: $UNIFI_API_KEY" \
    -H "Accept: application/json" \
    "$API/hosts" 2>/dev/null) || exit 0

DEVICES=$(curl -sf --connect-timeout 5 --max-time 15 \
    -H "X-API-Key: $UNIFI_API_KEY" \
    -H "Accept: application/json" \
    "$API/devices" 2>/dev/null) || exit 0

python3 << PYEOF
import json

hosts_data = json.loads('''$HOSTS''')
devices_data = json.loads('''$DEVICES''')

# Build hostId -> {wans: [ipv4s], hostname: str}
host_info = {}
for h in hosts_data.get("data", []):
    rs = h.get("reportedState", {})
    wans = [w["ipv4"] for w in rs.get("wans", []) if w.get("ipv4")]
    hostname = rs.get("hostname", "").replace("-", " ")
    if wans:
        host_info[h["id"]] = {"wans": wans, "hostname": hostname}

# Build wan_ip:lan_ip -> ap_name, wan_ip -> site_name, and mac -> {ap, site}
ap_map = {}
site_map = {}
by_mac = {}
for entry in devices_data.get("data", []):
    hid = entry.get("hostId")
    info = host_info.get(hid)
    if not info:
        continue
    site_name = entry.get("hostName", info["hostname"])
    for suffix in [" UNVR", " unvr"]:
        if site_name.endswith(suffix):
            site_name = site_name[:-len(suffix)]
    for wip in info["wans"]:
        site_map[wip] = site_name
    for dev in entry.get("devices", []):
        if dev.get("productLine") != "network":
            continue
        lip = dev.get("ip", "")
        name = dev.get("name", "")
        mac = dev.get("mac", "").upper()
        if lip and name:
            for wip in info["wans"]:
                ap_map[f"{wip}:{lip}"] = name
        if mac and name:
            by_mac[mac] = {"ap_name": name, "site_name": site_name}

with open("$${CACHE_FILE}.tmp", "w") as f:
    json.dump({"devices": ap_map, "sites": site_map, "by_mac": by_mac}, f)
PYEOF

    mv "$${CACHE_FILE}.tmp" "$CACHE_FILE" 2>/dev/null
UNIFICACHEEOF
    chmod 755 /usr/local/bin/unifi-ap-cache.sh

    # Run initial cache build
    /usr/local/bin/unifi-ap-cache.sh || true

    # Set up cron to refresh cache every 5 minutes
    echo "*/5 * * * * root /usr/local/bin/unifi-ap-cache.sh" > /etc/cron.d/unifi-ap-cache
    chmod 644 /etc/cron.d/unifi-ap-cache

    echo "UniFi AP cache configured."
fi

# ---------------------------------------------------------------------------
# 10a. Python lookup module (rlm_python3)
#      Single module handles both Jamf and UniFi lookups in post-auth and
#      accounting. Sets reply attributes directly — no exec output parsing.
# ---------------------------------------------------------------------------
if [ "$HAS_JAMF_LOOKUP" = "true" ] || [ "$HAS_UNIFI_LOOKUP" = "true" ]; then
    echo "=== Configuring Python lookup module ==="

    mkdir -p "$RADDB/mods-config/python3"

    cat > "$RADDB/mods-config/python3/radius_lookups.py" << 'PYMODEOF'
import radiusd
import json
import os
import time
import threading
import subprocess

JAMF_CRED_FILE = "/etc/freeradius/3.0/jamf-credentials.json"
JAMF_DEVICE_CACHE = "/etc/freeradius/3.0/jamf-device-cache.json"
JAMF_FETCH_SCRIPT = "/usr/local/bin/jamf-device-fetch.sh"
JAMF_CACHE_TTL = 3600  # 1 hour
UNIFI_CACHE_FILE = "/etc/freeradius/3.0/unifi-ap-cache.json"

# In-memory device cache — loaded from disk on startup and periodically
_jamf_cache = {}      # serial -> {"email":..., "device_name":..., "device_model":..., "ts": epoch}
_jamf_cache_lock = threading.Lock()
_jamf_cache_mtime = 0  # last mtime of disk cache when we loaded it
_pending_lookups = set()  # serials currently being fetched in background
_pending_lock = threading.Lock()


def _load_cache_from_disk():
    """Load the Jamf device cache from disk into memory if it changed."""
    global _jamf_cache, _jamf_cache_mtime
    try:
        if not os.path.isfile(JAMF_DEVICE_CACHE):
            return
        mtime = os.path.getmtime(JAMF_DEVICE_CACHE)
        if mtime == _jamf_cache_mtime:
            return  # no change
        with open(JAMF_DEVICE_CACHE, "r") as f:
            data = json.load(f)
        with _jamf_cache_lock:
            _jamf_cache = data
            _jamf_cache_mtime = mtime
        radiusd.radlog(radiusd.L_INFO,
            f"Loaded Jamf cache from disk: {len(data)} devices")
    except Exception as e:
        radiusd.radlog(radiusd.L_ERR, f"Failed to load Jamf cache from disk: {e}")


def _jamf_background_fetch(serial):
    """Background thread: call external script to fetch a single device."""
    try:
        subprocess.run(
            [JAMF_FETCH_SCRIPT, serial],
            timeout=15, capture_output=True,
        )
        # Reload cache from disk to pick up the new entry
        _load_cache_from_disk()
    except Exception as e:
        radiusd.radlog(radiusd.L_ERR, f"Jamf background fetch failed for {serial}: {e}")
    finally:
        with _pending_lock:
            _pending_lookups.discard(serial)


def instantiate(p):
    radiusd.radlog(radiusd.L_INFO, "radius_lookups module loaded")
    _load_cache_from_disk()
    return 0


def _get_cached_jamf(serial):
    """Read Jamf data from in-memory cache. Returns dict or None.
    If cache miss or expired, kicks off a background fetch via external script."""
    # Reload from disk if file changed (picks up cron updates)
    _load_cache_from_disk()

    now = int(time.time())

    with _jamf_cache_lock:
        entry = _jamf_cache.get(serial)

    if entry and (now - entry.get("ts", 0)) < JAMF_CACHE_TTL:
        return entry

    # Cache miss or expired — trigger background fetch if not already pending
    if os.path.isfile(JAMF_FETCH_SCRIPT):
        with _pending_lock:
            if serial not in _pending_lookups:
                _pending_lookups.add(serial)
                t = threading.Thread(target=_jamf_background_fetch, args=(serial,),
                                     daemon=True)
                t.start()

    # Return stale data if available (better than nothing)
    if entry:
        return entry
    return None


def _unifi_lookup(called_station_id):
    """Look up AP name and site from UniFi cache by Called-Station-Id MAC.

    Called-Station-Id contains a BSSID (per-radio virtual MAC) which is the
    AP's base MAC + a small offset (0-7) on the last byte. We try exact match
    first, then decrement the last byte by 1-7 to find the base MAC.
    Returns dict or None.
    """
    if not called_station_id or not os.path.isfile(UNIFI_CACHE_FILE):
        return None

    # Called-Station-Id format: "AA-BB-CC-DD-EE-FF:SSID" or "AA-BB-CC-DD-EE-FF"
    # Extract MAC portion (before colon) and normalize to uppercase hex without separators
    mac_part = called_station_id.split(":")[0] if ":" in called_station_id else called_station_id
    mac = mac_part.replace("-", "").replace(".", "").upper()

    if len(mac) != 12:
        return None

    with open(UNIFI_CACHE_FILE, "r") as f:
        cache = json.load(f)

    by_mac = cache.get("by_mac", {})

    # Try exact BSSID match first
    if mac in by_mac:
        entry = by_mac[mac]
        return {"ap_name": entry.get("ap_name", ""), "site_name": entry.get("site_name", "")}

    # BSSID = base_mac + offset (0-7) on last byte. Try decrementing to find base MAC.
    prefix = mac[:10]
    last_byte = int(mac[10:12], 16)
    for offset in range(1, 8):
        candidate = prefix + format(last_byte - offset, "02X")
        if candidate in by_mac:
            entry = by_mac[candidate]
            return {"ap_name": entry.get("ap_name", ""), "site_name": entry.get("site_name", "")}

    return None


def _get_attr(p, attr_name):
    """Extract a request attribute from p.

    p is always a dict with pass_all_vps_dict=yes:
      {"request": ((name, value), ...), "reply": ..., ...}
    The request value is a tuple of (name, value) tuples, NOT a dict.
    """
    request = p.get("request", ()) if isinstance(p, dict) else p
    if isinstance(request, (list, tuple)):
        for item in request:
            if isinstance(item, (list, tuple)) and len(item) >= 2 and item[0] == attr_name:
                return item[1]
    return ""


def post_auth(p):
    """Post-auth: Jamf device lookup (from cache) + UniFi AP/site lookup."""
    try:
        user_name = _get_attr(p, "User-Name")
        called_station = _get_attr(p, "Called-Station-Id")

        reply_attrs = []

        # Jamf lookup — read from local cache (instant, no API call)
        serial = user_name.strip()
        if serial:
            try:
                jamf = _get_cached_jamf(serial)
                if jamf:
                    if jamf.get("device_name"):
                        reply_attrs.append(("Filter-Id", jamf["device_name"]))
                    if jamf.get("device_model"):
                        reply_attrs.append(("Login-LAT-Node", jamf["device_model"]))
                    if jamf.get("email"):
                        reply_attrs.append(("Reply-Message", jamf["email"]))
            except Exception as e:
                radiusd.radlog(radiusd.L_ERR, f"Jamf cache read failed: {e}")

        # Extract SSID from Called-Station-Id (format: "AA-BB-CC-DD-EE-FF:SSID")
        if called_station and ":" in called_station:
            ssid = called_station.split(":", 1)[1]
            if ssid:
                reply_attrs.append(("Login-LAT-Port", ssid))

        # UniFi lookup — use Called-Station-Id (AP BSSID) to identify AP
        if called_station:
            try:
                unifi = _unifi_lookup(called_station)
                if unifi:
                    if unifi["ap_name"]:
                        reply_attrs.append(("Callback-Id", unifi["ap_name"]))
                    if unifi["site_name"]:
                        reply_attrs.append(("Connect-Info", unifi["site_name"]))
            except Exception as e:
                radiusd.radlog(radiusd.L_ERR, f"UniFi lookup failed: {e}")

        if reply_attrs:
            return radiusd.RLM_MODULE_UPDATED, {"reply": tuple(reply_attrs)}
        return radiusd.RLM_MODULE_OK

    except Exception as e:
        radiusd.radlog(radiusd.L_ERR, f"radius_lookups post_auth error: {e}")
        return radiusd.RLM_MODULE_OK


def accounting(p):
    """Accounting: enrich with Jamf device info + UniFi AP/site from cache."""
    try:
        user_name = _get_attr(p, "User-Name")
        called_station = _get_attr(p, "Called-Station-Id")

        reply_attrs = []

        # Extract serial from User-Name — may be "email - serial" if AP
        # cached the rewritten identity from post-auth, or just the serial
        serial = user_name.strip()
        if " - " in serial:
            serial = serial.rsplit(" - ", 1)[1]

        if serial:
            try:
                jamf = _get_cached_jamf(serial)
                if jamf:
                    if jamf.get("device_name"):
                        reply_attrs.append(("Filter-Id", jamf["device_name"]))
                    if jamf.get("device_model"):
                        reply_attrs.append(("Login-LAT-Node", jamf["device_model"]))
                    if jamf.get("email"):
                        reply_attrs.append(("Reply-Message", jamf["email"]))
            except Exception as e:
                radiusd.radlog(radiusd.L_ERR, f"Jamf cache read in accounting failed: {e}")

        # UniFi lookup
        if called_station:
            try:
                unifi = _unifi_lookup(called_station)
                if unifi:
                    if unifi["ap_name"]:
                        reply_attrs.append(("Callback-Id", unifi["ap_name"]))
                    if unifi["site_name"]:
                        reply_attrs.append(("Connect-Info", unifi["site_name"]))
            except Exception as e:
                radiusd.radlog(radiusd.L_ERR, f"UniFi lookup in accounting failed: {e}")

        if reply_attrs:
            return radiusd.RLM_MODULE_UPDATED, {"reply": tuple(reply_attrs)}
        return radiusd.RLM_MODULE_OK

    except Exception as e:
        radiusd.radlog(radiusd.L_ERR, f"radius_lookups accounting error: {e}")
        return radiusd.RLM_MODULE_OK


PYMODEOF
    chown -R freerad:freerad "$RADDB/mods-config/python3"

    # Configure FreeRADIUS python3 module
    cat > "$RADDB/mods-available/radius_lookups" << 'PYLOOKUPEOF'
python3 radius_lookups {
    python_path = /etc/freeradius/3.0/mods-config/python3
    module = radius_lookups
    pass_all_vps_dict = yes

    mod_instantiate = $${.module}
    func_instantiate = instantiate

    mod_post_auth = $${.module}
    func_post_auth = post_auth

    mod_accounting = $${.module}
    func_accounting = accounting

}
PYLOOKUPEOF
    ln -sf "$RADDB/mods-available/radius_lookups" "$RADDB/mods-enabled/radius_lookups"

    echo "Python lookup module configured."
fi

# ---------------------------------------------------------------------------
# 11. Configure FreeRADIUS JSON auth logging (linelog module)
#     Emits one JSON line per Access-Accept/Reject for Datadog SIEM.
#     device_owner field is populated by Jamf lookup (empty if disabled).
#     username is always the serial (request attribute); device_owner is the email.
# ---------------------------------------------------------------------------
echo "=== Configuring JSON auth logging ==="

cat > "$RADDB/mods-available/json_log" << 'JSONLOGEOF'
linelog json_log {
    filename = /var/log/freeradius/radius-auth.json
    permissions = 0640

    format = ""
    reference = "messages.%%{%%{reply:Packet-Type}:-unknown}"

    messages {
        Access-Accept = "{\"timestamp\":\"%S\",\"event\":\"Access-Accept\",\"serial\":\"%%{User-Name}\",\"device_owner\":\"%%{reply:Reply-Message}\",\"device_name\":\"%%{reply:Filter-Id}\",\"device_model\":\"%%{reply:Login-LAT-Node}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"nas_port\":\"%%{NAS-Port}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"ssid\":\"%%{reply:Login-LAT-Port}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\",\"session_id\":\"%%{Acct-Session-Id}\",\"multi_session_id\":\"%%{Acct-Multi-Session-Id}\",\"cert_cn\":\"%%{TLS-Client-Cert-Common-Name}\",\"cert_issuer\":\"%%{TLS-Client-Cert-Issuer}\",\"cert_expiration\":\"%%{TLS-Client-Cert-Expiration}\"}"
        Access-Reject = "{\"timestamp\":\"%S\",\"event\":\"Access-Reject\",\"username\":\"%%{User-Name}\",\"device_name\":\"%%{reply:Filter-Id}\",\"device_model\":\"%%{reply:Login-LAT-Node}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"nas_port\":\"%%{NAS-Port}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"ssid\":\"%%{reply:Login-LAT-Port}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\",\"session_id\":\"%%{Acct-Session-Id}\",\"multi_session_id\":\"%%{Acct-Multi-Session-Id}\",\"cert_cn\":\"%%{TLS-Client-Cert-Common-Name}\",\"cert_issuer\":\"%%{TLS-Client-Cert-Issuer}\",\"cert_expiration\":\"%%{TLS-Client-Cert-Expiration}\",\"reject_reason\":\"%%{Module-Failure-Message}\"}"
        unknown = "{\"timestamp\":\"%S\",\"event\":\"unknown\",\"username\":\"%%{User-Name}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\"}"
    }
}
JSONLOGEOF

ln -sf "$RADDB/mods-available/json_log" "$RADDB/mods-enabled/json_log"

touch /var/log/freeradius/radius-auth.json
chown freerad:freerad /var/log/freeradius/radius-auth.json
chmod 640 /var/log/freeradius/radius-auth.json

# Configure JSON accounting log (session start/stop/update with usage data)
cat > "$RADDB/mods-available/acct_log" << 'ACCTLOGEOF'
linelog acct_log {
    filename = /var/log/freeradius/radius-acct.json
    permissions = 0640

    format = ""
    reference = "messages.%%{Acct-Status-Type}"

    messages {
        Start = "{\"timestamp\":\"%S\",\"event\":\"Acct-Start\",\"username\":\"%%{User-Name}\",\"device_owner\":\"%%{reply:Reply-Message}\",\"device_name\":\"%%{reply:Filter-Id}\",\"device_model\":\"%%{reply:Login-LAT-Node}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"called_station\":\"%%{Called-Station-Id}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\",\"session_id\":\"%%{Acct-Session-Id}\",\"multi_session_id\":\"%%{Acct-Multi-Session-Id}\"}"
        Stop = "{\"timestamp\":\"%S\",\"event\":\"Acct-Stop\",\"username\":\"%%{User-Name}\",\"device_owner\":\"%%{reply:Reply-Message}\",\"device_name\":\"%%{reply:Filter-Id}\",\"device_model\":\"%%{reply:Login-LAT-Node}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"called_station\":\"%%{Called-Station-Id}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\",\"session_id\":\"%%{Acct-Session-Id}\",\"multi_session_id\":\"%%{Acct-Multi-Session-Id}\",\"session_time\":%%{Acct-Session-Time},\"input_bytes\":%%{Acct-Input-Octets},\"output_bytes\":%%{Acct-Output-Octets},\"terminate_cause\":\"%%{%%{Acct-Terminate-Cause}:-Unknown}\"}"
        Interim-Update = "{\"timestamp\":\"%S\",\"event\":\"Acct-Update\",\"username\":\"%%{User-Name}\",\"device_owner\":\"%%{reply:Reply-Message}\",\"device_name\":\"%%{reply:Filter-Id}\",\"device_model\":\"%%{reply:Login-LAT-Node}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"called_station\":\"%%{Called-Station-Id}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\",\"session_id\":\"%%{Acct-Session-Id}\",\"multi_session_id\":\"%%{Acct-Multi-Session-Id}\",\"session_time\":%%{Acct-Session-Time},\"input_bytes\":%%{Acct-Input-Octets},\"output_bytes\":%%{Acct-Output-Octets}\"}"
    }
}
ACCTLOGEOF

ln -sf "$RADDB/mods-available/acct_log" "$RADDB/mods-enabled/acct_log"

touch /var/log/freeradius/radius-acct.json
chown freerad:freerad /var/log/freeradius/radius-acct.json
chmod 640 /var/log/freeradius/radius-acct.json

# ---------------------------------------------------------------------------
# 11. Configure default virtual server (site)
#     Clean EAP-TLS-only site with SQL accounting and JSON logging.
# ---------------------------------------------------------------------------
echo "=== Configuring default virtual server ==="

# Build post-auth section — single Python module handles both Jamf + UniFi
POSTAUTH_MODULES=""
if [ "$HAS_JAMF_LOOKUP" = "true" ] || [ "$HAS_UNIFI_LOOKUP" = "true" ]; then
    POSTAUTH_MODULES="radius_lookups
        "
fi
# Set reply:User-Name to "email - serial" for NAS display (e.g. UniFi 802.1X Identity).
# This must be done via unlang, not rlm_python3, because rlm_python3 silently ignores
# User-Name in its return dict. The Python module stores the email in Reply-Message;
# unlang reads it and builds the enriched identity. The EAP module's mod_post_auth
# preserves an existing reply:User-Name (per RFC 3579).
if [ "$REWRITE_USERNAME" = "true" ]; then
    POSTAUTH_MODULES="$${POSTAUTH_MODULES}if (&reply:Reply-Message) {
            update reply {
                User-Name := \"%%{reply:Reply-Message}$${REWRITE_USERNAME_SEPARATOR}%%{User-Name}\"
            }
        }
        "
fi
POSTAUTH_MODULES="$${POSTAUTH_MODULES}json_log"

# Build accounting section — enrichment + SQL + JSON log
ACCT_MODULES=""
if [ "$HAS_JAMF_LOOKUP" = "true" ] || [ "$HAS_UNIFI_LOOKUP" = "true" ]; then
    ACCT_MODULES="radius_lookups
        "
fi
ACCT_MODULES="$${ACCT_MODULES}sql
        acct_log"

cat > "$RADDB/sites-available/default" << SITEEOF
server default {
    listen {
        type = auth
        ipaddr = *
        port = 1812
    }

    listen {
        type = acct
        ipaddr = *
        port = 1813
    }

    authorize {
        filter_username
        eap {
            ok = return
        }
    }

    authenticate {
        eap
    }

    preacct {
        acct_unique
    }

    accounting {
        $ACCT_MODULES
    }

    post-auth {
        $POSTAUTH_MODULES
        Post-Auth-Type REJECT {
            json_log
        }
    }
}
SITEEOF

# Remove inner-tunnel site (not needed for EAP-TLS)
rm -f "$RADDB/sites-enabled/inner-tunnel"

# ---------------------------------------------------------------------------
# 12. Configure status virtual server (for Prometheus exporter)
# ---------------------------------------------------------------------------
echo "=== Configuring status virtual server ==="

cat > "$RADDB/sites-available/status" << 'STATUSEOF'
server status {
    listen {
        type = status
        ipaddr = 127.0.0.1
        port = 18121
    }

    client localhost_status {
        ipaddr = 127.0.0.1
        secret = testing123
    }

    authorize {
        ok
    }
}
STATUSEOF

ln -sf "$RADDB/sites-available/status" "$RADDB/sites-enabled/status"

# ---------------------------------------------------------------------------
# 13. Start FreeRADIUS
# ---------------------------------------------------------------------------
echo "=== Starting FreeRADIUS ==="

# Validate config before starting
if ! freeradius -XC 2>&1 | tail -5; then
    echo "ERROR: FreeRADIUS config check failed. Full output:"
    freeradius -XC 2>&1 || true
    exit 1
fi

systemctl enable freeradius
systemctl start freeradius
echo "FreeRADIUS started successfully."

# ---------------------------------------------------------------------------
# 14. Install Datadog Agent
# ---------------------------------------------------------------------------
echo "=== Installing Datadog Agent ==="

DD_API_KEY=$(gcloud secrets versions access latest \
    --secret=datadog-api-key --project="$PROJECT_ID")

DD_API_KEY="$DD_API_KEY" DD_SITE="$DATADOG_SITE" \
    bash -c "$(curl -fsSL https://install.datadoghq.com/scripts/install_script_agent7.sh)"

# Set hostname to GCE instance name (ensures host tag matches dashboard queries)
INSTANCE_NAME=$(curl -sS -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/name)
sed -i "s/^# hostname:.*$/hostname: $INSTANCE_NAME/" /etc/datadog-agent/datadog.yaml
if ! grep -q "^hostname:" /etc/datadog-agent/datadog.yaml; then
    echo "hostname: $INSTANCE_NAME" >> /etc/datadog-agent/datadog.yaml
fi

# Enable log collection
sed -i 's/^# logs_enabled: false/logs_enabled: true/' /etc/datadog-agent/datadog.yaml
if ! grep -q "^logs_enabled: true" /etc/datadog-agent/datadog.yaml; then
    echo "logs_enabled: true" >> /etc/datadog-agent/datadog.yaml
fi

# Add dd-agent to freerad group so it can read FreeRADIUS logs
usermod -aG freerad dd-agent

# Configure log sources
mkdir -p /etc/datadog-agent/conf.d/freeradius.d
cat > /etc/datadog-agent/conf.d/freeradius.d/conf.yaml << 'DDLOGSEOF'
logs:
  - type: file
    path: /var/log/freeradius/radius-auth.json
    source: freeradius
    service: radius-auth
    log_processing_rules:
      - type: exclude_at_match
        name: exclude_empty
        pattern: "^$"

  - type: file
    path: /var/log/freeradius/radius-acct.json
    source: freeradius
    service: radius-acct
    log_processing_rules:
      - type: exclude_at_match
        name: exclude_empty
        pattern: "^$"

  - type: file
    path: /var/log/freeradius/radius.log
    source: freeradius
    service: radius

  - type: file
    path: /var/log/radius-bootstrap.log
    source: freeradius
    service: bootstrap
DDLOGSEOF

# ---------------------------------------------------------------------------
# 15. Install FreeRADIUS Prometheus Exporter
# ---------------------------------------------------------------------------
echo "=== Installing FreeRADIUS Prometheus Exporter ==="

EXPORTER_VERSION="0.1.9"
EXPORTER_URL="https://github.com/bvantagelimited/freeradius_exporter/releases/download/$${EXPORTER_VERSION}/freeradius_exporter-$${EXPORTER_VERSION}-amd64.tar.gz"
EXPORTER_DIR="/tmp/freeradius_exporter"

if [ ! -f /usr/local/bin/freeradius_exporter ]; then
    mkdir -p "$EXPORTER_DIR"
    curl -fsSL "$EXPORTER_URL" | tar xz -C "$EXPORTER_DIR"
    cp "$EXPORTER_DIR/freeradius_exporter-$${EXPORTER_VERSION}-amd64/freeradius_exporter" /usr/local/bin/freeradius_exporter
    chmod +x /usr/local/bin/freeradius_exporter
    rm -rf "$EXPORTER_DIR"
fi

# Create systemd service for the exporter
STATUS_SECRET="testing123"
cat > /etc/systemd/system/freeradius-exporter.service << EXPSVCEOF
[Unit]
Description=FreeRADIUS Prometheus Exporter
After=freeradius.service
Wants=freeradius.service

[Service]
Type=simple
ExecStart=/usr/local/bin/freeradius_exporter \\
    -radius.address=127.0.0.1:18121 \\
    -radius.secret=$STATUS_SECRET \\
    -web.listen-address=127.0.0.1:9812
Restart=always
RestartSec=5
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EXPSVCEOF

systemctl daemon-reload
systemctl enable freeradius-exporter
systemctl start freeradius-exporter

# ---------------------------------------------------------------------------
# 16. Configure Datadog OpenMetrics integration for FreeRADIUS metrics
# ---------------------------------------------------------------------------
echo "=== Configuring Datadog OpenMetrics for FreeRADIUS ==="

mkdir -p /etc/datadog-agent/conf.d/openmetrics.d
cat > /etc/datadog-agent/conf.d/openmetrics.d/conf.yaml << 'DDMETRICSEOF'
instances:
  - openmetrics_endpoint: http://localhost:9812/metrics
    namespace: freeradius
    metrics:
      - freeradius_total_access_requests: total_access_requests
      - freeradius_total_access_accepts: total_access_accepts
      - freeradius_total_access_rejects: total_access_rejects
      - freeradius_total_access_challenges: total_access_challenges
      - freeradius_total_auth_responses: total_auth_responses
      - freeradius_total_auth_duplicate_requests: total_auth_duplicate_requests
      - freeradius_total_auth_malformed_requests: total_auth_malformed_requests
      - freeradius_total_auth_invalid_requests: total_auth_invalid_requests
      - freeradius_total_auth_dropped_requests: total_auth_dropped_requests
      - freeradius_total_auth_unknown_types: total_auth_unknown_types
      - freeradius_total_acct_requests: total_acct_requests
      - freeradius_total_acct_responses: total_acct_responses
      - freeradius_total_acct_duplicate_requests: total_acct_duplicate_requests
      - freeradius_total_acct_malformed_requests: total_acct_malformed_requests
      - freeradius_total_acct_invalid_requests: total_acct_invalid_requests
      - freeradius_total_acct_dropped_requests: total_acct_dropped_requests
      - freeradius_total_acct_unknown_types: total_acct_unknown_types
      - freeradius_queue_len_internal: queue_len_internal
      - freeradius_queue_len_proxy: queue_len_proxy
      - freeradius_queue_len_auth: queue_len_auth
      - freeradius_queue_len_acct: queue_len_acct
      - freeradius_queue_len_detail: queue_len_detail
      - freeradius_queue_pps_in: queue_pps_in
      - freeradius_queue_pps_out: queue_pps_out
      - freeradius_start_time: start_time
      - freeradius_hup_time: hup_time
      - freeradius_up: up
DDMETRICSEOF

# Restart Datadog Agent to pick up all new config
systemctl restart datadog-agent

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
EXTERNAL_IP=$(curl -sf -H "Metadata-Flavor: Google" \
    http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)

echo ""
echo "=== FreeRADIUS bootstrap completed at $(date) ==="
echo "=== RADIUS: $EXTERNAL_IP:1812/udp (auth), $EXTERNAL_IP:1813/udp (acct) ==="
echo ""
echo "Next steps:"
echo "  1. Upload $CERT_DIR/server-ca.pem to Jamf as a trusted certificate"
echo "  2. Configure UniFi RADIUS profile with IP $EXTERNAL_IP and shared secret"
