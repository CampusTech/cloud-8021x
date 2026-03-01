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
apt-get install -y freeradius freeradius-utils freeradius-mysql mariadb-server

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
#    Resolves serial number → assigned user email via Jamf Pro API.
#    Runs in post-auth so it never blocks authentication.
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

    # Write credentials file for the lookup script
    cat > "$RADDB/jamf-credentials.conf" << JAMFCREDEOF
JAMF_URL=$JAMF_URL
JAMF_CLIENT_ID=$JAMF_CLIENT_ID
JAMF_CLIENT_SECRET=$JAMF_CLIENT_SECRET
JAMFCREDEOF
    chown freerad:freerad "$RADDB/jamf-credentials.conf"
    chmod 640 "$RADDB/jamf-credentials.conf"

    # Deploy the lookup script
    cat > /usr/local/bin/jamf-radius-lookup.sh << 'JAMFSCRIPTEOF'
#!/bin/bash
# Jamf Pro device owner lookup for FreeRADIUS exec module.
# Called with serial number as $1, outputs FreeRADIUS attribute pairs.
# On any failure, exits silently to avoid blocking auth.
set -uo pipefail

SERIAL="$1"
CRED_FILE="/etc/freeradius/3.0/jamf-credentials.conf"
TOKEN_CACHE="/tmp/jamf-token.json"

[ -z "$SERIAL" ] && exit 0
[ -f "$CRED_FILE" ] || exit 0

source "$CRED_FILE"

# Get or refresh OAuth2 token
get_token() {
    local now
    now=$(date +%s)

    # Check cached token
    if [ -f "$TOKEN_CACHE" ]; then
        local expires_at
        expires_at=$(jq -r '.expires_at // 0' "$TOKEN_CACHE" 2>/dev/null || echo 0)
        if [ "$now" -lt "$expires_at" ]; then
            jq -r '.access_token' "$TOKEN_CACHE" 2>/dev/null
            return 0
        fi
    fi

    # Request new token
    local response
    response=$(curl -sf --connect-timeout 3 --max-time 5 \
        -X POST "$JAMF_URL/api/v1/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=$JAMF_CLIENT_ID&client_secret=$JAMF_CLIENT_SECRET" 2>/dev/null) || return 1

    local token expires_in
    token=$(echo "$response" | jq -r '.access_token // empty' 2>/dev/null)
    expires_in=$(echo "$response" | jq -r '.expires_in // 300' 2>/dev/null)

    [ -z "$token" ] && return 1

    # Cache with expiry (subtract 30s buffer)
    local expires_at=$(( now + expires_in - 30 ))
    echo "{\"access_token\":\"$token\",\"expires_at\":$expires_at}" > "$TOKEN_CACHE"
    echo "$token"
}

TOKEN=$(get_token) || exit 0
[ -z "$TOKEN" ] && exit 0

# Query Jamf Pro API for device owner
RESPONSE=$(curl -sf --connect-timeout 3 --max-time 5 \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/json" \
    "$JAMF_URL/api/v3/computers-inventory?section=USER_AND_LOCATION&filter=hardware.serialNumber%3D%3D%22$SERIAL%22&page-size=1" 2>/dev/null) || exit 0

EMAIL=$(echo "$RESPONSE" | jq -r '.results[0].userAndLocation.email // empty' 2>/dev/null)

# Only output attributes if we got an email
if [ -n "$EMAIL" ]; then
    echo "Reply-Message := \"$EMAIL\""
    echo "User-Name := \"$EMAIL - $SERIAL\""
fi
JAMFSCRIPTEOF
    chmod 755 /usr/local/bin/jamf-radius-lookup.sh

    # Create cache directory
    mkdir -p /tmp/jamf-token
    chown freerad:freerad /tmp/jamf-token

    # Configure FreeRADIUS exec module for Jamf lookup
    cat > "$RADDB/mods-available/jamf_lookup" << 'JAMFMODEOF'
exec jamf_lookup {
    wait = yes
    program = "/usr/local/bin/jamf-radius-lookup.sh %%{User-Name}"
    input_pairs = request
    output_pairs = reply
    shell_escape = yes
    timeout = 10
}
JAMFMODEOF
    ln -sf "$RADDB/mods-available/jamf_lookup" "$RADDB/mods-enabled/jamf_lookup"
    echo "Jamf device owner lookup configured."
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

# Build wan_ip:lan_ip -> ap_name and wan_ip -> site_name
ap_map = {}
site_map = {}
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
        if lip and name:
            for wip in info["wans"]:
                ap_map[f"{wip}:{lip}"] = name

with open("$${CACHE_FILE}.tmp", "w") as f:
    json.dump({"devices": ap_map, "sites": site_map}, f)
PYEOF

    mv "$${CACHE_FILE}.tmp" "$CACHE_FILE" 2>/dev/null
UNIFICACHEEOF
    chmod 755 /usr/local/bin/unifi-ap-cache.sh

    # Deploy the FreeRADIUS lookup script
    cat > /usr/local/bin/unifi-ap-lookup.sh << 'UNIFILOOKUPEOF'
#!/bin/bash
# Called by FreeRADIUS exec module with Packet-Src-IP and NAS-IP.
# Reads from cached file, outputs reply attributes.
SRC_IP="$1"
NAS_IP="$2"
CACHE="/etc/freeradius/3.0/unifi-ap-cache.json"

[ -z "$SRC_IP" ] || [ -z "$NAS_IP" ] && exit 0
[ -f "$CACHE" ] || exit 0

AP_NAME=$(jq -r --arg key "$${SRC_IP}:$${NAS_IP}" '.devices[$key] // empty' "$CACHE" 2>/dev/null)
SITE_NAME=$(jq -r --arg ip "$SRC_IP" '.sites[$ip] // empty' "$CACHE" 2>/dev/null)

[ -n "$AP_NAME" ] && echo "Callback-Id := \"$AP_NAME\""
[ -n "$SITE_NAME" ] && echo "Connect-Info := \"$SITE_NAME\""
UNIFILOOKUPEOF
    chmod 755 /usr/local/bin/unifi-ap-lookup.sh

    # Run initial cache build
    /usr/local/bin/unifi-ap-cache.sh || true

    # Set up cron to refresh cache every 5 minutes
    echo "*/5 * * * * root /usr/local/bin/unifi-ap-cache.sh" > /etc/cron.d/unifi-ap-cache
    chmod 644 /etc/cron.d/unifi-ap-cache

    # Configure FreeRADIUS exec module for UniFi lookup
    cat > "$RADDB/mods-available/unifi_lookup" << 'UNIFIMODEOF'
exec unifi_lookup {
    wait = yes
    program = "/usr/local/bin/unifi-ap-lookup.sh %%{Packet-Src-IP-Address} %%{NAS-IP-Address}"
    input_pairs = request
    output_pairs = reply
    shell_escape = yes
    timeout = 3
}
UNIFIMODEOF
    ln -sf "$RADDB/mods-available/unifi_lookup" "$RADDB/mods-enabled/unifi_lookup"
    echo "UniFi AP name lookup configured."
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
        Access-Accept = "{\"timestamp\":\"%S\",\"event\":\"Access-Accept\",\"serial\":\"%%{User-Name}\",\"device_owner\":\"%%{reply:Reply-Message}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"nas_port\":\"%%{NAS-Port}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\",\"cert_cn\":\"%%{TLS-Client-Cert-Common-Name}\",\"cert_issuer\":\"%%{TLS-Client-Cert-Issuer}\"}"
        Access-Reject = "{\"timestamp\":\"%S\",\"event\":\"Access-Reject\",\"username\":\"%%{User-Name}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"nas_port\":\"%%{NAS-Port}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\",\"cert_cn\":\"%%{TLS-Client-Cert-Common-Name}\",\"cert_issuer\":\"%%{TLS-Client-Cert-Issuer}\",\"reject_reason\":\"%%{Module-Failure-Message}\"}"
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
        Start = "{\"timestamp\":\"%S\",\"event\":\"Acct-Start\",\"username\":\"%%{User-Name}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"session_id\":\"%%{Acct-Session-Id}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\"}"
        Stop = "{\"timestamp\":\"%S\",\"event\":\"Acct-Stop\",\"username\":\"%%{User-Name}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"session_id\":\"%%{Acct-Session-Id}\",\"session_time\":%%{Acct-Session-Time},\"input_bytes\":%%{Acct-Input-Octets},\"output_bytes\":%%{Acct-Output-Octets},\"terminate_cause\":\"%%{Acct-Terminate-Cause}\",\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\"}"
        Interim-Update = "{\"timestamp\":\"%S\",\"event\":\"Acct-Update\",\"username\":\"%%{User-Name}\",\"src_ip\":\"%%{Packet-Src-IP-Address}\",\"nas_ip\":\"%%{NAS-IP-Address}\",\"calling_station\":\"%%{Calling-Station-Id}\",\"session_id\":\"%%{Acct-Session-Id}\",\"session_time\":%%{Acct-Session-Time},\"input_bytes\":%%{Acct-Input-Octets},\"output_bytes\":%%{Acct-Output-Octets},\"site_name\":\"%%{reply:Connect-Info}\",\"ap_name\":\"%%{reply:Callback-Id}\"}"
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

# Build post-auth section — conditionally include lookups before logging
POSTAUTH_MODULES=""
[ "$HAS_JAMF_LOOKUP" = "true" ] && POSTAUTH_MODULES="$${POSTAUTH_MODULES}jamf_lookup
        "
[ "$HAS_UNIFI_LOOKUP" = "true" ] && POSTAUTH_MODULES="$${POSTAUTH_MODULES}unifi_lookup
        "
POSTAUTH_MODULES="$${POSTAUTH_MODULES}json_log"

# Build accounting section — conditionally include UniFi lookup for enrichment
ACCT_MODULES=""
[ "$HAS_UNIFI_LOOKUP" = "true" ] && ACCT_MODULES="unifi_lookup
        "
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

mkdir -p "$EXPORTER_DIR"
curl -fsSL "$EXPORTER_URL" | tar xz -C "$EXPORTER_DIR"
cp "$EXPORTER_DIR/freeradius_exporter-$${EXPORTER_VERSION}-amd64/freeradius_exporter" /usr/local/bin/freeradius_exporter
chmod +x /usr/local/bin/freeradius_exporter
rm -rf "$EXPORTER_DIR"

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
      - freeradius_total_access_requests
      - freeradius_total_access_accepts
      - freeradius_total_access_rejects
      - freeradius_total_access_challenges
      - freeradius_total_auth_responses
      - freeradius_total_auth_duplicate_requests
      - freeradius_total_auth_malformed_requests
      - freeradius_total_auth_invalid_requests
      - freeradius_total_auth_dropped_requests
      - freeradius_total_acct_requests
      - freeradius_total_acct_responses
      - freeradius_total_acct_duplicate_requests
      - freeradius_total_acct_dropped_requests
      - freeradius_queue_len_internal
      - freeradius_queue_len_proxy
      - freeradius_queue_len_auth
      - freeradius_queue_len_acct
      - freeradius_queue_pps_in
      - freeradius_queue_pps_out
      - freeradius_queue_use_percentage
      - freeradius_up
      - freeradius_outstanding_requests
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
