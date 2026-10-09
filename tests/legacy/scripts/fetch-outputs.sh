#!/bin/bash
# Fetch deployment outputs and secrets into the out/ directory.
# Run after terraform apply + VMs have finished bootstrapping.
# Requires: terraform, gcloud, jq
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
OUT_DIR="$REPO_DIR/out"

# Ensure we're in the Terraform root
cd "$REPO_DIR"

mkdir -p "$OUT_DIR"

echo "=== Fetching Terraform outputs ==="
PROJECT_ID=$(terraform output -raw project_id)
echo "Project: $PROJECT_ID"

# Save full terraform outputs as config.json
terraform output -json > "$OUT_DIR/config.json"
echo "Wrote out/config.json"

# ---------------------------------------------------------------------------
# RADIUS server CA certificate (for Jamf WiFi profile trust anchor)
# ---------------------------------------------------------------------------
echo "=== Fetching RADIUS server CA certificate ==="
if gcloud secrets versions access latest \
    --secret=radius-server-ca-cert \
    --project="$PROJECT_ID" > "$OUT_DIR/radius-ca.cer" 2>/dev/null; then
    echo "Wrote out/radius-ca.cer"
else
    echo "WARNING: radius-server-ca-cert not yet available (VM may still be bootstrapping)"
    rm -f "$OUT_DIR/radius-ca.cer"
fi

# ---------------------------------------------------------------------------
# RADIUS server certificate (full cert, for reference)
# ---------------------------------------------------------------------------
echo "=== Fetching RADIUS server certificate ==="
if gcloud secrets versions access latest \
    --secret=radius-server-cert \
    --project="$PROJECT_ID" > "$OUT_DIR/radius-server.cer" 2>/dev/null; then
    echo "Wrote out/radius-server.cer"
else
    echo "WARNING: radius-server-cert not yet available (VM may still be bootstrapping)"
    rm -f "$OUT_DIR/radius-server.cer"
fi

# ---------------------------------------------------------------------------
# Per-office RADIUS shared secrets
# ---------------------------------------------------------------------------
echo "=== Fetching per-office RADIUS shared secrets ==="
OFFICES=$(terraform output -json unifi_radius_config | jq -r '.shared_secrets | keys[]')
for OFFICE in $OFFICES; do
    SECRET_ID="radius-shared-secret-${OFFICE}"
    if gcloud secrets versions access latest \
        --secret="$SECRET_ID" \
        --project="$PROJECT_ID" > "$OUT_DIR/shared-secret-${OFFICE}.txt" 2>/dev/null; then
        echo "Wrote out/shared-secret-${OFFICE}.txt"
    else
        echo "WARNING: $SECRET_ID not found"
        rm -f "$OUT_DIR/shared-secret-${OFFICE}.txt"
    fi
done

# ---------------------------------------------------------------------------
# Generate summary markdown
# ---------------------------------------------------------------------------
echo "=== Generating summary ==="
PRIMARY_IP=$(terraform output -raw radius_primary_ip)
SECONDARY_IP=$(terraform output -raw radius_secondary_ip)
SSH_PRIMARY=$(terraform output -raw ssh_command_primary)
SSH_SECONDARY=$(terraform output -raw ssh_command_secondary)

cat > "$OUT_DIR/README.md" <<EOF
# RADIUS Deployment Summary

**Project:** \`$PROJECT_ID\`
**Generated:** $(date -u '+%Y-%m-%d %H:%M UTC')

## Server IPs

| Role | IP Address |
|------|------------|
| Primary | \`$PRIMARY_IP\` |
| Secondary | \`$SECONDARY_IP\` |

**Auth Port:** 1812
**Accounting Port:** 1813

## SSH Access

\`\`\`bash
# Primary
$SSH_PRIMARY

# Secondary
$SSH_SECONDARY
\`\`\`

## Per-Office Shared Secrets

| Office | Shared Secret |
|--------|---------------|
EOF

for OFFICE in $OFFICES; do
    SECRET_FILE="$OUT_DIR/shared-secret-${OFFICE}.txt"
    if [ -f "$SECRET_FILE" ]; then
        SECRET=$(cat "$SECRET_FILE")
        echo "| $OFFICE | \`$SECRET\` |" >> "$OUT_DIR/README.md"
    fi
done

cat >> "$OUT_DIR/README.md" <<EOF

## RADIUS Server CA Certificate

EOF

if [ -f "$OUT_DIR/radius-ca.cer" ]; then
    cat >> "$OUT_DIR/README.md" <<EOF
Upload this to Jamf as a Certificate payload. Use as the trust anchor in the WiFi profile.

\`\`\`
$(cat "$OUT_DIR/radius-ca.cer")
\`\`\`
EOF
else
    echo "*Not yet available — VMs still bootstrapping. Re-run \`./scripts/fetch-outputs.sh\` in a few minutes.*" >> "$OUT_DIR/README.md"
fi

cat >> "$OUT_DIR/README.md" <<EOF

## UniFi / Meraki Setup

For each office, configure RADIUS with:

- **Primary Server:** \`$PRIMARY_IP\`
- **Secondary Server:** \`$SECONDARY_IP\`
- **Auth Port:** 1812
- **Accounting Port:** 1813
- **Shared Secret:** see table above (each office has its own)
- **Interim Update Interval:** 120 seconds
EOF

echo "Wrote out/README.md"

echo ""
echo "=== Done — outputs saved to out/ ==="
ls -la "$OUT_DIR/"
