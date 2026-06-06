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
HAS_FLEET_LOOKUP="${has_fleet_lookup}"
FLEET_API_BASE_URL="${fleet_api_base_url}"
HAS_UNIFI_LOOKUP="${has_unifi_lookup}"
REWRITE_USERNAME="${rewrite_username}"
REWRITE_USERNAME_SEPARATOR="${rewrite_username_separator}"
TLS_SESSION_CACHE="${tls_session_cache}"
TLS_SESSION_CACHE_LIFETIME="${tls_session_cache_lifetime}"
TLS_MAX_VERSION="${tls_max_version}"
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
%{ if smallstep_enabled ~}

# ---------------------------------------------------------------------------
# Optional: self-hosted Smallstep step-ca (gated by enable_smallstep_ca)
# ---------------------------------------------------------------------------
echo "=== Setting up Smallstep step-ca ==="
export STEPPATH=/etc/step-ca
mkdir -p "$STEPPATH/db" "$STEPPATH/certs" "$STEPPATH/config" "$STEPPATH/secrets"

# Install step-ca + step CLI + step-kms-plugin. GitHub release assets carry a
# Debian revision suffix ("-1"), e.g. step-ca_0.30.2-1_amd64.deb — the bare
# step-ca_<ver>_amd64.deb name 404s. Pin all three to known-good releases.
#
# step-kms-plugin is REQUIRED: the CA-init below uses `step certificate create
# --kms cloudkms: --key <uri>` to sign the intermediate with the Cloud KMS key,
# which step shells out to `step-kms-plugin` for. Without it, init fails with
# `failed to get public key: exec: "step-kms-plugin": executable file not found`.
if ! command -v step >/dev/null 2>&1 || ! command -v step-ca >/dev/null 2>&1 || ! command -v step-kms-plugin >/dev/null 2>&1; then
  STEP_CLI_VERSION="0.30.2"
  STEP_CA_VERSION="0.30.2"
  STEP_KMS_PLUGIN_VERSION="0.17.0"
  STEP_DEB_REVISION="1"

  # Download each .deb + its release checksums.txt and verify the .deb's sha256
  # against it before installing (supply-chain integrity). checksums.txt lists
  # every release asset as "<sha256>  <filename>"; match our specific .deb.
  fetch_and_verify_deb() { # repo version asset out_path
    local repo="$1" ver="$2" asset="$3" out="$4"
    local base="https://github.com/smallstep/$repo/releases/download/v$ver"
    curl -fsSL "$base/$asset" -o "$out"
    curl -fsSL "$base/checksums.txt" -o /tmp/step-checksums.txt
    local want
    want=$(awk -v a="$asset" '$2==a || $2=="*"a {print $1; exit}' /tmp/step-checksums.txt)
    [ -n "$want" ] || { echo "FATAL: no checksum for $asset ($repo v$ver)" >&2; exit 1; }
    echo "$want  $out" | sha256sum -c - || { echo "FATAL: checksum mismatch for $asset" >&2; exit 1; }
  }
  fetch_and_verify_deb cli "$${STEP_CLI_VERSION}" "step-cli_$${STEP_CLI_VERSION}-$${STEP_DEB_REVISION}_amd64.deb" /tmp/step-cli.deb
  fetch_and_verify_deb certificates "$${STEP_CA_VERSION}" "step-ca_$${STEP_CA_VERSION}-$${STEP_DEB_REVISION}_amd64.deb" /tmp/step-ca.deb
  fetch_and_verify_deb step-kms-plugin "$${STEP_KMS_PLUGIN_VERSION}" "step-kms-plugin_$${STEP_KMS_PLUGIN_VERSION}-$${STEP_DEB_REVISION}_amd64.deb" /tmp/step-kms-plugin.deb

  # Install together so dependencies resolve; fail loudly if any is missing.
  dpkg -i /tmp/step-cli.deb /tmp/step-ca.deb /tmp/step-kms-plugin.deb || apt-get -fy install
  command -v step >/dev/null 2>&1 || { echo "FATAL: step-cli install failed" >&2; exit 1; }
  command -v step-ca >/dev/null 2>&1 || { echo "FATAL: step-ca install failed" >&2; exit 1; }
  command -v step-kms-plugin >/dev/null 2>&1 || { echo "FATAL: step-kms-plugin install failed" >&2; exit 1; }
fi

# Fetch DB password + SCEP challenge from Secret Manager.
SMALLSTEP_DB_PASSWORD="$(gcloud secrets versions access latest --secret=smallstep-db-password --project="${project_id}")"
SMALLSTEP_SCEP_CHALLENGE="$(gcloud secrets versions access latest --secret=smallstep-scep-challenge --project="${project_id}")"
%{ if acme_webhook_url != "" ~}
# ACME authorizing webhook signing secret. step-ca's ca.json "secret" field is
# base64; step-ca base64-DECODES it and HMACs the request body with the raw
# bytes. The webhook service receives the SAME raw secret (via its env) and
# HMACs with it directly — so both sides key on identical bytes. The Secret
# Manager value `acme-webhook-signing-secret` holds the RAW secret; we base64
# it only for ca.json here.
ACME_WEBHOOK_SECRET_B64="$(gcloud secrets versions access latest --secret=acme-webhook-signing-secret --project="${project_id}" | base64 -w0)"
%{ endif ~}

# Reuse an existing CA if one was already published to Secret Manager;
# otherwise initialize a new KMS-backed CA and publish BOTH certs.
#
# The CA topology: a LOCAL EC P-256 root key signs a KMS-backed INTERMEDIATE
# (the intermediate's signer is the Cloud KMS HSM key). The local root key is
# generated once, signs the intermediate, then is DISCARDED — the KMS HSM key
# is the only live private key. Both the root cert AND the intermediate cert
# must therefore persist: the intermediate cert's public key is byte-identical
# to the KMS signing key, so a 2nd VM / reboot MUST restore the exact same
# intermediate or step-ca serves a chain that doesn't match the live signer.
#
# We persist root_ca.crt -> smallstep-ca-cert and intermediate_ca.crt ->
# smallstep-intermediate-cert (two separate secrets). The "already initialized"
# signal is the smallstep-intermediate-cert secret having a usable version
# (it's the newer secret; if it exists, both do).
#
# NOTE: we only ADD a secret version + READ it; we never modify the secret's
# IAM or delete it (the VM SA holds secretVersionManager + secretAccessor only).
#
# RACE NOTE: two VMs booting simultaneously could both find neither secret
# populated and both run init, producing divergent roots. This is an accepted
# known limitation for now; a real fix would take a distributed lock (out of
# scope).
#
# RE-MINT GUARD (critical): the restore-vs-init decision is made in TWO steps,
# NOT a single `gcloud ... access` whose non-zero exit silently falls through to
# init. Re-initializing over an existing CA rotates the root/intermediate and
# breaks every device pinned to the old chain — so a TRANSIENT read failure
# (IAM propagation lag at boot, Secret Manager 5xx) must NEVER trigger init.
# History: a boot once ran init even though smallstep-intermediate-cert already
# existed, because the SA's secretAccessor grant hadn't propagated yet and the
# one-shot read returned non-zero.
#
# IMPORTANT: the existence probe must be VERSION-level, not container-level.
# Terraform creates the secret CONTAINER (google_secret_manager_secret) but adds
# NO version — the first init publishes the first version. So `gcloud secrets
# describe` (container) succeeds on a brand-new deploy with zero versions, which
# would make us treat an UN-initialized CA as "exists" and FATAL instead of
# initializing (a fresh deploy could never bootstrap). We therefore key on an
# ENABLED version:
#   1. List enabled versions (retry on transient errors).
#   2. >=1 enabled version  -> CA initialized: RESTORE (retry read; ABORT, never
#      re-init, if it stays unreadable — a present-but-unreadable CA is an error,
#      not a signal to mint a new one).
#   3. 0 enabled versions   -> genuine first init.
CA_HAS_VERSION=""
for attempt in 1 2 3 4 5; do
  LIST_OUT="$(gcloud secrets versions list smallstep-intermediate-cert \
      --project="${project_id}" --filter='state=ENABLED' --format='value(name)' \
      --limit=1 2>/tmp/ca-version-list.err)"
  LIST_RC=$?
  if [ "$LIST_RC" -eq 0 ]; then
    if [ -n "$LIST_OUT" ]; then CA_HAS_VERSION=yes; else CA_HAS_VERSION=no; fi
    break
  fi
  # A NOT_FOUND on the container itself also means "no usable CA yet" -> init.
  if grep -qiE 'NOT_FOUND|was not found|does not exist' /tmp/ca-version-list.err; then
    CA_HAS_VERSION=no
    break
  fi
  echo "smallstep-intermediate-cert version probe failed (attempt $attempt), retrying: $(cat /tmp/ca-version-list.err)" >&2
  sleep $((attempt * 5))
done
if [ -z "$CA_HAS_VERSION" ]; then
  echo "FATAL: could not determine whether smallstep-intermediate-cert has an enabled version after retries; refusing to re-init (would rotate the CA)" >&2
  exit 1
fi

RESTORE_CA=""
if [ "$CA_HAS_VERSION" = "yes" ]; then
  # An enabled version exists — the CA is already initialized. Read it with
  # backoff; a persistent read failure is FATAL (we must not mint a competing CA).
  for attempt in 1 2 3 4 5; do
    if gcloud secrets versions access latest --secret=smallstep-intermediate-cert --project="${project_id}" >"$STEPPATH/certs/intermediate_ca.crt" 2>/dev/null && [ -s "$STEPPATH/certs/intermediate_ca.crt" ]; then
      RESTORE_CA=yes
      break
    fi
    echo "smallstep-intermediate-cert read failed (attempt $attempt), retrying..." >&2
    sleep $((attempt * 5))
  done
  if [ "$RESTORE_CA" != "yes" ]; then
    echo "FATAL: smallstep-intermediate-cert has an enabled version but is unreadable after retries; refusing to re-init (would rotate the CA and break enrolled devices)" >&2
    exit 1
  fi
fi

if [ "$RESTORE_CA" = "yes" ]; then
  echo "Existing Smallstep CA found — restoring root + intermediate + SCEP decrypter cert + key."
  gcloud secrets versions access latest --secret=smallstep-ca-cert --project="${project_id}" >"$STEPPATH/certs/root_ca.crt"
  gcloud secrets versions access latest --secret=smallstep-scep-decrypter-cert --project="${project_id}" >"$STEPPATH/certs/scep_decrypter.crt"
  # The SCEP decrypter PRIVATE key is a shared software RSA key (not in KMS):
  # Cloud KMS keys are single-purpose, but step-ca's SCEP provisioner needs the
  # decrypter key to BOTH decrypt SCEP envelopes AND sign SCEP responses, so it
  # must be a dual-purpose software RSA key. Generated once at init and persisted
  # to Secret Manager so both HA nodes (and any rebuild) share the SAME decrypter
  # identity. The CA SIGNING key stays in Cloud KMS/HSM — this key only handles
  # SCEP message crypto, never issues certificates.
  gcloud secrets versions access latest --secret=smallstep-scep-decrypter-key --project="${project_id}" >"$STEPPATH/secrets/scep_decrypter_key"
  chmod 600 "$STEPPATH/secrets/scep_decrypter_key"
  # Guard against a partial-publish race: smallstep-intermediate-cert is the
  # readiness marker and is published LAST in the init branch, but assert the
  # other restored artifacts are all present + non-empty before starting. A
  # missing/empty decrypter cert or key would otherwise start step-ca with a
  # broken SCEP provisioner (PKIOperation 500s) until manual intervention.
  [ -s "$STEPPATH/certs/root_ca.crt" ] && [ -s "$STEPPATH/certs/scep_decrypter.crt" ] && [ -s "$STEPPATH/secrets/scep_decrypter_key" ] || {
    echo "FATAL: Smallstep CA secrets are partially published (intermediate present but root/decrypter missing)" >&2
    exit 1
  }
  # Stage the Smallstep client-cert trust chain (INTERMEDIATE + root) for the
  # RADIUS-trust step later in this script. The intermediate is the issuer that
  # directly signs Wi-Fi client certs, so FreeRADIUS MUST have it in ca_file to
  # build leaf->intermediate->root; root alone yields OpenSSL error 20
  # ("unable to get local issuer certificate") and rejects every client.
  cat "$STEPPATH/certs/intermediate_ca.crt" "$STEPPATH/certs/root_ca.crt" > /tmp/smallstep-ca.crt
else
  echo "Initializing new KMS-backed Smallstep CA..."
  # CONFIRMED ON-BOX (radius-primary, step/step-ca 0.30.2, 2026-06-03):
  # `step ca init --kms=cloudkms` is NOT viable on this version — its --kms flag
  # only accepts "azurekms" and always *generates* fresh keys; it cannot bind to
  # a pre-created Cloud KMS key. The working approach is to build the PKI by hand
  # with `step certificate create`, using --kms cloudkms: + --key <kms-uri> so the
  # intermediate (the actual leaf signer) is backed by the pre-created HSM key
  # ${smallstep_signing_key_uri}. The intermediate cert's public key is then
  # byte-identical to the KMS key's public key and chains to the local root, and
  # step-ca loads it via the "key"/"kms" stanza in ca.json (rendered below).
  #
  # Root: local EC P-256 self-signed root. The root key only signs the
  # intermediate once at init and then sits cold; the live signer is the KMS key.
  # Fail fast: a masked failure here (broken KMS binding, bad invocation) would
  # otherwise publish partial state and start step-ca with a broken chain.
  step certificate create "${ca_name_prefix} Root CA" \
    "$STEPPATH/certs/root_ca.crt" "$STEPPATH/secrets/root_ca_key" \
    --profile root-ca --kty EC --curve P-256 \
    --no-password --insecure --force
  # Intermediate: public key sourced from the Cloud KMS signing key; signed by
  # the local root. /dev/null for the key output because the private key lives in
  # Cloud KMS, never on disk.
  step certificate create "${ca_name_prefix} Intermediate CA" \
    "$STEPPATH/certs/intermediate_ca.crt" /dev/null \
    --profile intermediate-ca \
    --ca "$STEPPATH/certs/root_ca.crt" --ca-key "$STEPPATH/secrets/root_ca_key" \
    --kms "cloudkms:" --key "${smallstep_signing_key_uri}" \
    --no-password --insecure --force
  # SCEP decrypter: a SOFTWARE RSA keypair (NOT Cloud KMS). step-ca's SCEP
  # provisioner Init() calls BOTH CreateDecrypter AND CreateSigner on the
  # decrypter key (it decrypts the SCEP PKCS#7 envelope AND signs the SCEP
  # response). Cloud KMS keys are single-purpose (ASYMMETRIC_DECRYPT can't sign),
  # so a KMS-backed decrypter fails init with "does not have decrypter" and every
  # PKIOperation 500s. A local RSA key is dual-purpose and is the documented
  # step-ca SCEP pattern. This key is lower-sensitivity than the CA signing key
  # (it never issues certs); the signing key stays in Cloud KMS/HSM.
  #
  # Generated here once, then persisted to Secret Manager (cert AND key) so both
  # HA nodes + any VM rebuild share the SAME decrypter identity — critical behind
  # the round-robin LB, where the cert returned by GetCACert on one node must be
  # decryptable by whichever node receives the PKIOperation POST.
  #
  # Signed by the ROOT (root_ca.crt + root_ca_key), which still exists here. This
  # MUST run before the `rm -f "$STEPPATH/secrets/root_ca_key"` below.
  step certificate create "${ca_name_prefix} SCEP Decrypter" \
    "$STEPPATH/certs/scep_decrypter.crt" "$STEPPATH/secrets/scep_decrypter_key" \
    --ca "$STEPPATH/certs/root_ca.crt" --ca-key "$STEPPATH/secrets/root_ca_key" \
    --kty RSA --size 2048 \
    --not-after 87600h --no-password --insecure --force
  chmod 600 "$STEPPATH/secrets/scep_decrypter_key"
  # Single gate: only publish secrets + discard the root key once ALL certs +
  # the decrypter key genuinely exist and are non-empty. On failure, abort.
  [ -s "$STEPPATH/certs/root_ca.crt" ] && [ -s "$STEPPATH/certs/intermediate_ca.crt" ] && [ -s "$STEPPATH/certs/scep_decrypter.crt" ] && [ -s "$STEPPATH/secrets/scep_decrypter_key" ] || {
    echo "FATAL: Smallstep CA bootstrap did not produce all certificates/keys" >&2
    exit 1
  }
  # Publish ALL certs + the decrypter key so reboots / the 2nd VM restore a
  # matching chain and a working SCEP decrypter.
  #
  # ORDER MATTERS: smallstep-intermediate-cert is the readiness marker the
  # restore branch (above) keys on, so it MUST be published LAST. Publishing it
  # mid-sequence would let a later failure (e.g. decrypter cert/key) leave a
  # half-initialized CA that the next boot "restores" into a broken SCEP state.
  gcloud secrets versions add smallstep-ca-cert --project="${project_id}" \
    --data-file="$STEPPATH/certs/root_ca.crt"
  gcloud secrets versions add smallstep-scep-decrypter-cert --project="${project_id}" \
    --data-file="$STEPPATH/certs/scep_decrypter.crt"
  gcloud secrets versions add smallstep-scep-decrypter-key --project="${project_id}" \
    --data-file="$STEPPATH/secrets/scep_decrypter_key"
  # Readiness marker — published last, only after everything else is durable.
  gcloud secrets versions add smallstep-intermediate-cert --project="${project_id}" \
    --data-file="$STEPPATH/certs/intermediate_ca.crt"
  # Stage the Smallstep client-cert trust chain (INTERMEDIATE + root) for the
  # RADIUS-trust step later in this script. The intermediate is the issuer that
  # directly signs Wi-Fi client certs, so FreeRADIUS MUST have it in ca_file to
  # build leaf->intermediate->root; root alone yields OpenSSL error 20
  # ("unable to get local issuer certificate") and rejects every client.
  cat "$STEPPATH/certs/intermediate_ca.crt" "$STEPPATH/certs/root_ca.crt" > /tmp/smallstep-ca.crt
  # Discard the local root key — the KMS HSM key is the only live private key.
  rm -f "$STEPPATH/secrets/root_ca_key"
fi

# =============================================================================
# RSA CA (step-ca instance #2) — SELF-CONTAINED, independent of the EC CA above.
# Windows native SCEP + Apple SCEP require an RSA-signed leaf; the EC chain can't
# serve them. This CA has its OWN self-signed RSA root (the EC root key is
# discarded and the EC intermediate is pathlen:0, so the RSA intermediate cannot
# chain under the EC chain). RADIUS trusts BOTH roots. Its own init-or-restore
# decision keys on smallstep-rsa-intermediate-cert (the readiness marker).
# =============================================================================
%{ if smallstep_enabled ~}
mkdir -p /etc/step-ca-rsa/certs /etc/step-ca-rsa/secrets /etc/step-ca-rsa/config

# Probe: does the RSA CA already exist? (enabled version of the readiness marker)
RSA_CA_HAS_VERSION=""
for attempt in 1 2 3 4 5; do
  RSA_LIST_OUT="$(gcloud secrets versions list smallstep-rsa-intermediate-cert \
      --project="${project_id}" --filter='state=ENABLED' --format='value(name)' \
      --limit=1 2>/tmp/rsa-ca-version-list.err)"
  RSA_LIST_RC=$?
  if [ "$RSA_LIST_RC" -eq 0 ]; then
    if [ -n "$RSA_LIST_OUT" ]; then RSA_CA_HAS_VERSION=yes; else RSA_CA_HAS_VERSION=no; fi
    break
  fi
  if grep -qiE 'NOT_FOUND|was not found|does not exist' /tmp/rsa-ca-version-list.err; then
    RSA_CA_HAS_VERSION=no
    break
  fi
  echo "smallstep-rsa-intermediate-cert version probe failed (attempt $attempt), retrying: $(cat /tmp/rsa-ca-version-list.err)" >&2
  sleep $((attempt * 5))
done
if [ -z "$RSA_CA_HAS_VERSION" ]; then
  echo "FATAL: could not determine whether smallstep-rsa-intermediate-cert has an enabled version after retries; refusing to proceed" >&2
  exit 1
fi

RSA_RESTORE_CA=""
if [ "$RSA_CA_HAS_VERSION" = "yes" ]; then
  for attempt in 1 2 3 4 5; do
    if gcloud secrets versions access latest --secret=smallstep-rsa-intermediate-cert --project="${project_id}" >"/etc/step-ca-rsa/certs/intermediate_ca.crt" 2>/dev/null && [ -s "/etc/step-ca-rsa/certs/intermediate_ca.crt" ]; then
      RSA_RESTORE_CA=yes
      break
    fi
    echo "smallstep-rsa-intermediate-cert read failed (attempt $attempt), retrying..." >&2
    sleep $((attempt * 5))
  done
  if [ "$RSA_RESTORE_CA" != "yes" ]; then
    echo "FATAL: smallstep-rsa-intermediate-cert has an enabled version but is unreadable after retries; refusing to re-init (would rotate the RSA CA)" >&2
    exit 1
  fi
fi

if [ "$RSA_RESTORE_CA" = "yes" ]; then
  echo "Existing RSA CA found — restoring RSA root + intermediate + SCEP decrypter."
  gcloud secrets versions access latest --secret=smallstep-rsa-root-cert --project="${project_id}" >"/etc/step-ca-rsa/certs/root_ca.crt"
  gcloud secrets versions access latest --secret=smallstep-rsa-scep-decrypter-cert --project="${project_id}" >"/etc/step-ca-rsa/certs/scep_decrypter.crt"
  gcloud secrets versions access latest --secret=smallstep-rsa-scep-decrypter-key --project="${project_id}" >"/etc/step-ca-rsa/secrets/scep_decrypter_key"
  chmod 600 /etc/step-ca-rsa/secrets/scep_decrypter_key
  [ -s "/etc/step-ca-rsa/certs/root_ca.crt" ] && [ -s "/etc/step-ca-rsa/certs/scep_decrypter.crt" ] && [ -s "/etc/step-ca-rsa/secrets/scep_decrypter_key" ] || {
    echo "FATAL: RSA CA secrets are partially published (intermediate present but root/decrypter missing)" >&2
    exit 1
  }
else
  echo "Initializing new RSA CA (self-signed RSA root + KMS-backed RSA intermediate)..."
  # Self-signed RSA root. The root key signs the RSA intermediate once here, then
  # is discarded (like the EC root). Only the root CERT is persisted.
  step certificate create "${ca_name_prefix} RSA Root CA" \
    "/etc/step-ca-rsa/certs/root_ca.crt" "/etc/step-ca-rsa/secrets/root_ca_key" \
    --profile root-ca --kty RSA --size 4096 \
    --not-after 175200h --no-password --insecure --force
  # RSA intermediate: public key from the Cloud KMS RSA signing key; signed by the
  # local RSA root. /dev/null for the key (private key lives in Cloud KMS).
  step certificate create "${ca_name_prefix} RSA Intermediate CA" \
    "/etc/step-ca-rsa/certs/intermediate_ca.crt" /dev/null \
    --profile intermediate-ca \
    --ca "/etc/step-ca-rsa/certs/root_ca.crt" --ca-key "/etc/step-ca-rsa/secrets/root_ca_key" \
    --kms "cloudkms:" --key "${smallstep_rsa_signing_key_uri}" \
    --no-password --insecure --force
  # RSA SCEP decrypter: dual-purpose software RSA key, signed BY the RSA
  # intermediate (its key is in Cloud KMS -> --kms cloudkms: --ca-key <rsa-uri>).
  step certificate create "${ca_name_prefix} RSA SCEP Decrypter" \
    "/etc/step-ca-rsa/certs/scep_decrypter.crt" "/etc/step-ca-rsa/secrets/scep_decrypter_key" \
    --ca "/etc/step-ca-rsa/certs/intermediate_ca.crt" \
    --kms "cloudkms:" --ca-key "${smallstep_rsa_signing_key_uri}" \
    --kty RSA --size 2048 \
    --not-after 87600h --no-password --insecure --force
  chmod 600 /etc/step-ca-rsa/secrets/scep_decrypter_key
  # Gate: all RSA artifacts present before publishing.
  [ -s "/etc/step-ca-rsa/certs/root_ca.crt" ] && [ -s "/etc/step-ca-rsa/certs/intermediate_ca.crt" ] && [ -s "/etc/step-ca-rsa/certs/scep_decrypter.crt" ] && [ -s "/etc/step-ca-rsa/secrets/scep_decrypter_key" ] || {
    echo "FATAL: RSA CA bootstrap did not produce all certificates/keys" >&2
    exit 1
  }
  # Publish. Readiness marker smallstep-rsa-intermediate-cert LAST.
  gcloud secrets versions add smallstep-rsa-root-cert --project="${project_id}" \
    --data-file="/etc/step-ca-rsa/certs/root_ca.crt"
  gcloud secrets versions add smallstep-rsa-scep-decrypter-cert --project="${project_id}" \
    --data-file="/etc/step-ca-rsa/certs/scep_decrypter.crt"
  gcloud secrets versions add smallstep-rsa-scep-decrypter-key --project="${project_id}" \
    --data-file="/etc/step-ca-rsa/secrets/scep_decrypter_key"
  gcloud secrets versions add smallstep-rsa-intermediate-cert --project="${project_id}" \
    --data-file="/etc/step-ca-rsa/certs/intermediate_ca.crt"
  # Discard the RSA root key — the KMS key (intermediate signer) is the live signer.
  rm -f "/etc/step-ca-rsa/secrets/root_ca_key"
fi

# Append the RSA intermediate + RSA root to the RADIUS client-cert trust bundle
# (the EC block already wrote the EC chain to /tmp/smallstep-ca.crt). RADIUS now
# trusts BOTH chains.
cat "/etc/step-ca-rsa/certs/intermediate_ca.crt" "/etc/step-ca-rsa/certs/root_ca.crt" >> /tmp/smallstep-ca.crt
%{ endif ~}

# Render ca.json with ACME (device-attest-01 + optional authorizing webhook)
# and SCEP provisioners.
#
# The AUTHORIZING webhook is attached ONLY to the ACME provisioner and uses
# certType "X509" — it gates X509 issuance by checking the attested device
# serial (attestationData.permanentIdentifier) against Fleet. The SCEP
# provisioner is intentionally NOT webhook-gated; it authenticates with the
# static challenge, so the webhook never receives a serial-less SCEP request.
#
# step-ca's SCEP provisioner wants decrypterCertificate + decrypterKeyPEM as
# base64-encoded PEM. The decrypter key is the shared software RSA key restored
# from / generated into Secret Manager above.
#
# excludeIntermediate=true: by default step-ca's GetCACert returns BOTH the RSA
# decrypter (RA) cert AND the EC intermediate (scep/authority.go
# GetCACertificates: appends a.intermediates unless ShouldIncludeIntermediateInChain
# is false). The Windows native SCEP CSP (ClientCertificateInstall) can't handle
# the EC intermediate in that bundle — it picks the wrong PKCS#7 recipient /
# can't build a chain and fails to initialize with "server certs ''" / 0x80092004
# (CRYPT_E_NO_MATCH) on host 733. step-ca's own source documents this exact case
# ("useful in environments where the SCEP client doesn't select the right RSA
# decrypter certificate"). Setting excludeIntermediate makes GetCACert return
# ONLY the RSA decrypter, so the CSP has an unambiguous RSA recipient. The issued
# Wi-Fi cert is still signed by the EC intermediate (signAuth.SignWithContext) and
# the EC chain / all macOS ACME certs are completely unaffected — this only
# changes what the SCEP GetCACert response advertises. macOS uses ACME, not SCEP,
# so it never calls GetCACert and is untouched.
SCEP_DECRYPTER_CERT_B64="$(base64 -w0 < "$STEPPATH/certs/scep_decrypter.crt")"
SCEP_DECRYPTER_KEY_B64="$(base64 -w0 < "$STEPPATH/secrets/scep_decrypter_key")"
cat > "$STEPPATH/config/ca.json" <<CAJSON
{
  "root": "$STEPPATH/certs/root_ca.crt",
  "crt": "$STEPPATH/certs/intermediate_ca.crt",
  "key": "${smallstep_signing_key_uri}",
  "kms": { "type": "cloudkms" },
  "address": ":8443",
  "dnsNames": ["${smallstep_ca_dns_name}"],
  "metricsAddress": "127.0.0.1:9090",
  "db": {
    "type": "postgresql",
    "dataSource": "postgresql://${smallstep_db_user}:$${SMALLSTEP_DB_PASSWORD}@${smallstep_db_host}:5432/${smallstep_db_name}?sslmode=require"
  },
  "authority": {
    "provisioners": [
      {
        "type": "ACME",
        "name": "${smallstep_acme_name}",
        "challenges": ["device-attest-01"],
        "attestationFormats": ["apple"],
%{ if acme_webhook_url != "" ~}
        "webhooks": [
          {
            "name": "authorize",
            "url": "${acme_webhook_url}",
            "kind": "AUTHORIZING",
            "certType": "X509",
            "secret": "$${ACME_WEBHOOK_SECRET_B64}"
          }
        ],
%{ endif ~}
        "claims": { "maxTLSCertDuration": "2160h", "defaultTLSCertDuration": "2160h" }
      },
      {
        "type": "SCEP",
        "name": "${smallstep_scep_name}",
        "challenge": "$${SMALLSTEP_SCEP_CHALLENGE}",
        "minimumPublicKeyLength": 2048,
        "encryptionAlgorithmIdentifier": 2,
        "decrypterCertificate": "$${SCEP_DECRYPTER_CERT_B64}",
        "decrypterKeyPEM": "$${SCEP_DECRYPTER_KEY_B64}",
        "excludeIntermediate": true,
        "claims": { "maxTLSCertDuration": "2160h", "defaultTLSCertDuration": "2160h" }
      }
    ]
  },
  "tls": { "minVersion": 1.2, "maxVersion": 1.3 },
  "logger": { "format": "json" }
}
CAJSON

# SCEP decrypter readiness probe.
#
# step-ca 0.30.2 validates the SCEP decrypter (decrypterCertificate +
# decrypterKeyURI -> Cloud KMS) exactly ONCE at startup. If that KMS call
# fails transiently (IAM propagation lag, KMS latency, network blip on a
# fresh boot), step-ca logs the NON-FATAL line:
#   "failed validating SCEP authority: SCEP provisioner ... does not have decrypter"
# then keeps serving with the provisioner DEGRADED — every SCEP PKIOperation
# returns HTTP 500 ("does not have a decrypter available") for the life of the
# process, with no crash and no retry. On an HA pair behind a round-robin LB
# this silently breaks ~half of all SCEP enrollments until a manual restart.
#
# This probe runs after step-ca comes up and fails the unit (-> Restart=always
# re-execs it, by which point KMS is reachable) if the decrypter didn't load.
# Gated on a working SCEP provisioner via the marker file written above.
%{ if smallstep_enabled ~}
cat > /usr/local/bin/stepca-decrypter-probe.sh <<'PROBE'
#!/bin/bash
# Wait for the CA to answer health, then assert the SCEP decrypter initialized.
for i in $(seq 1 30); do
  curl -fsS -k https://127.0.0.1:8443/health >/dev/null 2>&1 && break
  sleep 1
done
# Look only at THIS invocation's logs (since the unit's current start).
since=$(systemctl show step-ca -p ActiveEnterTimestamp --value)
if journalctl -u step-ca --since "$since" --no-pager 2>/dev/null | grep -q "does not have decrypter"; then
  echo "stepca-decrypter-probe: SCEP decrypter failed to initialize; failing unit to force restart" >&2
  exit 1
fi
echo "stepca-decrypter-probe: SCEP decrypter OK"
exit 0
PROBE
chmod +x /usr/local/bin/stepca-decrypter-probe.sh
%{ endif ~}

# Log file for step-ca. step-ca has no native file-logging (its logger config is
# only format/traceHeader; logrus + Go's std log both write to stderr), and the
# Datadog journald tailer drops step-ca's PLAIN-TEXT operational lines (startup,
# "Serving HTTPS", and the "does not have decrypter" error) — only the JSON
# request lines survive journald. So tee step-ca's stdout/stderr to a file and
# tail THAT in Datadog (file tailer ships every line verbatim). journald is kept
# too (tee's stdout), so the decrypter ExecStartPost probe still works.
mkdir -p /var/log/step-ca
cat > /etc/logrotate.d/step-ca <<'LOGROTATE'
/var/log/step-ca/step-ca.log {
  daily
  rotate 7
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
LOGROTATE

# systemd unit for step-ca.
cat > /etc/systemd/system/step-ca.service <<'UNIT'
[Unit]
Description=Smallstep step-ca
After=network-online.target
Wants=network-online.target

[Service]
Environment=STEPPATH=/etc/step-ca
# Log the real client IP (X-Forwarded-For) instead of the L7 GCLB proxy peer
# (35.191.x.x / 130.211.x.x). The external HTTPS ALB re-originates TLS to this
# backend and injects X-Forwarded-For; STEP_LOGGER_LOG_REAL_IP makes step-ca's
# logging middleware use that header for the "remote-address" field. Safe here
# because the only path to :8443 is through the LB (Cloud Armor + the backend
# health-check ranges), so XFF can't be spoofed by a direct client.
Environment=STEP_LOGGER_LOG_REAL_IP=true
# tee to journald (stdout) AND the log file Datadog tails. A shell wraps the
# pipe; it stays as the unit's main process and Restart=always covers crashes.
ExecStart=/bin/sh -c '/usr/bin/step-ca /etc/step-ca/config/ca.json 2>&1 | tee -a /var/log/step-ca/step-ca.log'
%{ if smallstep_enabled ~}
# Assert the SCEP decrypter loaded; non-zero here trips Restart=always so a
# transient KMS failure at boot self-heals instead of silently 500-ing SCEP.
ExecStartPost=/usr/local/bin/stepca-decrypter-probe.sh
%{ endif ~}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now step-ca
echo "step-ca started."

%{ if smallstep_enabled ~}
# --- RSA step-ca (instance #2): ca.json, unit, log, probe -------------------
RSA_SCEP_DECRYPTER_CERT_B64="$(base64 -w0 < /etc/step-ca-rsa/certs/scep_decrypter.crt)"
RSA_SCEP_DECRYPTER_KEY_B64="$(base64 -w0 < /etc/step-ca-rsa/secrets/scep_decrypter_key)"
cat > /etc/step-ca-rsa/config/ca.json <<CARSAJSON
{
  "root": "/etc/step-ca-rsa/certs/root_ca.crt",
  "crt": "/etc/step-ca-rsa/certs/intermediate_ca.crt",
  "key": "${smallstep_rsa_signing_key_uri}",
  "kms": { "type": "cloudkms" },
  "address": ":8444",
  "dnsNames": ["${smallstep_ca_rsa_dns_name}"],
  "metricsAddress": "127.0.0.1:9091",
  "db": {
    "type": "postgresql",
    "dataSource": "postgresql://${smallstep_db_user}:$${SMALLSTEP_DB_PASSWORD}@${smallstep_db_host}:5432/stepca_rsa?sslmode=require"
  },
  "authority": {
    "provisioners": [
      {
        "type": "SCEP",
        "name": "${smallstep_scep_rsa_name}",
        "challenge": "$${SMALLSTEP_SCEP_CHALLENGE}",
        "minimumPublicKeyLength": 2048,
        "encryptionAlgorithmIdentifier": 2,
        "excludeIntermediate": true,
        "decrypterCertificate": "$${RSA_SCEP_DECRYPTER_CERT_B64}",
        "decrypterKeyPEM": "$${RSA_SCEP_DECRYPTER_KEY_B64}",
%{ if acme_webhook_enabled ~}
        "webhooks": [
          {
            "name": "scep-challenge",
            "url": "http://127.0.0.1:${webhook_port}/scep-challenge",
            "kind": "SCEPCHALLENGE",
            "secret": "$${ACME_WEBHOOK_SECRET_B64}"
          }
        ],
%{ endif ~}
        "claims": { "maxTLSCertDuration": "2160h", "defaultTLSCertDuration": "2160h" }
      }
    ]
  },
  "tls": { "minVersion": 1.2, "maxVersion": 1.3 },
  "logger": { "format": "json" }
}
CARSAJSON
%{ endif ~}

%{ if smallstep_enabled ~}
cat > /usr/local/bin/stepca-rsa-decrypter-probe.sh <<'PROBE'
#!/bin/bash
for i in $(seq 1 30); do
  curl -fsS -k https://127.0.0.1:8444/health >/dev/null 2>&1 && break
  sleep 1
done
since=$(systemctl show step-ca-rsa -p ActiveEnterTimestamp --value)
if journalctl -u step-ca-rsa --since "$since" --no-pager 2>/dev/null | grep -q "does not have decrypter"; then
  echo "stepca-rsa-decrypter-probe: SCEP decrypter failed to initialize; failing unit to force restart" >&2
  exit 1
fi
echo "stepca-rsa-decrypter-probe: SCEP decrypter OK"
exit 0
PROBE
chmod +x /usr/local/bin/stepca-rsa-decrypter-probe.sh
mkdir -p /var/log/step-ca-rsa
cat > /etc/logrotate.d/step-ca-rsa <<'LOGROTATE'
/var/log/step-ca-rsa/step-ca-rsa.log {
  daily
  rotate 7
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
LOGROTATE
%{ endif ~}

%{ if smallstep_enabled ~}
cat > /etc/systemd/system/step-ca-rsa.service <<'RSAUNIT'
[Unit]
Description=Smallstep step-ca (RSA SCEP instance)
After=network-online.target
Wants=network-online.target

[Service]
Environment=STEPPATH=/etc/step-ca-rsa
Environment=STEP_LOGGER_LOG_REAL_IP=true
ExecStart=/bin/sh -c '/usr/bin/step-ca /etc/step-ca-rsa/config/ca.json 2>&1 | tee -a /var/log/step-ca-rsa/step-ca-rsa.log'
ExecStartPost=/usr/local/bin/stepca-rsa-decrypter-probe.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
RSAUNIT
systemctl daemon-reload
systemctl enable --now step-ca-rsa
echo "step-ca-rsa started."
%{ endif ~}

%{ if acme_webhook_enabled ~}
# ---------------------------------------------------------------------------
# ACME authorizing webhook — localhost systemd service (not Cloud Run).
# step-ca calls http://127.0.0.1:${webhook_port}/authorize per ACME order and
# refuses to sign unless it returns allow:true (fail-closed). The binary is a
# static release asset built by the webhook-release GitHub Action.
# ---------------------------------------------------------------------------
echo "=== Installing ACME authorizing webhook ==="
WEBHOOK_BIN=/usr/local/bin/acme-authz-webhook
WEBHOOK_VERSION="${webhook_release_version}"
WEBHOOK_URL="https://github.com/${webhook_repo}/releases/download/webhook-v$${WEBHOOK_VERSION}/acme-authz-webhook-linux-amd64"
if [ ! -x "$WEBHOOK_BIN" ] || [ "$($WEBHOOK_BIN version 2>/dev/null || true)" != "$${WEBHOOK_VERSION}" ]; then
  curl -fsSL "$WEBHOOK_URL" -o /tmp/acme-authz-webhook
  # Verify the published sha256 if present (asset built alongside the binary).
  if curl -fsSL "$WEBHOOK_URL.sha256" -o /tmp/acme-authz-webhook.sha256 2>/dev/null; then
    EXPECTED=$(awk '{print $1}' /tmp/acme-authz-webhook.sha256)
    ACTUAL=$(sha256sum /tmp/acme-authz-webhook | awk '{print $1}')
    [ "$EXPECTED" = "$ACTUAL" ] || { echo "FATAL: webhook binary sha256 mismatch" >&2; exit 1; }
  fi
  install -m 0755 /tmp/acme-authz-webhook "$WEBHOOK_BIN"
  rm -f /tmp/acme-authz-webhook /tmp/acme-authz-webhook.sha256
fi

# Dedicated unprivileged user for the webhook.
id acme-webhook >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin acme-webhook

# Secrets from Secret Manager -> a root-owned EnvironmentFile (0600). The Fleet
# token + HMAC signing secret never land in the unit file or process args.
mkdir -p /etc/acme-authz-webhook
WEBHOOK_SIGNING_SECRET="$(gcloud secrets versions access latest --secret=acme-webhook-signing-secret --project="${project_id}")"
FLEET_API_TOKEN="$(gcloud secrets versions access latest --secret=fleet-api-token --project="${project_id}")"
[ -n "$WEBHOOK_SIGNING_SECRET" ] && [ -n "$FLEET_API_TOKEN" ] || { echo "FATAL: webhook secrets missing" >&2; exit 1; }
umask 077
cat > /etc/acme-authz-webhook/env <<WEBHOOKENV
PORT=${webhook_port}
FLEET_API_BASE_URL=${fleet_api_base_url}
ALLOW_LABEL=${webhook_allow_label}
WEBHOOK_SIGNING_SECRET=$WEBHOOK_SIGNING_SECRET
FLEET_API_TOKEN=$FLEET_API_TOKEN
SMALLSTEP_SCEP_CHALLENGE=$SMALLSTEP_SCEP_CHALLENGE
WEBHOOKENV
umask 022
chmod 600 /etc/acme-authz-webhook/env

cat > /etc/systemd/system/acme-authz-webhook.service <<'WEBHOOKUNIT'
[Unit]
Description=ACME authorizing webhook (Fleet-enrolled serial gate for step-ca)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/acme-authz-webhook/env
ExecStart=/usr/local/bin/acme-authz-webhook serve
Restart=always
RestartSec=5
User=acme-webhook
# Loopback-only service; harden it.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
WEBHOOKUNIT
systemctl daemon-reload
systemctl enable --now acme-authz-webhook
# Wait for it to answer before step-ca starts handing it ACME orders.
for i in $(seq 1 15); do
  curl -fsS -o /dev/null "http://127.0.0.1:${webhook_port}/healthz" 2>/dev/null && break
  sleep 1
done
echo "ACME authorizing webhook started on 127.0.0.1:${webhook_port}."
# step-ca services were started before this block; restart them now that the
# webhook is reachable so ACME orders / SCEP challenges arriving during the
# bootstrap window aren't rejected fail-closed on a connection-refused to the
# webhook. The RSA instance's SCEP provisioner uses the /scep-challenge webhook.
systemctl restart step-ca
%{ if smallstep_enabled ~}
systemctl restart step-ca-rsa
%{ endif ~}
%{ endif ~}

# Stage the Smallstep CA cert for RADIUS to validate client certs against.
#   - "smallstep": Smallstep replaces Okta in the client trust path.
#   - "both":      transitional dual-trust — RADIUS accepts client certs from
#                  EITHER the Okta intermediate OR the Smallstep intermediate,
#                  by validating against a concatenated bundle. Lets devices
#                  migrate from Okta-issued to Smallstep-issued Wi-Fi certs
#                  without a flag-day cutover.
if { [ "${radius_trust_mode}" = "smallstep" ] || [ "${radius_trust_mode}" = "both" ]; } && [ -s /tmp/smallstep-ca.crt ]; then
  cp /tmp/smallstep-ca.crt "$CERT_DIR/smallstep-ca.pem"
  chown freerad:freerad "$CERT_DIR/smallstep-ca.pem" || true
fi
if [ "${radius_trust_mode}" = "both" ] && [ -s "$CERT_DIR/smallstep-ca.pem" ]; then
  cat "$CERT_DIR/okta-ca.pem" "$CERT_DIR/smallstep-ca.pem" > "$CERT_DIR/trust-bundle.pem"
  chown freerad:freerad "$CERT_DIR/trust-bundle.pem" || true
fi

# ---------------------------------------------------------------------------
# RADIUS SERVER certificate from Smallstep (server-trust direction).
#
# EAP-TLS is mutual: the trust-bundle above fixes the CLIENT->server direction
# (RADIUS validating the device's cert). This block fixes the SERVER->client
# direction — the cert RADIUS PRESENTS to the device.
#
# The Wi-Fi client profiles anchor server-trust on the Smallstep ROOT
# (com.apple.security.root on macOS / TrustedRootCA on Windows). The legacy,
# self-signed "<org> RADIUS CA" server cert generated above does NOT chain to
# that root, so a migrated device aborts the handshake with
# "certificate unknown" / errSSLXCertChainInvalid (-9807). When trusting
# Smallstep, RADIUS must present a Smallstep-issued server cert so it chains
# leaf -> intermediate (EE2ADD0F...) -> root (the anchor the device trusts).
#
# Cached in its OWN secrets (radius-smallstep-server-cert/-key), separate from
# the legacy radius-server-cert, so the two paths never clobber each other and
# rollback (radius_trust_mode=okta) cleanly reverts to the legacy cert.
if [ "${radius_trust_mode}" = "smallstep" ] || [ "${radius_trust_mode}" = "both" ]; then
  echo "=== Issuing Smallstep-signed RADIUS server certificate ==="
  SS_SRV_CN="$SERVER_CERT_CN"
  SS_SRV_LEAF=/tmp/ss-server-cert.pem
  SS_SRV_KEY=/tmp/ss-server-key.pem

  # Restore from Secret Manager if a valid, non-expired Smallstep server cert
  # already exists (survives reboots without re-minting on every boot).
  RESTORED_SS_SRV=false
  if fetch_secret "radius-smallstep-server-cert" > "$SS_SRV_LEAF" 2>/dev/null && [ -s "$SS_SRV_LEAF" ] \
     && fetch_secret "radius-smallstep-server-key" > "$SS_SRV_KEY" 2>/dev/null && [ -s "$SS_SRV_KEY" ]; then
    # Accept the cached pair only if the cert still has >30 days of validity, it
    # chains to the CURRENT intermediate (a CA rotation would orphan an old
    # leaf), AND the restored key matches the cert. The two secrets are read
    # independently, so a partial earlier write could pair a cert with a key
    # from a different issuance attempt — a mismatched key would otherwise be
    # copied into FreeRADIUS and break server TLS after reboot.
    if openssl x509 -in "$SS_SRV_LEAF" -noout -checkend 2592000 >/dev/null 2>&1 \
       && openssl verify -CAfile <(cat "$STEPPATH/certs/intermediate_ca.crt" "$STEPPATH/certs/root_ca.crt") "$SS_SRV_LEAF" >/dev/null 2>&1 \
       && diff -q <(openssl x509 -in "$SS_SRV_LEAF" -pubkey -noout 2>/dev/null) \
                  <(openssl pkey -in "$SS_SRV_KEY" -pubout 2>/dev/null) >/dev/null 2>&1; then
      RESTORED_SS_SRV=true
      echo "Restored Smallstep RADIUS server cert from Secret Manager."
    else
      echo "Cached Smallstep server cert is expiring, no longer chains to the live CA, or its key does not match — re-issuing."
    fi
  fi

  if [ "$RESTORED_SS_SRV" = false ]; then
    # Issue a fresh leaf signed by the Smallstep intermediate (KMS-backed key).
    # Use `step certificate create` with --ca/--ca-key (NOT `certificate sign`,
    # whose --kms tries to resolve the issuer CERT via the KMS plugin and fails
    # with "cloudkms: does not implement a CertificateManager").
    step certificate create "$SS_SRV_CN" "$SS_SRV_LEAF" "$SS_SRV_KEY" \
      --ca "$STEPPATH/certs/intermediate_ca.crt" \
      --ca-key "${smallstep_signing_key_uri}" --kms cloudkms: \
      --san "$SS_SRV_CN" \
      --not-after 2160h \
      --kty RSA --size 2048 \
      --no-password --insecure --force \
    && openssl verify -CAfile <(cat "$STEPPATH/certs/intermediate_ca.crt" "$STEPPATH/certs/root_ca.crt") "$SS_SRV_LEAF" >/dev/null 2>&1 \
    && {
      # Persist both halves. Report cache success ONLY if BOTH writes land — a
      # cert-without-key (or vice versa) would let a later boot restore a
      # mismatched pair. The freshly-issued pair on disk is still used this boot
      # regardless; the warning only flags that the cache is incomplete.
      ss_cert_cached=false
      ss_key_cached=false
      gcloud secrets versions add radius-smallstep-server-cert --data-file="$SS_SRV_LEAF" --project="$PROJECT_ID" >/dev/null 2>&1 && ss_cert_cached=true
      gcloud secrets versions add radius-smallstep-server-key  --data-file="$SS_SRV_KEY"  --project="$PROJECT_ID" >/dev/null 2>&1 && ss_key_cached=true
      if [ "$ss_cert_cached" = true ] && [ "$ss_key_cached" = true ]; then
        echo "Issued + cached a fresh Smallstep RADIUS server cert (CN=$SS_SRV_CN)."
      else
        echo "WARNING: issued a fresh Smallstep RADIUS server cert but failed to cache a complete cert/key pair to Secret Manager (cert=$ss_cert_cached key=$ss_key_cached); a future boot will re-issue." >&2
      fi
    } || {
      # Fail-OPEN to the legacy cert: a server-cert issuance failure must not
      # take RADIUS down. Leave server-cert.pem as the legacy cert; migrated
      # devices stay broken (logged) but Okta-trust devices keep working.
      echo "WARNING: Smallstep RADIUS server-cert issuance failed; keeping the legacy server cert. EAP-TLS server-trust for migrated devices will fail until resolved." >&2
      SS_SRV_LEAF=""
    }
  fi

  # Swap in the Smallstep server cert + key. certificate_file MUST be the full
  # chain (leaf + intermediate) so the device can build leaf->intermediate->root.
  if [ -n "$SS_SRV_LEAF" ] && [ -s "$SS_SRV_LEAF" ]; then
    cat "$SS_SRV_LEAF" "$STEPPATH/certs/intermediate_ca.crt" > "$CERT_DIR/server-cert.pem"
    cp "$SS_SRV_KEY" "$CERT_DIR/server-key.pem"
    chown freerad:freerad "$CERT_DIR/server-cert.pem" "$CERT_DIR/server-key.pem"
    chmod 644 "$CERT_DIR/server-cert.pem"
    chmod 600 "$CERT_DIR/server-key.pem"
    echo "RADIUS now presents a Smallstep-chained server cert (leaf + intermediate)."
  fi
  rm -f /tmp/ss-server-cert.pem /tmp/ss-server-key.pem
fi
%{ endif ~}

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
        ca_file = $${certdir}/%{ if smallstep_enabled }%{ if radius_trust_mode == "smallstep" }smallstep-ca.pem%{ else }%{ if radius_trust_mode == "both" }trust-bundle.pem%{ else }okta-ca.pem%{ endif }%{ endif }%{ else }okta-ca.pem%{ endif }
        dh_file = $${certdir}/dh.pem
        ca_path = $${cadir}

        cipher_list = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256"
        ecdh_curve = "prime256v1"

        tls_min_version = "1.2"
        tls_max_version = "__TLS_MAX_VERSION__"

        # In-memory TLS session cache — speeds up re-auths within a server's uptime.
        # Note: persist_dir (disk cache) is broken in FreeRADIUS 3.x + OpenSSL 3.0
        # due to changed session callback APIs. Sessions won't survive restarts.
        # FreeRADIUS 4.0's cache_tls module will fix this.
        cache {
            enable = __TLS_CACHE_ENABLE__
            name = "eap-tls"
            lifetime = __TLS_CACHE_LIFETIME__
            max_entries = 4096
        }

        verify {
        }
    }

    tls {
        tls = tls-common
    }
}
EAPEOF

# Substitute TLS cache settings into EAP config
if [ "$TLS_SESSION_CACHE" = "true" ]; then
    sed -i 's/__TLS_CACHE_ENABLE__/yes/' "$RADDB/mods-available/eap"
else
    sed -i 's/__TLS_CACHE_ENABLE__/no/' "$RADDB/mods-available/eap"
fi
sed -i "s/__TLS_CACHE_LIFETIME__/$TLS_SESSION_CACHE_LIFETIME/" "$RADDB/mods-available/eap"
sed -i "s/__TLS_MAX_VERSION__/$TLS_MAX_VERSION/" "$RADDB/mods-available/eap"


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
# 9b. Fleet device owner lookup (optional)
#     Fleet-managed counterpart of the Jamf lookup above. Resolves serial ->
#     assigned-user email, device name, model via the Fleet REST API. Writes
#     to the SAME serial-keyed cache schema the Python module consumes
#     (email/device_name/device_model/ts), so json_log fields are unchanged.
#     Mutually exclusive with Jamf (enforced in variables.tf).
# ---------------------------------------------------------------------------
if [ "$HAS_FLEET_LOOKUP" = "true" ]; then
    echo "=== Configuring Fleet device owner lookup ==="

    # Fleet API token from Secret Manager (out-of-band observer token; same
    # secret the ACME webhook uses). Base URL comes from the Terraform var.
    FLEET_API_TOKEN=$(gcloud secrets versions access latest \
        --secret=fleet-api-token --project="$PROJECT_ID")

    # Write the credentials to a TMPFS-backed file under /run so the standing
    # Fleet token never lives at rest on the persistent disk. /run is tmpfs on
    # Debian (cleared on reboot); startup.sh re-creates it on every boot, and
    # the cache/fetch scripts + cron read it from there. umask 077 + explicit
    # perms keep it readable only by freerad.
    FLEET_CRED_FILE="/run/fleet-credentials.json"
    ( umask 077; cat > "$FLEET_CRED_FILE" << FLEETCREDEOF
{"url": "$FLEET_API_BASE_URL", "token": "$FLEET_API_TOKEN"}
FLEETCREDEOF
    )
    chown freerad:freerad "$FLEET_CRED_FILE"
    chmod 600 "$FLEET_CRED_FILE"
    unset FLEET_API_TOKEN

    # Deploy the Fleet device cache script (bulk inventory pull).
    cat > /usr/local/bin/fleet-device-cache.sh << 'FLEETCACHEEOF'
#!/bin/bash
# Fetches all Fleet hosts, builds serial -> device info cache.
# Called on boot and every 30 minutes via cron.
set -uo pipefail

CRED_FILE="/run/fleet-credentials.json"
CACHE_FILE="/etc/freeradius/3.0/fleet-device-cache.json"

[ -f "$CRED_FILE" ] || exit 0

python3 << 'PYEOF'
import json, urllib.request, urllib.error, sys, time, os

with open("/run/fleet-credentials.json") as f:
    cred = json.load(f)
base = cred["url"].rstrip("/")
token = cred["token"]
if not base or not token:
    sys.exit(0)

cache = {}
page = 0
page_size = 100
now = int(time.time())

while True:
    # device_mapping=true surfaces the assigned-user email in the list response,
    # avoiding a per-host detail call for the bulk build.
    api_url = (
        f"{base}/api/v1/fleet/hosts"
        f"?page={page}&per_page={page_size}&device_mapping=true"
    )
    req = urllib.request.Request(api_url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    try:
        resp = urllib.request.urlopen(req, timeout=30)
    except Exception as e:
        print(f"Fleet API error on page {page}: {e}", file=sys.stderr)
        break
    data = json.loads(resp.read())
    hosts = data.get("hosts") or []
    if not hosts:
        break
    for h in hosts:
        serial = (h.get("hardware_serial") or "").strip()
        if not serial:
            continue
        dm = h.get("device_mapping") or []
        email = (dm[0].get("email") if dm else "") or ""
        cache[serial] = {
            "email": email,
            "device_name": h.get("display_name") or h.get("computer_name") or h.get("hostname") or "",
            "device_model": h.get("hardware_model") or "",
            "ts": now,
        }
    # Fleet returns fewer than page_size on the last page.
    if len(hosts) < page_size:
        break
    page += 1

cache_file = "/etc/freeradius/3.0/fleet-device-cache.json"
tmp_file = cache_file + ".tmp"
with open(tmp_file, "w") as f:
    json.dump(cache, f)
os.replace(tmp_file, cache_file)  # atomic publish
print(f"Fleet cache: {len(cache)} devices")
PYEOF
FLEETCACHEEOF
    chmod 755 /usr/local/bin/fleet-device-cache.sh

    # Run initial cache build.
    /usr/local/bin/fleet-device-cache.sh || true

    # Refresh cache every 30 minutes.
    echo "*/30 * * * * root /usr/local/bin/fleet-device-cache.sh" > /etc/cron.d/fleet-device-cache
    chmod 644 /etc/cron.d/fleet-device-cache

    # Deploy single-device fetch script (for cache misses).
    cat > /usr/local/bin/fleet-device-fetch.sh << 'FLEETFETCHEOF'
#!/bin/bash
# Fetches a single host from Fleet by serial, updates the cache file.
# Called from the FreeRADIUS Python module via subprocess on cache miss.
set -uo pipefail

SERIAL="$1"
CRED_FILE="/run/fleet-credentials.json"

[ -n "$SERIAL" ] || exit 1
[ -f "$CRED_FILE" ] || exit 0

SERIAL="$SERIAL" python3 << 'PYEOF'
import json, urllib.request, urllib.parse, os, time, sys

serial = os.environ["SERIAL"]
with open("/run/fleet-credentials.json") as f:
    cred = json.load(f)
base = cred["url"].rstrip("/")
token = cred["token"]
if not base or not token:
    sys.exit(0)

# The by-identifier endpoint accepts serial/uuid/hostname.
api_url = f"{base}/api/v1/fleet/hosts/identifier/{urllib.parse.quote(serial, safe='')}"
req = urllib.request.Request(api_url, headers={
    "Authorization": f"Bearer {token}",
    "Accept": "application/json",
})
try:
    resp = urllib.request.urlopen(req, timeout=10)
except Exception:
    sys.exit(0)

host = (json.loads(resp.read()) or {}).get("host") or {}
if not host:
    sys.exit(0)

# Owner email: detail endpoint exposes it via end_users[].idp_username
# (device_mapping is often null on the detail view). Fall back to device_mapping.
email = ""
eu = host.get("end_users") or []
if eu:
    email = eu[0].get("idp_username") or ""
if not email:
    dm = host.get("device_mapping") or []
    email = (dm[0].get("email") if dm else "") or ""

entry = {
    "email": email,
    "device_name": host.get("display_name") or host.get("computer_name") or host.get("hostname") or "",
    "device_model": host.get("hardware_model") or "",
    "ts": int(time.time()),
}

CACHE_FILE = "/etc/freeradius/3.0/fleet-device-cache.json"
cache = {}
if os.path.isfile(CACHE_FILE):
    with open(CACHE_FILE) as f:
        cache = json.load(f)
cache[serial] = entry
with open(CACHE_FILE + ".tmp", "w") as f:
    json.dump(cache, f)
os.replace(CACHE_FILE + ".tmp", CACHE_FILE)
PYEOF
FLEETFETCHEOF
    chmod 755 /usr/local/bin/fleet-device-fetch.sh

    echo "Fleet credentials and cache configured."
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
if [ "$HAS_JAMF_LOOKUP" = "true" ] || [ "$HAS_FLEET_LOOKUP" = "true" ] || [ "$HAS_UNIFI_LOOKUP" = "true" ]; then
    echo "=== Configuring Python lookup module ==="

    mkdir -p "$RADDB/mods-config/python3"

    # Generated config the module imports — keeps the Terraform-templated
    # username separator out of the (single-quoted, non-interpolated) module
    # heredoc below. This small file IS interpolated by Terraform/shell so the
    # separator value is baked in; the module reads it with a safe fallback.
    cat > "$RADDB/mods-config/python3/radius_lookups_config.py" << RLCFGEOF
# Auto-generated by startup.sh — do not edit.
REWRITE_USERNAME_SEPARATOR = "$REWRITE_USERNAME_SEPARATOR"
RLCFGEOF
    chown freerad:freerad "$RADDB/mods-config/python3/radius_lookups_config.py"

    cat > "$RADDB/mods-config/python3/radius_lookups.py" << 'PYMODEOF'
import radiusd
import json
import os
import time
import threading
import subprocess

# Username separator used when post-auth rewrites User-Name to "email<sep>serial".
# Sourced from the generated radius_lookups_config.py (Terraform-templated) so the
# accounting serial-recovery path matches whatever separator post-auth applied.
# Falls back to the historical default if the config file is absent.
try:
    from radius_lookups_config import REWRITE_USERNAME_SEPARATOR
except Exception:
    REWRITE_USERNAME_SEPARATOR = " - "

# Device-owner enrichment source. Jamf and Fleet are mutually-exclusive MDM
# back-ends that write the SAME serial-keyed schema
# ({"email","device_name","device_model","ts"}); whichever is CONFIGURED wins.
# Selection keys on the CREDENTIALS file (presence = the source is configured),
# NOT the cache file — so a cache-miss fetch can still self-heal even if the
# initial bulk cache build hasn't succeeded yet. Fleet is preferred if both are
# somehow configured. Each entry: (cred_file, cache_file, fetch_script).
# Fleet creds live on tmpfs (/run) to avoid a standing token at rest on disk.
_MDM_SOURCES = [
    ("/run/fleet-credentials.json", "/etc/freeradius/3.0/fleet-device-cache.json", "/usr/local/bin/fleet-device-fetch.sh"),
    ("/etc/freeradius/3.0/jamf-credentials.json", "/etc/freeradius/3.0/jamf-device-cache.json", "/usr/local/bin/jamf-device-fetch.sh"),
]
DEVICE_CACHE_TTL = 3600  # 1 hour
UNIFI_CACHE_FILE = "/etc/freeradius/3.0/unifi-ap-cache.json"

# In-memory device cache — loaded from disk on startup and periodically
_device_cache = {}    # serial -> {"email":..., "device_name":..., "device_model":..., "ts": epoch}
_device_cache_lock = threading.Lock()
_device_cache_mtime = 0  # last mtime of disk cache when we loaded it
_pending_lookups = set()  # serials currently being fetched in background
_pending_lock = threading.Lock()


def _active_source():
    """Return (cache_file, fetch_script) for the configured MDM source, or
    (None, None) if no source is configured. Selection is based on the
    CREDENTIALS file (config presence), not the cache file, so cache misses can
    self-heal via the fetch script even before the first bulk build succeeds."""
    for cred_file, cache_file, fetch_script in _MDM_SOURCES:
        if os.path.isfile(cred_file):
            return cache_file, fetch_script
    return None, None


def _load_cache_from_disk():
    """Load the active MDM device cache from disk into memory if it changed."""
    global _device_cache, _device_cache_mtime
    try:
        cache_file, _ = _active_source()
        if not cache_file:
            return
        mtime = os.path.getmtime(cache_file)
        if mtime == _device_cache_mtime:
            return  # no change
        with open(cache_file, "r") as f:
            data = json.load(f)
        with _device_cache_lock:
            _device_cache = data
            _device_cache_mtime = mtime
        radiusd.radlog(radiusd.L_INFO,
            f"Loaded device cache from disk: {len(data)} devices ({cache_file})")
    except Exception as e:
        radiusd.radlog(radiusd.L_ERR, f"Failed to load device cache from disk: {e}")


def _device_background_fetch(serial):
    """Background thread: call external script to fetch a single device."""
    try:
        _, fetch_script = _active_source()
        if fetch_script and os.path.isfile(fetch_script):
            subprocess.run(
                [fetch_script, serial],
                timeout=15, capture_output=True,
            )
            # Reload cache from disk to pick up the new entry
            _load_cache_from_disk()
    except Exception as e:
        radiusd.radlog(radiusd.L_ERR, f"Device background fetch failed for {serial}: {e}")
    finally:
        with _pending_lock:
            _pending_lookups.discard(serial)


def instantiate(p):
    radiusd.radlog(radiusd.L_INFO, "radius_lookups module loaded")
    _load_cache_from_disk()
    return 0


def _get_cached_device(serial):
    """Read device-owner data from the in-memory cache. Returns dict or None.
    On cache miss or expiry, kicks off a background fetch via the active
    MDM source's external script."""
    # Reload from disk if file changed (picks up cron updates)
    _load_cache_from_disk()

    now = int(time.time())

    with _device_cache_lock:
        entry = _device_cache.get(serial)

    if entry and (now - entry.get("ts", 0)) < DEVICE_CACHE_TTL:
        return entry

    # Cache miss or expired — trigger background fetch if not already pending
    _, fetch_script = _active_source()
    if fetch_script and os.path.isfile(fetch_script):
        with _pending_lock:
            if serial not in _pending_lookups:
                _pending_lookups.add(serial)
                t = threading.Thread(target=_device_background_fetch, args=(serial,),
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


def _serial_from_username(user_name):
    """Normalize an EAP-TLS User-Name to the bare hardware serial used as the
    device-cache key.

    The MDM caches (Jamf/Fleet) are keyed on the bare serial (e.g.
    "FRAGAACPA74412000D"), but the EAP identity that arrives in User-Name is the
    client cert's Subject CN, which varies by platform:
      - Windows machine cert: "host/FRAGAACPA74412000D Campus WiFi"
          (Windows prefixes machine auth with "host/"; the CN carries a
           " Campus WiFi" suffix from the SCEP SubjectName, and an "OU=Campus
           WiFi" may follow as ",OU=...").
      - macOS:                "HXJKL3NH1WG2"  (bare serial, no suffix)
    Without this normalization the cache lookup misses and device_owner /
    device_name / device_model come back empty in the accept log.

    Steps: drop a leading "host/" (machine-auth prefix), take the CN portion
    before any ",OU=/,O=/," RDN, strip a trailing " Campus WiFi" suffix, trim.
    Idempotent on an already-bare serial.
    """
    if not user_name:
        return ""
    s = user_name.strip()
    # Drop the Windows machine-auth "host/" prefix (case-insensitive).
    if s[:5].lower() == "host/":
        s = s[5:]
    # If the CN string includes RDN separators (e.g. "<serial> Campus WiFi,OU=..."),
    # keep only the CN value before the first comma.
    s = s.split(",", 1)[0].strip()
    # Strip the " Campus WiFi" CN suffix our SCEP profiles append.
    if s.endswith(" Campus WiFi"):
        s = s[: -len(" Campus WiFi")].strip()
    return s


def post_auth(p):
    """Post-auth: MDM device-owner lookup (from cache) + UniFi AP/site lookup."""
    try:
        user_name = _get_attr(p, "User-Name")
        called_station = _get_attr(p, "Called-Station-Id")

        reply_attrs = []

        # Device-owner lookup — read from local cache (instant, no API call).
        # Normalize the EAP identity (host/<serial> Campus WiFi, etc.) to the
        # bare serial the MDM cache is keyed on.
        serial = _serial_from_username(user_name)
        if serial:
            try:
                dev = _get_cached_device(serial)
                if dev:
                    if dev.get("device_name"):
                        reply_attrs.append(("Filter-Id", dev["device_name"]))
                    if dev.get("device_model"):
                        reply_attrs.append(("Login-LAT-Node", dev["device_model"]))
                    if dev.get("email"):
                        reply_attrs.append(("Reply-Message", dev["email"]))
            except Exception as e:
                radiusd.radlog(radiusd.L_ERR, f"Device cache read failed: {e}")

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
    """Accounting: enrich with MDM device-owner info + UniFi AP/site from cache."""
    try:
        user_name = _get_attr(p, "User-Name")
        called_station = _get_attr(p, "Called-Station-Id")

        reply_attrs = []

        # Extract serial from User-Name — may be "email - serial" if the AP
        # cached the rewritten identity from post-auth, or just the EAP cert CN.
        serial = user_name.strip()
        if REWRITE_USERNAME_SEPARATOR and REWRITE_USERNAME_SEPARATOR in serial:
            serial = serial.rsplit(REWRITE_USERNAME_SEPARATOR, 1)[1]
        # Normalize whatever remains (host/<serial> Campus WiFi, bare serial, or
        # the post-rewrite serial half) to the bare serial the cache is keyed on.
        serial = _serial_from_username(serial)

        if serial:
            try:
                dev = _get_cached_device(serial)
                if dev:
                    if dev.get("device_name"):
                        reply_attrs.append(("Filter-Id", dev["device_name"]))
                    if dev.get("device_model"):
                        reply_attrs.append(("Login-LAT-Node", dev["device_model"]))
                    if dev.get("email"):
                        reply_attrs.append(("Reply-Message", dev["email"]))
            except Exception as e:
                radiusd.radlog(radiusd.L_ERR, f"Device cache read in accounting failed: {e}")

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
#     device_owner field is populated by the MDM lookup — Jamf or Fleet,
#     whichever is configured (empty if neither is enabled).
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

# Build post-auth section — single Python module handles Jamf/Fleet + UniFi
POSTAUTH_MODULES=""
if [ "$HAS_JAMF_LOOKUP" = "true" ] || [ "$HAS_FLEET_LOOKUP" = "true" ] || [ "$HAS_UNIFI_LOOKUP" = "true" ]; then
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
if [ "$HAS_JAMF_LOOKUP" = "true" ] || [ "$HAS_FLEET_LOOKUP" = "true" ] || [ "$HAS_UNIFI_LOOKUP" = "true" ]; then
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

%{ if smallstep_enabled ~}
# ---------------------------------------------------------------------------
# 16b. Datadog integration for the Smallstep step-ca
#      step-ca exposes NATIVE Prometheus metrics (namespace step_ca) on the
#      metricsAddress we set in ca.json (127.0.0.1:9090/metrics) — scraped via
#      Datadog OpenMetrics. Plus: journald log shipping, a /health HTTP check, a
#      process check, and custom cert-expiry + decrypter-readiness gauges (which
#      step_ca metrics don't cover). No OTLP — step-ca has no OpenTelemetry.
# ---------------------------------------------------------------------------
echo "=== Configuring Datadog for step-ca ==="

# --- OpenMetrics: scrape step-ca's native Prometheus endpoint. Counters are
# labeled by provisioner (wifi-acme / wifi-scep), so issuance + webhook +
# KMS-error rates break down per provisioner automatically.
mkdir -p /etc/datadog-agent/conf.d/openmetrics.d
cat > /etc/datadog-agent/conf.d/openmetrics.d/stepca.yaml << 'DDSTEPCAMETRICSEOF'
instances:
  - openmetrics_endpoint: http://127.0.0.1:9090/metrics
    namespace: smallstep
    tags:
      - "service:smallstep-ca"
    metrics:
      - step_ca_uptime_seconds: uptime
      - step_ca_provisioner_signed_total: provisioner.signed
      - step_ca_provisioner_renewed_total: provisioner.renewed
      - step_ca_provisioner_rekeyed_total: provisioner.rekeyed
      - step_ca_provisioner_webhook_authorized_total: provisioner.webhook_authorized
      - step_ca_provisioner_webhook_enriched_total: provisioner.webhook_enriched
      - step_ca_kms_signed: kms.signed
      - step_ca_kms_errors: kms.errors
DDSTEPCAMETRICSEOF

# --- Logs: ship step-ca's journald unit as source=stepca service=smallstep-ca.
# step-ca logs structured JSON (logger.format=json); the Datadog stepca log
# pipeline (UI/Terraform) parses path/status/method/duration and the decrypter/
# error lines. The agent just ships the lines with the right source/service.
mkdir -p /etc/datadog-agent/conf.d/stepca.d
cat > /etc/datadog-agent/conf.d/stepca.d/conf.yaml << 'DDSTEPCALOGSEOF'
logs:
  # Tail the tee'd step-ca log file (text + JSON lines). A file tailer ships
  # every line verbatim, unlike the journald tailer which dropped step-ca's
  # plain-text operational lines.
  - type: file
    path: /var/log/step-ca/step-ca.log
    source: stepca
    service: smallstep-ca
    log_processing_rules:
      - type: exclude_at_match
        name: exclude_healthy_health_checks
        # Drop /health lines only when they return 200 (GCLB + Datadog probe
        # noise); a failing /health still ships. step-ca's JSON field order is
        # stable: "path" precedes "status".
        pattern: '"path":"/health".*"status":200'
DDSTEPCALOGSEOF

# dd-agent must be in systemd-journal to read the unit's journal.
usermod -aG systemd-journal dd-agent || true

# --- HTTP check: step-ca /health on :8443 (the cert is the CA's own chain, so
# skip TLS verify on the loopback probe).
mkdir -p /etc/datadog-agent/conf.d/http_check.d
cat > /etc/datadog-agent/conf.d/http_check.d/conf.yaml << 'DDHTTPEOF'
instances:
  - name: stepca-health
    url: https://127.0.0.1:8443/health
    tls_verify: false
    timeout: 5
    tags:
      - "service:smallstep-ca"
      - "component:step-ca"
DDHTTPEOF

# --- Process check: alert if the step-ca process disappears.
mkdir -p /etc/datadog-agent/conf.d/process.d
cat > /etc/datadog-agent/conf.d/process.d/conf.yaml << 'DDPROCEOF'
instances:
  - name: step-ca
    search_string:
      - 'step-ca'
    exact_match: false
    tags:
      - "service:smallstep-ca"
DDPROCEOF

# --- Custom gauges step_ca metrics don't expose: cert days-until-expiry and
# SCEP decrypter readiness. Emitted to the agent via DogStatsD on a timer.
#   smallstep.cert.days_until_expiry{cert:intermediate|decrypter}
#   smallstep.scep.decrypter_ready  (1 = initialized, 0 = degraded)
cat > /usr/local/bin/stepca-dd-metrics.sh << 'STEPCAMETRICSEOF'
#!/bin/bash
# Emit step-ca health gauges to the Datadog Agent via DogStatsD (UDP 8125).
set -uo pipefail
STEP=/etc/step-ca
DSD=127.0.0.1
PORT=8125

emit() { # full_datagram (name:value|type|#tags)
  printf '%s\n' "$1" >"/dev/udp/$DSD/$PORT" 2>/dev/null || true
}

days_left() { # pem-file -> integer days, or empty
  local f="$1" end now
  [ -s "$f" ] || { echo ""; return; }
  end=$(date -d "$(openssl x509 -enddate -noout -in "$f" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null) || { echo ""; return; }
  now=$(date +%s)
  echo $(( (end - now) / 86400 ))
}

di=$(days_left "$STEP/certs/intermediate_ca.crt")
[ -n "$di" ] && emit "smallstep.cert.days_until_expiry:$di|g|#cert:intermediate,service:smallstep-ca"
dd=$(days_left "$STEP/certs/scep_decrypter.crt")
[ -n "$dd" ] && emit "smallstep.cert.days_until_expiry:$dd|g|#cert:decrypter,service:smallstep-ca"

ready=1
since=$(systemctl show step-ca -p ActiveEnterTimestamp --value 2>/dev/null)
if [ -n "$since" ] && journalctl -u step-ca --since "$since" --no-pager 2>/dev/null | grep -q "does not have decrypter"; then
  ready=0
fi
emit "smallstep.scep.decrypter_ready:$ready|g|#service:smallstep-ca"
STEPCAMETRICSEOF
chmod +x /usr/local/bin/stepca-dd-metrics.sh

# Ensure DogStatsD is enabled so the custom gauges are accepted.
if ! grep -q "^use_dogstatsd:" /etc/datadog-agent/datadog.yaml; then
  echo "use_dogstatsd: true" >> /etc/datadog-agent/datadog.yaml
fi

cat > /etc/systemd/system/stepca-dd-metrics.service << 'STEPCASVCEOF'
[Unit]
Description=Emit step-ca cert-expiry + decrypter gauges to Datadog
After=step-ca.service datadog-agent.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/stepca-dd-metrics.sh
STEPCASVCEOF
cat > /etc/systemd/system/stepca-dd-metrics.timer << 'STEPCATIMEREOF'
[Unit]
Description=Run step-ca Datadog gauge emitter every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
STEPCATIMEREOF
systemctl daemon-reload
systemctl enable --now stepca-dd-metrics.timer
%{ endif ~}

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
