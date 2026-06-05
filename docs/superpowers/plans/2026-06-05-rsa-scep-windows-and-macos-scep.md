# RSA SCEP CA (Windows + non-ADE Macs) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Shipped correction:** the plan originally put the RSA intermediate "under the existing EC root." That proved impossible (the EC root key is discarded after EC init; the EC intermediate is `pathlen:0`). The shipped RSA CA is **self-contained**: its own self-signed **RSA-4096 root** → RSA intermediate (KMS) → RSA decrypter, in a **standalone init-or-restore block decoupled from the EC CA** (keyed on `smallstep-rsa-intermediate-cert`). RADIUS trusts **both** roots (EC + RSA → 4 anchors). New secret `smallstep-rsa-root-cert` persists the RSA root. Read "under the existing EC root" / "EC-root-signed" anywhere below as "self-signed RSA root."

**Goal:** Stand up a second, **self-contained** step-ca instance on the existing RADIUS VMs with its own RSA-4096 root + RSA-2048 KMS-HSM issuing intermediate, serving SCEP to both Windows and non-ADE/DEP Macs, without touching the EC ACME path or the 460 attested-ACME Macs.

**Architecture:** A new Cloud KMS RSA signing key + new Secret Manager secrets (incl. `smallstep-rsa-root-cert`) + a new GCLB stack (`ca-rsa.campusgroup.co`:8444, sharing the existing instance groups via a second named port) are added in Terraform. `startup.sh` gains a **standalone** RSA CA bootstrap block (its own init-or-restore, independent of the EC block) that mints a self-signed RSA root → RSA intermediate + RSA SCEP decrypter, renders a second `ca.json` (`excludeIntermediate: true`), and runs a `step-ca-rsa.service` on :8444. FreeRADIUS adds the RSA intermediate **and RSA root** to its client-cert trust bundle. Fleet profiles for Windows and non-ADE Macs point at the new RSA endpoint and carry the RSA intermediate as a profile payload.

**Tech Stack:** Terraform (google provider), GCP (Cloud KMS HSM, Secret Manager, Cloud SQL Postgres, GCLB), step-ca 0.30.2 + step-kms-plugin, FreeRADIUS, Fleet GitOps.

**Verification model:** This is infrastructure, not unit-tested code. Each task's "test" is a concrete command (`terraform validate`, `terraform plan`, `curl` GetCACert, `openssl` chain verify, on-device event-log read) with expected output. Make change → run verification → confirm expected → commit.

**Reference design:** `docs/superpowers/specs/2026-06-05-rsa-scep-windows-and-macos-scep-design.md`

**Key facts (proven this session, do not re-litigate):**
- Windows native SCEP CSP can't verify an EC-signed leaf (`signature of the certificate cannot be verified`); needs RSA issuer.
- Apple SCEP `Key Type` is "Always RSA", file-based (not Secure Enclave), and is incompatible with an EC issuing CA. So non-ADE Macs ALSO need the RSA CA.
- step-ca can't do EC-ACME + RSA-SCEP in one instance (single top-level `crt`/`key`; SCEP has no per-provisioner issuer). Hence a 2nd instance.
- `excludeIntermediate: true` is required on the SCEP provisioner so GetCACert returns only the RSA decrypter (else the Windows CSP picks the wrong PKCS#7 recipient). Consequence: both profiles must carry the RSA intermediate as a separate cert payload.
- EC root signing an RSA intermediate is valid X.509 (already done for the existing RSA SCEP decrypter `7C639509`).
- step-ca 0.30.2 `step ca init --kms` can't bind a pre-created KMS key; build the PKI by hand with `step certificate create ... --kms cloudkms: --key <uri>`.

---

## File Structure

**cloud-8021x:**
- `smallstep.tf` — MODIFY: add RSA KMS key + IAM, 3 new secrets + IAM, RSA LB stack (IP, cert, IG named-port, backend, HC, URL map, proxy, forwarding rule), firewall :8444.
- `variables.tf` — MODIFY: add `smallstep_ca_rsa_dns_name`, `smallstep_scep_rsa_provisioner_name`.
- `compute.tf` — MODIFY: pass new template vars (`smallstep_ca_rsa_dns_name`, `smallstep_rsa_signing_key_uri`, `smallstep_scep_rsa_name`) into `templatefile()`.
- `outputs.tf` — MODIFY: add `smallstep_scep_rsa_url`, `smallstep_rsa_lb_ip`.
- `scripts/startup.sh` — MODIFY: add RSA CA bootstrap (init/restore), render `ca-rsa` ca.json, `step-ca-rsa.service`, RSA-intermediate into RADIUS trust bundle.
- `terraform.tfvars` — MODIFY: set the two new vars.

**fleet-gitops:**
- `lib/windows/configuration-profiles/campus-wifi-smallstep-scep-direct.xml` — MODIFY: repoint to `ca-rsa`, new CAThumbprint, ensure RSA intermediate on-device.
- `lib/macos/configuration-profiles/campus-wifi-scep.mobileconfig` — CREATE/finish (from paused branch): RSA SCEP against `ca-rsa` + separate RSA-intermediate cert payload.
- `fleets/workstations.yml` — MODIFY: scoping for both.

---

## Phase 1 — Terraform: RSA KMS key, secrets, LB (additive, no disruption)

### Task 1: RSA signing key in Cloud KMS

**Files:**
- Modify: `cloud-8021x/smallstep.tf` (after the `smallstep_signing` key block, ~line 47)

- [ ] **Step 1: Add the RSA signing key + IAM**

In `smallstep.tf`, after `resource "google_kms_crypto_key" "smallstep_signing"` (the EC key) and its IAM members, add:

```hcl
# RSA CA signing key — backs the SECOND step-ca instance's intermediate, which
# issues SCEP leaves for Windows + non-ADE/DEP Macs. Windows native SCEP and
# Apple SCEP both require an RSA-signed leaf; the EC key (above) cannot serve
# them. ASYMMETRIC_SIGN purpose (issuing only — distinct from the single-purpose
# ASYMMETRIC_DECRYPT scep-decrypter key). HSM for FIPS posture, matching ca-signing.
resource "google_kms_crypto_key" "smallstep_signing_rsa" {
  count    = local.smallstep_enabled
  name     = "ca-signing-rsa"
  key_ring = google_kms_key_ring.smallstep[0].id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "RSA_SIGN_PKCS1_2048_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "smallstep_signing_rsa_use" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing_rsa[0].id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_kms_crypto_key_iam_member" "smallstep_signing_rsa_viewer" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing_rsa[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.radius.email}"
}
```

- [ ] **Step 2: Validate**

Run: `cd ~/Repos/Campus/IT/cloud-8021x && terraform fmt && terraform validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add smallstep.tf
git commit -m "stepca(rsa): add RSA-2048 HSM signing key for the SCEP CA instance"
```

### Task 2: New Secret Manager secrets for the RSA chain

**Files:**
- Modify: `cloud-8021x/smallstep.tf` (after the existing `smallstep_scep_decrypter_key` secret block, ~line 344)

- [ ] **Step 1: Add three secrets + IAM (RSA intermediate cert, RSA decrypter cert, RSA decrypter key)**

In `smallstep.tf`, after the existing `smallstep_scep_decrypter_key` IAM members, add:

```hcl
# --- RSA CA (instance #2) persisted artifacts. Same model as instance #1:
#     created empty here, populated by the first VM at RSA-CA init, restored by
#     the 2nd VM / any reboot. smallstep-rsa-intermediate-cert is the readiness
#     marker (published LAST). -------------------------------------------------
resource "google_secret_manager_secret" "smallstep_rsa_intermediate_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-rsa-intermediate-cert"
  replication { auto {} }
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_intermediate_cert_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_intermediate_cert[0].secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_intermediate_cert_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_intermediate_cert[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret" "smallstep_rsa_scep_decrypter_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-rsa-scep-decrypter-cert"
  replication { auto {} }
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_scep_decrypter_cert_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_scep_decrypter_cert[0].secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_scep_decrypter_cert_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_scep_decrypter_cert[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret" "smallstep_rsa_scep_decrypter_key" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-rsa-scep-decrypter-key"
  replication { auto {} }
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_scep_decrypter_key_version_manager" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_scep_decrypter_key[0].secret_id
  role      = "roles/secretmanager.secretVersionManager"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_rsa_scep_decrypter_key_accessor" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_rsa_scep_decrypter_key[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}
```

- [ ] **Step 2: Validate**

Run: `terraform fmt && terraform validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add smallstep.tf
git commit -m "stepca(rsa): add Secret Manager secrets for the RSA chain"
```

### Task 3: Variables + outputs for the RSA endpoint

**Files:**
- Modify: `cloud-8021x/variables.tf` (after `smallstep_scep_provisioner_name`, ~line 235)
- Modify: `cloud-8021x/outputs.tf` (after `smallstep_scep_url`, ~line 54)

- [ ] **Step 1: Add variables**

In `variables.tf`:

```hcl
variable "smallstep_ca_rsa_dns_name" {
  description = "DNS name for the RSA SCEP step-ca instance (instance #2). A record must point at smallstep_rsa_lb_ip. Required when enable_smallstep_ca is true."
  type        = string
  default     = ""

  validation {
    condition     = !var.enable_smallstep_ca || trimspace(var.smallstep_ca_rsa_dns_name) != ""
    error_message = "smallstep_ca_rsa_dns_name must be set when enable_smallstep_ca is true."
  }
}

variable "smallstep_scep_rsa_provisioner_name" {
  description = "Name of the SCEP provisioner on the RSA step-ca instance (path segment in the SCEP URL)."
  type        = string
  default     = "wifi-scep"
}
```

- [ ] **Step 2: Add outputs**

In `outputs.tf`:

```hcl
output "smallstep_scep_rsa_url" {
  description = "RSA SCEP enrollment URL (Windows + non-ADE Macs point here). Empty if disabled."
  value       = var.enable_smallstep_ca ? "https://${var.smallstep_ca_rsa_dns_name}/scep/${var.smallstep_scep_rsa_provisioner_name}" : ""
}

output "smallstep_rsa_lb_ip" {
  description = "Public IP of the RSA step-ca load balancer; point smallstep_ca_rsa_dns_name at this A record. Empty if disabled."
  value       = var.enable_smallstep_ca ? google_compute_global_address.smallstep_rsa_lb[0].address : ""
}
```

- [ ] **Step 3: Validate** (will fail until Task 4 creates `smallstep_rsa_lb` — that's expected; just confirm the var/output syntax parses with fmt)

Run: `terraform fmt`
Expected: files reformatted, no syntax error. (`terraform validate` is deferred to Task 4 Step 2, since the output references a not-yet-created resource.)

- [ ] **Step 4: Commit**

```bash
git add variables.tf outputs.tf
git commit -m "stepca(rsa): add RSA endpoint variables + outputs"
```

### Task 4: RSA LB stack + firewall

**Files:**
- Modify: `cloud-8021x/smallstep.tf` (after the existing `google_compute_global_forwarding_rule.smallstep`, ~line 496)

- [ ] **Step 1: Add the RSA LB stack** (mirror of the existing `smallstep_*` LB block, `-rsa` names, port 8444, named port `stepca-rsa`)

```hcl
# --- RSA step-ca (instance #2): firewall + external HTTPS LB on :8444 ----------
resource "google_compute_firewall" "allow_stepca_rsa_lb" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "allow-stepca-rsa-lb"
  network = google_compute_network.radius.id
  allow {
    protocol = "tcp"
    ports    = ["8444"]
  }
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["radius-server"]
}

resource "google_compute_global_address" "smallstep_rsa_lb" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-rsa-lb-ip"
}

resource "google_compute_managed_ssl_certificate" "smallstep_rsa" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-rsa-cert"
  managed {
    domains = [var.smallstep_ca_rsa_dns_name]
  }
}

resource "google_compute_instance_group" "smallstep_rsa_primary" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  name      = "smallstep-rsa-ig-primary"
  zone      = var.zone
  instances = [google_compute_instance.radius.self_link]
  named_port {
    name = "stepca-rsa"
    port = 8444
  }
}

resource "google_compute_instance_group" "smallstep_rsa_secondary" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  name      = "smallstep-rsa-ig-secondary"
  zone      = var.secondary_zone
  instances = [google_compute_instance.radius_secondary.self_link]
  named_port {
    name = "stepca-rsa"
    port = 8444
  }
}

resource "google_compute_health_check" "smallstep_rsa" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-rsa-hc"
  https_health_check {
    port         = 8444
    request_path = "/health"
  }
}

resource "google_compute_backend_service" "smallstep_rsa" {
  count                 = local.smallstep_enabled
  project               = google_project.this.project_id
  name                  = "smallstep-ca-rsa-backend"
  protocol              = "HTTPS"
  port_name             = "stepca-rsa"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  health_checks         = [google_compute_health_check.smallstep_rsa[0].id]
  security_policy       = google_compute_security_policy.smallstep[0].id

  backend {
    group = google_compute_instance_group.smallstep_rsa_primary[0].id
  }
  backend {
    group = google_compute_instance_group.smallstep_rsa_secondary[0].id
  }
}

resource "google_compute_url_map" "smallstep_rsa" {
  count           = local.smallstep_enabled
  project         = google_project.this.project_id
  name            = "smallstep-ca-rsa-urlmap"
  default_service = google_compute_backend_service.smallstep_rsa[0].id
}

resource "google_compute_target_https_proxy" "smallstep_rsa" {
  count            = local.smallstep_enabled
  project          = google_project.this.project_id
  name             = "smallstep-ca-rsa-https-proxy"
  url_map          = google_compute_url_map.smallstep_rsa[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.smallstep_rsa[0].id]
}

resource "google_compute_global_forwarding_rule" "smallstep_rsa" {
  count                 = local.smallstep_enabled
  project               = google_project.this.project_id
  name                  = "smallstep-ca-rsa-fr"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.smallstep_rsa_lb[0].address
  port_range            = "443"
  target                = google_compute_target_https_proxy.smallstep_rsa[0].id
}
```

- [ ] **Step 2: Validate**

Run: `terraform fmt && terraform validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add smallstep.tf
git commit -m "stepca(rsa): add RSA step-ca LB stack + firewall on :8444"
```

### Task 5: Wire RSA template vars into compute.tf + tfvars

**Files:**
- Modify: `cloud-8021x/compute.tf` (the `templatefile(...)` map, ~lines 114-160)
- Modify: `cloud-8021x/terraform.tfvars`
- Modify: `cloud-8021x/terraform.tfvars.example`

- [ ] **Step 1: Add template vars**

In `compute.tf`, inside the `templatefile("${path.module}/scripts/startup.sh", { ... })` map, after the `smallstep_signing_key_uri` line, add:

```hcl
    smallstep_ca_rsa_dns_name = var.smallstep_ca_rsa_dns_name
    smallstep_scep_rsa_name   = var.smallstep_scep_rsa_provisioner_name
    smallstep_rsa_signing_key_uri = var.enable_smallstep_ca ? "cloudkms:projects/${google_project.this.project_id}/locations/${var.region}/keyRings/smallstep-ca/cryptoKeys/ca-signing-rsa/cryptoKeyVersions/1" : ""
```

- [ ] **Step 2: Set the new vars in tfvars**

In `terraform.tfvars` add (use a real DNS name under campusgroup.co):

```hcl
smallstep_ca_rsa_dns_name = "ca-rsa.campusgroup.co"
```

In `terraform.tfvars.example` add the same key with an explanatory comment.

- [ ] **Step 3: Validate**

Run: `terraform fmt && terraform validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 4: Plan (review additive-only)**

Run: `terraform plan -out=tfplan-rsa 2>&1 | tee /tmp/rsa-plan.txt | tail -40`
Expected: only **additions** (KMS key, 3 secrets + IAM, LB resources, firewall). **Zero changes/destroys to existing `smallstep_*` (EC) resources, the VMs, or `google_compute_instance.radius*`.** If any existing resource shows `~`/`-`, STOP and investigate before applying.

- [ ] **Step 5: Commit**

```bash
git add compute.tf terraform.tfvars terraform.tfvars.example
git commit -m "stepca(rsa): wire RSA template vars + ca-rsa DNS into startup"
```

---

## Phase 2 — startup.sh: RSA CA bootstrap

> The RSA CA bootstrap mirrors the EC block (startup.sh ~lines 269-431) but: reuses the existing EC root cert/key (the local root key is still on-box during init, before `rm -f root_ca_key`), mints an RSA intermediate via `--kms cloudkms: --key ${smallstep_rsa_signing_key_uri}`, mints a dedicated RSA decrypter, persists to the `smallstep-rsa-*` secrets, and stages the RSA intermediate for RADIUS trust. It renders a SECOND ca.json and a SECOND systemd unit. The RSA init MUST run inside the SAME `else` (first-init) branch as the EC init, BEFORE `rm -f "$STEPPATH/secrets/root_ca_key"`, because it needs the root key to sign the RSA intermediate + decrypter.

### Task 6: RSA CA init — mint RSA intermediate + decrypter (first-init branch)

**Files:**
- Modify: `cloud-8021x/scripts/startup.sh` (inside the EC first-init `else` branch, AFTER the SCEP decrypter `step certificate create` ~line 399 and BEFORE the single publish/`rm root_ca_key` gate ~line 401)

- [ ] **Step 1: Add RSA intermediate + RSA decrypter minting**

Immediately after the existing EC `step certificate create "${ca_name_prefix} SCEP Decrypter" ...` block and its `chmod 600`, and BEFORE the `[ -s ... root_ca.crt ] && ...` publish gate, insert:

```bash
  # --- RSA CA (instance #2): intermediate + SCEP decrypter --------------------
  # Windows native SCEP and Apple SCEP both require an RSA-signed leaf. The EC
  # intermediate (above) cannot serve them, and step-ca can't issue from two
  # chains in one process, so instance #2 has its OWN RSA intermediate, signed by
  # the SAME local EC root (valid X.509: EC issuer signs RSA subject) so RADIUS
  # keeps one trust anchor. KMS-backed signer, same hand-built approach as EC.
  mkdir -p /etc/step-ca-rsa/certs /etc/step-ca-rsa/secrets /etc/step-ca-rsa/config
  # RSA intermediate: public key from the Cloud KMS RSA signing key; signed by
  # the local EC root. /dev/null for the key (private key lives in Cloud KMS).
  step certificate create "${ca_name_prefix} RSA Intermediate CA" \
    "/etc/step-ca-rsa/certs/intermediate_ca.crt" /dev/null \
    --profile intermediate-ca \
    --ca "$STEPPATH/certs/root_ca.crt" --ca-key "$STEPPATH/secrets/root_ca_key" \
    --kms "cloudkms:" --key "${smallstep_rsa_signing_key_uri}" \
    --no-password --insecure --force
  # RSA SCEP decrypter (dedicated to instance #2): a dual-purpose software RSA
  # key (KMS keys are single-purpose; the SCEP decrypter must decrypt AND sign),
  # signed BY the RSA intermediate. The intermediate's private key lives in Cloud
  # KMS, so sign with `--kms cloudkms: --ca-key <rsa-kms-uri>` (NOT the local root
  # key). Issuer of the decrypter == the RSA intermediate; verify in Task 9.5.
  step certificate create "${ca_name_prefix} RSA SCEP Decrypter" \
    "/etc/step-ca-rsa/certs/scep_decrypter.crt" "/etc/step-ca-rsa/secrets/scep_decrypter_key" \
    --ca "/etc/step-ca-rsa/certs/intermediate_ca.crt" \
    --kms "cloudkms:" --ca-key "${smallstep_rsa_signing_key_uri}" \
    --kty RSA --size 2048 \
    --not-after 87600h --no-password --insecure --force
  chmod 600 /etc/step-ca-rsa/secrets/scep_decrypter_key
```

> RISK (verify at execution, Task 9.5): the `--kms cloudkms: --ca-key <rsa-uri>` form for signing the decrypter is the one invocation NOT directly copied from existing working code. If `step certificate create` rejects a KMS URI as `--ca-key`, fall back to: generate the decrypter as a CSR (`step certificate create --csr`) and sign it with `step certificate sign --kms cloudkms: --key <rsa-uri>` using the RSA intermediate as issuer. Confirm the decrypter's issuer == the RSA intermediate before publishing.

- [ ] **Step 2: Extend the publish gate + add RSA publishes**

Find the existing publish gate and publish sequence (startup.sh ~lines 401-422). Replace the gate condition and add RSA publishes so the RSA artifacts publish BEFORE the existing `smallstep-intermediate-cert` readiness marker (the RSA marker `smallstep-rsa-intermediate-cert` is published LAST among RSA artifacts). Change:

```bash
  [ -s "$STEPPATH/certs/root_ca.crt" ] && [ -s "$STEPPATH/certs/intermediate_ca.crt" ] && [ -s "$STEPPATH/certs/scep_decrypter.crt" ] && [ -s "$STEPPATH/secrets/scep_decrypter_key" ] || {
    echo "FATAL: Smallstep CA bootstrap did not produce all certificates/keys" >&2
    exit 1
  }
```

to also assert the RSA artifacts:

```bash
  [ -s "$STEPPATH/certs/root_ca.crt" ] && [ -s "$STEPPATH/certs/intermediate_ca.crt" ] && [ -s "$STEPPATH/certs/scep_decrypter.crt" ] && [ -s "$STEPPATH/secrets/scep_decrypter_key" ] \
    && [ -s "/etc/step-ca-rsa/certs/intermediate_ca.crt" ] && [ -s "/etc/step-ca-rsa/certs/scep_decrypter.crt" ] && [ -s "/etc/step-ca-rsa/secrets/scep_decrypter_key" ] || {
    echo "FATAL: Smallstep CA bootstrap did not produce all certificates/keys (EC + RSA)" >&2
    exit 1
  }
```

Then, AFTER the existing `gcloud secrets versions add smallstep-scep-decrypter-key ...` and BEFORE the EC readiness marker `gcloud secrets versions add smallstep-intermediate-cert ...`, add the RSA publishes (RSA decrypter cert+key first, RSA intermediate marker last):

```bash
  gcloud secrets versions add smallstep-rsa-scep-decrypter-cert --project="${project_id}" \
    --data-file="/etc/step-ca-rsa/certs/scep_decrypter.crt"
  gcloud secrets versions add smallstep-rsa-scep-decrypter-key --project="${project_id}" \
    --data-file="/etc/step-ca-rsa/secrets/scep_decrypter_key"
  # RSA readiness marker — published last among RSA artifacts.
  gcloud secrets versions add smallstep-rsa-intermediate-cert --project="${project_id}" \
    --data-file="/etc/step-ca-rsa/certs/intermediate_ca.crt"
```

- [ ] **Step 3: Stage RSA intermediate for RADIUS trust (init branch)**

Find the init-branch trust staging `cat "$STEPPATH/certs/intermediate_ca.crt" "$STEPPATH/certs/root_ca.crt" > /tmp/smallstep-ca.crt` (~line 428) and append the RSA intermediate:

```bash
  cat "$STEPPATH/certs/intermediate_ca.crt" "/etc/step-ca-rsa/certs/intermediate_ca.crt" "$STEPPATH/certs/root_ca.crt" > /tmp/smallstep-ca.crt
```

- [ ] **Step 4: Bash syntax check**

Run: `cd ~/Repos/Campus/IT/cloud-8021x && terraform fmt -check && bash -n <(terraform console <<<'' 2>/dev/null; cat scripts/startup.sh | sed 's/\${[a-z_]*}/X/g; s/%{[^}]*}//g')`
Expected: no syntax error printed. (The `sed` strips Terraform interpolations so `bash -n` can parse the template. If `bash -n` errors on a stripped directive, inspect manually.)

- [ ] **Step 5: Commit**

```bash
git add scripts/startup.sh
git commit -m "stepca(rsa): mint RSA intermediate + decrypter at CA init"
```

### Task 7: RSA CA restore (reboot / 2nd VM)

**Files:**
- Modify: `cloud-8021x/scripts/startup.sh` (the `RESTORE_CA=yes` branch, ~lines 322-349)

- [ ] **Step 1: Add an RSA readiness probe + restore, mirroring the EC one**

The EC restore keys on `smallstep-intermediate-cert` having an enabled version. Add an analogous probe for `smallstep-rsa-intermediate-cert` and restore the RSA artifacts. Inside the `if [ "$RESTORE_CA" = "yes" ]; then` block, after the EC restore + partial-publish gate (~line 343) and before the trust-staging `cat`, add:

```bash
  # Restore the RSA CA (instance #2). Same model: the RSA intermediate cert is
  # the readiness marker. Read with backoff; FATAL on persistent failure (a
  # present-but-unreadable RSA CA must not be re-minted).
  mkdir -p /etc/step-ca-rsa/certs /etc/step-ca-rsa/secrets /etc/step-ca-rsa/config
  RSA_RESTORE=""
  for attempt in 1 2 3 4 5; do
    if gcloud secrets versions access latest --secret=smallstep-rsa-intermediate-cert --project="${project_id}" >"/etc/step-ca-rsa/certs/intermediate_ca.crt" 2>/dev/null && [ -s "/etc/step-ca-rsa/certs/intermediate_ca.crt" ]; then
      RSA_RESTORE=yes
      break
    fi
    echo "smallstep-rsa-intermediate-cert read failed (attempt $attempt), retrying..." >&2
    sleep $((attempt * 5))
  done
  if [ "$RSA_RESTORE" != "yes" ]; then
    echo "FATAL: smallstep-rsa-intermediate-cert unreadable after retries; refusing to start (RSA SCEP would be broken)" >&2
    exit 1
  fi
  gcloud secrets versions access latest --secret=smallstep-rsa-scep-decrypter-cert --project="${project_id}" >"/etc/step-ca-rsa/certs/scep_decrypter.crt"
  gcloud secrets versions access latest --secret=smallstep-rsa-scep-decrypter-key --project="${project_id}" >"/etc/step-ca-rsa/secrets/scep_decrypter_key"
  chmod 600 /etc/step-ca-rsa/secrets/scep_decrypter_key
  [ -s "/etc/step-ca-rsa/certs/scep_decrypter.crt" ] && [ -s "/etc/step-ca-rsa/secrets/scep_decrypter_key" ] || {
    echo "FATAL: RSA SCEP decrypter cert/key partially published" >&2
    exit 1
  }
  # RSA instance reuses the SAME root cert (already restored to $STEPPATH/certs/root_ca.crt).
  cp "$STEPPATH/certs/root_ca.crt" "/etc/step-ca-rsa/certs/root_ca.crt"
```

- [ ] **Step 2: Stage RSA intermediate for RADIUS trust (restore branch)**

Replace the restore-branch trust staging line (~line 349) `cat "$STEPPATH/certs/intermediate_ca.crt" "$STEPPATH/certs/root_ca.crt" > /tmp/smallstep-ca.crt` with:

```bash
  cat "$STEPPATH/certs/intermediate_ca.crt" "/etc/step-ca-rsa/certs/intermediate_ca.crt" "$STEPPATH/certs/root_ca.crt" > /tmp/smallstep-ca.crt
```

- [ ] **Step 3: Syntax check**

Run: `cat scripts/startup.sh | sed 's/\${[a-z_]*}/X/g; s/%{[^}]*}//g' | bash -n`
Expected: no output (valid).

- [ ] **Step 4: Commit**

```bash
git add scripts/startup.sh
git commit -m "stepca(rsa): restore RSA chain on reboot / 2nd VM"
```

### Task 8: Render the RSA ca.json + systemd unit + log/probe

**Files:**
- Modify: `cloud-8021x/smallstep.tf` (add `stepca_rsa` database)
- Modify: `cloud-8021x/scripts/startup.sh` (after the EC `step-ca.service` enable, ~line 586; before the webhook block)

The two step-ca instances share the one Cloud SQL Postgres instance but use **separate databases** (`stepca` for EC, `stepca_rsa` for RSA) for clean isolation — selected via the database segment of the connection path.

- [ ] **Step 1: Create the `stepca_rsa` database in Terraform**

In `smallstep.tf`, after `google_sql_database.smallstep`, add:

```hcl
resource "google_sql_database" "smallstep_rsa" {
  count    = local.smallstep_enabled
  project  = google_project.this.project_id
  name     = "stepca_rsa"
  instance = google_sql_database_instance.smallstep[0].name
}
```

Run: `terraform fmt && terraform validate` → `Success!`

- [ ] **Step 2: Render ca-rsa ca.json**

After `systemctl enable --now step-ca` and `echo "step-ca started."`, add. Note: `excludeIntermediate: true` (proven required for Windows), NO ACME provisioner, dataSource points at the `stepca_rsa` database, distinct `metricsAddress` (9091, EC uses 9090):

```bash
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
        "claims": { "maxTLSCertDuration": "2160h", "defaultTLSCertDuration": "2160h" }
      }
    ]
  },
  "tls": { "minVersion": 1.2, "maxVersion": 1.3 },
  "logger": { "format": "json" }
}
CARSAJSON
%{ endif ~}
```

- [ ] **Step 3: RSA decrypter probe + log dir**

After the ca.json heredoc, add the probe (mirrors `stepca-decrypter-probe.sh` but for port 8444 / unit `step-ca-rsa`) and log dir:

```bash
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
```

- [ ] **Step 4: systemd unit for step-ca-rsa**

Add:

```bash
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
```

- [ ] **Step 5: Validate + syntax check + commit**

Run: `terraform fmt && terraform validate` → `Success!`
Run: `cat scripts/startup.sh | sed 's/\${[a-z_]*}/X/g; s/%{[^}]*}//g' | bash -n` → no output.

```bash
git add scripts/startup.sh smallstep.tf
git commit -m "stepca(rsa): render ca.json #2 + step-ca-rsa.service on :8444 + stepca_rsa DB"
```

---

## Phase 3 — Apply + verify the RSA CA

### Task 9: Apply Terraform + roll startup.sh to both VMs

**Files:** none (operational)

- [ ] **Step 1: Apply**

Run: `terraform apply tfplan-rsa` (or re-plan + apply). Expected: KMS key, secrets, DB, LB created; existing resources untouched.

- [ ] **Step 2: Point DNS**

Get the IP: `terraform output smallstep_rsa_lb_ip`. Create an A record `ca-rsa.campusgroup.co` → that IP (Cloudflare). Wait for the managed SSL cert to go ACTIVE (can take 15-60 min): `gcloud compute ssl-certificates describe smallstep-ca-rsa-cert --global --project=campus-cloud-8021x-42e6 --format='value(managed.status)'` → `ACTIVE`.

- [ ] **Step 3: Re-run startup.sh on radius-primary (first — it does the RSA init)**

Per ARCHITECTURE.md "Re-running the startup script": on radius-primary, `sudo systemctl stop freeradius` then re-exec the metadata startup-script. This runs the RSA first-init (mints + publishes RSA chain). Verify:
- `systemctl is-active step-ca-rsa` → `active`
- `journalctl -u step-ca-rsa --no-pager | grep -i 'decrypter\|Serving'` → `stepca-rsa-decrypter-probe: SCEP decrypter OK`
- `gcloud secrets versions list smallstep-rsa-intermediate-cert --filter=state=ENABLED` → 1 version

- [ ] **Step 4: Re-run startup.sh on radius-secondary (RESTORE path)**

Same procedure on radius-secondary; it restores the RSA chain from Secret Manager. Verify `step-ca-rsa` active + decrypter OK. Both nodes must now serve identical RSA chains.

- [ ] **Step 5: Verify GetCACert + chain (the real test)**

```bash
# Single RSA decrypter only (excludeIntermediate)
curl -fsS "https://ca-rsa.campusgroup.co/scep/wifi-scep/pkiclient.exe?operation=GetCACert" -o /tmp/rsa-ca.bin -w "ctype=%{content_type} bytes=%{size_download}\n"
# Expect: application/x-x509-ca-cert (single DER), subject=CN=... RSA SCEP Decrypter, key=RSA
openssl x509 -inform DER -in /tmp/rsa-ca.bin -noout -subject -issuer
openssl x509 -inform DER -in /tmp/rsa-ca.bin -noout -text | grep -A1 'Public Key Algorithm' | head -2
# Decrypter SHA-1 (this is the new CAThumbprint for the Fleet profiles):
openssl x509 -inform DER -in /tmp/rsa-ca.bin -noout -fingerprint -sha1 | sed 's/.*=//; s/://g'
# GetCACaps healthy:
curl -fsS "https://ca-rsa.campusgroup.co/scep/wifi-scep/pkiclient.exe?operation=GetCACaps"
```
Expected: single RSA decrypter cert (issuer = the RSA intermediate), RSA 2048; GetCACaps returns POSTPKIOperation/SHA-256 etc. **Record the decrypter SHA-1 — it's the CAThumbprint for Task 11/12.**

- [ ] **Step 6: Verify the issued leaf chains RSA-intermediate → EC root + RADIUS trusts it**

On radius-primary, confirm `/etc/freeradius/3.0/certs/smallstep-ca.pem` (or trust-bundle.pem in `both` mode) now contains the RSA intermediate:
```bash
sudo grep -c 'BEGIN CERTIFICATE' /etc/freeradius/3.0/certs/smallstep-ca.pem  # >= 3 (EC int, RSA int, EC root)
```
Expected: the RSA intermediate is present; FreeRADIUS restarted clean (`systemctl is-active freeradius`).

- [ ] **Step 7: Commit** (operational notes only, if any tfvars changed)

```bash
git add -A && git commit -m "stepca(rsa): apply + roll RSA CA to both VMs" --allow-empty
```

---

## Phase 4 — Fleet profiles

### Task 10: Repoint Windows SCEP profile to the RSA CA

**Files:**
- Modify: `fleet-gitops/lib/windows/configuration-profiles/campus-wifi-smallstep-scep-direct.xml`

- [ ] **Step 1: Update ServerURL + CAThumbprint**

Change the ServerURL `<Data>` to `https://ca-rsa.campusgroup.co/scep/wifi-scep` and the CAThumbprint `<Data>` to the **RSA decrypter SHA-1** recorded in Task 9 Step 5. Keep the inlined static challenge (per fleet-gitops #40), RSA-2048 subject key, `<Replace>` nodes, `./Device` scope. Update the comments to reflect the RSA CA.

- [ ] **Step 2: Ensure the RSA intermediate is available on-device for chain building**

Add a sibling Windows cert profile (or a `<Replace>` ROOTSTORE/CA payload) that installs the **RSA intermediate** into `LocalMachine\CA`, since `excludeIntermediate` removes it from GetCACert. (Alternatively confirm the EAP supplicant builds the chain from the cert store; the safe path is to push the RSA intermediate explicitly.)

- [ ] **Step 3: Validate (fragment well-formed, vars correct)**

Run:
```bash
cd ~/Repos/Campus/IT/fleet-gitops
P=lib/windows/configuration-profiles/campus-wifi-smallstep-scep-direct.xml
grep -c '\$FLEET_SECRET' "$P"            # 0
grep -oE '\$FLEET_VAR_[A-Z_]+' "$P" | sort -u   # only HOST_HARDWARE_SERIAL + SCEP_WINDOWS_CERTIFICATE_ID
{ echo '<root>'; cat "$P"; echo '</root>'; } | xmllint --noout - && echo FRAGMENT_OK
grep -c 'ca-rsa.campusgroup.co' "$P"     # >= 1
```
Expected: 0 FLEET_SECRET, only the two host vars, FRAGMENT_OK, ca-rsa present.

- [ ] **Step 4: Commit + PR + CI green + merge** (per existing fleet-gitops flow: `./gitops-fleets.sh` dry-run runs in CI). After merge, watch the post-merge apply succeed.

```bash
git checkout -b windows-scep-repoint-rsa-ca
git add "$P" && git commit -m "windows scep: repoint to RSA CA (ca-rsa), new CAThumbprint"
git push -u origin windows-scep-repoint-rsa-ca
gh pr create --base main --title "windows scep: repoint to RSA CA" --body "Repoints the Windows SCEP profile at the new RSA step-ca instance (ca-rsa.campusgroup.co), which issues RSA-signed leaves the Windows CSP can verify. CAThumbprint = RSA decrypter."
```

- [ ] **Step 5: Verify on 733 (the proven failure case)**

After merge + apply, force MDM sync on 733. Verify:
- SCEP event log: **no** `0x80092004` / `signature cannot be verified` — a SUCCESS event.
- `Get-ChildItem Cert:\LocalMachine\My` shows a cert issued by `... RSA Intermediate CA`.
- 733 authenticates to Campus (RADIUS Access-Accept; check `radius-auth.json` on the CA VMs).

### Task 11: non-ADE Mac SCEP profile (resume paused branch, repoint to RSA)

**Files:**
- Modify/Create: `fleet-gitops/lib/macos/configuration-profiles/campus-wifi-scep.mobileconfig`
- Modify: `fleet-gitops/fleets/workstations.yml`

- [ ] **Step 1: Locate the paused branch work**

```bash
cd ~/Repos/Campus/IT/fleet-gitops
git log --oneline feat/macos-scep-wifi-fallback 2>/dev/null | head
git diff main...feat/macos-scep-wifi-fallback --stat
```
Expected: 6 commits, SCEP `.mobileconfig` + label + default.yml reg. Review what's there.

- [ ] **Step 2: Build/repoint the SCEP mobileconfig to the RSA CA**

The `com.apple.security.scep` payload `PayloadContent.SCEP` must have:
- `URL` = `https://ca-rsa.campusgroup.co/scep/wifi-scep`
- `Key Type` = `RSA` (Apple-mandated; the only valid value), `Keysize` = `2048`
- `Challenge` = the static SCEP challenge (1Password-backed via the gitops secret mechanism for macOS profiles, or inline — match the Windows decision; macOS `.mobileconfig` DOES support `$FLEET_SECRET_` unlike Windows SCEP, so use `$FLEET_SECRET_SMALLSTEP_SCEP_CHALLENGE` here if the gitops env provides it)
- `CAFingerprint` = SHA-1 of the RSA decrypter (Task 9 Step 5), as `data` (base64 of the 20 raw bytes)
- `Key Usage` = `5` (signing + encryption) or per the EAP-TLS requirement
- `Subject` = CN with `%SerialNumber%` or a static OU per Campus convention
- A SECOND payload `com.apple.security.pkcs1` (or root/pkcs7) carrying the **RSA intermediate** cert PEM, because `excludeIntermediate` strips it from GetCACert and macOS won't persist a SCEP-returned intermediate anyway.
- A Wi-Fi `com.apple.wifi.managed` payload with `EAPClientConfiguration` referencing the SCEP identity (`PayloadCertificateUUID`).

- [ ] **Step 3: Scope to non-ADE Macs in workstations.yml**

Add the profile under macOS `configuration_profiles` scoped with `labels_include_any` on a dynamic label that selects non-ADE hosts (`mdm.installed_from_dep != 'true'`). Verify the label exists in `default.yml`/labels (from the paused branch).

- [ ] **Step 4: Validate (mobileconfig plist well-formed, keys valid)**

Run:
```bash
plutil -lint lib/macos/configuration-profiles/campus-wifi-scep.mobileconfig
```
Expected: `OK`.

- [ ] **Step 5: Commit + PR + CI + merge**, then verify a non-ADE Mac gets an RSA cert and joins Campus (check RADIUS Access-Accept; the SE-invisible-cert memory note does NOT apply here — this is a file-based RSA cert, so `certificates` osquery table / keychain WILL show it).

```bash
git add lib/macos/configuration-profiles/campus-wifi-scep.mobileconfig fleets/workstations.yml
git commit -m "macos scep: non-ADE Wi-Fi cert via RSA CA (ca-rsa), file-based RSA key"
```

---

## Phase 5 — Datadog + cleanup (follow-up)

### Task 12: Datadog coverage for step-ca-rsa

**Files:**
- Modify: `cloud-8021x/datadog-smallstep.tf`

- [ ] **Step 1: Extend the smallstep log pipeline + monitors to the `step-ca-rsa` service / `/var/log/step-ca-rsa/step-ca-rsa.log` tail.** Mirror the existing `smallstep-ca` Datadog config with a `step-ca-rsa` service tag. (Detail deferred — model after the existing `datadog-smallstep.tf` blocks; not blocking the cert flow.)

- [ ] **Step 2: Validate + commit**

```bash
terraform fmt && terraform validate
git add datadog-smallstep.tf
git commit -m "datadog(stepca-rsa): logs + monitors for the RSA instance"
```

### Task 13: Remove the now-unused EC SCEP provisioner (cleanup)

**Files:**
- Modify: `cloud-8021x/scripts/startup.sh` (EC ca.json SCEP provisioner block)

- [ ] **Step 1: After all SCEP devices are confirmed on the RSA CA**, remove the SCEP provisioner from instance #1's ca.json (it served the old Windows/Mac SCEP that's now on the RSA instance). Leave the EC SCEP **decrypter** key/secret in place (harmless) or remove in the same pass. Keep ACME untouched. Re-roll startup.sh.

- [ ] **Step 2: Verify** instance #1 GetCACert for the old SCEP path 404s/410s and ACME still works (a test ADE/DEP Mac still enrolls). Commit.

---

## Self-Review Notes

- **Spec coverage:** All 7 components from the spec's "Components" list map to tasks (KMS+IAM→T1, LB→T4, secrets→T2, startup RSA bootstrap→T6/7/8, RADIUS trust→T6.3/T7.2, Windows profile→T10, Mac SCEP→T11). Open questions resolved inline: DB→separate `stepca_rsa` (T8/T8a); decrypter→dedicated (T6); Datadog→T12; init race→reuses EC probe pattern (T8.2).
- **Known risk to watch at execution:** the RSA decrypter signing invocation (`--kms cloudkms: --ca-key <rsa-uri>`) is the one step not directly copied from existing working code — verify the issued decrypter's issuer == the RSA intermediate on first apply (T9.5). If `step certificate create` rejects `--ca-key` as a KMS URI, fall back to: have the RSA intermediate sign via a temporary `step-kms-plugin`-backed flow, or generate the decrypter as a CSR and sign it with `step certificate sign --kms`.
- **CAThumbprint dependency:** T10/T11 depend on the value recorded in T9.5 — do not hardcode before the RSA CA is live.
