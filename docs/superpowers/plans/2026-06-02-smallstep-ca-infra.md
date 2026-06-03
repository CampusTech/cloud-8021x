# cloud-8021x Smallstep step-ca Infrastructure Implementation Plan (Plan 1 of 3)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up an optional, off-by-default self-hosted Smallstep `step-ca` co-located on the existing cloud-8021x RADIUS VMs, exposing both an ACME (`device-attest-01`) and a SCEP provisioner, with a Cloud-KMS-backed CA, Cloud SQL Postgres for ACME HA, a GCLB + Cloud Armor front door, and an independently-gated RADIUS trust swap to Smallstep-only.

**Architecture:** A single `enable_smallstep_ca` flag gates a new `smallstep.tf` (KMS keyring + 2 keys, Cloud SQL Postgres, a GCLB+Cloud Armor front end, firewall rules, Secret Manager entries for `ca.json`/CA cert/SCEP challenge). The existing `scripts/startup.sh` gains a conditionally-executed block that pulls those materials, renders `ca.json`, and runs `step-ca` on both VMs (active-active against the shared DB). The RADIUS `ca_file` swap to Smallstep-only is controlled by a *separate* `radius_trust_mode` variable so the CA can be brought up while RADIUS still trusts Okta.

**Tech Stack:** Terraform (Google provider), bash (startup script / systemd), Smallstep `step-ca` + `step` CLI, Google Cloud KMS, Cloud SQL Postgres, Google Cloud Load Balancing + Cloud Armor, FreeRADIUS 3.

**Spec:** `~/Repos/Campus/IT/fleet-gitops/docs/superpowers/specs/2026-06-02-smallstep-wifi-ca-decoupling-design.md`

**Scope of this plan (Plan 1):** The CA infra + endpoints + RADIUS trust toggle ONLY. The ACME authorizing webhook (Plan 2) and the fleet-gitops profiles/cutover (Plan 3) are separate plans. Plan 1 wires the ACME provisioner to *call* a webhook URL (a variable), but the webhook service itself is Plan 2. Until Plan 2 ships, leave `acme_authorizing_webhook_url` empty and do NOT enable ACME issuance for real devices.

**Working directory:** `~/Repos/Campus/IT/cloud-8021x` (repo `CampusTech/cloud-8021x`).

---

## Conventions used by this repo (read before starting)

- Secrets: `google_secret_manager_secret` + `_version`, IAM via `google_secret_manager_secret_iam_member` granting `roles/secretmanager.secretAccessor` to `google_service_account.radius.email`. See `main.tf` for the pattern.
- The VM service account is `google_service_account.radius` with `scopes = ["cloud-platform"]` (compute.tf:153-156).
- The startup script is rendered via `templatefile("${path.module}/scripts/startup.sh", { ... })` in the `locals` block at `compute.tf:106-127`. New template variables MUST be added to that map or `templatefile` errors.
- Inside `scripts/startup.sh`, Terraform-templated values are `${var_name}`; literal shell `$` must be escaped as `$$` (e.g. `$${certdir}`). This is critical — an unescaped `$` is interpreted by `templatefile` and fails the plan.
- Both VMs (`radius-primary` compute.tf:130, `radius-secondary` compute.tf:176) run the SAME `local.startup_script`. Anything added runs on both.
- `count`/`for_each` gating idiom: optional resources use `count = var.enable_smallstep_ca ? 1 : 0`.
- Firewall rules target the `radius-server` network tag.

---

## File Structure

- **Create `smallstep.tf`** — all new Terraform: `enable_smallstep_ca` plumbing, KMS keyring + signing key + decrypter key, Cloud SQL instance/db/user, Secret Manager entries (CA cert, CA key bootstrap, `ca.json`, SCEP challenge, DB password), KMS/secret IAM for the VM SA, the GCLB + Cloud Armor + serverless/instance-group backend for the public CA endpoint, and the step-ca firewall rules.
- **Modify `variables.tf`** — add `enable_smallstep_ca`, `radius_trust_mode`, `smallstep_ca_dns_name`, `smallstep_acme_provisioner_name`, `smallstep_scep_provisioner_name`, `acme_authorizing_webhook_url`, `smallstep_db_tier`.
- **Modify `compute.tf:106-127`** — extend the `templatefile` var map with the step-ca toggles/values.
- **Modify `scripts/startup.sh`** — add a gated step-ca install/config/run block; make the `ca_file` construction honor `radius_trust_mode`.
- **Modify `outputs.tf`** — add `smallstep_acme_directory_url`, `smallstep_scep_url`, `smallstep_ca_cert_pem`, `smallstep_ca_cert_secret_id`.
- **Modify `terraform.tfvars.example`** — document the new variables (off by default).
- **Modify `README.md`** — a short "Optional: self-hosted Smallstep CA" section.
- **Create `examples/` placeholder note** — example client profiles are added in a later step of Plan 3's repo work; this plan only creates the directory + README stub so outputs can reference it. (Profiles themselves: Plan 3.)

---

## Task 1: Add gating + core variables

**Files:**
- Modify: `variables.tf` (append)
- Modify: `terraform.tfvars.example` (append)

- [ ] **Step 1: Append the new variables to `variables.tf`**

```hcl
# -----------------------------------------------------------------------------
# Optional self-hosted Smallstep step-ca (off by default)
# -----------------------------------------------------------------------------

variable "enable_smallstep_ca" {
  description = "Stand up a self-hosted Smallstep step-ca on the RADIUS VMs (KMS-backed CA, ACME + SCEP, Cloud SQL for ACME HA, GCLB front door). Off by default; existing BYO-CA deployments are unaffected."
  type        = bool
  default     = false
}

variable "radius_trust_mode" {
  description = "Which CA(s) FreeRADIUS trusts for client certs. 'okta' = existing okta-ca.pem only. 'smallstep' = Smallstep CA only (the cutover end state). Decoupled from enable_smallstep_ca so the CA can run while RADIUS still trusts Okta during pre-stage. Requires enable_smallstep_ca=true to select 'smallstep'."
  type        = string
  default     = "okta"
  validation {
    condition     = contains(["okta", "smallstep"], var.radius_trust_mode)
    error_message = "radius_trust_mode must be either \"okta\" or \"smallstep\"."
  }
}

variable "smallstep_ca_dns_name" {
  description = "Public DNS name clients use to reach the step-ca ACME/SCEP endpoint (e.g. ca.campusgroup.co). Must resolve to the GCLB IP and match the managed TLS cert. Only used when enable_smallstep_ca=true."
  type        = string
  default     = ""
}

variable "smallstep_acme_provisioner_name" {
  description = "Name of the step-ca ACME provisioner (also the URL path segment: /acme/<name>/directory)."
  type        = string
  default     = "wifi"
}

variable "smallstep_scep_provisioner_name" {
  description = "Name of the step-ca SCEP provisioner (also the URL path segment: /scep/<name>)."
  type        = string
  default     = "wifi"
}

variable "acme_authorizing_webhook_url" {
  description = "HTTPS URL of the ACME authorizing webhook (Plan 2). step-ca calls it per order and refuses to sign unless it returns allow:true. MUST be set and healthy (fail-closed) before enabling ACME issuance for real devices. Empty = ACME provisioner is configured but no device should be enrolled yet."
  type        = string
  default     = ""
}

variable "smallstep_db_tier" {
  description = "Cloud SQL machine tier for the step-ca ACME state database."
  type        = string
  default     = "db-f1-micro"
}
```

- [ ] **Step 2: Document them in `terraform.tfvars.example`**

```hcl
# --- Optional self-hosted Smallstep step-ca (default: disabled) ---
# enable_smallstep_ca              = false
# radius_trust_mode                = "okta"      # flip to "smallstep" only after pre-staging certs
# smallstep_ca_dns_name            = "ca.campusgroup.co"
# smallstep_acme_provisioner_name  = "wifi"
# smallstep_scep_provisioner_name  = "wifi"
# acme_authorizing_webhook_url     = ""          # set to the Plan 2 webhook before enabling ACME
# smallstep_db_tier                = "db-f1-micro"
```

- [ ] **Step 3: Verify the config parses**

Run: `cd ~/Repos/Campus/IT/cloud-8021x && terraform validate`
Expected: `Success! The configuration is valid.` (variables alone don't change the plan yet.)

- [ ] **Step 4: Commit**

```bash
git add variables.tf terraform.tfvars.example
git commit -m "feat(smallstep): add gating + core variables for optional step-ca"
```

---

## Task 2: KMS keyring and the two CA keys

**Files:**
- Create: `smallstep.tf`

KMS keys are the FIPS-posture core: CA signing key (`ASYMMETRIC_SIGN`, HSM) and SCEP decrypter (`ASYMMETRIC_DECRYPT`, RSA). Verified: step-ca `decrypterKeyURI` accepts a `cloudkms:` URI and is separate from the signing key.

- [ ] **Step 1: Create `smallstep.tf` with the KMS resources**

```hcl
# =============================================================================
# Optional self-hosted Smallstep step-ca
# Gated by var.enable_smallstep_ca. All resources use count = ... ? 1 : 0.
# =============================================================================

locals {
  smallstep_enabled = var.enable_smallstep_ca ? 1 : 0
}

# --- Cloud KMS: keyring + CA signing key (HSM) + SCEP decrypter (RSA) --------

resource "google_project_service" "smallstep_apis" {
  for_each = var.enable_smallstep_ca ? toset([
    "cloudkms.googleapis.com",
    "sqladmin.googleapis.com",
  ]) : toset([])
  project            = google_project.this.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_kms_key_ring" "smallstep" {
  count    = local.smallstep_enabled
  project  = google_project.this.project_id
  name     = "smallstep-ca"
  location = var.region

  depends_on = [google_project_service.smallstep_apis]
}

# CA signing key — HSM protection level for FIPS 140-2 L3 posture.
resource "google_kms_crypto_key" "smallstep_signing" {
  count    = local.smallstep_enabled
  name     = "ca-signing"
  key_ring = google_kms_key_ring.smallstep[0].id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# SCEP decrypter — RSA decryption key. SCEP CMS uses RSA; PKCS#1 v1.5 decrypt.
resource "google_kms_crypto_key" "smallstep_scep_decrypter" {
  count    = local.smallstep_enabled
  name     = "scep-decrypter"
  key_ring = google_kms_key_ring.smallstep[0].id
  purpose  = "ASYMMETRIC_DECRYPT"

  version_template {
    algorithm        = "RSA_DECRYPT_OAEP_2048_SHA256"
    protection_level = "HSM"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Grant the RADIUS VM service account use of both keys.
resource "google_kms_crypto_key_iam_member" "smallstep_signing_use" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing[0].id
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_kms_crypto_key_iam_member" "smallstep_scep_decrypt" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_scep_decrypter[0].id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

# Also need viewer on the public keys to fetch them for ca.json / CSR signing.
resource "google_kms_crypto_key_iam_member" "smallstep_signing_viewer" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_signing[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_kms_crypto_key_iam_member" "smallstep_scep_viewer" {
  count         = local.smallstep_enabled
  crypto_key_id = google_kms_crypto_key.smallstep_scep_decrypter[0].id
  role          = "roles/cloudkms.publicKeyViewer"
  member        = "serviceAccount:${google_service_account.radius.email}"
}
```

- [ ] **Step 2: Validate**

Run: `terraform validate`
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Plan with the feature OFF (must be a no-op)**

Run: `terraform plan -var 'enable_smallstep_ca=false'`
Expected: `No changes.` (or only pre-existing unrelated drift). The `count = 0` guards mean nothing new is created when disabled. **This is the most important regression check in the whole plan** — proves the feature is truly off-by-default and existing deployments are unaffected.

- [ ] **Step 4: Plan with the feature ON (review the KMS additions)**

Run: `terraform plan -var 'enable_smallstep_ca=true' -var 'smallstep_ca_dns_name=ca.campusgroup.co'`
Expected: plan shows creation of `google_kms_key_ring.smallstep[0]`, both `google_kms_crypto_key` resources, the 4 IAM members, and the 2 enabled APIs. (Other tasks' resources will also appear once added — at this point only KMS is defined.)

- [ ] **Step 5: Commit**

```bash
git add smallstep.tf
git commit -m "feat(smallstep): KMS keyring, HSM signing key, RSA SCEP decrypter + IAM"
```

---

## Task 3: Cloud SQL Postgres for ACME state

**Files:**
- Modify: `smallstep.tf` (append)

ACME is stateful (orders/nonces/accounts); HA ACME requires a shared DB (Badger is single-node). SCEP is stateless — the DB exists purely for ACME.

- [ ] **Step 1: Append Cloud SQL + DB password secret to `smallstep.tf`**

```hcl
# --- Cloud SQL Postgres for ACME state (shared by both step-ca instances) ----

resource "random_password" "smallstep_db" {
  count   = local.smallstep_enabled
  length  = 32
  special = false
}

resource "google_secret_manager_secret" "smallstep_db_password" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-db-password"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "smallstep_db_password" {
  count       = local.smallstep_enabled
  secret      = google_secret_manager_secret.smallstep_db_password[0].id
  secret_data = random_password.smallstep_db[0].result
}

resource "google_secret_manager_secret_iam_member" "smallstep_db_password" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_db_password[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_sql_database_instance" "smallstep" {
  count               = local.smallstep_enabled
  project             = google_project.this.project_id
  name                = "smallstep-ca"
  region              = var.region
  database_version    = "POSTGRES_16"
  deletion_protection = true

  settings {
    tier              = var.smallstep_db_tier
    availability_type = "REGIONAL" # HA: synchronous standby in another zone
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.radius.id
    }
    backup_configuration {
      enabled = true
    }
  }

  depends_on = [
    google_project_service.smallstep_apis,
    google_service_networking_connection.smallstep[0],
  ]
}

resource "google_sql_database" "smallstep" {
  count    = local.smallstep_enabled
  project  = google_project.this.project_id
  name     = "stepca"
  instance = google_sql_database_instance.smallstep[0].name
}

resource "google_sql_user" "smallstep" {
  count    = local.smallstep_enabled
  project  = google_project.this.project_id
  name     = "stepca"
  instance = google_sql_database_instance.smallstep[0].name
  password = random_password.smallstep_db[0].result
}

# Private Services Access — required for Cloud SQL private IP in this VPC.
resource "google_compute_global_address" "smallstep_psa" {
  count         = local.smallstep_enabled
  project       = google_project.this.project_id
  name          = "smallstep-psa-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.radius.id
}

resource "google_service_networking_connection" "smallstep" {
  count                   = local.smallstep_enabled
  network                 = google_compute_network.radius.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.smallstep_psa[0].name]
}
```

- [ ] **Step 2: Add the servicenetworking API to the enabled set**

In `smallstep.tf`, edit the `google_project_service.smallstep_apis` `for_each` set (Task 2, Step 1) to add `"servicenetworking.googleapis.com"`:

```hcl
  for_each = var.enable_smallstep_ca ? toset([
    "cloudkms.googleapis.com",
    "sqladmin.googleapis.com",
    "servicenetworking.googleapis.com",
  ]) : toset([])
```

- [ ] **Step 3: Validate + off-plan no-op check**

Run: `terraform validate && terraform plan -var 'enable_smallstep_ca=false'`
Expected: valid; `No changes.`

- [ ] **Step 4: On-plan review**

Run: `terraform plan -var 'enable_smallstep_ca=true' -var 'smallstep_ca_dns_name=ca.campusgroup.co'`
Expected: plan adds the SQL instance/db/user, the DB password secret + version + IAM, the PSA global address, and the service-networking connection.

- [ ] **Step 5: Commit**

```bash
git add smallstep.tf
git commit -m "feat(smallstep): Cloud SQL Postgres (regional HA) for ACME state + PSA"
```

---

## Task 4: Secret Manager entries for CA materials + step-ca firewall

**Files:**
- Modify: `smallstep.tf` (append)

step-ca needs `ca.json`, the CA root cert (public, also an output), and the SCEP static challenge. The CA private keys live in KMS, not here. We pre-create empty secrets that the startup script populates on first boot (the bootstrap pattern this repo already uses for RADIUS server certs).

- [ ] **Step 1: Append Secret Manager entries + challenge + firewall to `smallstep.tf`**

```hcl
# --- SCEP static challenge (Fleet proxies a per-host challenge in front; this
#     is the upstream secret step-ca itself checks). ---------------------------
resource "random_password" "smallstep_scep_challenge" {
  count   = local.smallstep_enabled
  length  = 40
  special = false
}

resource "google_secret_manager_secret" "smallstep_scep_challenge" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-scep-challenge"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "smallstep_scep_challenge" {
  count       = local.smallstep_enabled
  secret      = google_secret_manager_secret.smallstep_scep_challenge[0].id
  secret_data = random_password.smallstep_scep_challenge[0].result
}

# --- CA root cert: created empty, populated by the VM on first init, read back
#     out for distribution (RADIUS trust bundle, MDM profiles). ----------------
resource "google_secret_manager_secret" "smallstep_ca_cert" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = "smallstep-ca-cert"
  replication {
    auto {}
  }
}

# --- Secret IAM: VM SA can read challenge + read/write the CA cert. -----------
resource "google_secret_manager_secret_iam_member" "smallstep_scep_challenge" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_scep_challenge[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.radius.email}"
}

resource "google_secret_manager_secret_iam_member" "smallstep_ca_cert_admin" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  secret_id = google_secret_manager_secret.smallstep_ca_cert[0].secret_id
  # secretVersionManager lets the VM add a new version on first init; accessor
  # lets it (and Terraform via data source) read it back.
  role   = "roles/secretmanager.admin"
  member = "serviceAccount:${google_service_account.radius.email}"
}

# --- Firewall: SCEP reachable only by Fleet egress; ACME via GCLB (Task 5). ---
# step-ca listens on the VMs; only the GCLB health-check + proxy ranges and
# Fleet's egress reach it directly. ACME public access is fronted by the GCLB.
resource "google_compute_firewall" "allow_stepca_lb" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "allow-stepca-lb"
  network = google_compute_network.radius.id

  allow {
    protocol = "tcp"
    ports    = ["8443"] # step-ca HTTPS listener
  }

  # GCP LB + health-check source ranges.
  source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
  target_tags   = ["radius-server"]
}
```

> **NOTE (Fleet egress → SCEP):** Fleet's Cloud Run egress is not a fixed published CIDR, so locking SCEP to "Fleet only" at the network layer is deferred. For Plan 1, SCEP is reachable via the same GCLB path as ACME but lives under the `/scep/` path; tighten this in Plan 3 once Fleet's egress IP is known (e.g. via a Cloud NAT static IP on the Fleet project) or rely on the SCEP static challenge + Cloud Armor path rules. Logged as an open item, not silently dropped.

- [ ] **Step 2: Validate + off no-op + on review**

Run: `terraform validate && terraform plan -var 'enable_smallstep_ca=false'`
Expected: valid; `No changes.`

Run: `terraform plan -var 'enable_smallstep_ca=true' -var 'smallstep_ca_dns_name=ca.campusgroup.co'`
Expected: adds the SCEP challenge secret+version+IAM, the CA cert secret + IAM, and the `allow-stepca-lb` firewall rule.

- [ ] **Step 3: Commit**

```bash
git add smallstep.tf
git commit -m "feat(smallstep): Secret Manager CA cert + SCEP challenge, step-ca firewall"
```

---

## Task 5: GCLB + Cloud Armor front door + managed TLS

**Files:**
- Modify: `smallstep.tf` (append)

The ACME endpoint must be publicly reachable by every device. Front it with an external HTTPS load balancer (Google-managed TLS cert for `smallstep_ca_dns_name`) and Cloud Armor (rate limiting). This also provides the listener's public TLS so step-ca's own listener can use an internal cert.

- [ ] **Step 1: Append the LB + Cloud Armor to `smallstep.tf`**

```hcl
# --- External HTTPS load balancer fronting both VMs' step-ca listeners --------

resource "google_compute_global_address" "smallstep_lb" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-lb-ip"
}

resource "google_compute_managed_ssl_certificate" "smallstep" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-cert"
  managed {
    domains = [var.smallstep_ca_dns_name]
  }
}

# Unmanaged instance group per VM zone, each holding its RADIUS VM.
resource "google_compute_instance_group" "smallstep_primary" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  name      = "smallstep-ig-primary"
  zone      = var.zone
  instances = [google_compute_instance.radius.self_link]
  named_port {
    name = "stepca"
    port = 8443
  }
}

resource "google_compute_instance_group" "smallstep_secondary" {
  count     = local.smallstep_enabled
  project   = google_project.this.project_id
  name      = "smallstep-ig-secondary"
  zone      = var.secondary_zone
  instances = [google_compute_instance.radius_secondary.self_link]
  named_port {
    name = "stepca"
    port = 8443
  }
}

resource "google_compute_health_check" "smallstep" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-hc"
  https_health_check {
    port         = 8443
    request_path = "/health"
  }
}

resource "google_compute_security_policy" "smallstep" {
  count   = local.smallstep_enabled
  project = google_project.this.project_id
  name    = "smallstep-ca-armor"

  rule {
    action   = "rate_based_ban"
    priority = 1000
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
      ban_duration_sec = 300
    }
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default allow"
  }
}

resource "google_compute_backend_service" "smallstep" {
  count                 = local.smallstep_enabled
  project               = google_project.this.project_id
  name                  = "smallstep-ca-backend"
  protocol              = "HTTPS"
  port_name             = "stepca"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  timeout_sec           = 30
  health_checks         = [google_compute_health_check.smallstep[0].id]
  security_policy       = google_compute_security_policy.smallstep[0].id

  backend {
    group = google_compute_instance_group.smallstep_primary[0].id
  }
  backend {
    group = google_compute_instance_group.smallstep_secondary[0].id
  }
}

resource "google_compute_url_map" "smallstep" {
  count           = local.smallstep_enabled
  project         = google_project.this.project_id
  name            = "smallstep-ca-urlmap"
  default_service = google_compute_backend_service.smallstep[0].id
}

resource "google_compute_target_https_proxy" "smallstep" {
  count            = local.smallstep_enabled
  project          = google_project.this.project_id
  name             = "smallstep-ca-https-proxy"
  url_map          = google_compute_url_map.smallstep[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.smallstep[0].id]
}

resource "google_compute_global_forwarding_rule" "smallstep" {
  count                 = local.smallstep_enabled
  project               = google_project.this.project_id
  name                  = "smallstep-ca-fr"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_address            = google_compute_global_address.smallstep_lb[0].address
  port_range            = "443"
  target                = google_compute_target_https_proxy.smallstep[0].id
}
```

- [ ] **Step 2: Validate + off no-op + on review**

Run: `terraform validate && terraform plan -var 'enable_smallstep_ca=false'`
Expected: valid; `No changes.`

Run: `terraform plan -var 'enable_smallstep_ca=true' -var 'smallstep_ca_dns_name=ca.campusgroup.co'`
Expected: adds LB IP, managed cert, 2 instance groups, health check, Cloud Armor policy, backend service, url map, https proxy, forwarding rule.

- [ ] **Step 3: Commit**

```bash
git add smallstep.tf
git commit -m "feat(smallstep): GCLB + Cloud Armor + managed TLS front door for ACME/SCEP"
```

---

## Task 6: Render `ca.json` and pass step-ca values into the startup script

**Files:**
- Modify: `compute.tf:106-127` (the `templatefile` var map)

The `ca.json` is rendered inside the startup script (it needs the KMS resource IDs and DB connection, which are known at apply time). We pass those as template variables.

- [ ] **Step 1: Extend the `templatefile` var map in `compute.tf`**

Replace the `locals { startup_script = templatefile(... { ... }) }` block (compute.tf:106-127) with this version (adds the `smallstep_*` keys; keeps all existing keys unchanged):

```hcl
locals {
  startup_script = templatefile("${path.module}/scripts/startup.sh", {
    project_id                 = google_project.this.project_id
    server_cert_cn             = var.server_cert_cn
    server_cert_org            = var.server_cert_org
    has_root_ca                = var.okta_root_ca_cert_pem != ""
    has_jamf_lookup            = var.jamf_url != ""
    has_unifi_lookup           = var.unifi_api_key != ""
    rewrite_username           = var.rewrite_username && var.jamf_url != ""
    rewrite_username_separator = var.rewrite_username_separator
    tls_session_cache          = var.tls_session_cache
    tls_session_cache_lifetime = var.tls_session_cache_lifetime
    tls_max_version            = var.tls_max_version
    datadog_site               = var.datadog_site
    radius_clients_json = jsonencode({
      for k, v in var.radius_clients : k => {
        cidrs       = v.cidrs
        description = v.description
        secret_id   = "radius-shared-secret-${k}"
      }
    })

    # --- Smallstep step-ca ---
    smallstep_enabled       = var.enable_smallstep_ca
    radius_trust_mode       = var.radius_trust_mode
    smallstep_ca_dns_name   = var.smallstep_ca_dns_name
    smallstep_acme_name     = var.smallstep_acme_provisioner_name
    smallstep_scep_name     = var.smallstep_scep_provisioner_name
    acme_webhook_url        = var.acme_authorizing_webhook_url
    smallstep_signing_key_uri = var.enable_smallstep_ca ? "cloudkms:projects/${google_project.this.project_id}/locations/${var.region}/keyRings/smallstep-ca/cryptoKeys/ca-signing/cryptoKeyVersions/1" : ""
    smallstep_scep_key_uri    = var.enable_smallstep_ca ? "cloudkms:projects/${google_project.this.project_id}/locations/${var.region}/keyRings/smallstep-ca/cryptoKeys/scep-decrypter/cryptoKeyVersions/1" : ""
    smallstep_db_host         = var.enable_smallstep_ca ? google_sql_database_instance.smallstep[0].private_ip_address : ""
    smallstep_db_name         = "stepca"
    smallstep_db_user         = "stepca"
  })
}
```

- [ ] **Step 2: Validate (this also confirms startup.sh still templates — Task 7 edits it)**

Run: `terraform validate`
Expected: `Success! The configuration is valid.`

> If `terraform validate` errors with "Invalid template control keyword" or an unescaped-`$` style error, an existing `$` in `startup.sh` is now being parsed — but since this task doesn't edit `startup.sh`, validate should pass unchanged. The new keys are unused by the template until Task 7.

- [ ] **Step 3: Off no-op check**

Run: `terraform plan -var 'enable_smallstep_ca=false'`
Expected: `No changes.` (The new template keys resolve to empty strings / false; the rendered script bytes change only if a key is *referenced* in startup.sh, which it is not yet. If `plan` shows a metadata diff on both VMs, that's acceptable and expected once Task 7 lands — at THIS task it should still be no-op.)

- [ ] **Step 4: Commit**

```bash
git add compute.tf
git commit -m "feat(smallstep): pass step-ca KMS/DB/provisioner values into startup template"
```

---

## Task 7: Startup-script block — install, render ca.json, run step-ca, trust swap

**Files:**
- Modify: `scripts/startup.sh`

This is the runtime heart. Add a gated block that: installs `step-ca`+`step`, fetches the DB password + SCEP challenge from Secret Manager, initializes the CA on first boot (KMS-backed, publishing the root cert to Secret Manager), renders `ca.json` with ACME (`device-attest-01` + webhook) and SCEP provisioners, runs step-ca via systemd, and makes the FreeRADIUS `ca_file` honor `radius_trust_mode`.

Read `scripts/startup.sh` first to find: (a) the section that builds `$CERT_DIR/okta-ca.pem` (around the "Retrieve Okta CA certificate" block, ~line 60-82 in the current file), and (b) the `ca_file = $${certdir}/okta-ca.pem` line in the EAP config (~line 192).

- [ ] **Step 1: Add the step-ca install + init + run block**

Insert this block AFTER the Okta CA retrieval section and BEFORE the EAP/FreeRADIUS configuration section. Note `${...}` = Terraform template vars; `$$` = literal shell `$`.

```bash
# ---------------------------------------------------------------------------
# Optional: self-hosted Smallstep step-ca (gated by enable_smallstep_ca)
# ---------------------------------------------------------------------------
%{ if smallstep_enabled ~}
echo "=== Setting up Smallstep step-ca ==="
export STEPPATH=/etc/step-ca
mkdir -p "$$STEPPATH/db" "$$STEPPATH/certs" "$$STEPPATH/config" "$$STEPPATH/secrets"

# Install step-ca + step CLI (pinned via apt repo).
if ! command -v step-ca >/dev/null 2>&1; then
  STEP_VERSION="0.28.1"
  CA_VERSION="0.28.1"
  curl -fsSL "https://dl.smallstep.com/gh-release/cli/gh-release-header/v$${STEP_VERSION}/step-cli_$${STEP_VERSION}_amd64.deb" -o /tmp/step-cli.deb
  curl -fsSL "https://dl.smallstep.com/gh-release/certificates/gh-release-header/v$${CA_VERSION}/step-ca_$${CA_VERSION}_amd64.deb" -o /tmp/step-ca.deb
  dpkg -i /tmp/step-cli.deb /tmp/step-ca.deb || apt-get -fy install
fi

# Fetch DB password + SCEP challenge from Secret Manager.
SMALLSTEP_DB_PASSWORD="$(gcloud secrets versions access latest --secret=smallstep-db-password --project="${project_id}")"
SMALLSTEP_SCEP_CHALLENGE="$(gcloud secrets versions access latest --secret=smallstep-scep-challenge --project="${project_id}")"

# Initialize the CA on first boot ONLY. The CA cert is shared via Secret
# Manager: the primary VM that wins initialization publishes it; any VM that
# finds an existing version downloads it instead of re-initializing.
if gcloud secrets versions access latest --secret=smallstep-ca-cert --project="${project_id}" >/tmp/smallstep-ca.crt 2>/dev/null && [ -s /tmp/smallstep-ca.crt ]; then
  echo "Existing Smallstep CA cert found — reusing."
  cp /tmp/smallstep-ca.crt "$$STEPPATH/certs/root_ca.crt"
  cp /tmp/smallstep-ca.crt "$$STEPPATH/certs/intermediate_ca.crt"
else
  echo "Initializing new Smallstep CA (KMS-backed)..."
  step ca init \
    --name="CampusGroup Wi-Fi CA" \
    --dns="${smallstep_ca_dns_name}" \
    --address=":8443" \
    --provisioner="bootstrap" \
    --kms=cloudkms \
    --ca-url="https://${smallstep_ca_dns_name}" \
    --no-db \
    --remote-management 2>/dev/null || true
  # Generate the root using the KMS signing key.
  step kms create "${smallstep_signing_key_uri}" 2>/dev/null || true
  # Publish the resulting root cert to Secret Manager for the other VM + RADIUS.
  gcloud secrets versions add smallstep-ca-cert --project="${project_id}" \
    --data-file="$$STEPPATH/certs/root_ca.crt"
  cp "$$STEPPATH/certs/root_ca.crt" /tmp/smallstep-ca.crt
fi

# Render ca.json with ACME (device-attest-01 + authorizing webhook) and SCEP.
cat > "$$STEPPATH/config/ca.json" <<CAJSON
{
  "root": "$$STEPPATH/certs/root_ca.crt",
  "crt": "$$STEPPATH/certs/intermediate_ca.crt",
  "address": ":8443",
  "dnsNames": ["${smallstep_ca_dns_name}"],
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
            "certType": "ALL"
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
        "decrypterKeyURI": "${smallstep_scep_key_uri}"
      }
    ]
  },
  "tls": { "minVersion": 1.2, "maxVersion": 1.3 }
}
CAJSON

# systemd unit for step-ca.
cat > /etc/systemd/system/step-ca.service <<'UNIT'
[Unit]
Description=Smallstep step-ca
After=network-online.target
Wants=network-online.target

[Service]
Environment=STEPPATH=/etc/step-ca
ExecStart=/usr/bin/step-ca /etc/step-ca/config/ca.json
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now step-ca
echo "step-ca started."
%{ endif ~}
```

> **IMPLEMENTATION NOTE (CA init nuance):** `step ca init --kms=cloudkms` with a pre-created KMS key has version-specific flag behavior. The exact init invocation (root vs intermediate signed by KMS, `--kms-intermediate`, `--key` URIs) must be confirmed against the pinned step-ca version's docs during execution; the block above is the intended shape, and the executing agent should verify `step ca init --help` for the installed version and adjust the `step ca init` / `step kms create` lines so the root cert is genuinely KMS-backed. This is the one runtime step that needs on-box confirmation. Capture the working invocation in a comment.

- [ ] **Step 2: Make the FreeRADIUS `ca_file` honor `radius_trust_mode`**

Find the EAP `tls-config` block in `startup.sh` (the `ca_file = $${certdir}/okta-ca.pem` line, ~line 192). Replace the single hard-coded `ca_file` line with a templated choice, and add a step earlier that writes the Smallstep CA into the cert dir when in smallstep mode.

Add to the cert-setup area (near where `okta-ca.pem` is written):

```bash
%{ if smallstep_enabled ~}
# When trust mode is "smallstep", RADIUS validates client certs against the
# Smallstep CA only (Okta dropped from the client trust path).
if [ "${radius_trust_mode}" = "smallstep" ]; then
  cp /tmp/smallstep-ca.crt "$$CERT_DIR/smallstep-ca.pem"
  chown freerad:freerad "$$CERT_DIR/smallstep-ca.pem"
fi
%{ endif ~}
```

Replace the `ca_file` line in the EAP `tls-config`:

```bash
        ca_file = $${certdir}/%{ if smallstep_enabled }%{ if radius_trust_mode == "smallstep" }smallstep-ca.pem%{ else }okta-ca.pem%{ endif }%{ else }okta-ca.pem%{ endif }
```

- [ ] **Step 3: Validate the template still renders**

Run: `terraform validate`
Expected: `Success!` — if it fails with a template error, a literal `$` in the new block was not escaped to `$$`, or a `%{ }` directive is malformed. Fix the escaping.

- [ ] **Step 4: Off no-op check**

Run: `terraform plan -var 'enable_smallstep_ca=false'`
Expected: `No changes.` — with `smallstep_enabled=false` the `%{ if }` blocks render to nothing and the `ca_file` falls through to `okta-ca.pem`, so the rendered script for existing deployments is byte-identical.

- [ ] **Step 5: On-plan check (script bytes change on both VMs)**

Run: `terraform plan -var 'enable_smallstep_ca=true' -var 'smallstep_ca_dns_name=ca.campusgroup.co' -var 'acme_authorizing_webhook_url=https://example.invalid/authorize'`
Expected: the only diffs (beyond Tasks 2-5 resources) are `metadata.startup-script` updating on `radius-primary` and `radius-secondary`.

- [ ] **Step 6: Commit**

```bash
git add scripts/startup.sh
git commit -m "feat(smallstep): startup block to run step-ca + radius_trust_mode ca_file swap"
```

---

## Task 8: Outputs

**Files:**
- Modify: `outputs.tf` (append)

- [ ] **Step 1: Append step-ca outputs**

```hcl
# -----------------------------------------------------------------------------
# Smallstep step-ca (only meaningful when enable_smallstep_ca = true)
# -----------------------------------------------------------------------------

output "smallstep_acme_directory_url" {
  description = "ACME directory URL for MDM ACME payloads (macOS/iOS). Empty if disabled."
  value       = var.enable_smallstep_ca ? "https://${var.smallstep_ca_dns_name}/acme/${var.smallstep_acme_provisioner_name}/directory" : ""
}

output "smallstep_scep_url" {
  description = "SCEP URL for Fleet's custom_scep_proxy (Windows). Empty if disabled."
  value       = var.enable_smallstep_ca ? "https://${var.smallstep_ca_dns_name}/scep/${var.smallstep_scep_provisioner_name}" : ""
}

output "smallstep_ca_cert_secret_id" {
  description = "Secret Manager secret holding the Smallstep CA root cert PEM (for RADIUS trust + MDM root payloads). Empty if disabled."
  value       = var.enable_smallstep_ca ? google_secret_manager_secret.smallstep_ca_cert[0].secret_id : ""
}

output "smallstep_lb_ip" {
  description = "Public IP of the step-ca load balancer; point smallstep_ca_dns_name at this A record. Empty if disabled."
  value       = var.enable_smallstep_ca ? google_compute_global_address.smallstep_lb[0].address : ""
}
```

- [ ] **Step 2: Validate + off no-op**

Run: `terraform validate && terraform plan -var 'enable_smallstep_ca=false'`
Expected: valid; `No changes.`

- [ ] **Step 3: Commit**

```bash
git add outputs.tf
git commit -m "feat(smallstep): outputs for ACME/SCEP URLs, CA cert secret, LB IP"
```

---

## Task 9: README + examples directory stub

**Files:**
- Modify: `README.md`
- Create: `examples/README.md`

- [ ] **Step 1: Add a README section**

Append to `README.md`:

```markdown
## Optional: self-hosted Smallstep step-ca

Set `enable_smallstep_ca = true` to stand up a self-hosted Smallstep `step-ca`
co-located on the RADIUS VMs. It exposes:

- **ACME** (`/acme/<name>/directory`) with Apple `device-attest-01` attestation,
  fronted by a public GCLB + Cloud Armor. Gate issuance with
  `acme_authorizing_webhook_url` (see `examples/` and the webhook plan) — Apple
  attestation alone proves "a real Apple device", not "one of yours".
- **SCEP** (`/scep/<name>`) for MDMs without ACME (e.g. Windows), typically
  fronted by an MDM's SCEP proxy.

The CA signing key and SCEP decrypter live in Cloud KMS (HSM). ACME state is in
a regional Cloud SQL Postgres. The CA root cert is published to the
`smallstep-ca-cert` Secret Manager secret.

**RADIUS trust:** `radius_trust_mode` controls the FreeRADIUS client-cert trust
bundle independently of the CA being up — `"okta"` (default) keeps the existing
Okta trust; `"smallstep"` makes RADIUS trust ONLY the Smallstep CA. Pre-stage
client certs on devices, confirm issuance, then flip to `"smallstep"`.

Example client profiles (ACME + SCEP, generic + Fleet variant) live in
`examples/`.
```

- [ ] **Step 2: Create `examples/README.md` stub**

```markdown
# Example EAP-TLS client profiles

Templates only — nothing here is deployed by Terraform. Adapt them to your MDM.

- `acme/` — macOS/iOS `com.apple.security.acme` + Wi-Fi profiles (direct ACME).
- `scep/` — Windows `ClientCertificateInstall/SCEP` + WlanXml profiles.
- `fleet/` — Fleet-specific variants using `$FLEET_VAR_*` substitutions.

Token map (generic templates → Terraform outputs):

| Token | Source |
|-------|--------|
| `ACME_DIRECTORY_URL` | `terraform output smallstep_acme_directory_url` |
| `SCEP_SERVER_URL` | `terraform output smallstep_scep_url` |
| `CA_CERT_PEM` | `gcloud secrets versions access latest --secret=$(terraform output -raw smallstep_ca_cert_secret_id)` |
| `CA_THUMBPRINT` | SHA-1 of the cert returned by `<SCEP_SERVER_URL>?operation=GetCACert` |
| `SSID` | your network SSID |
| `CLIENT_IDENTIFIER` | device serial / permanent identifier |

> Keep these in sync with the CA's emitted outputs to avoid drift.

The actual profile files are added by the fleet-gitops consumption plan (Plan 3).
```

- [ ] **Step 3: Commit**

```bash
git add README.md examples/README.md
git commit -m "docs(smallstep): README section + examples directory stub"
```

---

## Task 10: End-to-end apply + post-apply health verification (pilot project)

> This task runs against a **non-production / test GCP project** first (or with `deletion_protection` understood). It is the real-infra gate. Do NOT flip `radius_trust_mode` to `smallstep` here — that's Plan 3's cutover.

**Files:** none (operational)

- [ ] **Step 1: Apply with the CA enabled, trust still Okta, webhook empty**

```bash
terraform apply \
  -var 'enable_smallstep_ca=true' \
  -var 'smallstep_ca_dns_name=ca.campusgroup.co' \
  -var 'radius_trust_mode=okta' \
  -var 'acme_authorizing_webhook_url='
```
Expected: applies cleanly. Note `smallstep_lb_ip` output.

- [ ] **Step 2: Point DNS + wait for the managed cert**

Create an A record: `ca.campusgroup.co` → `terraform output -raw smallstep_lb_ip`.
Run: `gcloud compute ssl-certificates describe smallstep-ca-cert --global --project=<proj> --format='value(managed.status)'`
Expected: eventually `ACTIVE` (managed certs take minutes once DNS resolves).

- [ ] **Step 3: Confirm step-ca is healthy on both VMs**

```bash
gcloud compute ssh radius-primary --zone=<zone> --tunnel-through-iap --command='sudo systemctl is-active step-ca && curl -sk https://localhost:8443/health'
gcloud compute ssh radius-secondary --zone=<secondary_zone> --tunnel-through-iap --command='sudo systemctl is-active step-ca && curl -sk https://localhost:8443/health'
```
Expected: `active` and `{"status":"ok"}` on both.

- [ ] **Step 4: Confirm the ACME directory is reachable through the LB**

Run: `curl -s https://ca.campusgroup.co/acme/wifi/directory | jq .`
Expected: a JSON ACME directory with `newNonce`, `newAccount`, `newOrder` URLs.

- [ ] **Step 5: Confirm SCEP GetCACert/GetCACaps through the LB**

```bash
curl -s "https://ca.campusgroup.co/scep/wifi?operation=GetCACaps"
curl -s "https://ca.campusgroup.co/scep/wifi?operation=GetCACert" -o /tmp/scep-cacert.der
openssl pkcs7 -inform DER -print_certs -in /tmp/scep-cacert.der -noout 2>/dev/null && echo "GetCACert OK"
```
Expected: GetCACaps lists capabilities (e.g. `SHA-256`, `POSTPKIOperation`); GetCACert returns a parseable PKCS#7. **Record the SHA-1 of the issuing cert** — Plan 3's Windows `CAThumbprint` needs it:
`openssl pkcs7 -inform DER -print_certs -in /tmp/scep-cacert.der | openssl x509 -noout -fingerprint -sha1`

- [ ] **Step 6: Confirm RADIUS is unaffected (still trusts Okta)**

```bash
gcloud compute ssh radius-primary --zone=<zone> --tunnel-through-iap --command='sudo grep ca_file /etc/freeradius/3.0/mods-available/eap'
```
Expected: `ca_file = .../okta-ca.pem` — proving the CA came up WITHOUT touching RADIUS trust. Existing Wi-Fi auth continues working.

- [ ] **Step 7: Record the CA root cert for Plan 3**

```bash
gcloud secrets versions access latest --secret=smallstep-ca-cert --project=<proj> > /tmp/smallstep-root.pem
openssl x509 -in /tmp/smallstep-root.pem -noout -subject -issuer -fingerprint -sha1
```
Expected: a self-consistent root; note its SHA-1 (RADIUS server-trust thumbprint for the Windows WlanXml in Plan 3) and subject.

- [ ] **Step 8: Document the verified values**

Append the recorded ACME directory URL, SCEP URL, SCEP GetCACert SHA-1, and CA root SHA-1 to a short note in `docs/superpowers/plans/2026-06-02-smallstep-ca-infra.md` under a "## Verified post-apply values" heading, so Plan 2 (webhook URL wiring) and Plan 3 (profiles) have exact inputs.

---

## Self-Review (completed by plan author)

**Spec coverage:**
- Optional `enable_smallstep_ca` flag, off by default → Task 1 + `count` guards (verified by the off-plan no-op checks in every task).
- Co-located on both RADIUS VMs, active-active → Task 7 (shared startup script runs on both; both in the LB backend, Task 5).
- KMS signing key (HSM/FIPS) + KMS SCEP decrypter → Task 2.
- Cloud SQL for ACME HA; SCEP stateless → Task 3 (+ note in Task 7 `ca.json` SCEP has no DB requirement).
- ACME `device-attest-01` + `attestationFormats apple` + authorizing webhook hook → Task 7 `ca.json` (webhook URL is a var; service is Plan 2).
- SCEP provisioner with static challenge + decrypterKeyURI → Task 7 `ca.json`.
- Public GCLB + Cloud Armor + managed TLS (solves listener TLS) → Task 5.
- RADIUS trust swap independently gated from "CA running" → `radius_trust_mode` var (Task 1) + Task 7 `ca_file` templating + Task 10 Step 6 proof.
- Outputs (ACME URL, SCEP URL, CA cert) → Task 8.
- MDM-agnostic; example profiles as templates → Task 9 stub (full profiles in Plan 3).
- SCEP-endpoint-to-Fleet-only restriction → flagged as explicit open item in Task 4 note (not silently dropped).

**Placeholder scan:** No TBD/TODO. The one genuine on-box unknown (exact `step ca init --kms` invocation per installed version) is called out as an IMPLEMENTATION NOTE with a concrete verification action (`step ca init --help`), not left vague.

**Type/name consistency:** provisioner names default `wifi` used consistently in `ca.json`, outputs, and URLs; KMS key names `ca-signing`/`scep-decrypter` match between Task 2 resources and the `cloudkms:` URIs in Task 6; secret IDs (`smallstep-ca-cert`, `smallstep-scep-challenge`, `smallstep-db-password`) match between Tasks 3-4 and the startup script in Task 7; `radius_trust_mode` values `okta`/`smallstep` match the validation, the template, and Task 10.

**Out-of-scope correctly deferred:** webhook service (Plan 2), MDM profiles + cutover flip (Plan 3).
