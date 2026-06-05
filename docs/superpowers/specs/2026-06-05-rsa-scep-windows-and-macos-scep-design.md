# Design: RSA SCEP for Windows + EC SCEP for non-ADE/DEP Macs

**Date:** 2026-06-05
**Status:** Design — pending review
**Repo:** cloud-8021x (step-ca + FreeRADIUS), with companion changes in fleet-gitops

## Problem

Campus Wi-Fi (802.1X EAP-TLS) certs are issued by the self-hosted Smallstep step-ca
on the `radius-primary`/`radius-secondary` VMs. Today there are three device
populations and only one works end-to-end:

| Population | Count | Enrollment | Status |
|---|---|---|---|
| ADE/DEP Macs | ~460 | ACME `device-attest-01` (Apple attestation, EC P-384, Secure Enclave) | ✅ Works |
| non-ADE/DEP Macs | <40 | (none yet) | ❌ Apple omits serial in attestation → ACME webhook can't authorize; stranded after the legacy-SSID forget |
| Windows | <15 (e.g. 733) | SCEP | ❌ Windows native SCEP CSP can't verify the **EC-signed leaf** step-ca issues |

### Root causes (proven this session)

- **Windows:** step-ca signs SCEP leaves with the top-level intermediate, which is
  **EC P-256** (Cloud KMS). The Windows `ClientCertificateInstall/SCEP` CSP cannot
  verify an ECDSA leaf signature → `The signature of the certificate cannot be
  verified` (after `excludeIntermediate` clears the earlier `0x80092004`). Windows
  native SCEP **requires an RSA-issuing CA**. (macOS/Secure Enclave, by contrast,
  *requires* EC — so the EC chain is correct for Macs.)
- **non-ADE/DEP Macs:** Apple's attested ACME (`com.apple.security.acme`) does not
  include the device serial/UDID in the `device-attest-01` attestation for
  non-ADE/DEP devices, so any serial-from-attestation authorizer (our step-ca ACME
  webhook; Fleet's own ACME, which additionally hard-blocks non-DEP) rejects them.

### Why one CA can't serve both SCEP populations

step-ca issues from a **single** top-level intermediate (`crt`/`key` in ca.json).
Provisioners cannot use different issuing chains, and the SCEP provisioner has **no
per-provisioner issuing key** (`scep.go`: `// TODO(hs): support distinct signer key`).
Confirmed three ways: source (v0.30.2), Smallstep docs ("you cannot have both ACME
ECDSA and SCEP RSA provisioners ... in one instance ... run separate instances"),
and the issue tracker (#244 closed, not this feature). Converting the whole CA to
RSA is rejected: it would break the 460 attested-ACME Macs (Apple ACME is
structurally EC/Secure-Enclave).

## Decision

Three issuance paths, two CA instances, one shared EC root → **one RADIUS trust anchor**:

| Path | Issuer | Instance | Devices |
|---|---|---|---|
| ACME `device-attest-01` | existing **EC** intermediate | step-ca #1 (existing, :8443) | ~460 ADE/DEP Macs (unchanged) |
| **EC SCEP** | existing **EC** intermediate | step-ca #1 (existing, :8443) | <40 non-ADE/DEP Macs |
| **RSA SCEP** | **NEW RSA** intermediate | **step-ca #2 (new, :8444)** | <15 Windows |

- The non-ADE/DEP Macs use the **existing** EC `wifi-scep` provisioner — macOS/SE is
  EC-happy, so **no new CA** is needed for them. (Resume the paused
  `feat/macos-scep-wifi-fallback` fleet-gitops branch.)
- Only **Windows** forces new infra: a **second step-ca process** on the same two VMs
  whose top-level intermediate is **RSA** (RSA-2048, Cloud KMS HSM `ASYMMETRIC_SIGN`),
  signed by the **existing EC root** (EC-root-signing-RSA-intermediate is valid X.509
  — already done today for the RSA SCEP decrypter). RADIUS already trusts the EC root,
  so adding the RSA intermediate to its client-cert trust bundle is the only RADIUS change.

### Accepted tradeoff (scope-driven)

~55 SCEP devices on Wi-Fi. The non-ADE Mac SCEP keys stay hardware-bound (EC/SE). The
Windows RSA path is standard file-based SCEP. The second step-ca instance is permanent
extra infra justified solely by Windows native SCEP's RSA-only verification. At this
scale, operational simplicity of "supported, separate RSA instance" beats alternatives
(PFX import per host; converting/breaking the ACME fleet). Hardware-binding of the
Windows Wi-Fi key is explicitly **not** a requirement here.

## Architecture

### CA instance #2 (RSA, Windows SCEP only)

- **Signing key:** new Cloud KMS key `ca-signing-rsa`, purpose `ASYMMETRIC_SIGN`,
  algorithm `RSA_SIGN_PKCS1_2048_SHA256`, protection `HSM`, in the existing
  `smallstep-ca` keyring. IAM: RADIUS VM SA gets `signerVerifier` + `publicKeyViewer`
  (mirrors the EC key grants).
- **Chain:** existing **EC root** signs a new **RSA intermediate** (`CampusGroup Wi-Fi
  RSA Intermediate CA`). Same init dance as the EC intermediate: a (transient, already
  on-box at init) local EC root key signs the KMS-backed RSA intermediate via
  `step certificate create ... --kms cloudkms: --key <rsa-uri>`. The RSA intermediate
  cert is persisted to a new secret `smallstep-rsa-intermediate-cert`.
- **SCEP decrypter:** instance #2 gets its **own** dedicated software RSA decrypter
  cert/key (same pattern as instance #1: dual-purpose software RSA key persisted to
  Secret Manager, shared across both HA nodes), signed by instance #2's RSA
  intermediate. Kept independent from instance #1's decrypter so the two CAs don't
  share crypto material. The RSA *intermediate* (issuer) is distinct from the RSA
  *decrypter* (SCEP envelope crypto) — two separate RSA keys, distinct roles.
- **ca.json #2:** top-level `crt` = RSA intermediate, `key` = RSA KMS URI, `kms` =
  cloudkms. One SCEP provisioner (static challenge, same `smallstep-scep-challenge`
  secret), `excludeIntermediate: true` (so GetCACert returns only the RSA decrypter — we
  proved this is required for the Windows CSP to initialize), `minimumPublicKeyLength`,
  `encryptionAlgorithmIdentifier: 2`. **No ACME provisioner.**
- **Process:** second systemd unit `step-ca-rsa.service`, `STEPPATH=/etc/step-ca-rsa`,
  listens `:8444`, own log file + Datadog tail + the same decrypter-readiness probe.
- **Persistence/HA:** same Secret-Manager-backed restore model as instance #1 (root
  cert reused from `smallstep-ca-cert`; RSA intermediate cert + RSA decrypter cert/key
  in new secrets) so both VMs and any rebuild restore an identical RSA chain.
- **DB:** reuse the existing Cloud SQL Postgres (separate `authorityId`/schema or a
  second database `stepca_rsa` — TBD-resolved below).

### Networking / endpoint

- New hostname **`ca-rsa.campusgroup.co`** (managed SSL cert), new global IP, backend
  service on named port `stepca-rsa` → `:8444`, both VM instance groups, own health
  check `/health` on 8444, Cloud Armor reuse. Mirrors the existing `smallstep_*` LB
  block. Firewall: allow `:8444` from the LB/health-check ranges (extend the existing
  rule or add a sibling).
- Existing `ca.campusgroup.co` (ACME + EC SCEP, :8443) is **unchanged**.

### RADIUS trust

- FreeRADIUS `ca_file` (client-cert trust) must include the **RSA intermediate** so it
  can build Windows leaf → RSA intermediate → EC root. The EC root and EC intermediate
  are already present. Add the RSA intermediate to the staged
  `/tmp/smallstep-ca.crt` bundle (and the `both`/`smallstep` trust modes). One concat.

### Fleet (fleet-gitops) profiles

- **Windows:** point `campus-wifi-smallstep-scep-direct.xml` (test-pilots → later all
  Windows) ServerURL at `https://ca-rsa.campusgroup.co/scep/wifi-scep`, CAThumbprint =
  the **RSA decrypter** of instance #2 (GetCACert position 0), static challenge inlined
  (per the proven fleet-gitops #40 finding that `$FLEET_SECRET_` isn't substituted into
  Windows SCEP `<Data>`). Subject key stays RSA 2048.
- **non-ADE/DEP Macs:** resume `feat/macos-scep-wifi-fallback` — SCEP `.mobileconfig`
  against the **existing EC** `https://ca.campusgroup.co/scep/wifi-scep`, scoped to the
  dynamic label `mdm.installed_from_dep != 'true'`, EC key (`ECSECPrimeRandom`, SE),
  include the EC intermediate in the profile (macOS doesn't persist the SCEP-returned
  intermediate — known gotcha).

## Components (isolation / interfaces)

1. **Terraform: RSA KMS key + IAM** (`smallstep.tf`) — `ca-signing-rsa` + grants. Pure
   add, gated by existing `enable_smallstep_ca`.
2. **Terraform: instance #2 LB stack** (`smallstep.tf`) — IP, managed cert, backend,
   health check, URL map, proxy, forwarding rule, firewall :8444. Mirror of the
   existing block with `-rsa` names.
3. **Terraform: new secrets** (`smallstep.tf`) — `smallstep-rsa-intermediate-cert`,
   `smallstep-rsa-scep-decrypter-cert`, `smallstep-rsa-scep-decrypter-key` (+ IAM).
4. **startup.sh: RSA CA bootstrap** — init/restore the RSA intermediate (KMS-backed) +
   RSA decrypter, render `ca.json` #2, `step-ca-rsa.service`, log/probe. Bounded,
   mirrors the EC bootstrap; the readiness/partial-publish gates are reused verbatim.
5. **startup.sh: RADIUS trust** — append RSA intermediate to the client-cert bundle.
6. **fleet-gitops: Windows profile** — repoint to `ca-rsa`, new CAThumbprint.
7. **fleet-gitops: non-ADE Mac SCEP** — finish the paused branch (scoping + PR).

## Rollout

1. Terraform apply (KMS, secrets, LB) — additive, no disruption to instance #1.
2. Re-run startup.sh on both VMs (documented stop-FreeRADIUS + metadata re-exec) — brings
   up step-ca #2, persists RSA chain, updates RADIUS trust. Instance #1 untouched.
3. Verify `ca-rsa.campusgroup.co` GetCACert returns the single RSA decrypter; verify
   leaf chains RSA-intermediate → EC root.
4. fleet-gitops: ship non-ADE Mac EC-SCEP (existing instance) → verify a non-ADE Mac
   gets an EC cert + joins Campus.
5. fleet-gitops: repoint Windows (test-pilots/733) at `ca-rsa` → verify 733's SCEP
   event log shows success (no `signature ... cannot be verified`), cert in
   `LocalMachine\My`, RADIUS Access-Accept. Then widen to all Windows.

## Error handling / safety

- **Never re-key the EC chain.** Instance #2 reuses the existing EC root cert; the EC
  intermediate + 460 ACME Mac certs are never touched. The RSA path is purely additive.
- Reuse instance #1's hard-won safety gates: refuse-to-reinit on transient secret read
  failures; publish the readiness-marker secret LAST; decrypter-readiness probe trips
  `Restart=always` on KMS lag.
- HA: both VMs must serve identical RSA chains (shared persisted RSA intermediate +
  decrypter), same as instance #1 — else round-robin GetCACert is inconsistent.

## Open questions (resolve in plan)

1. **DB:** second database (`stepca_rsa`) vs. shared DB with distinct `authorityId`.
   Lean: separate database for clean isolation; confirm step-ca 0.30.2 supports two
   schemas on one Postgres instance cleanly.
2. **RSA decrypter reuse:** does instance #2 need its own decrypter cert/key, or can it
   reuse instance #1's? Lean: dedicated, signed by instance #2's RSA intermediate, to
   keep the two CAs independent.
3. **Datadog:** extend the smallstep dashboard/monitors/log pipeline to cover
   `step-ca-rsa` (separate service tag).
4. **Single-VM init race:** the existing EC CA documents an accepted first-boot race;
   the RSA init must use the same readiness-probe guard.

## Non-goals

- No change to the 460 ADE/DEP ACME Macs.
- No hardware-binding of Windows Wi-Fi keys (accepted).
- No custom ACME/TPM client (the earlier exploration) — SCEP suffices for both SCEP
  populations once the RSA instance exists.
- No conversion of the existing CA to RSA.
