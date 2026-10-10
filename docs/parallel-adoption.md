# Parallel deployment adoption

This is the root-only operator workflow for the two green Debian 13 instances. Deployment, secret publication, IAM changes, traffic switching and original-source scheduling changes require the separately reviewed deployment/cutover. These commands are implemented here; the tests use disposable synthetic environments, not the production deployment.

## Configuration and trust

Use the infrastructure-rendered pair of strict YAML configurations. Validate each with `cloud-8021x --config <rendered-file> config validate` as an ordinary user before staging it. The protected commands accept only the fixed installed configuration, or `bootstrap --incoming` selecting `/var/cache/cloud-8021x/artifacts/config.yaml`. They reject arbitrary root configuration paths/listener overrides.

`deployment.mode` is `parallel`. `deployment.id` is an immutable bounded deployment name, with physical instances `<id>-primary` and `<id>-secondary`. Logical `instance_id` remains `radius-primary` or `radius-secondary`. Explicit `source_id`, `source_primary` and `source_secondary` identify the original deployment and its actual hosts. `collection_epoch` is an immutable UTC whole-second timestamp. `state_transition` is an explicit 64-hex transition. The database is `cloud8021x_<id with hyphens replaced by underscores>`; bootstrap runtime/native roles append `_runtime` and `_native`. CA databases remain exactly `stepca` and `stepca_rsa`.

Enroll a separate root receipt key on each of the four physical hosts with the verified standalone binary:

```sh
/var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap source-key --incoming
```

The private Ed25519 key remains at `/var/lib/cloud-8021x-bootstrap/parallel-source.key`, root-only. Obtain its public pin through the authenticated operator SSH/IAP channel. Put the original-host pins in `deployment.source_primary_key` and `source_secondary_key`, and the green-host pins in `destination_primary_key` and `destination_secondary_key`. All four pins are required, distinct, and 64 lowercase hex characters before capture/preparation. Preparation also verifies its local root key matches the reviewed destination pin. Enroll before freezing the final reviewed pair, package manifests and collection epoch. Changing a pin/configuration after preparation changes the immutable manifest and is refused.

The common pair manifest normalizes only the role-specific hostname, physical instance, ordered peer addresses, peer DNS and physical firewall node. Each source receipt also binds the full destination configuration, physical role, release binary digest, original source configuration, collection epoch, Class key, CA trust, source scheduler fence and original observation timestamps. Runtime Class keys and cloud metadata credentials cannot sign these receipts.

Stage the complete verified artifact release, protected YAML and `postgres-ca.pem` in `/var/cache/cloud-8021x/artifacts`. The source uses the same verified standalone binary on its existing OS; capture does not install any package. Signed transfer files contain private webhook/CA connection configuration and must remain root-owned mode 0600 over authenticated transport. Do not print them or place them in logs, source control, SQL or ordinary object storage.

## Capture and passive preparation

On each original host, stage the corresponding green role's final configuration and invoke:

```sh
/var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap capture --incoming
```

Capture persistently fences only the known original scheduler/helper writers, proves their locks/processes have stopped, and reads fixed original policy/certificate state. Original native RADIUS authentication and both CA services continue. Missing certificate command provenance, malformed policy, missing CA trust, unexpected process/file state or a physical-host/pin mismatch fails capture. No accounting/MariaDB/checkpoint/outbox history enters the signed schema.

The output reports only a digest and the fixed root transfer file:

- `/var/lib/cloud-8021x-bootstrap/parallel-radius-primary.json`
- `/var/lib/cloud-8021x-bootstrap/parallel-radius-secondary.json`

Transfer each to the corresponding green host at `/var/cache/cloud-8021x/artifacts/parallel-radius-<role>.json`, preserving root ownership and mode 0600. Then on each green host:

```sh
/var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap prepare --incoming
```

Prepare checks the physical destination, private database/CA pin, separate app authority, CA ACLs and existing EC/RSA KMS public keys. It reads existing enabled CA material and server cache; missing, partial, disabled or unreadable material never falls back to initialization or renewal. Source CA roots/intermediates must match the inherited secrets. Existing webhook key/certificate, native CA configuration and enrollment templates are validated and retained byte-for-byte. Private native material remains local and is removed before storing the public authorization receipt in PostgreSQL.

Persistent systemd conditions precede package operations. RADIUS, step-ca, Go workers, renewal, source mutation and monitoring exporters remain stopped and cannot start after reboot without the root activation marker. The native configuration is validated without service activation. Preparation creates the immutable empty accounting epoch and imports only original certificate-command guards. Original pending work stays quarantined, including uncertain submissions; a missing/404 response is not terminal evidence.

A completed prepare reuses its exact installation receipt. An interrupted maintenance attempt blocks subsequent changes. Recover the reported exact attempt with:

```sh
/var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap prepare --incoming --resume-attempt <attempt>
```

Recovery requires the same configuration/release, original helper PID-start death, stopped services and the shared/local original installation reference. A completed physical installation is acknowledged; a partial installation restores its saved state while keeping passive barriers. After partial rollback, run ordinary prepare again. Recovery does not renew certificates, enable workers or clear arbitrary maintenance attempts.

## Activate the green pair

Keep green endpoints/NAS destinations isolated while preparing and testing. Refresh both source captures immediately before activation and transfer them again. Run `bootstrap prepare --incoming` on both completed passive green nodes again to publish these final receipts without reinstalling; both database publications must be fresh before the first activation. Source scheduler proofs expire after ten minutes; original certificate observation timestamps are never refreshed by transfer.

On primary, secondary, then primary again:

```sh
/usr/local/bin/cloud-8021x bootstrap activate
```

Each call verifies both green preparation publications, both original source fences, matching Class/CA trust, immutable pair identity and current command provenance. A stopped green node receives its final signed authorization snapshot before starting. The first healthy node reports `waiting_for_peer`; the shared worker epoch enables only once both local publications and authenticated peer readiness exist. Repeat on the first node to start its local renewal/source timers. Once active, a repeat verifies installed health and does not require recapturing obsolete source data.

An interrupted activation uses `bootstrap activate --resume-attempt <attempt>`. It proves the original helper has exited; it cannot revive a revoked epoch or bypass a missing peer/source receipt. Before authority exists it stops an incomplete isolated start and clears only its local readiness, retaining the original maintenance history. Then refresh/reprepare both receipts and run ordinary activation again. An already enabled epoch is checked and acknowledged without restarting production services.

After activation, existing server-certificate renewal is enabled, with the same CA identity and peer restart checks. It cannot initialize a CA. Discovery work retains the two logical SQL roles while its validated physical firewall mapping targets only the green deployment. Only the reviewed infrastructure/operator action switches traffic; activation does not change endpoints or NAS settings.

Accounting starts at the configured epoch. Pre-epoch records create no credit/export. The first ongoing Interim/Stop establishes a zero-credit baseline; later exact deltas are counted. A new Start follows normal zero-baseline behavior. Old accounting remains untouched in the original deployment.

## Reverse handoff

On both green hosts:

```sh
/usr/local/bin/cloud-8021x bootstrap deactivate
```

This revokes the shared worker epoch before stopping local production services and retaining original physical worker/PID/native receipts. Interrupted fencing uses `bootstrap deactivate --resume-attempt <attempt>`. Revocation is permanent for that epoch; rollback never treats an expired lease or missing node as proof of quiescence.

Resolve any imported original command guard with the existing protected `state recover-collection` operation, and started/pending/uncertain green submissions with `state recover-work --kind fleet-terminal`, using the exact retained command/work identity. Those paths query authenticated original terminal evidence and never repeat a POST. A 404 or still-pending command blocks source resumption. Never-attempted queued/leased work is retained in the revoked green epoch; it has no external delivery to reconcile. Green accounting/export state remains in green and is not copied backwards.

Only after both green physical fence/state receipts exist and all attempted certificate delivery is resolved, run on each green host:

```sh
/usr/local/bin/cloud-8021x bootstrap rollback-proof
```

Transfer the two root-only `rollback-radius-primary.json` and `rollback-radius-secondary.json` files from `/var/lib/cloud-8021x-bootstrap` into the fixed artifact directory on **each** original host. The signed proofs bind the reviewed pair, release, physical roles, revoked/fenced authority and reconciled command state; they expire after ten minutes. Then on each original physical host:

```sh
/var/cache/cloud-8021x/artifacts/cloud-8021x bootstrap resume-source --incoming
```

The receiver verifies both pinned green signatures and its original physical scheduler fence lineage before restoring only the original scheduler/helper files. It neither restores a stale CA database nor merges accounting history. Native/CA services on the original hosts were never stopped by source capture. Traffic restoration remains the separate reviewed infrastructure/operator action.

## Verification boundary

Run `sh tests/integration/parallel.sh` with the already cached `postgres:16` image to reproduce the owned no-host-port Linux and TLS PostgreSQL checks. The harness never pulls images and removes only its own labelled containers and temporary files.

Tests cover real TLS PostgreSQL epoch isolation, signed authorization publication, duplicate pending-command guards, two-node activation, revoked worker authority, unresolved-delivery refusal and exact expired preparation/activation recovery. Owned Linux fixtures cover root file/process capture, private key pins, original timestamp preservation, absence of accounting import, refusal of zero/one reverse receipt, original scheduler restoration, live-helper refusal and persistent passive files. The package fixture verifies the rendered conditions with actual Debian 13 `systemd-analyze verify` and evaluates marker absence/presence. This is not a claim of a real PID1 reboot or production cloud/HA cutover acceptance.
