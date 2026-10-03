# Device-bound SCEP issuance

VLAN policy trusts the certificate's device identity. A password shared by all
devices cannot authorize that identity: someone holding it could request a CSR
with another enrolled device's CN and inherit that device's VLAN.

Webhook v2.0.0 accepts only HMAC-SHA256 tokens containing an identity, provisioner,
issue time, and expiration. It compares the authenticated claims to the CSR CN
and provisioner before checking current enrollment and the optional Fleet label.
The maximum enrollment window is 24 hours; the CLI defaults to 15 minutes.
Renewal requires a new valid challenge. Retries for the same identity during the
window are allowed, so these tokens must not be described as one-time passwords.

The signing key lives in Secret Manager as `scep-challenge-signing-key`, shared
by the two webhook instances and trusted issuers only. It is newly generated;
the retired client-distributed SCEP password is not reused as a signing key.
No signing key or VLAN is placed in the certificate or delivered to devices.

The CA configuration always invokes the SCEP challenge webhook, even if the
service is disabled or unavailable. There is no shared-password fallback.
The webhook uses mutual TLS: it verifies both CA roots, the configured CA DNS
SANs, and clientAuth/serverAuth EKUs. step-ca sends its own automatically renewed
service certificate; device certificates cannot substitute for it. The local
webhook HTTPS certificate is trusted via the VM system store, with daily expiry
checks and rotation 30 days before its one-year expiration.

Both ACME and SCEP webhooks are inside `options.webhooks`; top-level `webhooks`
is ignored by step-ca 0.30.2. The SCEP certificate template allows clientAuth
only, preserves the bound CN and untrusted renewal OU, and omits requested SANs.
The OU is never an authorization identity.

## Dynamic SCEP and Fleet

Fleet supports dynamic SCEP with its Smallstep and NDES integrations. A dynamic
password alone does not establish which device identity the password authorizes.
Fleet's current Smallstep challenge request contains the CA URL, a random
payload identifier, and payload types; it does not contain a host UUID or serial.
The custom SCEP proxy validates its URL token but forwards an encrypted CSR, so
the CA cannot infer the permitted CN from that token either.

To use this verifier, the trusted issuer must select the identity from MDM
inventory and deliver the bound token only to that device. The
[`scep-challenge` command](../webhook/README.md#scep-and-serial-free-byod-v200)
supports this contract for any MDM. A native Fleet dynamic challenge integration
also needs Fleet to send authenticated host context to the challenge issuer;
an anonymous or device-selected identity must never be accepted for minting.
[Fleet PR #54717](https://github.com/fleetdm/fleet/pull/54717) adds that upstream
context. This implementation works independently; native integration can follow
after that change is available.
Do not configure Fleet's static custom-SCEP challenge as the new signing key.

## Generate and deliver an iOS profile

Choose the host UUID/enrollment ID from trusted Fleet inventory. The generator
runs on a trusted admin/MDM machine; it is not a device self-service endpoint.
Access the signing key from Secret Manager into a private file, and obtain the
RADIUS server root certificate through your normal trusted configuration channel.
Build the webhook CLI with `cd webhook && go build -o acme-authz-webhook .`.

```sh
umask 077
ENROLLMENT_DIR="$(mktemp -d)"
# Use the project actually hosting this CA; keep the resulting key server-side.
gcloud secrets versions access latest --secret=scep-challenge-signing-key \
  --project=YOUR_PROJECT > "$ENROLLMENT_DIR"/signing-key

python3 scripts/byod_profile.py \
  --webhook-bin ./webhook/acme-authz-webhook \
  --identity ENROLLMENT_UUID --provisioner wifi-scep \
  --scep-url https://scep.example.com/scep/wifi-scep \
  --ssid Campus --radius-server-name radius.example.com \
  --radius-ca-cert /secure/radius-root.crt \
  --signing-key-file "$ENROLLMENT_DIR"/signing-key \
  --ttl 15m \
  --out "$ENROLLMENT_DIR"/device.mobileconfig \
  --fleet-command-out "$ENROLLMENT_DIR"/install.json
```

The outputs are 0600 files. Existing files are never overwritten. `--dry-run`
validates without minting a token or writing files; `--debug` logs no secrets.
The certificate CN, token identity, and sole Fleet command target are identical.
The profile installs the server trust root, SCEP identity and EAP-TLS Wi-Fi
settings, with matching payload references and private keys marked nonextractable.
Profile identifiers are stable per device/network so renewal replaces the old
profile. The signing key never enters either output.

Submit the generated request through Fleet's authenticated admin API:

```sh
curl --fail-with-body "$FLEET_URL/api/v1/fleet/commands/run" \
  -H "Authorization: Bearer $FLEET_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @"$ENROLLMENT_DIR"/install.json
```

Check the returned command UUID using Fleet's command-results API before treating
installation as complete. A queued command is not proof of installation. Deliver
before the challenge expires; offline devices need newly generated files. Protect
and remove the sensitive working files after delivery. Other MDMs can deliver
the `.mobileconfig` through their equivalent per-device authenticated channel.

This self-contained path uses direct InstallProfile commands, not Fleet's
managed profile renewal pipeline. Generate and deliver a new profile before the
90-day certificate expires, with a fresh challenge and the same identity/network
inputs. It can be invoked from your trusted enrollment and renewal automation.
Do not deploy one generated profile or token to a fleet of devices.

## Upgrade sequence

This is a breaking SCEP enrollment change. Existing static-challenge profiles
will fail new enrollment and renewal after the upgrade.

1. Publish webhook **2.0.0** before applying the Terraform default that downloads
   that release. Terraform creates the new signing key and retires the old
   `smallstep-scep-challenge` and unused `acme-webhook-signing-secret` resources. Protect Terraform state as before.
2. Update the trusted MDM issuance integration to mint challenges for the exact
   identity and SCEP provisioner, and deliver them through each device's
   authenticated enrollment channel. Keep the signing key on trusted servers.
3. Replace any explicit `http://127.0.0.1:.../authorize` override with HTTPS,
   or leave `acme_authorizing_webhook_url` empty to select the managed local
   HTTPS endpoint when `enable_acme_webhook = true`.
4. Roll out the webhook and CA configuration together on both nodes. Check that
   valid enrollment works, cross-device CN changes fail, and an unavailable
   webhook denies issuance. The ACME gate now also enforces its configured Fleet
   enrollment/label policy because step-ca loads the corrected options field.
5. Reissue or retire certificates from the old issuance path before treating
   them as a BYOD isolation boundary. Fixing issuance does not revoke existing
   certificates. If impersonated certificates may have been issued, remove the
   old issuer from RADIUS trust after deploying a replacement chain, or enforce
   revocation for all affected certificates; changing the shared password alone
   is insufficient. Clear TLS session caches/restart RADIUS when withdrawing
   that trust so a resumed session cannot retain it.

Key rotation invalidates outstanding enrollment tokens, not issued certificates.
Devices offline past token expiry need a freshly delivered challenge. Certificate
renewal must likewise request a fresh challenge through the trusted integration.
The token authenticates the MDM-assigned identity; it does not add hardware
attestation to User Enrollment.

## References

- [Fleet Smallstep challenge request](https://github.com/fleetdm/fleet/blob/main/ee/server/service/scep/scep_proxy.go)
- [Fleet certificate authority integrations](https://fleetdm.com/docs/configuration/yaml-files#certificate-authorities)
- [step-ca SCEP provisioner and webhook validation](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/scep.go)
- [step-ca provisioner options schema](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/options.go)
