# Fleet-specific EAP-TLS client profiles

Variants of the `acme/` and `scep/` templates that use Fleet's
`$FLEET_VAR_*` substitution syntax. Deliver these as configuration profiles
via Fleet GitOps. Templates only — substitute the generic tokens
(`ACME_DIRECTORY_URL`, `SSID`, `CA_CERT_PEM`, `CA_THUMBPRINT`, `CANAME`)
before use. See [`../README.md`](../README.md) for the token map.

| File | Platform | Purpose |
|------|----------|---------|
| `wifi-acme.mobileconfig` | macOS / iOS | EAP-TLS identity via direct ACME |
| `wifi-scep.xml` | Windows | EAP-TLS identity via SCEP (Fleet SCEP proxy) |

For the root CA trust and the WlanXml 802.1X profile on Windows, reuse
`../scep/root-ca.xml` and `../scep/wifi-8021x.xml` (they carry no Fleet
variables).

## The `$FLEET_VAR_*` mechanism

Fleet replaces `$FLEET_VAR_*` tokens at profile delivery time, per host.
The ones used here:

- `$FLEET_VAR_HOST_HARDWARE_SERIAL` — the host's hardware serial. Used as
  the ACME `ClientIdentifier` / CSR Subject CN (macOS) and the SCEP Subject
  CN (Windows).
- `$FLEET_VAR_SCEP_WINDOWS_CERTIFICATE_ID` — Fleet-generated GUID naming the
  Windows `ClientCertificateInstall/SCEP` node.
- `$FLEET_VAR_CUSTOM_SCEP_PROXY_URL_CANAME` — URL of Fleet's custom SCEP
  proxy for the CA named `CANAME`.
- `$FLEET_VAR_CUSTOM_SCEP_CHALLENGE_CANAME` — the SCEP challenge for that
  CA, injected by Fleet (not stored in the profile).
- `$FLEET_VAR_SCEP_RENEWAL_ID` — placed in the cert Subject OU so Fleet can
  auto-renew the certificate.

Replace `CANAME` with your custom SCEP proxy CA name everywhere it appears
in the variable names.

## Prerequisite: register the CA in Fleet first

Before the SCEP profile can resolve `$FLEET_VAR_CUSTOM_SCEP_PROXY_URL_CANAME`
and `$FLEET_VAR_CUSTOM_SCEP_CHALLENGE_CANAME`, the CA must be registered in
Fleet under `org_settings.certificate_authorities.custom_scep_proxy` with a
name matching `CANAME`, pointing at the step-ca SCEP provisioner URL and
challenge. If the CA name does not match, Fleet leaves the variable
unresolved and the profile fails to deliver.

## Gotcha: SCEP variable literal must appear only once

Fleet rejects a profile if a custom-SCEP proxy URL or challenge variable
literal appears more than **once** in the file — including inside comments.
That is why this README and the profile comments write those variable names
**without** the leading `$` (e.g. `FLEET_VAR_CUSTOM_SCEP_PROXY_URL_CANAME`).
The single live occurrence of each is in its `<Data>` node.
