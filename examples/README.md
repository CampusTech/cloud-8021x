# Example EAP-TLS client profiles

Templates only: Terraform does not deliver these files. Customize them for your
network, render the certificate data and placeholders, then deploy through MDM.

| Templates | Intended use |
| --- | --- |
| [`fleet/`](fleet/README.md) | Recommended reusable Fleet profiles: attested Apple ACME, serial-free Apple SCEP, and Windows machine SCEP/Wi-Fi. |
| `acme/` | Generic attested Apple ACME. Requires supported hardware/enrollment that exposes the attested permanent identifier used by the authorization webhook. |
| `scep/wifi-ios-byod.mobileconfig` | Generic identity-bound Apple SCEP for a trusted integration that supplies a fresh device-bound challenge. Fleet users should use `fleet/` instead. |
| `scep/wifi-scep.xml` + `wifi-8021x.xml` | Legacy generic Windows **user-store** SCEP and user authentication. Not compatible with the built-in Fleet certificate collector. |
| `scep/root-ca.xml` | Windows machine-store RADIUS **server** trust root; shared by both Windows variants. |

For User Enrollment and other serial-free Apple devices, use SCEP. Keep existing
valid, managed ACME identities when adding inventory authorization; changing VLAN
rules does not require new certificates. Generic MDM integrations must arrange
renewal themselves. See [Fleet staging and renewal](../docs/scep-identity-binding.md).

## Tokens

| Token | Replacement |
| --- | --- |
| `ACME_DIRECTORY_URL` | `terraform output -raw smallstep_acme_directory_url` |
| `SCEP_SERVER_URL` | `terraform output -raw smallstep_scep_rsa_url` |
| `SCEP_PROXY_URL` | Your trusted MDM's HTTPS SCEP proxy, or the RSA SCEP URL for a direct legacy integration. |
| `SCEP_CA_NAME` | The configured SCEP provisioner name. |
| `SCEP_CHALLENGE` | Fresh signed challenge from a trusted integration. For legacy mode it must bind the exact normalized CSR identity and provisioner; never use a static shared password. |
| `DEVICE_IDENTIFIER` | Generic BYOD: exact enrolled identity selected by the trusted integration, not a device-selected claim. |
| `CLIENT_IDENTIFIER` | ACME: attested device serial, identical in ClientIdentifier and CN. Legacy Windows: enrolled identity matching its signed challenge (the template adds the supported ` Campus WiFi` CN suffix). |
| `CERTIFICATE_RENEWAL_ID` | Generic BYOD: renewal tracking value supplied by your trusted MDM integration; it does not schedule renewal on its own. |
| `CERT_ID_GUID` | Stable GUID for the generic Windows SCEP node; retain across updates. |
| `CA_CERT_PEM`, `RADIUS_CA_CERT_BASE64_DER` | Base64 **DER** of the RADIUS server trust root, without PEM headers. Despite its old name, `CA_CERT_PEM` is not PEM. See below. |
| `RADIUS_SERVER_CN` | Exact RADIUS certificate name (`server_cert_cn`), e.g. `radius.example.com`. This is independent of the AP's RADIUS IP address and the SCEP/ACME HTTPS name. |
| `CA_THUMBPRINT` | SHA-1 of the signing intermediate returned by RSA SCEP `GetCACert`: 40 hex characters, no separators. |
| `ROOT_CA_THUMBPRINT` | SHA-1 of the **server trust root**: space-separated hex byte pairs in Wi-Fi `TrustedRootCA`, but 40 contiguous hex characters in `root-ca.xml`'s LocURI. |
| `INTERMEDIATE_CA_THUMBPRINT` | SHA-1 of the **client issuer**, space-separated hex byte pairs, for Wi-Fi `IssuerHash`. This is not necessarily the server root or server issuer. |
| `SSID` | Network name. In a Windows LocURI only, percent-encode the path component. |
| `SSID_HEX` | Hex of the SSID's UTF-8 bytes, no spaces; `printf '%s' 'YourSSID' \| xxd -p -u \| tr -d '\n'`. |
| `CANAME` | Fleet Smallstep integration name; replace only this suffix inside Fleet's URL/challenge variables. |

Leave other `$FLEET_VAR_*` values intact in Fleet templates. Apple uses
`$FLEET_VAR_CERTIFICATE_RENEWAL_ID` in the subject OU; Windows uses
`$FLEET_VAR_SCEP_RENEWAL_ID`. These are renewal metadata, not authorization keys.

## Choose the correct trust root

Client issuance and RADIUS server trust are separate. With the standard bootstrap:

| RADIUS trust mode | Server trust root secret | Presented server leaf secret |
| --- | --- | --- |
| `okta` | `radius-server-ca-cert` | `radius-server-cert` |
| `smallstep` or `both` | `smallstep-ca-cert` (EC root) | `radius-smallstep-server-cert` |

RSA SCEP clients chain to `smallstep-rsa-root-cert`, but RADIUS normally presents
an **EC-rooted** server certificate even to those Windows/BYOD clients. Do not
put the RSA client root into the server trust payload just because SCEP used it.
For a migration or custom deployment, verify the certificate actually presented
by both RADIUS nodes before selecting the root.

Fetch the chosen **public** certificate and encode it, for example in Smallstep mode:

```sh
gcloud secrets versions access latest \
  --project="$(terraform output -raw project_id)" \
  --secret=smallstep-ca-cert > /tmp/radius-server-root.pem
openssl x509 -in /tmp/radius-server-root.pem -outform DER | openssl base64 -A
openssl x509 -in /tmp/radius-server-root.pem -noout -fingerprint -sha1
```

`fetch-outputs.sh` currently exports the **legacy** `radius-server-ca-cert` and
`radius-server-cert`, even in Smallstep mode. Its exported root is not the
Smallstep server trust anchor. A `.cer` extension alone does not tell you
whether a file is PEM or DER.

## Rendering and validation

Use a plist/XML-aware renderer. Avoid replacing `SSID` inside `SSID_HEX` or
`CA_THUMBPRINT` inside the longer thumbprint tokens. Windows Wi-Fi has two XML
layers: XML-escape values inside the WLAN document, then escape that entire
document inside SyncML `Data`. Percent-encoding is only for the LocURI path,
not the SSID inside WLAN XML. Apple values need one XML escaping layer.

Windows SCEP files are SyncML command fragments with multiple top-level
commands; the MDM supplies the envelope. Keep `Exec/Enroll` last. The Fleet
examples use `Replace`; other MDMs may need `Add` for the initial Wi-Fi node and
`Replace` for updates, as described in [Microsoft's WiFi CSP reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/wifi-csp).

All Wi-Fi templates pin the server name and root. Apple trust exceptions and
Windows user trust prompts are disabled. See [Apple's 802.1X settings](https://support.apple.com/guide/deployment/connect-to-8021x-networks-depabc994b84/web).
Private MACs work with fingerprint authorization and verified accounting; the
ACME/Windows examples disable randomization only as a stable-MAC operational
choice. BYOD templates leave it enabled by default.

Parse rendered profiles, check all identity/root UUID references and certificate
thumbprints, and verify installation, connection, VLAN/DHCP, and renewal on a
pilot device before broad delivery. Do not commit rendered challenges or keys.
