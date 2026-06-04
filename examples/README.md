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
| `CA_CERT_PEM` | base64 DER of the root CA cert, **single line** (no wraps): `gcloud secrets versions access latest --secret=$(terraform output -raw smallstep_ca_cert_secret_id) \| openssl x509 -outform DER \| base64 \| tr -d '\n'` (or `base64 -w0` on GNU / `openssl base64 -A`) |
| `CA_THUMBPRINT` | SCEP only — SHA-1 of the (intermediate) cert returned by `<SCEP_SERVER_URL>?operation=GetCACert`, as 40 hex chars, **no** colons (matches the SCEP `CAThumbprint` node) |
| `ROOT_CA_THUMBPRINT` | SHA-1 of the **root** CA. Format differs by file: `wifi-8021x.xml` `<TrustedRootCA>` wants **space-separated lowercase hex byte pairs** (e.g. `aa bb cc … 22`); `root-ca.xml` LocURI wants the same 40 hex chars with **no** separators/colons. Convert, don't blind-replace. |
| `INTERMEDIATE_CA_THUMBPRINT` | 802.1X client-cert auto-select (`<IssuerHash>`) — SHA-1 of the **intermediate** CA that signs client certs, same **space-separated lowercase hex pairs** format |
| `SSID` | your network SSID |
| `CLIENT_IDENTIFIER` | device serial / permanent identifier |

> Keep these in sync with the CA's emitted outputs to avoid drift.

The actual profile files are added by the fleet-gitops consumption plan (Plan 3).
