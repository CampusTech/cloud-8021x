# acme-authz-webhook

A step-ca **AUTHORIZING** webhook (the reference implementation for cloud-8021x's
optional ACME path). step-ca calls it on every certificate order; it returns
`{"allow": true}` **only** for device serials that are enrolled hosts in Fleet.
Every other case denies. It is **fail-closed by construction**.

## Why it exists

Apple `device-attest-01` proves the requester is a genuine, unmodified Apple
device — NOT that it is one of *your* devices. Without this gate, any attacker
with any iPhone/Mac could obtain a Wi-Fi certificate from your CA. The attested
serial (`attestationData.permanentIdentifier`) is Apple-signed and bound to the
request, so it is a trustworthy key: this service looks it up in Fleet and only
allows enrolled hosts.

## Authentication

The deployed service listens only on loopback HTTPS and requires mutual TLS.
It trusts the two configured CA roots and accepts only the CA service DNS SANs
with both clientAuth and serverAuth EKUs. Ordinary Wi-Fi certificates cannot
call the authorization endpoints. step-ca supplies its automatically renewed
internal TLS certificate. The local webhook server certificate is installed in
the system trust store and renewed before expiry by a daily systemd timer.

Static step-ca 0.30.2 JSON ignores webhook `secret`, `bearerToken`, and `basicAuth`.
Do not use an empty-key HMAC as authentication. Its supported mTLS transport is
why the deployed service uses certificate authentication.

## Endpoints

- `POST /authorize` — step-ca calls this. Verifies the TLS
  client certificate, extracts the attested serial, decides, returns
  `{"allow": true|false}`.
- `POST /scep-challenge` — verifies the CA client identity, an identity-bound enrollment token, and current Fleet enrollment.
- `GET /healthz` — liveness.

## It denies (allow=false) when

- the CA client certificate is missing, invalid, or has the wrong identity,
- the body is malformed,
- the serial is empty,
- the serial is not an enrolled Fleet host,
- (if `ALLOW_LABEL` is set) the host lacks that label,
- Fleet is unreachable / errors / times out.

## Configuration (env)

| Var | Required | Meaning |
|-----|----------|---------|
| `WEBHOOK_CLIENT_DNS_NAMES` | yes | Comma-separated exact CA service DNS names allowed in client certificate SANs. |
| `WEBHOOK_CLIENT_CA_FILES` | no | Colon-separated PEM trust bundles; default `/etc/acme-authz-webhook/client-cas.pem`. |
| `WEBHOOK_TLS_CERT_FILE` | no | HTTPS certificate; default `/etc/acme-authz-webhook/server.crt`. |
| `WEBHOOK_TLS_KEY_FILE` | no | HTTPS private key; default `/etc/acme-authz-webhook/server.key`. |
| `FLEET_API_BASE_URL` | yes | e.g. `https://fleet.example.com` |
| `FLEET_API_TOKEN` | yes | Fleet API token (a read-only, API-only user). |
| `ALLOW_LABEL` | no | If set, host must carry this Fleet label (e.g. `test-pilots`) to be allowed. Empty = any enrolled host. |
| `PORT` | no | Loopback listen port (default `8080`). |
| `SCEP_CHALLENGE_SIGNING_KEY` | SCEP only | Server-only random key of at least 32 bytes. Missing disables SCEP; a short key fails startup. Never put this in an MDM profile. |

## Build & run

```bash
go test ./...
go build -o acme-authz-webhook .
# serve additionally requires the TLS files and trusted CA identities above.
WEBHOOK_CLIENT_DNS_NAMES=ca.example.com,scep.example.com \
  FLEET_API_BASE_URL=https://fleet.example FLEET_API_TOKEN=... ./acme-authz-webhook serve
```

Container image: `docker build -t acme-authz-webhook .` (see `Dockerfile`).
Runs as a systemd service on each RADIUS VM. Authorization is loopback-only;
optional inventory mode adds the HTTPS broker listener. `webhook.tf` manages
its secrets, IAM, and broker backend (gated by `enable_acme_webhook`).

## Legacy identity-bound SCEP (v2.0.0)

With inventory mode disabled, SCEP challenges are signed tokens bound to the normalized CSR CN and exact
step-ca provisioner, with an expiry of at most 24 hours. Static passwords,
including the old `SMALLSTEP_SCEP_CHALLENGE`, are never accepted. The dedicated
signing key is independent of both the retired password and the webhook HMAC.
Tokens allow retries for the same device until expiry; they are not single-use.

The verifier then resolves the CSR CN as a currently enrolled device. Exact
hardware-serial and UUID/enrollment-ID matches are accepted; mutable hostname
matches are denied. The Windows ` Campus WiFi` suffix remains supported.
Opaque identifiers are case-sensitive; use the same identity when issuing the
challenge and rendering the device's CSR subject.

An administrator or trusted MDM integration can issue a challenge locally:

```sh
./acme-authz-webhook scep-challenge \
  --identity 'enrollment-uuid' --provisioner wifi-scep \
  --signing-key-file /secure/scep-signing-key --ttl 15m \
  --out /secure/device.challenge
```

The command creates a new 0600 file, never overwrites it, and supports `--dry-run`
and `--debug` (no secrets in logs). Alternatively supply the key through
`SCEP_CHALLENGE_SIGNING_KEY`. Only deliver the resulting challenge to its bound
device, via the authenticated MDM channel. Do not give devices the signing key.

ACME `/authorize` still requires an attested permanent identifier and never
falls back to a CSR CN. Both provisioners must place hooks in
`options.webhooks`, which is the schema step-ca actually loads. The SCEP template
issues clientAuth-only certificates with no requester-supplied SANs.

See [SCEP identity binding and migration](../docs/scep-identity-binding.md).

## Native Fleet dynamic SCEP with certificate inventory

For reusable Apple and Windows profiles with Fleet-managed renewal, use the optional
broker instead of the per-device CLI. Set `SCEP_CERTIFICATE_INVENTORY=true` and
configure `SCEP_BROKER_USERNAME`, `SCEP_BROKER_TOKEN` (32+ bytes),
`SCEP_BROKER_SCEP_URL`, and `SCEP_BROKER_PROVISIONER`. The public HTTPS broker
listens on `SCEP_BROKER_PORT` (9081) using the configured webhook TLS certificate.
`POST /fleet/scep-challenge` implements Fleet's native HTTP Basic authentication
and raw-string response protocol. The SCEP URL must match exactly, including
trailing slash behavior. `GET /fleet/ndes-challenge` implements the Windows
NDES integration with the same Basic credentials and Fleet-compatible HTML.
No Microsoft NDES server is required. CA authorization remains a separate
loopback mTLS listener.

Neutral v2 challenges are provisioner-scoped, random, and expire after 15 minutes;
Windows v3 challenges last 60 minutes to cover Fleet's 57-minute NDES cache and
use standard base64 for Windows PrintableString compatibility. Both permit
retries without asserting a device identity. Never enable this mode with CN
network authorization: enforce exact certificate fingerprints from authenticated
MDM or Fleet agent inventory. Terraform wires and validates these prerequisites. Existing v1
identity-bound tokens continue to work in their separate legacy mode.

See [deployment, shared profile, and rollout checks](../docs/scep-identity-binding.md).
