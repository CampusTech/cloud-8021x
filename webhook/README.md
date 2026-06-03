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

## Endpoints

- `POST /authorize` — step-ca calls this. Verifies the `X-Smallstep-Signature`
  HMAC-SHA256 over the raw body, extracts the serial, decides, returns
  `{"allow": true|false}`.
- `GET /healthz` — liveness.

## It denies (allow=false) when

- the signature is missing or invalid,
- the body is malformed,
- the serial is empty,
- the serial is not an enrolled Fleet host,
- (if `ALLOW_LABEL` is set) the host lacks that label,
- Fleet is unreachable / errors / times out.

## Configuration (env)

| Var | Required | Meaning |
|-----|----------|---------|
| `WEBHOOK_SIGNING_SECRET` | yes | Raw shared HMAC secret. step-ca's ca.json carries the **base64** of this; step-ca base64-decodes before HMAC, so both sides key on identical raw bytes. |
| `FLEET_API_BASE_URL` | yes | e.g. `https://fleet.campusgroup.co` |
| `FLEET_API_TOKEN` | yes | Fleet API token (a read-only, API-only user). |
| `ALLOW_LABEL` | no | If set, host must carry this Fleet label (e.g. `test-pilots`) to be allowed. Empty = any enrolled host. |
| `PORT` | no | Listen port (default `8080`; Cloud Run injects it). |

## Build & run

```bash
go test ./...
go build .
WEBHOOK_SIGNING_SECRET=... FLEET_API_BASE_URL=https://fleet.example FLEET_API_TOKEN=... ./acme-authz-webhook serve
```

Container image: `docker build -t acme-authz-webhook .` (see `Dockerfile`).
Deployed on Cloud Run via the repo's `webhook.tf` (gated by `enable_acme_webhook`).
