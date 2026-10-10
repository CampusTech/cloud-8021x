# Real step-ca SCEP integration

From the repository root:

```sh
python3 tests/scep/run.py --binary /path/to/fixed/step-ca --sha256 EXPECTED_SHA256
```

Requires Python 3, Go 1.27.2 and a locally built, security-scanned step-ca
0.30.2+campus1 executable for the host architecture. The mandatory checksum binds
the exact executable tested. The runner creates only temporary local certificates,
keys, a database and loopback listeners; it uses no cloud credentials or Docker.
There is no download fallback to the vulnerable official binary. The authenticated
source and bounded patches are documented in `../../patches/step-ca/README.md`.

The test consumes the real Go CA renderer's RSA provisioner and certificate
template. It substitutes local keys, network addresses and challenge keys, launches
the fixed step-ca binary and real webhook handler, then submits signed PKCS#7
messages containing real PKCS#10 CSRs. `NewMutualTLS` and `ClientTLSConfig`
authenticate step-ca using its automatically issued internal TLS certificate.

Coverage includes:

- Serial-free BYOD issuance with the expected certificate identity.
- Rejection of the BYOD token when requesting another enrolled device's CN.
- Rejection of shared passwords and absent challenges.
- Renewal requests signed by a previously issued certificate: valid bound
  challenge succeeds; missing challenge or changed identity fails.
- Rejection after unenrollment despite a still-valid challenge.
- Certificate verification, removal of unapproved SANs, clientAuth-only EKU,
  and preservation of the renewal OU.
- Stock Fleet's Basic-authenticated Smallstep raw challenge protocol and neutral v2 tokens.
- Windows NDES HTML challenges and neutral v3 tokens: issuance, renewal, and
  rejection when fingerprint mode is disabled.
- Separate rendered inventory-mode CA, reserved issued CN despite arbitrary CSR
  names, retry and renewal, and mode-disabled rejection of neutral tokens.

`go test ./...` in the root module does not run this suite. Directly
running Go tests in this directory skips the integration unless the runner's
fixture environment variables are present.

The same fixed CA is also tested with independent PostgreSQL databases and a
local verified TLS endpoint:

```sh
scripts/test_step_ca_postgres.sh /path/to/fixed/step-ca EXPECTED_SHA256
```

This runner owns its temporary PostgreSQL container, credentials and certificate
authority. It never accepts a production DSN. Both modes execute the same real
issuance/renewal/mTLS suite with the restricted `stepca` database owner.
