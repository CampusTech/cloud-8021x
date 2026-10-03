# Real step-ca SCEP integration

From the repository root:

```sh
python3 tests/scep/run.py
```

Requires Python 3, Terraform, Go, and internet access on macOS/Linux (arm64 or
amd64). The runner downloads the official step-ca 0.30.2 release, verifies its
published SHA-256 checksum, and creates only temporary local certificates,
keys, a database, and loopback listeners. It does not use cloud credentials or
Docker. Its Go dependencies are isolated from the production webhook module.

The test consumes the RSA provisioner and certificate template from the actual
rendered startup script. It substitutes local keys, network addresses, and test
challenge keys, launches the pinned step-ca binary and the real webhook handler, then
submits signed PKCS#7 messages containing real PKCS#10 CSRs. The actual
`NewMutualTLS` handler and `ClientTLSConfig` authenticate step-ca using its
automatically issued internal TLS certificate; no HMAC bypass is used.

Coverage includes:

- Serial-free BYOD issuance with the expected certificate identity.
- Rejection of the BYOD token when requesting another enrolled device's CN.
- Rejection of shared passwords and absent challenges.
- Renewal requests signed by a previously issued certificate: valid bound
  challenge succeeds; missing challenge or changed identity fails.
- Rejection after unenrollment despite a still-valid challenge.
- Certificate verification, removal of unapproved SANs, clientAuth-only EKU,
  and preservation of the renewal OU.
- Stock Fleet's Basic-authenticated raw challenge protocol and neutral v2 tokens.
- Separate rendered inventory-mode CA, reserved issued CN despite arbitrary CSR
  names, retry and renewal, and mode-disabled rejection of neutral tokens.

`go test ./...` in the webhook directory does not run this suite. Directly
running Go tests in this directory skips the integration unless the runner's
fixture environment variables are present.
