# Tests

Fast policy/inventory tests use only Python's standard library:

```sh
python3 -m unittest discover -s tests -v
```

The webhook's Go tests include the complete SCEP handler → authorizer → Fleet
HTTP adapter flow for an enrolled iOS device without a serial:

```sh
cd webhook
go test ./...
golangci-lint run
```

## FreeRADIUS / UniFi packet integration

Requires local Docker and Terraform:

```sh
python3 tests/radius_integration.py
```

This creates a disposable Debian 12 container, installs FreeRADIUS 3.x and
`eapol_test`, renders the repository's real startup template with dummy values,
and executes the auth-configuration portions. It generates one-day test CAs and
certificates, then completes EAP-TLS exchanges through a UDP relay that decodes
the actual RADIUS packets. No ports are exposed to the host. The container is
removed on exit; no cloud APIs or production secrets are used.

Coverage includes numeric UniFi tunnel attributes, a serial-free certificate
with a spoofed staff username, another group's assignment, real TLS resumption
after a group change, rejection after unenrollment during resumption, and
unknown/unmapped/stale/corrupt inventory rejection. The relay updates the
inventory **before** delivering the initial Access-Accept, so reauthentication
cannot race the test's membership change.

The fixture enables a temporary disk TLS cache solely to force actual resumed
handshakes on Debian's OpenSSL 3 build. Deployment cache settings are preserved.
Accounting's SQL invocation is replaced by `noop` in the fixture; VLAN policy,
EAP certificate authorization, post-auth and reject configuration come from the rendered startup script.
This test does not simulate SCEP issuance or physical UniFi VLAN/trunk/DHCP setup.

To inspect logs, create your own disposable test container with the same packages
and pass `--container <name>`; that mode leaves it available afterward. Logs are
`/tmp/radius-debug.log` and `/tmp/eap-<case>.log` inside the container.

## Certificate issuance

`python3 tests/scep/run.py` exercises actual step-ca issuance and renewal through
the mutual-TLS webhook using the rendered CA configuration. See
[`scep/README.md`](scep/README.md). The normal Python suite also tests the private
per-device profile generator using a locally built webhook CLI.
