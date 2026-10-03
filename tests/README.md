# Tests

The policy/profile tests use Python's standard library. The full suite also
invokes OpenSSL and Go for certificate fixtures and the profile-generator CLI:

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
python3 tests/radius_integration.py --certificate-inventory
python3 tests/radius_integration.py --certificate-inventory --source-discovery
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
The `--certificate-inventory` run uses SHA256 of the actual verified leaf DER.
It rejects another CA-signed certificate copying a known staff CN, unknown,
ambiguous and stale certificate observations, and a missing fingerprint hook.
It verifies full handshakes on reauthentication (resumption is disabled in this
mode), current group/enrollment changes, and removal of private handoff files.
Both modes also exercise the same device from NYC and ATL clients with different
VLAN IDs, reauthentication, a spoofed NAS-Identifier, and an unknown location.
Both also verify opted-out locations return no VLAN attributes while keeping
verified identity, and reauthentication follows changes between mapped and
opted-out policy. Certificate mode checks signed Class accounting with no VLAN.

The `--source-discovery` run uses the generated source guard with local API-state
fixtures: fresh dynamic sources, stale authentication/accounting rejection,
static `/24` acceptance despite stale discovery, spoofed NAS rejection, and
changed console-ID rejection. Unit tests cover discovery pagination, exact host
matching, address changes, overlap rejection, rollback, and firewall failure.
GCP PATCH/IAM and physical UniFi WAN behavior still require a deployment pilot.

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

## Windows certificate inventory

The Python suite covers authenticated Fleet script results, exact DER hashing,
CA/expiry checks, host re-enrollment, missing scripts, duplicate or malformed
responses, second-precision request timestamps, absent results, and bounded
pending scripts after an uncertain POST. Profile tests check Device-scoped SCEP,
NDES variables, machine authentication, and server name/root validation.

The automated suite uses API fixtures rather than executing on Windows. Pilot the PowerShell collector,
Fleet profile installation, pre-login Wi-Fi, NYC VLAN/DHCP, and renewal on a real
Windows device before enabling fingerprint enforcement.
