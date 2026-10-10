# Tests

The supported runtime is the unified Go daemon on Debian 13, with FreeRADIUS,
step-ca, PostgreSQL and Datadog Agent/DDOT. Development test scripts are not
installed on servers.

## Fast checks

```sh
go test -race ./...
golangci-lint run
```

Use Go 1.27.2 and the pinned compatible linter from `go-security.yml`. That workflow
also tests/scans the `tests/scep` and `tools/dashboard` modules. The root race suite
skips database and installed-package tests unless their explicit fixture inputs
are present; a passing unit suite is not an integration result.

## Reproducible integration checks

One entrypoint reuses the existing assertions. It fails when required tools or
inputs are absent. Run from the repository root with Docker, Go, OpenSSL, Terraform 1.14.5,
Python3 and PyYAML 6.0.3 installed:

```sh
docker pull postgres:16
tests/integration/run.sh postgres
tests/integration/run.sh native arm64 /path/to/verified-bundle
tests/integration/run.sh collector arm64 /path/to/monitoring-packages /tmp/ddot-results
tests/integration/run.sh monitoring arm64 /path/to/verified-bundle CACHED_IMAGE /tmp/agent-results
tests/integration/run.sh scep /path/to/step-ca SHA256
```

Use `amd64` on an amd64 Docker host. The bundle must contain the complete actual
release package family, `package-manifest.json` and mandatory hashes. Build it
using the tooling in [releasing](../docs/releasing.md); dummy archives cannot
satisfy native integration. The collector input is the rebuilt monitoring
package directory with `SHA256SUMS`. The monitoring image is a cached image built
from `tests/native_package_fixture.Dockerfile`.

| Suite | What it executes |
| --- | --- |
| `postgres` | Real TLS PostgreSQL, race-enabled storage and TLS/provisioning suites, concurrent workers, crash/commit ambiguity, epoch isolation, signed handoff, source capture and assembled-daemon outage/cancellation. |
| `native` | Actual package installation/ABI, ACK/noACK and source freshness, policy activation, interrupted rollback, private auth-log retention, then EAP-TLS, native accounting with PostgreSQL outage/replay and actual step-ca SCEP issuance/renewal on Badger and TLS PostgreSQL. |
| `collector` | Actual DDOT persistent export queue, restart and full-storage behavior. |
| `monitoring` | Actual shipped Agent checks and native FreeRADIUS statistics, both CA endpoints and TLS failure visibility. |
| `scep` | Actual step-ca issuance/renewal with rendered configuration, mutual-TLS webhook and independent CA databases. |

The PostgreSQL/storage and native package suites run in CI; publication remains
limited to an explicit version tag. PostgreSQL tests use disposable credentials
and a random localhost-only port. Parallel and native fixtures publish no host
ports. Native fixture image construction accesses pinned Debian snapshot
repositories; running native packets uses an isolated container network.

These checks do not prove a systemd PID 1 reboot, production KMS/IAM integration,
physical AP VLAN/DHCP behavior, real Windows/iOS/macOS profile renewal or office
cutover/failover. Those remain staging gates before deployment. No suite uses
production secrets, Fleet hosts, Datadog accounts or Terraform state.

## Retained historical parity tests

`python3 -m unittest discover -s tests -v` includes the previous Bash/Python runtime's
parity tests under `tests/legacy`. Some require Terraform and `cryptography`.
`tests/radius_integration.py` without `--native` exercises that legacy runtime;
it is historical evidence, not validation of the new daemon.

Windows inventory assertions use API fixtures. Pilot the retained PowerShell
collector, machine certificate, pre-login networking and renewal on an actual
Windows device before rollout.

See [the validation scope review](../docs/validation/scope-review.md) for the
removed test machinery, application simplifications and their acceptance limits.
