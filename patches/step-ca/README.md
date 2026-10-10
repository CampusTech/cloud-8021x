# Fixed Smallstep CA 0.30.2 build

The shipping package is `step-ca 0.30.2-1+campus1`; its executable identifies
itself as `0.30.2+campus1`. It is an explicit downstream security rebuild, not an
upstream release. `scripts/build-step-ca.sh EMPTY_OUTPUT_DIRECTORY` authenticates
the source, applies the two bounded patches, runs upstream compatibility tests,
builds Linux amd64/arm64, scans each exact binary and creates inert Debian packages.
Run as an unprivileged build user with Go1.27.2, cosign2.6.5,
govulncheck1.8.0, Python3, curl, patch and dpkg-deb. Nothing is installed or published.

Source: [official v0.30.2](https://github.com/smallstep/certificates/releases/tag/v0.30.2),
commit `6e8ec61405239cf3f37b2bbf260a587b7d2e4e31`.
The source archive SHA256 is
`944b205d5ba89f393cbdc09d68ab7ce485f5b44f44c28025d30508af956c1cba`.
The pinned signed checksum document and bundle are verified against the exact
`https://github.com/smallstep/workflows/.github/workflows/goreleaser.yml@refs/heads/main`
identity and GitHub OIDC issuer, including the transparency bundle. The build
refuses missing tools, signature/hash failures and vulnerability findings.

`security-dependencies.patch` fixes go-jose/v3 3.0.5, go-jose/v4 4.1.4,
pgx5.9.2, chi5.3.0, compress1.18.7, x/net0.60.0, x/crypto0.57.0,
x/text0.42.0, gRPC1.83.2 and the required OpenTelemetry1.44.0 graph. All
resulting transitive versions and sums are recorded in the patch. Go1.27.2 is
mandatory independently of the upstream module's minimum Go directive.
`go127-vet.patch` changes only the format of an invalid SSH certificate-type error
from a quoted uint32 to its decimal value; policy behavior is unchanged. The new
Go vet rejected the upstream format, so the build retains vet rather than skipping it.

The official Go1.26.1 binary failed the current scanner with52 called findings.
The fixed exact binaries have0 called and0 imported findings. Their3 remaining
module advisories concern OpenPGP/S3crypto packages absent from the actual compiled
package graph. The executable retains symbols: govulncheck's stripped-binary
fallback conservatively reports all vulnerable module symbols. Do not strip the
package after scanning, suppress advisories, or substitute an official vulnerable
binary. Archive hashes, binary build information, exact patches, source signatures,
upstream test results and current binary scan results accompany `SHA256SUMS`.

Actual validation includes both Debian13 architecture installs/version execution,
upstream ACME/SCEP/authority/API/CA/database suites, direct CloudKMS mocked-client
race tests, and the project's real SCEP issuance/renewal/mTLS tests against the
same fixed source. KMS tests use mocks; no live KMS/CA data or credentials are used.
The full protected two-node deployment acceptance is a separate release gate.
CA files, databases, signer references and existing certificates remain managed
by protected Go bootstrap; this package has no maintainer scripts or service actions.

For local project interoperability, build the same patched source for the local
host with Go1.27.2, preserving the version flags and symbols, scan that executable,
then pass its mandatory hash to `tests/scep/run.py --binary ... --sha256 ...`.
The runner uses temporary local CA state and has no vulnerable download fallback.
