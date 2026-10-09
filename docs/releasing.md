# Release builds

The root `VERSION` is the only application release version. Build the root
module with its exact `go.mod` toolchain (currently Go1.27.2):

```sh
mkdir /tmp/cloud8021x-release
scripts/build-release.sh /tmp/cloud8021x-release
```

Each supported architecture has one static application binary. The
`acme-authz-webhook-linux-amd64` and `acme-authz-webhook-linux-arm64` assets are
byte-identical copies of their `cloud-8021x` counterpart. Installing or copying
one under `acme-authz-webhook` selects the existing environment-based webhook
commands; the canonical name selects the unified YAML-based daemon. No separate
webhook module, version or executable build exists. The compatibility name is
for a controlled transition, never a second concurrently enabled server.

`SHA256SUMS` covers every binary and alias. Verify its values against trusted,
pinned release configuration before executing any incoming artifact. Downloading
an untrusted checksum beside a binary does not establish authenticity. The
protected bootstrap also verifies its fixed manifest and package checksums.

The release workflow builds on pull requests and manual invocation without
publishing. Publishing requires an explicit `v<VERSION>` tag, verifies that it
matches root `VERSION`, runs actual binary vulnerability scans for both Linux
architectures and verifies checksums after artifact transfer. GitHub generates
release notes from merged PRs with contributor attribution. A merge to main does
not automatically tag or publish. Creating a tag/release or deploying it requires
separate authorization. No release was published during this implementation.
