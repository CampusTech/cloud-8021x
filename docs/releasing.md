# Release builds

The root `VERSION` is the only application release version. Build the root
module with its exact `go.mod` toolchain (currently Go1.27.2):

```sh
mkdir /tmp/cloud8021x-release
scripts/build-release.sh /tmp/cloud8021x-release
```

Each supported architecture has one static `cloud-8021x-linux-amd64` or
`cloud-8021x-linux-arm64` application binary. Executable naming does not change
its commands: all names use the unified YAML-based daemon. The old standalone
webhook runtime and its release aliases have been removed.

`SHA256SUMS` covers both application binaries. Verify its values against trusted,
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
