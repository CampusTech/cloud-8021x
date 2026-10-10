#!/usr/bin/env bash
# Development/CI only. No installation, cloud access, or release publication.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:?usage: build-release.sh EMPTY_OUTPUT_DIRECTORY}
[[ -d "$output" && -z "$(ls -A -- "$output")" ]] || { echo 'output directory must exist and be empty' >&2; exit 2; }
output=$(cd -- "$output" && pwd)
cd -- "$root"
version=$(tr -d '\n' < VERSION)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'invalid release version' >&2; exit 2; }
toolchain=$(awk '$1 == "go" {print "go" $2}' go.mod)
[[ "$toolchain" =~ ^go[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
export GOTOOLCHAIN="$toolchain"
[[ "$(go env GOVERSION)" == "$toolchain" ]] || { echo 'release toolchain does not match root go.mod' >&2; exit 2; }
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=true \
    -ldflags="-s -w -X main.version=$version" \
    -o "$output/cloud-8021x-linux-$arch" ./cmd/cloud-8021x
done
cd -- "$output"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum cloud-8021x-linux-* > SHA256SUMS
else
  shasum -a 256 cloud-8021x-linux-* > SHA256SUMS
fi
