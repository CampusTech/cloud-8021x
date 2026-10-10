#!/usr/bin/env bash
# Reproducible development/CI containers only; never a production loader.
set -euo pipefail
# Package modes must not depend on the invoking shell or builder account.
umask 022
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=golang@sha256:e58d6f83b3416618d8bcac2b3dde1b7f7e3c4a77d25e88637f8bbae81536c48d
if [[ "${1:-}" != --inside ]]; then
  target=${1:?usage: build-debian.sh native_or_monitoring_or_step-ca_or_dependencies amd64_or_arm64 EMPTY_OUTPUT_DIRECTORY}
  arch=${2:?architecture required}
  output=${3:?empty output required}
  [[ "$target" == native || "$target" == monitoring || "$target" == step-ca || "$target" == dependencies ]] || exit 2
  [[ "$arch" == amd64 || "$arch" == arm64 ]] || exit 2
  [[ -d "$output" && -z "$(ls -A -- "$output")" ]] || exit 2
  output=$(cd -- "$output" && pwd)
  exec docker run --rm --platform "linux/$arch" --cpus 2 \
    --label cloud8021x.disposable=true --label cloud8021x.task=10 \
    -v "$root:/source:ro" -v "$output:/output" \
    -e C8021X_DISPOSABLE_BUILD=1 -e GOMAXPROCS=2 \
    -e "C8021X_BUILD_COMMIT=$(git -C "$root" rev-parse HEAD)" "$image" \
    bash /source/scripts/build-debian.sh --inside "$target" "$arch"
fi
[[ -f /.dockerenv && "${C8021X_DISPOSABLE_BUILD:-}" == 1 && "$(id -u)" == 0 ]] || exit 2
target=${2:?}; arch=${3:?}
[[ "$(dpkg --print-architecture)" == "$arch" ]] || exit 2
. /etc/os-release
[[ "$ID:$VERSION_ID" == debian:13 ]] || exit 2
mkdir /build-evidence
cd /build-evidence
for archive in debian debian-security; do
  suite=trixie
  expected=0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675
  if [[ "$archive" == debian-security ]]; then
    suite=trixie-security
    expected=196497ce238846de78a067dac3f347a0a211b11e6979c1558e12f7db799ab82c
  fi
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    "https://snapshot.debian.org/archive/$archive/20261008T000000Z/dists/$suite/InRelease" -o "$suite.InRelease"
  printf '%s  %s.InRelease\n' "$expected" "$suite" | sha256sum --check
  sqv --keyring /usr/share/keyrings/debian-archive-keyring.pgp --cleartext --output "$suite.Release" "$suite.InRelease" > "$suite.signature"
done
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list
cat > /etc/apt/sources.list.d/campus-build.sources <<'SOURCES'
Types: deb deb-src
URIs: https://snapshot.debian.org/archive/debian/20261008T000000Z/
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
Check-Valid-Until: no

Types: deb deb-src
URIs: https://snapshot.debian.org/archive/debian-security/20261008T000000Z/
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
Check-Valid-Until: no
SOURCES
# Only this immutable, independently checksum-and-signature-verified archive
# disables wall-clock expiry. apt still verifies every index/archive signature.
export DEBIAN_FRONTEND=noninteractive GOTOOLCHAIN=go1.27.2 GOCACHE=/build-go-cache
apt-get update
for suite in trixie trixie-security; do
  mapfile -t files < <(find /var/lib/apt/lists -maxdepth 1 -name "*_dists_${suite}_InRelease")
  [[ ${#files[@]} == 1 ]]
  cmp "$suite.InRelease" "${files[0]}"
done
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
case "$target" in
  native)
    apt-get install -y --no-install-recommends devscripts quilt debian-keyring gpgv
    mkdir /native-source
    cd /native-source
    for name in freeradius_3.2.10+dfsg-2.dsc freeradius_3.2.10+dfsg.orig.tar.gz freeradius_3.2.10+dfsg-2.debian.tar.xz; do
      curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "https://deb.debian.org/debian/pool/main/f/freeradius/$name" -o "$name"
    done
    sha256sum --check "$root/patches/freeradius/source.sha256"
    gpgv --keyring /usr/share/keyrings/debian-keyring.gpg freeradius_3.2.10+dfsg-2.dsc
    dpkg-source -x freeradius_3.2.10+dfsg-2.dsc
    apt-get build-dep -y ./freeradius-3.2.10+dfsg
    "$root/scripts/build-native.sh" "$arch" /output
    ;;
  dependencies)
    apt-get install -y --no-install-recommends python3
    "$root/scripts/build-dependencies.sh" "$arch" /output
    ;;
  monitoring)
    apt-get install -y --no-install-recommends patch python3-yaml zstd libsystemd-dev gpg
    go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
    "$root/scripts/build-monitoring.sh" "$arch" /output
    ;;
  step-ca)
    apt-get install -y --no-install-recommends patch python3 sudo
    go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
    go install github.com/sigstore/cosign/v2/cmd/cosign@v2.6.5
    useradd --create-home --shell /bin/bash builder
    chown builder:builder /output
    chown -R builder:builder /go/pkg/mod /build-go-cache
    runuser -u builder -- env PATH="$PATH" GOPATH=/home/builder/go GOMODCACHE=/go/pkg/mod GOCACHE=/build-go-cache GOTOOLCHAIN=go1.27.2 GOMAXPROCS=2 "$root/scripts/build-step-ca.sh" /output
    ;;
  *) exit 2 ;;
esac
cd /build-evidence
printf '%s\n' "$image" > build-image.txt
printf '%s\n' "${C8021X_BUILD_COMMIT:?}" > checkout-commit.txt
sha256sum "$root"/scripts/build-* > build-definitions.sha256
find "$root/patches" -type f ! -path '*/__pycache__/*' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > source-patches.sha256
cp /etc/apt/sources.list.d/campus-build.sources .
dpkg-query -W > build-environment.tsv
cp -r /build-evidence /output/build-environment
cd /output
find . -type f ! -name SHA256SUMS -printf '%P\0' | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
