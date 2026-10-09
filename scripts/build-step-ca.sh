#!/usr/bin/env bash
# CI/development only: authenticated source -> fixed binaries -> inert packages.
# No package install, CA initialization, service action, or publication.
set -euo pipefail
# Package modes must not depend on the invoking shell or builder account.
umask 022
[[ "$(id -u)" != 0 ]] || { echo "CA upstream permission tests require an unprivileged build user" >&2; exit 2; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${1:?usage: build-step-ca.sh EMPTY_OUTPUT_DIRECTORY}
[[ -d "$output" && -z "$(ls -A -- "$output")" ]] || { echo 'output directory must exist and be empty' >&2; exit 2; }
output=$(cd -- "$output" && pwd)
export GOTOOLCHAIN=go1.27.2
[[ "$(go env GOVERSION)" == go1.27.2 ]] || exit 2
for tool in curl sha256sum cosign govulncheck dpkg-deb patch python3; do command -v "$tool" >/dev/null || { echo "required build tool unavailable: $tool" >&2; exit 2; }; done
cosign version --json | python3 -c 'import json,sys; assert json.load(sys.stdin)["gitVersion"] == "v2.6.5"'
govulncheck -version | tee "$output/scanner-version.txt"
grep -Fx "Scanner: govulncheck@v1.8.0" "$output/scanner-version.txt" >/dev/null
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
base=https://github.com/smallstep/certificates/releases/download/v0.30.2
for asset in checksums.txt checksums.txt.sigstore.json step-ca_0.30.2.tar.gz; do
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "$base/$asset" -o "$work/$asset"
done
cat > "$work/acquisition.sha256" <<'HASHES'
5076defb1b4759f270fd85a31fc7e4756ddf2551237249aa12739f5be1544f98  checksums.txt
73a47cce07cbba26f1e0d0797d1d1f26dbf5dc5bb42f5e3cf5f65532b967d502  checksums.txt.sigstore.json
944b205d5ba89f393cbdc09d68ab7ce485f5b44f44c28025d30508af956c1cba  step-ca_0.30.2.tar.gz
HASHES
(cd "$work" && sha256sum --check acquisition.sha256)
cosign verify-blob --bundle "$work/checksums.txt.sigstore.json" \
  --certificate-identity 'https://github.com/smallstep/workflows/.github/workflows/goreleaser.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$work/checksums.txt" > "$output/source-signature-verification.txt" 2>&1
grep -Fx '944b205d5ba89f393cbdc09d68ab7ce485f5b44f44c28025d30508af956c1cba  step-ca_0.30.2.tar.gz' "$work/checksums.txt" >/dev/null
mkdir "$work/source"
tar -xzf "$work/step-ca_0.30.2.tar.gz" -C "$work/source"
cd "$work/source"
for patch in security-dependencies go127-vet; do
  patch --batch --fuzz=0 -p1 < "$root/patches/step-ca/$patch.patch"
done
go mod verify
go test -p 2 -timeout 5m ./acme/... ./scep/... ./authority/... ./api/... ./ca/... ./db/... > "$output/upstream-compatibility.txt" 2>&1
# Fixed timestamp and trimpath make the archive independent of its build location.
export SOURCE_DATE_EPOCH=1791417600
for arch in amd64 arm64; do
  package="$work/package-$arch"
  mkdir -p "$package/DEBIAN" "$package/usr/bin" "$package/usr/share/doc/step-ca"
  # Retain symbols: govulncheck cannot resolve inlined symbols in stripped files.
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -mod=readonly -trimpath \
    -ldflags '-X main.Version=0.30.2+campus1 -X main.BuildTime=2026-10-08' \
    -o "$package/usr/bin/step-ca" ./cmd/step-ca
  govulncheck -mode=binary "$package/usr/bin/step-ca" > "$output/step-ca-$arch-security.txt" 2>&1
  go version -m "$package/usr/bin/step-ca" > "$output/step-ca-$arch-buildinfo.txt"
  cp LICENSE "$package/usr/share/doc/step-ca/copyright"
  cat > "$package/DEBIAN/control" <<CONTROL
Package: step-ca
Version: 0.30.2-1+campus1
Architecture: $arch
Maintainer: CampusGroup Infrastructure
Section: admin
Priority: optional
Description: Smallstep CA 0.30.2 with pinned security dependency rebuild
 Authenticated upstream commit 6e8ec61405239cf3f37b2bbf260a587b7d2e4e31.
 Service configuration and CA state are managed by protected cloud-8021x bootstrap.
CONTROL
  dpkg-deb --root-owner-group --uniform-compression -Zgzip -z9 --build "$package" "$output/step-ca_0.30.2-1+campus1_$arch.deb"
done
cp "$work/acquisition.sha256" "$work/checksums.txt" "$work/checksums.txt.sigstore.json" "$output/"
cp "$root/patches/step-ca/"*.patch "$output/"
cp go.mod go.sum "$output/"
cd "$output"
sha256sum -- * > SHA256SUMS
