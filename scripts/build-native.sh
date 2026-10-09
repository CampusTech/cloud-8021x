#!/usr/bin/env bash
# Build-only: authenticated Debian source, two bounded runtime patches, Debian13.
set -euo pipefail
# Package modes must not depend on the invoking shell or builder account.
umask 022
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
arch=${1:?usage: build-native.sh amd64_or_arm64 EMPTY_OUTPUT_DIRECTORY}
output=${2:?empty output directory required}
[[ "$arch" == amd64 || "$arch" == arm64 ]] || exit 2
[[ "$(dpkg --print-architecture)" == "$arch" ]] || exit 2
. /etc/os-release
[[ "$ID:$VERSION_ID" == debian:13 ]] || exit 2
[[ -d "$output" && -z "$(ls -A -- "$output")" ]] || exit 2
output=$(cd -- "$output" && pwd)
[[ -f /.dockerenv && "${C8021X_DISPOSABLE_BUILD:-}" == 1 ]] || exit 2
# Upstream prints compiler flags including -ffile-prefix-map; use an invariant
# isolated build path so that diagnostic text does not encode a random mktemp.
work=/build-native-source
mkdir "$work"
trap 'rm -rf "$work"' EXIT
export SOURCE_DATE_EPOCH=1791417600
cd "$work"
for name in freeradius_3.2.10+dfsg-2.dsc freeradius_3.2.10+dfsg.orig.tar.gz freeradius_3.2.10+dfsg-2.debian.tar.xz; do
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "https://deb.debian.org/debian/pool/main/f/freeradius/$name" -o "$name"
done
sha256sum --check "$root/patches/freeradius/source.sha256"
gpgv --status-fd 1 --keyring /usr/share/keyrings/debian-keyring.gpg freeradius_3.2.10+dfsg-2.dsc > "$output/source-signature.txt" 2>&1
grep -q '^\[GNUPG:\] VALIDSIG D6E01EC516A5DFCEF71956D3775079E5B850BC93 ' "$output/source-signature.txt"
dpkg-source -x freeradius_3.2.10+dfsg-2.dsc
cd freeradius-3.2.10+dfsg
for name in detail-close-error source-fresh; do
  cp "$root/patches/freeradius/$name.patch" "debian/patches/campus-$name.patch"
  printf 'campus-%s.patch\n' "$name" >> debian/patches/series
done
quilt push -a
# An immutable changelog timestamp, not the wall clock of a package build.
cat > "$work/changelog" <<'CHANGELOG'
freeradius (3.2.10+dfsg-2+trixie.campus4) trixie; urgency=medium

  * Preserve failed-close no-ACK and original packet source deadline checks.

 -- CampusGroup Infrastructure <infrastructure@campus.edu>  Thu, 08 Oct 2026 00:00:00 +0000

CHANGELOG
cat debian/changelog >> "$work/changelog"
cp "$work/changelog" debian/changelog
# Build dependencies are installed only by the pinned disposable build wrapper.
dpkg-checkbuilddeps
dpkg-buildpackage -us -uc -j2
cd "$work"
for package in freeradius freeradius-common freeradius-config freeradius-utils freeradius-rest freeradius-postgresql libfreeradius3; do
  package_arch=$arch
  [[ "$package" != freeradius-common ]] || package_arch=all
  archive="${package}_3.2.10+dfsg-2+trixie.campus4_${package_arch}.deb"
  [[ "$(dpkg-deb -f "$archive" Package)" == "$package" ]]
  [[ "$(dpkg-deb -f "$archive" Version)" == 3.2.10+dfsg-2+trixie.campus4 ]]
  cp "$archive" "$output/"
done
cp "$root/patches/freeradius/source.sha256" "$root/patches/freeradius/detail-close-error.patch" "$root/patches/freeradius/source-fresh.patch" "$output/"
cp ./*.buildinfo ./*.changes "$output/"
dpkg-query -W > "$output/build-dependencies.tsv"
cd "$output"
sha256sum -- * > SHA256SUMS
