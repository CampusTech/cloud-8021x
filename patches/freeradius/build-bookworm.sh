#!/bin/sh
# Development/build-container only. No installed daemon runtime scripting.
set -eu
test -f /.dockerenv
test "$(id -u)" = 0
. /etc/os-release
test "$ID:$VERSION_CODENAME" = debian:bookworm
patch_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir=${C8021X_NATIVE_BUILD_DIR:-/build/cloud8021x-freeradius}
test ! -e "$build_dir"
mkdir -p "$build_dir"
cd "$build_dir"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y build-essential devscripts quilt debian-keyring ca-certificates
# Source metadata only: never enable sid binary packages on Bookworm.
printf '%s\n' 'deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian sid main' > /etc/apt/sources.list.d/cloud8021x-native-source.list
apt-get update
apt-get source --download-only freeradius=3.2.10+dfsg-2
dscverify --no-conf freeradius_3.2.10+dfsg-2.dsc
gpgv --status-fd 1 --keyring /usr/share/keyrings/debian-keyring.gpg freeradius_3.2.10+dfsg-2.dsc > source-signature.txt
grep -q '^\[GNUPG:\] VALIDSIG D6E01EC516A5DFCEF71956D3775079E5B850BC93 ' source-signature.txt
sha256sum -c "$patch_dir/source.sha256"
dpkg-source -x freeradius_3.2.10+dfsg-2.dsc
cd freeradius-3.2.10+dfsg
patch -p1 < "$patch_dir/bookworm-packaging.patch"
cp "$patch_dir/detail-close-error.patch" debian/patches/campus-detail-close-error.patch
cp "$patch_dir/source-fresh.patch" debian/patches/campus-source-fresh.patch
printf '%s\n' campus-detail-close-error.patch campus-source-fresh.patch >> debian/patches/series
quilt push -a
apt-get build-dep -y .
dpkg-buildpackage -us -uc -j"${C8021X_BUILD_JOBS:-4}"
cd ..
sha256sum ./*campus3*.deb ./*campus3*.dsc ./*campus3*.debian.tar.xz > artifacts.sha256
dpkg-query -W > build-dependencies.tsv
printf '%s\n' 'Build complete. Install the entire matching server/common/config/lib/rest/postgresql/utils family; do not copy individual modules.'
