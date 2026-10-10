#!/usr/bin/env bash
# CI/development only. No host installation, account/service changes or publication.
set -euo pipefail
# Package modes must not depend on the invoking shell or builder account.
umask 022
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
arch=${1:?usage: build-monitoring.sh amd64_or_arm64 EMPTY_OUTPUT_DIRECTORY}
output=${2:?empty output directory required}
[[ "$arch" == amd64 || "$arch" == arm64 ]] || exit 2
[[ "$(dpkg --print-architecture)" == "$arch" ]] || { echo 'native Debian build architecture required' >&2; exit 2; }
. /etc/os-release
[[ "$ID:$VERSION_ID" == debian:13 ]] || exit 2
[[ -d "$output" && -z "$(ls -A -- "$output")" ]] || exit 2
output=$(cd -- "$output" && pwd)
export GOTOOLCHAIN=go1.27.2 SOURCE_DATE_EPOCH=1791417600
[[ "$(go env GOVERSION)" == go1.27.2 ]] || exit 2
for tool in curl gpg sha256sum dpkg-deb patch python3 zstd govulncheck; do command -v "$tool" >/dev/null || { echo "required build tool unavailable: $tool" >&2; exit 2; }; done
govulncheck -version > "$output/scanner-version.txt"
grep -Fx 'Scanner: govulncheck@v1.8.0' "$output/scanner-version.txt" >/dev/null
[[ -f /.dockerenv && "${C8021X_DISPOSABLE_BUILD:-}" == 1 ]] || exit 2
# Stable C/Python ABI input paths also keep unstripped cgo debug data reproducible.
work=/build-monitoring-source
mkdir "$work"
trap 'rm -rf "$work"' EXIT
fetch() {
  local name=$1 url=$2 hash=$3
  if [[ -f "$root/patches/datadog/provenance/$name" ]]; then
    cp "$root/patches/datadog/provenance/$name" "$work/$name"
  elif [[ -f "$root/patches/datadog/provenance/$name.gz" ]]; then
    gzip -dc "$root/patches/datadog/provenance/$name.gz" > "$work/$name"
  elif [[ -n "${C8021X_BUILD_DOWNLOAD_CACHE:-}" && -f "$C8021X_BUILD_DOWNLOAD_CACHE/$name" ]]; then
    cp "$C8021X_BUILD_DOWNLOAD_CACHE/$name" "$work/$name"
  else
    curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error "$url" -o "$work/$name"
  fi
  printf '%s  %s\n' "$hash" "$name" >> "$output/acquisition.sha256"
  (cd "$work" && printf '%s  %s\n' "$hash" "$name" | sha256sum --check)
}
fetch datadog-key.asc https://keys.datadoghq.com/DATADOG_APT_KEY_CURRENT.public 954b17e0d81bef0028e0c65ea6e07626b5bdb1dc2f4abf58604eb37d03ac2909
fetch datadog-Release https://apt.datadoghq.com/dists/stable/Release 0138e80bafc3ee76c15ac95db88ce536e93c0c132cce067dd22d86490628fa9f
fetch datadog-Release.gpg https://apt.datadoghq.com/dists/stable/Release.gpg bef5d26289242746d814dc3767cad983d96c5e3335e95ef54827ab7d2b04e945
if [[ "$arch" == amd64 ]]; then
  index_hash=8ac02d483e1a1bfd49424d1ab08ed36521caa53ef6474cd919f98f5618dcdea1
  package_hash=cbfde54c2485e07ad75e5359d3fe5a20f5d587bc1d21e75409613865da8d0ad0
  index_name=datadog-Packages
else
  index_hash=cd81c57e394b61cb43fbe24695a80bad2d6fabea62e4f4f87b30dea3fad50828
  package_hash=a7cedb25fde2c3eac0307d2df6e88333e170589b09d5f5172d4c0b9419baebb2
  index_name=datadog-arm64-Packages
fi
fetch "$index_name" "https://apt.datadoghq.com/dists/stable/7/binary-$arch/Packages" "$index_hash"
archive="datadog-agent_7.84.2-1_$arch.deb"
fetch "$archive" "https://apt.datadoghq.com/pool/d/da/$archive" "$package_hash"
mkdir -m 700 "$work/gnupg"
gpg --homedir "$work/gnupg" --batch --import "$work/datadog-key.asc" >/dev/null 2>&1
gpg --homedir "$work/gnupg" --status-fd 1 --verify "$work/datadog-Release.gpg" "$work/datadog-Release" > "$output/source-signature.txt" 2>&1
grep -q '^\[GNUPG:\] VALIDSIG 5F1E256061D813B125E156E8E6266D4AC0962C7D ' "$output/source-signature.txt"
python3 - "$work" "$arch" "$index_name" "$index_hash" "$package_hash" <<'PY'
import pathlib,sys
root,arch,index,index_hash,package_hash=sys.argv[1:]
p=pathlib.Path(root)
release=(p/'datadog-Release').read_text().split('SHA256:',1)[1].split('\nSHA',1)[0]
assert any(line.split()==[index_hash,str((p/index).stat().st_size),f'7/binary-{arch}/Packages'] for line in release.splitlines())
entries=[dict(line.split(': ',1) for line in block.splitlines() if ': ' in line and not line.startswith(' ')) for block in (p/index).read_text().split('\n\n')]
entry=[e for e in entries if e.get('Package')=='datadog-agent' and e.get('Version')=='1:7.84.2-1' and e.get('Architecture')==arch]
assert len(entry)==1 and entry[0]['SHA256']==package_hash
assert entry[0]['Filename']==f'pool/d/da/datadog-agent_7.84.2-1_{arch}.deb'
assert int(entry[0]['Size'])==(p/f'datadog-agent_7.84.2-1_{arch}.deb').stat().st_size
PY
fetch datadog-agent-7.84.2-source.tar.gz https://codeload.github.com/DataDog/datadog-agent/tar.gz/refs/tags/7.84.2 57df53c8d7a0d332b886c436af2298220686bf2b3d1772e561426c35a677f27b
dpkg-deb -x "$work/$archive" "$work/official"
# The signed official binary binds the release source revision independently of a tag name.
go version -m "$work/official/opt/datadog-agent/bin/agent/agent" > "$output/official-buildinfo.txt"
grep -F 'vcs.revision=73e6b0351caa6028bfc21e2668aef5a1463bff05' "$output/official-buildinfo.txt" >/dev/null
tar -xzf "$work/datadog-agent-7.84.2-source.tar.gz" -C "$work"
cd "$work/datadog-agent-7.84.2"
patch --batch --fuzz=0 -p1 < "$root/patches/datadog/security-dependencies.patch"
python3 "$root/patches/datadog/generate-schema.py"
go mod verify
mkdir "$work/binaries"
export CGO_ENABLED=1 CGO_CFLAGS="-I$work/official/opt/datadog-agent/embedded/include"
export CGO_LDFLAGS="-L$work/official/opt/datadog-agent/embedded/lib -Wl,-rpath,/opt/datadog-agent/embedded/lib"
version_package=github.com/DataDog/datadog-agent/pkg/version
flags="-X $version_package.Commit=73e6b035 -X $version_package.FullCommit=73e6b0351caa6028bfc21e2668aef5a1463bff05 -X $version_package.AgentVersion=7.84.2+campus1 -X $version_package.AgentPackageVersion=7.84.2-1+campus1 -X $version_package.AgentVersionURLSafe=7.84.2-campus1 -X $version_package.AgentPayloadVersion=5.0.209"
go build -p 2 -trimpath -ldflags "$flags" -tags python,systemd,netcgo,zlib,zstd,otlp,datadog.no_waf,grpcnotrace,retrynotrace,trivy_no_javadb -o "$work/binaries/agent" ./cmd/agent
unset CGO_LDFLAGS
go build -p 2 -trimpath -ldflags "$flags -X github.com/DataDog/datadog-agent/cmd/otel-agent/command.BYOC=false" -tags otlp,zlib,zstd,kubelet,grpcnotrace,retrynotrace,trivy_no_javadb -o "$work/binaries/otel-agent" ./cmd/otel-agent
for name in agent otel-agent; do
  govulncheck -mode=binary "$work/binaries/$name" > "$output/$name-security.txt" 2>&1
  go version -m "$work/binaries/$name" > "$output/$name-buildinfo.txt"
done
for package in datadog-agent datadog-agent-ddot; do
  stage="$work/$package"
  mkdir -p "$stage/DEBIAN" "$stage/opt/datadog-agent" "$stage/usr/share/doc/$package"
  cp LICENSE "$stage/usr/share/doc/$package/copyright"
  if [[ "$package" == datadog-agent ]]; then
    base="$stage/opt/datadog-agent"
    mkdir -p "$base/embedded/bin" "$base/bin/agent"
    # Preserve the matching official Python/rtloader/native ABI, not any official Go helper.
    cp -a "$work/official/opt/datadog-agent/embedded/lib" "$base/embedded/"
    cp -a "$work/official/opt/datadog-agent/LICENSES" "$base/"
    cp -a "$work/official/opt/datadog-agent/embedded/bin/"python* "$base/embedded/bin/"
    cp "$work/binaries/agent" "$base/bin/agent/agent"
    for check in cpu disk io load memory network uptime; do
      mkdir -p "$stage/etc/datadog-agent/conf.d/$check.d"
      cp "$work/official/etc/datadog-agent/conf.d/$check.d/conf.yaml.default" "$stage/etc/datadog-agent/conf.d/$check.d/"
    done
    depends='libc6 (>= 2.41), libsystemd0, libgcc-s1, ca-certificates'
  else
    mkdir -p "$stage/opt/datadog-agent/embedded/bin"
    cp "$work/binaries/otel-agent" "$stage/opt/datadog-agent/embedded/bin/otel-agent"
    depends='datadog-agent (= 1:7.84.2-1+campus1), libc6 (>= 2.41)'
  fi
  cat > "$stage/DEBIAN/control" <<CONTROL
Package: $package
Version: 1:7.84.2-1+campus1
Architecture: $arch
Maintainer: CampusGroup Infrastructure
Section: admin
Priority: optional
Depends: $depends
Description: Datadog 7.84.2 minimal host monitoring with pinned security rebuild
 Authenticated matching source 73e6b0351caa6028bfc21e2668aef5a1463bff05.
 Protected cloud-8021x bootstrap owns accounts, units, credentials and activation.
CONTROL
  archive="$output/${package}_1:7.84.2-1+campus1_$arch.deb"
  dpkg-deb --root-owner-group --uniform-compression -Zgzip -z9 --build "$stage" "$archive"
  python3 "$root/tests/monitoring_package_layout.py" "$package" "$arch" "$archive"
done
cp go.mod go.sum "$output/"
cp "$root/patches/datadog/security-dependencies.patch" "$root/patches/datadog/generate-schema.py" "$output/"
cp "$work/datadog-key.asc" "$work/datadog-Release" "$work/datadog-Release.gpg" "$work/$index_name" "$output/"
cd "$output"
sha256sum -- * > SHA256SUMS
