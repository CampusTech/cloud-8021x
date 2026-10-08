#!/usr/bin/env bash
# Actual campus3 health/activation proof in an owned disposable namespace.
set -euo pipefail
fixture=$(mktemp -d /private/tmp/cloud8021x-task8-native.XXXXXX)
container="cloud8021x-task8-native-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
arch=$(docker version --format '{{.Server.Arch}}')
if [[ "$arch" != arm64 ]]; then echo 'Reviewed local campus3 fixture artifacts currently require arm64' >&2; exit 1; fi
mkdir "$fixture/artifacts"
for package in freeradius freeradius-common freeradius-config freeradius-utils freeradius-rest freeradius-postgresql libfreeradius3; do
  deb_arch=arm64
  if [[ "$package" == freeradius-common ]]; then deb_arch=all; fi
  name="${package}_3.2.10+dfsg-2~bookworm+campus3_${deb_arch}.deb"
  docker cp "cloud8021x-daemon-fr-c7d492:/task6-secure-build/$name" "$fixture/artifacts/$name" >/dev/null
  expected=$(awk -v n="$name" '$2==n{print $1}' patches/freeradius/campus3-arm64-artifacts.sha256)
  actual=$(shasum -a 256 "$fixture/artifacts/$name" | awk '{print $1}')
  [[ -n "$expected" && "$actual" == "$expected" ]]
done
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o "$fixture/host.test" ./internal/privileged/host
cp examples/cloud-8021x.yaml "$fixture/config.yaml"
docker run -d --name "$container" --label cloud8021x.test=task8 --label cloud8021x.disposable=true --cap-add NET_ADMIN -v "$fixture:/fixture:ro" debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 sleep infinity >/dev/null
# Acquisition/dependency resolution is a development fixture only. Product
# installation accepts only its preverified fixed local manifest, without apt.
docker exec "$container" sh -c 'printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d; apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends /fixture/artifacts/*.deb sudo passwd iproute2 ca-certificates' >/dev/null
docker exec -e C8021X_NATIVE_FIXTURE=task8 "$container" /fixture/host.test -test.run '^TestInstalled(NativeStatusAndPolicyActivation|PackageRollbackAndMaintainerSuppression)$' -test.v
