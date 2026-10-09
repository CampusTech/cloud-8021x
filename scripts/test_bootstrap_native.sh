#!/usr/bin/env bash
# Actual current Trixie native health/activation/rollback in an owned fixture.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
arch=${1:?usage: test_bootstrap_native.sh amd64_or_arm64 VERIFIED_BUNDLE_DIRECTORY}
bundle=${2:?mandatory verified bundle directory required}
[[ "$arch" == amd64 || "$arch" == arm64 ]] || exit 2
bundle=$(cd -- "$bundle" && pwd)
fixture=$(mktemp -d)
container="cloud8021x-task10-bootstrap-$(openssl rand -hex 5)"
started=false
cleanup() {
  if [[ "$started" == true ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$fixture"
}
trap cleanup EXIT
# Mandatory complete manifest and archive hashes before any Docker operation.
python3 "$root/tests/native_package_inputs.py" "$bundle" "$arch" > "$fixture/archives.txt"
manifest_hash=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$bundle/package-manifest.json")
cd "$root"
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/host.test" ./internal/privileged/host
cp examples/cloud-8021x.yaml "$fixture/config.yaml"
mkdir "$fixture/artifacts"
docker build --platform "linux/$arch" --iidfile "$fixture/image" -f tests/native_package_fixture.Dockerfile "$fixture"
docker create --name "$container" --platform "linux/$arch" --network none \
  --label cloud8021x.test=task10 --label cloud8021x.task=10 --label cloud8021x.disposable=true \
  --label "cloud8021x.bundle.sha256=$manifest_hash" --cap-add NET_ADMIN \
  -v "$fixture:/fixture:ro" -v "$bundle:/bundle:ro" -v "$bundle:/fixture/artifacts:ro" \
  "$(cat "$fixture/image")" sleep infinity >/dev/null
started=true
docker start "$container" >/dev/null
# Exact preverified local archives only; no apt/network resolver in this fixture.
docker exec "$container" sh -c 'set -eu; set --; while IFS= read -r archive; do set -- "$@" "$archive"; done < /fixture/archives.txt; dpkg --install "$@"' > "$fixture/install.log" 2>&1 || { cat "$fixture/install.log" >&2; exit 1; }
docker exec -e C8021X_NATIVE_FIXTURE=task8 "$container" /fixture/host.test \
  -test.run '^TestInstalled(NativeStatusAndPolicyActivation|PackageRollbackAndMaintainerSuppression)$' -test.v
