#!/usr/bin/env bash
# Networkless actual archive install/packet/interruption/rollback gate.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
arch=${1:?usage: native_package_acceptance.sh amd64_or_arm64 VERIFIED_BUNDLE_DIRECTORY}
bundle=${2:?bundle directory required}
[[ "$arch" == amd64 || "$arch" == arm64 ]] || exit 2
bundle=$(cd -- "$bundle" && pwd)
python3 "$root/tests/native_package_inputs.py" "$bundle" "$arch" >/dev/null
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
cd "$root"
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -o "$fixture/cloud-8021x" ./cmd/cloud-8021x
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/host.test" ./internal/privileged/host
docker build --platform "linux/$arch" --iidfile "$fixture/image" \
  -f "$root/tests/native_package_fixture.Dockerfile" "$fixture"
docker run --rm --network none --platform "linux/$arch" --memory 1536m \
  --label cloud8021x.task=10 --label cloud8021x.disposable=true \
  -v "$fixture/host.test:/fixture.test:ro" -v "$bundle:/bundle:ro" \
  -v "$fixture/cloud-8021x:/usr/local/bin/cloud-8021x:ro" \
  -v "$root/tests/native_package_probe.py:/native-probe.py:ro" \
  -e C8021X_ACTUAL_CLOSURE=task10 -e C8021X_PACKAGE_FIXTURE=task10 \
  "$(cat "$fixture/image")" \
  /fixture.test -test.run '^TestActualShippingClosureInstallAndInterruptedRollback$' -test.v
