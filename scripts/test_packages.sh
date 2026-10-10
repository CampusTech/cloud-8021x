#!/usr/bin/env bash
# Actual package mutation proof only in an owned, network-isolated Debian 13 container.
set -euo pipefail
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
arch=$(docker version --format '{{.Server.Arch}}')
case "$arch" in amd64|arm64) ;; *) echo 'Unsupported fixture architecture' >&2; exit 1 ;; esac
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/host.test" ./internal/privileged/host
docker run --rm --network=none --label cloud8021x.disposable=true \
  -v "$fixture/host.test:/fixture.test:ro" -e C8021X_PACKAGE_FIXTURE=task10 \
  debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f \
  /fixture.test -test.run '^TestIsolatedUtilityRetirementAndInterruptedRollback$' -test.v
