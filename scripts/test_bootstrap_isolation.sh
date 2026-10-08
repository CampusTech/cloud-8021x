#!/usr/bin/env bash
# Development-only root network namespace; no host ports or host network mode.
set -euo pipefail
fixture=$(mktemp -d /private/tmp/cloud8021x-task8-isolation.XXXXXX)
container="cloud8021x-task8-isolation-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
arch=$(docker version --format '{{.Server.Arch}}')
case "$arch" in arm64|amd64) ;; *) echo "Unsupported fixture architecture" >&2; exit 1;; esac
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/host.test" ./internal/privileged/host
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -o "$fixture/cloud-8021x" ./cmd/cloud-8021x
cp examples/cloud-8021x.yaml "$fixture/config.yaml"
docker run -d --name "$container" --label cloud8021x.test=task8 --label cloud8021x.disposable=true --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 -v "$fixture:/fixture:ro" debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 sleep infinity >/dev/null
docker exec "$container" sh -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends nftables iproute2 util-linux ca-certificates sudo passwd openssl' >/dev/null
docker exec -e C8021X_ISOLATION_FIXTURE=task8 "$container" /fixture/host.test -test.run '^TestInstalled(MetadataIsolation|ProtectedTransactionAndSudo|CredentialRebootConsistency|ArtifactInputs)$' -test.v
