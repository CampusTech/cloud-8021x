#!/usr/bin/env bash
# Owned Task9 fixture: real protected files, fixed systemctl sequencing probe.
set -euo pipefail
fixture=$(mktemp -d /private/tmp/cloud8021x-task9-writers.XXXXXX)
container="cloud8021x-task9-writers-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
arch=$(docker version --format '{{.Server.Arch}}')
case "$arch" in arm64|amd64) ;; *) exit 1;; esac
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/host.test" ./internal/privileged/host
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/auth.test" ./internal/events/auth
docker run --rm --label cloud8021x.test=task9 --label cloud8021x.disposable=true -e C8021X_FRESH_FIXTURE=task9 -v "$fixture:/fixture:ro" debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 /fixture/host.test -test.run '^TestInstalledFreshAbsenceRefusesPartialFootprint$' -test.v
docker run --name "$container" --label cloud8021x.test=task9 --label cloud8021x.disposable=true -e C8021X_WRITER_FIXTURE=task9 -v "$fixture:/fixture:ro" debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 /bin/sh -c "/fixture/host.test -test.run '^TestInstalledLegacyWriter' -test.v && /fixture/auth.test -test.run 'TestClosedGenerationRetention' -test.v && /fixture/host.test -test.run '^TestInstalledWorkerFenceInterruptedProcessAndUnitProof$|^TestInstalledStatePublicationInterruptedOriginalArchive$|^TestInstalledSourceOriginalHelperQuiescence$|^TestInstalledFreshInitialOriginalHelper$' -test.v"
