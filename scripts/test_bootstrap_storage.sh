#!/usr/bin/env bash
# Own disposable mount namespace and own image only; no host paths/ports/services.
set -euo pipefail
fixture=$(mktemp -d /private/tmp/cloud8021x-task8-storage.XXXXXX)
container="cloud8021x-task8-storage-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
arch=$(docker version --format '{{.Server.Arch}}')
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/host.test" ./internal/privileged/host
docker run -d --name "$container" --label cloud8021x.test=task8 --label cloud8021x.disposable=true --cap-add SYS_ADMIN --security-opt apparmor=unconfined --device-cgroup-rule 'c 10:237 rwm' --device-cgroup-rule 'b 7:* rwm' -v "$fixture:/fixture:ro" debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 sleep infinity >/dev/null
[[ $(docker inspect --format '{{ index .Config.Labels "cloud8021x.test" }} {{ index .Config.Labels "cloud8021x.disposable" }} {{ len .HostConfig.PortBindings }}' "$container") == 'task8 true 0' ]]
# Device nodes provide only loop control; mount allocates a free device for the
# image created inside this container, with autoclear on unmount. No pre-existing
# loop backing image or device is read, mounted, detached or otherwise changed.
docker exec "$container" sh -c 'apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends e2fsprogs util-linux python3-minimal' >/dev/null
docker exec "$container" sh -c 'mknod /dev/loop-control c 10 237; python3 -c '\''import os,fcntl; f=os.open("/dev/loop-control",os.O_RDWR); n=fcntl.ioctl(f,0x4c82); os.close(f); os.mknod("/dev/loop%d"%n,0o60600,os.makedev(7,n))'\'''
docker exec -e C8021X_STORAGE_FIXTURE=task8 "$container" /fixture/host.test -test.run '^TestInstalledPersistentCollectorQuota$' -test.v
