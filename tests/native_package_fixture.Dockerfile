# Development only: Debian13's minimal image lacks the sysusers/systemd base
# and sudo prerequisites present on the supported cloud OS. Never shipped as a VM image.
FROM golang@sha256:e58d6f83b3416618d8bcac2b3dde1b7f7e3c4a77d25e88637f8bbae81536c48d AS public-trust
FROM debian@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
LABEL cloud8021x.disposable=true cloud8021x.task=10
COPY --from=public-trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN printf 'Acquire::https::CaInfo "/etc/ssl/certs/ca-certificates.crt";\n' > /etc/apt/apt.conf.d/campus-fixture-trust && \
    rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list && \
    printf '%s\n' \
      'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] https://snapshot.debian.org/archive/debian/20261008T000000Z/ trixie main' \
      'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.pgp] https://snapshot.debian.org/archive/debian-security/20261008T000000Z/ trixie-security main' \
      > /etc/apt/sources.list && \
    apt-get update && \
    test "$(sha256sum /var/lib/apt/lists/*_dists_trixie_InRelease | cut -d ' ' -f 1)" = 0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675 && \
    test "$(sha256sum /var/lib/apt/lists/*_dists_trixie-security_InRelease | cut -d ' ' -f 1)" = 196497ce238846de78a067dac3f347a0a211b11e6979c1558e12f7db799ab82c && \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd=257.13-1~deb13u1 sudo=1.9.16p2-3+deb13u2 iproute2=6.15.0-1 libfaketime=0.9.10+2024-06-05+gba9ed5b2-0.6 && \
    dpkg-query -W > /var/lib/cloud8021x-fixture-base.tsv && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
