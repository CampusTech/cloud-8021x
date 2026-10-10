# Development packet tools only; the base inherits the authenticated pinned snapshot.
ARG BASE
FROM ${BASE}
RUN apt-get update && \
    test "$(sha256sum /var/lib/apt/lists/*_dists_trixie_InRelease | cut -d ' ' -f 1)" = 0584fba32e13e0ab8285fb16c27adea1ec03a73669c18702821094fd6ca86675 && \
    test "$(sha256sum /var/lib/apt/lists/*_dists_trixie-security_InRelease | cut -d ' ' -f 1)" = 196497ce238846de78a067dac3f347a0a211b11e6979c1558e12f7db799ab82c && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      eapoltest=2:2.10-24 libpcsclite1=2.3.3-1 \
      postgresql-client-17=17.11-0+deb13u1 postgresql-client-common=278 && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
ENV PATH="/usr/lib/postgresql/17/bin:${PATH}"
