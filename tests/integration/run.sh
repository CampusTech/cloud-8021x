#!/usr/bin/env bash
# Development/CI entrypoint. Own disposable fixtures only; never deployment.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$root"
usage() {
  cat >&2 <<'USAGE'
usage: tests/integration/run.sh postgres
       tests/integration/run.sh native ARCH VERIFIED_BUNDLE
       tests/integration/run.sh packets ARCH VERIFIED_BUNDLE
       tests/integration/run.sh collector ARCH MONITORING_PACKAGES OUTPUT
       tests/integration/run.sh monitoring ARCH VERIFIED_BUNDLE CACHED_IMAGE OUTPUT
       tests/integration/run.sh scep STEP_CA_BINARY SHA256
The PostgreSQL image must already be cached (docker pull postgres:16).
Native fixture image construction uses pinned Debian snapshot repositories.
All test credentials are synthetic. No production resources are read or changed.
USAGE
  exit 2
}
case "${1:-}" in
  postgres)
    [[ $# == 1 ]] || usage
    docker image inspect postgres:16 >/dev/null
    C8021X_PG_FIXTURE_PACKAGE=./internal/storage/postgres scripts/test_postgres.sh
    C8021X_PG_FIXTURE_PACKAGE=./internal/provisioning scripts/test_postgres.sh
    sh tests/integration/parallel.sh
    scripts/test_daemon.sh
    ;;
  native)
    [[ $# == 3 ]] || usage
    tests/native_package_acceptance.sh "$2" "$3"
    scripts/test_bootstrap_native.sh "$2" "$3"
    scripts/test_auth_retention.sh "$2" "$3"
    python3 tests/integration/packets.py "$2" "$3"
    ;;
  packets)
    [[ $# == 3 ]] || usage
    python3 tests/integration/packets.py "$2" "$3"
    ;;
  collector)
    [[ $# == 4 ]] || usage
    python3 tests/ddot_queue.py --architecture "$2" --packages "$3" --evidence "$4/normal" --full-config
    python3 tests/ddot_queue.py --architecture "$2" --packages "$3" --evidence "$4/storage-full" --full-config --storage-full
    ;;
  monitoring)
    [[ $# == 5 ]] || usage
    sh tests/integration/monitoring.sh "$2" "$3" "$4" "$5"
    ;;
  scep)
    [[ $# == 3 ]] || usage
    scripts/test_step_ca_postgres.sh "$2" "$3"
    ;;
  *) usage ;;
esac
