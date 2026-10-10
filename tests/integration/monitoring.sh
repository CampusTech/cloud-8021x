#!/bin/sh
# Current authenticated packages, owned native packets and supported Agent checks.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
arch=${1:?native architecture required}
bundle=${2:?verified bundle directory required}
image=${3:?cached exact fixture base image required}
output=${4:?local evidence output directory required}
case "$arch" in amd64|arm64) ;; *) exit 2 ;; esac
python3 tests/native_package_inputs.py "$bundle" "$arch" >/dev/null
docker image inspect "$image" >/dev/null
mkdir -p "$output"
fixture=$(mktemp -d "${TMPDIR:-/tmp}/cloud8021x-monitoring.XXXXXX")
name="cloud8021x-task10-monitoring-$(openssl rand -hex 5)"
cleanup(){ docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT HUP INT TERM
C8021X_MONITORING_FIXTURE_OUTPUT="$fixture" GOMAXPROCS=2 go test ./internal/privileged/host ./internal/telemetry -run 'TestExportFreshMonitoringContract|TestCertificateSafetyMetricsUnitsTagsAndExpiredValues' -count=1
GOMAXPROCS=2 GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/native.test" ./internal/adapters/freeradius/native
GOMAXPROCS=2 GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/adoption.test" ./internal/adoption
cp "$fixture/native-monitoring.json" "$fixture/neutral-metrics.json" "$output/"
cat > "$fixture/run.sh" <<'RUN'
#!/bin/sh
set -eu
printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
dpkg -i /bundle/*.deb >/output/install.log 2>&1
/opt/datadog-agent/embedded/bin/python3 -c 'from datadog_checks.openmetrics import OpenMetricsCheck; from datadog_checks.http_check import HTTPCheck; from datadog_checks.process import ProcessCheck; print("supported native integrations loaded")'
/opt/datadog-agent/embedded/bin/python3 /probe.py
C8021X_NATIVE_STATS_FIXTURE=task10 C8021X_NATIVE_STATS_OUTPUT=/output/native-statistics.json /fixture/native.test -test.run TestInstalledNativeStatistics -test.v -test.timeout=90s
TZ=UTC /fixture/adoption.test -test.run 'TestSignedAuthorizationHandoffRejectsWrongAuthorityAndReplay|TestExpectedBinding' -test.v
RUN
docker run --rm --pull=never --platform "linux/$arch" --network none --cpus 1 --memory 1024m --name "$name" \
 --label cloud8021x.test=task10-parallel-runtime --label cloud8021x.disposable=true \
 -v "$bundle:/bundle:ro" -v "$fixture:/fixture:ro" -v "$output:/output" -v "$PWD/tests/integration/monitoring_probe.py:/probe.py:ro" \
 "$image" sh /fixture/run.sh
