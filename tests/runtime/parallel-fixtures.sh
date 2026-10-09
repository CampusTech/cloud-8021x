#!/bin/sh
# Owned synthetic source/reverse and TLS database tests. No published host ports.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
docker image inspect postgres:16 >/dev/null
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) fixture_arch=arm64 ;;
  x86_64|amd64) fixture_arch=amd64 ;;
  *) echo 'Unsupported disposable fixture architecture' >&2; exit 1 ;;
esac
runtime_fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/cloud8021x-runtime.XXXXXX")
runtime_fixture_name="cloud8021x-task10-runtime-$(openssl rand -hex 5)"
cleanup() {
  docker rm -f "$runtime_fixture_name" "$runtime_fixture_name-source" >/dev/null 2>&1 || true
  rm -rf "$runtime_fixture_dir"
}
trap cleanup EXIT HUP INT TERM
GOMAXPROCS=2 GOOS=linux GOARCH="$fixture_arch" CGO_ENABLED=0 go test -c ./internal/privileged/host -o "$runtime_fixture_dir/host.test"
docker run --rm --pull=never --name "$runtime_fixture_name-source" --hostname radius-primary \
  --label cloud8021x.test=task10-parallel-runtime --label cloud8021x.disposable=true \
  -e C8021X_PARALLEL_RUNTIME_FIXTURE=task10 -v "$runtime_fixture_dir:/fixture:ro" \
  postgres:16 /fixture/host.test -test.run TestInstalledParallelSourceCapture -test.v -test.timeout=90s
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$runtime_fixture_dir/ca.key" -out "$runtime_fixture_dir/ca.pem" -days 2 -subj /CN=Task10-Runtime-Test-CA >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$runtime_fixture_dir/server.key" -out "$runtime_fixture_dir/server.csr" -subj /CN=localhost >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$runtime_fixture_dir/ext"
openssl x509 -req -in "$runtime_fixture_dir/server.csr" -CA "$runtime_fixture_dir/ca.pem" -CAkey "$runtime_fixture_dir/ca.key" -CAcreateserial -out "$runtime_fixture_dir/server.crt" -days 2 -extfile "$runtime_fixture_dir/ext" >/dev/null 2>&1
GOMAXPROCS=2 GOOS=linux GOARCH="$fixture_arch" CGO_ENABLED=0 go test -c ./internal/storage/postgres -o "$runtime_fixture_dir/postgres.test"
cat > "$runtime_fixture_dir/ssl.sql" <<'SQL'
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '/tls/server.crt';
ALTER SYSTEM SET ssl_key_file = '/tls/server.key';
CREATE ROLE app_runtime LOGIN PASSWORD 'disposable-runtime';
CREATE ROLE app_native LOGIN PASSWORD 'disposable-native';
SQL
docker run -d --pull=never --name "$runtime_fixture_name" \
  --label cloud8021x.test=task10-parallel-runtime --label cloud8021x.disposable=true \
  -e POSTGRES_PASSWORD=disposable-migration -e POSTGRES_DB=cloud8021x \
  -v "$runtime_fixture_dir:/fixture:ro" -v "$runtime_fixture_dir/ssl.sql:/docker-entrypoint-initdb.d/ssl.sql:ro" \
  postgres:16 bash -c 'mkdir -p /tls; cp /fixture/server.key /fixture/server.crt /tls/; chown postgres:postgres /tls/*; chmod 600 /tls/server.key; exec docker-entrypoint.sh postgres' >/dev/null
fixture_ready=false
for _ in $(seq 1 100); do
  if docker exec "$runtime_fixture_name" pg_isready -h 127.0.0.1 -U postgres -d cloud8021x >/dev/null 2>&1; then fixture_ready=true; break; fi
  sleep 0.2
done
if [ "$fixture_ready" != true ]; then echo 'Owned TLS PostgreSQL did not become ready' >&2; exit 1; fi
docker exec -e C8021X_PG_TEST_DSN=postgres://postgres:disposable-migration@localhost/cloud8021x \
  -e C8021X_PG_TEST_CA=/fixture/ca.pem "$runtime_fixture_name" \
  /fixture/postgres.test -test.v -test.run 'TestPostgresParallel|TestPostgresWholeBundleAtomicPublicationAndPendingGuards' -test.count=1 -test.timeout=180s
