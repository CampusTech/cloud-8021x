#!/usr/bin/env bash
# Task7 only: disposable TLS PostgreSQL; no host ports and no inherited DSN.
set -euo pipefail
fixture=$(mktemp -d /private/tmp/cloud8021x-task7-pg.XXXXXX)
container="cloud8021x-task7-pg-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$fixture/ca.key" -out "$fixture/ca.pem" -days 2 -subj /CN=Task7-Disposable-CA >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$fixture/server.key" -out "$fixture/server.csr" -subj /CN=localhost >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$fixture/ext"
openssl x509 -req -in "$fixture/server.csr" -CA "$fixture/ca.pem" -CAkey "$fixture/ca.key" -CAcreateserial -out "$fixture/server.crt" -days 2 -extfile "$fixture/ext" >/dev/null 2>&1
arch=$(docker image inspect postgres:16 --format '{{.Architecture}}')
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go test -c -o "$fixture/postgres.test" ./internal/storage/postgres
docker run -d --name "$container" --network none --label cloud8021x.task=7 --label cloud8021x.disposable=true -e POSTGRES_PASSWORD=task7-synthetic-admin -e POSTGRES_DB=cloud8021x -v "$fixture:/task7:ro" postgres:16 bash -c 'mkdir -p /tls; cp /task7/server.key /task7/server.crt /tls/; chown postgres:postgres /tls/*; chmod 600 /tls/server.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls/server.key' >/dev/null
[[ "$(docker inspect "$container" --format '{{.HostConfig.NetworkMode}}')" == none ]]
[[ "$(docker inspect "$container" --format '{{len .HostConfig.PortBindings}}')" == 0 ]]
for _ in $(seq 1 100); do
 if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -d cloud8021x >/dev/null 2>&1; then break; fi
 sleep 0.2
done
docker exec -i "$container" psql -U postgres -d cloud8021x -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE ROLE app_runtime LOGIN PASSWORD 'disposable-runtime';
CREATE ROLE app_native LOGIN PASSWORD 'disposable-native';
SQL
docker exec -e C8021X_PG_TEST_DSN=postgres://postgres:task7-synthetic-admin@localhost:5432/cloud8021x -e C8021X_PG_TEST_CA=/task7/ca.pem "$container" /task7/postgres.test -test.v -test.run 'TestPostgres(Telemetry|WorkClaims|LeaseGenerationsAndOutcomes|CollectionMigration)'
