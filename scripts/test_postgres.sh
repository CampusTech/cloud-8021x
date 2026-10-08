#!/usr/bin/env bash
# Development-only disposable PostgreSQL16 TLS fixture. Never uses production DSNs.
set -euo pipefail
fixture=$(mktemp -d /private/tmp/cloud8021x-pg.XXXXXX)
fixture_task=${C8021X_PG_FIXTURE_TASK:-task3}
[[ "$fixture_task" =~ ^task[0-9]+$ ]] || exit 2
container="cloud8021x-pg-$fixture_task-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$fixture/ca.key" -out "$fixture/ca.pem" -days 2 -subj /CN=Disposable-Test-CA >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$fixture/server.key" -out "$fixture/server.csr" -subj /CN=localhost >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$fixture/ext"
openssl x509 -req -in "$fixture/server.csr" -CA "$fixture/ca.pem" -CAkey "$fixture/ca.key" -CAcreateserial -out "$fixture/server.crt" -days 2 -extfile "$fixture/ext" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$fixture/wrong.key" -out "$fixture/wrong.pem" -days 2 -subj /CN=Wrong-Test-CA >/dev/null 2>&1
cat > "$fixture/ssl.sql" <<'SQL'
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '/tls/server.crt';
ALTER SYSTEM SET ssl_key_file = '/tls/server.key';
SQL
docker run -d --name "$container" --label "cloud8021x.test=$fixture_task" --label cloud8021x.disposable=true -e POSTGRES_PASSWORD=disposable-migration -e POSTGRES_DB=cloud8021x -p 127.0.0.1::5432 -v "$fixture:/certs:ro" -v "$fixture/ssl.sql:/docker-entrypoint-initdb.d/ssl.sql:ro" postgres:16 bash -c 'mkdir -p /tls; cp /certs/server.key /certs/server.crt /tls/; chown postgres:postgres /tls/*; chmod 600 /tls/server.key; exec docker-entrypoint.sh postgres' >/dev/null
for _ in $(seq 1 60); do
 if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres -d cloud8021x >/dev/null 2>&1; then break; fi
 sleep 0.25
done
docker exec -i "$container" psql -U postgres -d cloud8021x -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE ROLE app_runtime LOGIN PASSWORD 'disposable-runtime';
CREATE ROLE app_native LOGIN PASSWORD 'disposable-native';
CREATE DATABASE ca_sentinel;
REVOKE ALL ON DATABASE ca_sentinel FROM PUBLIC;
SQL
docker exec -i "$container" psql -U postgres -d ca_sentinel -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE ca_keys (secret text);
INSERT INTO ca_keys VALUES ('untouched-test-sentinel');
SQL
port=$(docker port "$container" 5432/tcp | sed 's/.*://')
export C8021X_PG_TEST_DSN="postgres://postgres:disposable-migration@localhost:$port/cloud8021x"
export C8021X_PG_TEST_CA="$fixture/ca.pem"
export C8021X_PG_TEST_WRONG_CA="$fixture/wrong.pem"
export C8021X_PG_TEST_CONTAINER="$container"
export C8021X_PG_TEST_TLS_CERT="$fixture/server.crt"
export C8021X_PG_TEST_TLS_KEY="$fixture/server.key"
go test -race -count=1 -v ./internal/storage/postgres "$@"
