#!/usr/bin/env bash
# Local CA interoperability against owned TLS PostgreSQL; no production DSNs.
set -euo pipefail
binary=${1:?usage: test_step_ca_postgres.sh FIXED_HOST_BINARY SHA256}
checksum=${2:?mandatory fixed binary SHA256}
fixture=$(mktemp -d)
container="cloud8021x-ca-pg-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$fixture/ca.key" -out "$fixture/ca.pem" -days 2 -subj /CN=Disposable-CA-Postgres >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$fixture/server.key" -out "$fixture/server.csr" -subj /CN=localhost >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$fixture/ext"
openssl x509 -req -in "$fixture/server.csr" -CA "$fixture/ca.pem" -CAkey "$fixture/ca.key" -CAcreateserial -out "$fixture/server.crt" -days 2 -extfile "$fixture/ext" >/dev/null 2>&1
cat > "$fixture/init.sql" <<'SQL'
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '/tls/server.crt';
ALTER SYSTEM SET ssl_key_file = '/tls/server.key';
CREATE ROLE stepca LOGIN PASSWORD 'disposable-ca';
CREATE DATABASE stepca OWNER stepca;
CREATE DATABASE stepca_rsa OWNER stepca;
REVOKE ALL ON DATABASE stepca FROM PUBLIC;
REVOKE ALL ON DATABASE stepca_rsa FROM PUBLIC;
SQL
docker run -d --name "$container" --label cloud8021x.disposable=true \
 -e POSTGRES_PASSWORD=disposable-admin -p 127.0.0.1::5432 \
 -v "$fixture:/certs:ro" -v "$fixture/init.sql:/docker-entrypoint-initdb.d/init.sql:ro" \
 postgres:16 bash -c 'mkdir -p /tls; cp /certs/server.key /certs/server.crt /tls/; chown postgres:postgres /tls/*; chmod 600 /tls/server.key; exec docker-entrypoint.sh postgres' >/dev/null
for _ in $(seq 1 60); do
 if docker exec "$container" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1; then break; fi
 sleep .25
done
port=$(docker port "$container" 5432/tcp | sed 's/.*://')
export SCEP_PG_LEGACY_DSN="postgresql://stepca:disposable-ca@localhost:$port/stepca?sslmode=verify-full&sslrootcert=$fixture/ca.pem"
export SCEP_PG_INVENTORY_DSN="postgresql://stepca:disposable-ca@localhost:$port/stepca_rsa?sslmode=verify-full&sslrootcert=$fixture/ca.pem"
python3 tests/scep/run.py --binary "$binary" --sha256 "$checksum"
