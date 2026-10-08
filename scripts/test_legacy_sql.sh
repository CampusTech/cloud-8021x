#!/usr/bin/env bash
# Owned migration-only MariaDB fixture. No existing service/container mutation.
set -euo pipefail
fixture=$(mktemp -d /private/tmp/cloud8021x-task9-sql.XXXXXX)
container="cloud8021x-task9-sql-$(openssl rand -hex 5)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
arch=$(docker version --format '{{.Server.Arch}}')
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c -o "$fixture/host.test" ./internal/privileged/host
docker run -d --name "$container" --label cloud8021x.test=task9 --label cloud8021x.disposable=true -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 -e C8021X_SQL_FIXTURE=task9 -v "$fixture:/fixture:ro" mariadb@sha256:1292844148b311e4ed4300022a996d39083f415a963e970cf47cad1b3b18e3a6 --skip-networking >/dev/null
for _ in $(seq 1 60); do if [[ $(docker exec "$container" cat /proc/1/comm 2>/dev/null) == mariadbd ]] && docker exec "$container" mariadb-admin --protocol=socket ping >/dev/null 2>&1; then break; fi; sleep 1; done
docker exec -i "$container" mariadb --protocol=socket -u root <<'SQL'
CREATE DATABASE radius;
CREATE TABLE radius.radacct(radacctid BIGINT UNSIGNED PRIMARY KEY,acctuniqueid VARCHAR(64),acctsessionid VARCHAR(64),username VARCHAR(64),nasipaddress VARCHAR(64),callingstationid VARCHAR(64),calledstationid VARCHAR(64),acctstarttime DATETIME(6),acctupdatetime DATETIME(6),acctstoptime DATETIME(6),acctsessiontime BIGINT UNSIGNED,acctinputoctets BIGINT UNSIGNED,acctoutputoctets BIGINT UNSIGNED,acctterminatecause VARCHAR(64));
INSERT INTO radius.radacct VALUES(1,'unique','session','opaque','192.0.2.1','','','2026-10-08 12:34:56.123456','2026-10-08 12:35:56.123456','2026-10-08 12:36:56.123456',120,18446744073709551615,7,'User-Request'),(2,'open','open','opaque','192.0.2.2','','','2026-10-08 12:34:56.123456',NULL,NULL,NULL,NULL,NULL,'');
ALTER USER root@localhost IDENTIFIED VIA unix_socket;
SET GLOBAL log_output='TABLE';
SET GLOBAL general_log=ON;
SQL
# Match the deployed Debian tmpfiles 0755 mysql-owned socket directory; upstream container uses 0777.
docker exec -u root "$container" chmod 0755 /run/mysqld
docker exec -u root "$container" /fixture/host.test -test.run '^TestInstalledLegacySQLCapture'  -test.v
# The Go connector used START TRANSACTION READ ONLY and issued no row/schema writes.
docker exec "$container" mariadb --protocol=socket -u root -N -e "SELECT COUNT(*)=2 FROM radius.radacct; SELECT COUNT(*)>0 FROM mysql.general_log WHERE argument='START TRANSACTION READ ONLY'; SELECT COUNT(*)=0 FROM mysql.general_log WHERE command_type='Query' AND argument REGEXP '^(INSERT|UPDATE|DELETE|REPLACE|ALTER|CREATE|DROP|TRUNCATE)'" | awk 'BEGIN { n=0 } { if ($0 != 1) exit 1; n++ } END { if (n != 3) exit 1 }'
