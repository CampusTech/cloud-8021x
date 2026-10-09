"""Owned PostgreSQL TLS fixture, direct private container IP; no published ports."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]

def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)

with tempfile.TemporaryDirectory(prefix='cloud8021x-infra-pg-') as directory:
    fixture = Path(directory)
    container = 'cloud8021x-infra-pg-' + uuid.uuid4().hex[:10]
    (fixture / 'ssl.sql').write_text("ALTER SYSTEM SET ssl='on'; ALTER SYSTEM SET ssl_cert_file='/tls/server.crt'; ALTER SYSTEM SET ssl_key_file='/tls/server.key';\n")
    run('docker', 'run', '-d', '--name', container, '--label', 'cloud8021x.slice=infrastructure', '--label', 'cloud8021x.disposable=true',
        '-e', 'POSTGRES_PASSWORD=disposable-migration', '-e', 'POSTGRES_DB=cloud8021x', '-v', directory + ':/certs:ro',
        '-v', str(fixture / 'ssl.sql') + ':/docker-entrypoint-initdb.d/ssl.sql:ro', 'postgres:16', 'bash', '-c',
        'while [ ! -f /certs/ready ]; do sleep 0.1; done; mkdir /tls; cp /certs/server.* /tls/; chown postgres:postgres /tls/*; chmod 600 /tls/server.key; exec docker-entrypoint.sh postgres', stdout=subprocess.DEVNULL)
    try:
        instance = json.loads(subprocess.check_output(['docker', 'inspect', container]))[0]
        assert not instance['HostConfig']['PortBindings']
        address = instance['NetworkSettings']['Networks']['bridge']['IPAddress']
        with open(os.devnull, 'w') as quiet:
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(fixture / 'ca.key'), '-out', str(fixture / 'ca.pem'), '-days', '2', '-subj', '/CN=Disposable-Infrastructure-CA', stdout=quiet, stderr=quiet)
            run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(fixture / 'server.key'), '-out', str(fixture / 'server.csr'), '-subj', '/CN=localhost', stdout=quiet, stderr=quiet)
            (fixture / 'ext').write_text('subjectAltName=DNS:localhost,IP:' + address + '\nextendedKeyUsage=serverAuth\n')
            run('openssl', 'x509', '-req', '-in', str(fixture / 'server.csr'), '-CA', str(fixture / 'ca.pem'), '-CAkey', str(fixture / 'ca.key'), '-CAcreateserial', '-out', str(fixture / 'server.crt'), '-days', '2', '-extfile', str(fixture / 'ext'), stdout=quiet, stderr=quiet)
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(fixture / 'wrong.key'), '-out', str(fixture / 'wrong.pem'), '-days', '2', '-subj', '/CN=Wrong-Test-CA', stdout=quiet, stderr=quiet)
        (fixture / 'ready').touch()
        for attempt in range(120):
            if subprocess.run(['docker', 'exec', container, 'pg_isready', '-h', address, '-U', 'postgres'], capture_output=True).returncode == 0:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('owned fixture did not start')
        run('docker', 'exec', container, 'psql', '-U', 'postgres', '-d', 'cloud8021x', '-v', 'ON_ERROR_STOP=1', '-c', "CREATE ROLE app_runtime LOGIN PASSWORD 'disposable-runtime'; CREATE ROLE app_native LOGIN PASSWORD 'disposable-native';", stdout=subprocess.DEVNULL)
        env = {**os.environ, 'C8021X_PG_TEST_DSN': 'postgres://postgres:disposable-migration@' + address + ':5432/cloud8021x', 'C8021X_PG_TEST_CA': str(fixture / 'ca.pem'), 'C8021X_PG_TEST_WRONG_CA': str(fixture / 'wrong.pem')}
        run('go', 'test', '-race', '-count=1', '-v', './internal/provisioning', '-run', 'TestTerraformGreenPrivateRunnerPreservesBlue|TestCAProvisioningTLSAndACL|TestDeploymentDatabaseIdentity', cwd=ROOT, env=env)
    finally:
        run('docker', 'rm', '-f', container, stdout=subprocess.DEVNULL)
