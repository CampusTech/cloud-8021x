#!/usr/bin/env python3
"""Disposable native EAP/accounting/SCEP/TLS PostgreSQL tests; no production inputs."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests'))
from native_package_inputs import verify_bundle


def run(*args, **kwargs):
    kwargs.setdefault('timeout', 180)
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('architecture', choices=['amd64', 'arm64'])
    parser.add_argument('bundle', type=Path)
    args = parser.parse_args()
    bundle = args.bundle.resolve()
    _, archives, manifest_hash = verify_bundle(bundle, args.architecture)
    server_arch = run('docker', 'version', '--format', '{{.Server.Arch}}', capture_output=True).stdout.strip()
    if server_arch != args.architecture:
        raise RuntimeError('packet/account acceptance requires the native Docker architecture')
    pg_image = json.loads(run('docker', 'image', 'inspect', 'postgres:16', capture_output=True).stdout)[0]
    if pg_image['Architecture'] != args.architecture:
        raise RuntimeError('cached postgres:16 architecture differs from the bundle')
    owner = 'cloud8021x-packets-' + uuid.uuid4().hex[:12]
    native, database, network = owner + '-native', owner + '-pg', owner + '-net'
    base, image = owner + '-base', owner + '-image'
    labels = ['--label', 'cloud8021x.disposable=true', '--label', 'cloud8021x.test=task10',
              '--label', 'cloud8021x.owner=' + owner, '--label', 'cloud8021x.bundle.sha256=' + manifest_hash]
    containers, network_created = [], False
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    with tempfile.TemporaryDirectory(prefix='cloud8021x-packets-') as temporary:
        fixture = Path(temporary)
        env = {**os.environ, 'GOOS': 'linux', 'GOARCH': args.architecture, 'CGO_ENABLED': '0'}
        try:
            for package, name in [('./cmd/cloud-8021x', 'cloud-8021x'), ('./tests/native_fixture', 'native-fixture')]:
                run('go', 'build', '-o', str(fixture / name), package, cwd=ROOT, env=env)
            run('go', 'test', '-c', '-o', str(fixture / 'systemd.test'), './internal/templates/systemd', cwd=ROOT, env=env)
            run('go', 'test', '-count=1', '-run', '^TestExportSCEPFixtures$', './internal/adapters/stepca',
                cwd=ROOT, env={**os.environ, 'C8021X_SCEP_FIXTURE_OUTPUT': str(fixture)})
            run('go', 'test', '-c', '-o', str(fixture / 'scep.test'), '.', cwd=ROOT / 'tests/scep', env=env)
            run('docker', 'build', '--platform', 'linux/' + args.architecture, '-t', base,
                '-f', str(ROOT / 'tests/native_package_fixture.Dockerfile'), str(fixture), timeout=900)
            run('docker', 'build', '--platform', 'linux/' + args.architecture, '--build-arg', 'BASE=' + base,
                '-t', image, '-f', str(ROOT / 'tests/integration/packets.Dockerfile'), str(fixture), timeout=900)
            run('docker', 'network', 'create', '--internal', *labels, network)
            network_created = True
            run('docker', 'create', '--name', native, '--pull', 'never', '--network', network,
                '--cpus', '1.5', '--memory', '2304m', '--pids-limit', '256', *labels,
                '-v', str(bundle) + ':/bundle:ro', image, 'sleep', 'infinity')
            containers.append(native)
            run('docker', 'start', native)

            def execute(*command, **kwargs):
                return run('docker', 'exec', native, *command, **kwargs)

            def mode(name):
                print('Native packet check: ' + name, flush=True)
                execute('/opt/datadog-agent/embedded/bin/python3', '/native-packets.py', name, timeout=300)

            execute('dpkg', '--install', *['/bundle/' + filename for filename in archives.values()])
            for name, destination in [('cloud-8021x', '/usr/local/bin/cloud-8021x'),
                                      ('native-fixture', '/task6-native-fixture'), ('systemd.test', '/systemd.test')]:
                run('docker', 'cp', str(fixture / name), native + ':' + destination)
            run('docker', 'cp', str(ROOT / 'tests/native_radius_container.py'), native + ':/native-packets.py')
            mode('prepare')
            execute('sh', '-c', "printf 'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n' > /task6/certs/pg.ext")
            execute('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', '/task6/certs/pg.key',
                    '-out', '/task6/certs/pg.csr', '-subj', '/CN=localhost')
            execute('openssl', 'x509', '-req', '-in', '/task6/certs/pg.csr', '-CA', '/task6/certs/ca.pem',
                    '-CAkey', '/task6/certs/ca.key', '-CAcreateserial', '-out', '/task6/certs/pg.crt',
                    '-days', '1', '-extfile', '/task6/certs/pg.ext')
            tls = fixture / 'tls'
            tls.mkdir()
            for name in ['pg.key', 'pg.crt']:
                run('docker', 'cp', native + ':/task6/certs/' + name, str(tls / name))
            sql = fixture / 'init.sql'
            sql.write_text("CREATE ROLE app_native LOGIN PASSWORD 'fixture-native';\n"
                           "CREATE ROLE app_runtime LOGIN PASSWORD 'fixture-runtime';\nCREATE DATABASE cloud8021x;\n"
                           "CREATE ROLE stepca LOGIN PASSWORD 'disposable-ca';\n"
                           "CREATE DATABASE stepca OWNER stepca;\nCREATE DATABASE stepca_rsa OWNER stepca;\n"
                           "REVOKE ALL ON DATABASE stepca FROM PUBLIC;\nREVOKE ALL ON DATABASE stepca_rsa FROM PUBLIC;\n")
            run('docker', 'create', '--name', database, '--pull', 'never', '--network', 'container:' + native,
                '--cpus', '0.5', '--memory', '768m', '--pids-limit', '128', *labels,
                '-e', 'POSTGRES_PASSWORD=fixture-migration', '-v', str(tls) + ':/certs:ro',
                '-v', str(sql) + ':/docker-entrypoint-initdb.d/init.sql:ro', pg_image['Id'], 'bash', '-c',
                'set -eu; mkdir -p /tls; cp /certs/pg.key /certs/pg.crt /tls/; chown postgres:postgres /tls/*; '
                'chmod 600 /tls/pg.key; exec docker-entrypoint.sh postgres -p 55432 -c ssl=on '
                '-c ssl_cert_file=/tls/pg.crt -c ssl_key_file=/tls/pg.key')
            containers.append(database)
            run('docker', 'start', database)
            states = json.loads(run('docker', 'inspect', native, database, capture_output=True).stdout)
            if any(state['HostConfig'].get('PortBindings') for state in states):
                raise RuntimeError('disposable packet fixture unexpectedly exposes host ports')
            if not json.loads(run('docker', 'network', 'inspect', network, capture_output=True).stdout)[0]['Internal']:
                raise RuntimeError('disposable packet network is not internal')

            def wait_database():
                for _ in range(120):
                    ready = subprocess.run(['docker', 'exec', database, 'pg_isready', '-h', '127.0.0.1',
                                            '-p', '55432', '-U', 'postgres'], capture_output=True, timeout=5)
                    if ready.returncode == 0:
                        return
                    time.sleep(.25)
                raise RuntimeError('disposable PostgreSQL did not become ready')

            wait_database()
            execute('/task6-native-fixture', 'migrate', '/etc/cloud-8021x/config.yaml')
            run('docker', 'exec', '-e', 'C8021X_SUDO_FIXTURE=task11-protocol', native,
                '/systemd.test', '-test.run', '^TestFreshDebianNativeAccountAllowsOnlyFixedLeaf$', '-test.v')
            mode('test')
            mode('full')
            run('docker', 'stop', '--time', '5', database)
            mode('outage')
            run('docker', 'start', database)
            wait_database()
            mode('replay-duplicate')
            for name in ['legacy.json', 'inventory.json', 'scep.test']:
                run('docker', 'cp', str(fixture / name), native + ':/' + name)
            for backend in ['badger', 'postgres']:
                scep_env = ['-e', 'STEP_CA_BINARY=/usr/bin/step-ca', '-e', 'SCEP_RENDERED_CONFIG=/legacy.json',
                            '-e', 'SCEP_INVENTORY_RENDERED_CONFIG=/inventory.json']
                if backend == 'postgres':
                    for suffix, dbname in [('LEGACY', 'stepca'), ('INVENTORY', 'stepca_rsa')]:
                        scep_env += ['-e', f'SCEP_PG_{suffix}_DSN=postgresql://stepca:disposable-ca@localhost:55432/{dbname}?sslmode=verify-full&sslrootcert=/task6/certs/ca.pem']
                print('Native SCEP check: ' + backend, flush=True)
                run('docker', 'exec', *scep_env, native, '/scep.test', '-test.v', '-test.run', '^TestActualStepCASCEP$', timeout=300)
        finally:
            for name in reversed(containers):
                subprocess.run(['docker', 'rm', '-fv', name], check=False, timeout=30)
            if network_created:
                subprocess.run(['docker', 'network', 'rm', network], check=False, timeout=30)
            subprocess.run(['docker', 'image', 'rm', image, base], check=False, timeout=30)


if __name__ == '__main__':
    main()
