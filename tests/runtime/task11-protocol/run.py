#!/usr/bin/env python3
"""Owned, offline protocol fixture; retains existing genuine packet assertions."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tests'))
from native_package_inputs import verify_bundle

OUT = Path('/private/tmp/cloud8021x-task11-protocol-91a6')
BUNDLE = Path('/private/tmp/cloud8021x-task10-final-bundle-arm64')
DEV = Path('/private/tmp/cloud8021x-task11-debian-20261001.d5B0lJ/prerequisites')
BASE = 'sha256:196dfccbfa1af58025d2d0309c330413995c9592d8cc7f2b33bdb712665741cd'
NAME = 'task11-protocol-native-91a6'
PG = 'task11-protocol-pg-91a6'
NET = 'task11-protocol-net-91a6'
OWNER = 'task11-protocol'
MANIFEST = '32ee7a3f741b557ae12d0e3fb7eb160d28fc485fe0d91402bd610fc7ed886054'
APPSHA = None
SOURCE_SHA = None
PYTHON = '/opt/datadog-agent/embedded/bin/python3'
created = []

def command(*args, log=None, input=None, timeout=180):
    result = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if len(result.stdout.encode()) > 16 * 1024 * 1024:
        raise RuntimeError('fixture command output exceeds 16MiB bound')
    if log:
        (OUT / (log + '.log')).write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exit {result.returncode}: {result.stdout[-5000:]}')
    return result.stdout

def docker(*args, **kwargs):
    return command('docker', *args, **kwargs)

def labels():
    return [arg for key, value in {'cloud8021x.owner': OWNER, 'cloud8021x.task': '11', 'cloud8021x.test': 'task11', 'cloud8021x.disposable': 'true', 'cloud8021x.bundle.sha256': MANIFEST, 'cloud8021x.app.sha256': APPSHA, 'cloud8021x.app.source': SOURCE_SHA}.items() for arg in ('--label', key + '=' + value)]

def execute(*args, **kwargs):
    return docker('exec', NAME, *args, **kwargs)

def mode(name):
    print('RUN native ' + name, flush=True)
    output = execute(PYTHON, '/task6-native.py', name, log='native-' + name)
    print(output, end='', flush=True)

def arguments(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--application-dir',type=Path,required=True)
    parser.add_argument('--source-sha',required=True)
    parser.add_argument('--application-sha256',required=True)
    parser.add_argument('--go',default='go',help='cached compatible Go executable used only to inspect build metadata')
    parser.add_argument('--output-dir',type=Path,default=OUT)
    modes=parser.add_mutually_exclusive_group()
    for mode in ['ca-only','account-only','sudo-regression']:
        modes.add_argument('--'+mode,action='store_true')
    return parser.parse_args(argv)

def application_inputs(options):
    if not re.fullmatch('[a-f0-9]{40}',options.source_sha) or not re.fullmatch('[a-f0-9]{64}',options.application_sha256):
        raise ValueError('exact source SHA and application SHA256 required')
    application=options.application_dir/'cloud-8021x-linux-arm64'
    checksum=hashlib.sha256(application.read_bytes()).hexdigest()
    if checksum!=options.application_sha256:
        raise ValueError('application SHA256 mismatch')
    lines=(options.application_dir/'SHA256SUMS').read_text().splitlines()
    matched=[line.split() for line in lines if len(line.split())==2 and line.split()[1]=='cloud-8021x-linux-arm64']
    if matched!=[[checksum,'cloud-8021x-linux-arm64']]:
        raise ValueError('application directory checksum binding mismatch')
    env=dict(os.environ,GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off')
    result=subprocess.run([options.go,'version','-m',str(application)],text=True,capture_output=True,check=True,env=env)
    settings=dict(re.findall(r'^\s*build\s+([^=\s]+)=(.*)$',result.stdout,re.M))
    expected={'GOOS':'linux','GOARCH':'arm64','vcs.revision':options.source_sha,'vcs.modified':'false'}
    if any(settings.get(key)!=value for key,value in expected.items()):
        raise ValueError('application build metadata does not match clean exact Linux/ARM64 source')
    return application,checksum,result.stdout

def main():
    global OUT,APPSHA,SOURCE_SHA
    options=arguments()
    APP,APPSHA,buildinfo=application_inputs(options)
    SOURCE_SHA=options.source_sha
    OUT=options.output_dir
    OUT.mkdir(exist_ok=True)
    manifest, archives, checksum = verify_bundle(BUNDLE)
    assert checksum == MANIFEST and manifest['architecture'] == 'arm64'
    (OUT/'application-buildinfo.log').write_text(buildinfo)
    assert (OUT / 'native-fixture').is_file() and (OUT / 'scep.test').is_file()
    dev = json.loads((DEV / 'dev-prerequisites.lock.json').read_text())
    selected = {'eapoltest', 'libpcsclite1'}
    devpaths = []
    for item in dev['packages']:
        if item['name'] not in selected:
            continue
        archive = DEV / 'archives' / item['url'].rsplit('/', 1)[-1]
        assert archive.stat().st_size == item['size'] and hashlib.sha256(archive.read_bytes()).hexdigest() == item['sha256']
        devpaths.append('/dev-archives/' + archive.name)
    assert len(devpaths) == len(selected)
    pgimage = json.loads(docker('image', 'inspect', 'postgres:16'))[0]['Id']
    base = json.loads(docker('image', 'inspect', BASE))[0]
    assert base['Architecture'] == 'arm64'
    (OUT / 'inputs.json').write_text(json.dumps({'manifest': MANIFEST, 'app': APPSHA, 'application_source': SOURCE_SHA, 'application_directory': str(options.application_dir), 'fixture_helper_sha256': hashlib.sha256((OUT/'native-fixture').read_bytes()).hexdigest(), 'native_fixture_source_sha256': hashlib.sha256((ROOT/'tests/native_fixture/main.go').read_bytes()).hexdigest(), 'native_packet_source_sha256': hashlib.sha256((ROOT/'tests/native_radius_container.py').read_bytes()).hexdigest(), 'base': base['Id'], 'postgres_image': pgimage, 'development_lock': hashlib.sha256((DEV / 'dev-prerequisites.lock.json').read_bytes()).hexdigest()}, indent=2))
    docker('network', 'create', '--internal', *labels(), NET)
    created.append(('network', NET))
    docker('create', '--name', NAME, '--pull', 'never', '--network', NET, '--cpus', '1.5', '--memory', '2304m', '--pids-limit', '256', '--log-opt', 'max-size=8m', '--log-opt', 'max-file=1', *labels(), '-v', str(BUNDLE) + ':/bundle:ro', '-v', str(DEV / 'archives') + ':/dev-archives:ro', '-v', str(OUT) + ':/fixture:ro', BASE, 'sleep', 'infinity')
    created.append(('container', NAME))
    docker('start', NAME)
    install = ['/bundle/' + filename for filename in archives.values()]
    execute('dpkg', '--install', *install, log='install', timeout=180)
    execute('dpkg', '--install', *devpaths, log='dev-install')
    docker('cp', str(APP), NAME + ':/usr/local/bin/cloud-8021x')
    docker('cp', str(OUT / 'native-fixture'), NAME + ':/task6-native-fixture')
    docker('cp', str(ROOT / 'tests/native_radius_container.py'), NAME + ':/task6-native.py')
    assert hashlib.sha256((OUT / 'psql16').read_bytes()).hexdigest() == '2cbb857ac3889d22cfe0dce6581cf2321ce69bcb253cc8b55b981914cd3ee22a'
    docker('cp', str(OUT / 'psql16'), NAME + ':/usr/local/bin/psql')
    execute('psql', '--version', log='psql-version')
    execute('ldd', '/usr/local/bin/psql', log='psql-linked-abi')
    assert execute('sha256sum', '/usr/local/bin/cloud-8021x').split()[0] == APPSHA
    for package in ['freeradius', 'libfreeradius3', 'freeradius-common', 'freeradius-config', 'freeradius-rest', 'freeradius-postgresql', 'freeradius-utils']:
        assert execute('dpkg-query', '-W', '-f=${Status} ${Version}', package) == 'install ok installed 3.2.10+dfsg-2+trixie.campus4'
    mode('prepare')
    execute('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', '/task6/certs/pg.key', '-out', '/task6/certs/pg.csr', '-subj', '/CN=localhost', log='pg-key')
    execute('openssl', 'x509', '-req', '-in', '/task6/certs/pg.csr', '-CA', '/task6/certs/ca.pem', '-CAkey', '/task6/certs/ca.key', '-CAcreateserial', '-out', '/task6/certs/pg.crt', '-days', '1', '-extfile', '/task6/certs/ext', log='pg-cert')
    # prepare's final extension is clientAuth; use explicit serverAuth and SAN.
    execute('sh', '-c', "printf 'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n' > /task6/certs/pg.ext")
    execute('openssl', 'x509', '-req', '-in', '/task6/certs/pg.csr', '-CA', '/task6/certs/ca.pem', '-CAkey', '/task6/certs/ca.key', '-CAcreateserial', '-out', '/task6/certs/pg.crt', '-days', '1', '-extfile', '/task6/certs/pg.ext', log='pg-cert')
    tls = OUT / 'tls'; tls.mkdir(exist_ok=True)
    for name in ['pg.key', 'pg.crt']:
        docker('cp', NAME + ':/task6/certs/' + name, str(tls / name))
    (OUT / 'init.sql').write_text("CREATE ROLE app_native LOGIN PASSWORD 'fixture-native';\nCREATE ROLE app_runtime LOGIN PASSWORD 'fixture-runtime';\nCREATE DATABASE cloud8021x;\nCREATE ROLE stepca LOGIN PASSWORD 'disposable-ca';\nCREATE DATABASE stepca OWNER stepca;\nCREATE DATABASE stepca_rsa OWNER stepca;\nREVOKE ALL ON DATABASE stepca FROM PUBLIC;\nREVOKE ALL ON DATABASE stepca_rsa FROM PUBLIC;\n")
    docker('create', '--name', PG, '--pull', 'never', '--network', 'container:' + NAME, '--cpus', '0.5', '--memory', '768m', '--pids-limit', '128', '--log-opt', 'max-size=8m', '--log-opt', 'max-file=1', *labels(), '-e', 'POSTGRES_PASSWORD=fixture-migration', '-v', str(tls) + ':/certs:ro', '-v', str(OUT / 'init.sql') + ':/docker-entrypoint-initdb.d/init.sql:ro', pgimage, 'bash', '-c', 'mkdir -p /tls; cp /certs/pg.key /certs/pg.crt /tls/; chown postgres:postgres /tls/*; chmod 600 /tls/pg.key; exec docker-entrypoint.sh postgres -p 55432 -c ssl=on -c ssl_cert_file=/tls/pg.crt -c ssl_key_file=/tls/pg.key')
    created.append(('container', PG)); docker('start', PG)
    states = json.loads(docker('inspect', NAME, PG))
    proof = [{'name': x['Name'], 'image': x['Image'], 'labels': x['Config']['Labels'], 'ports': x['HostConfig'].get('PortBindings'), 'cpu': x['HostConfig']['NanoCpus'], 'memory': x['HostConfig']['Memory'], 'network': x['HostConfig']['NetworkMode'], 'binds': x['HostConfig']['Binds']} for x in states]
    network = json.loads(docker('network', 'inspect', NET))[0]
    assert network['Internal'] and all(not x['ports'] for x in proof)
    assert sum(x['cpu'] for x in proof) == 2000000000 and sum(x['memory'] for x in proof) == 3 * 1024 ** 3
    (OUT / 'isolation-proof.json').write_text(json.dumps({'containers': proof, 'network_internal': network['Internal']}, indent=2))
    (OUT / 'resource-stats.txt').write_text(docker('stats', '--no-stream', '--format', '{{.Name}} CPU={{.CPUPerc}} MEM={{.MemUsage}}', NAME, PG))
    for _ in range(60):
        result = subprocess.run(['docker', 'exec', PG, 'pg_isready', '-p', '55432', '-U', 'postgres'], capture_output=True)
        if result.returncode == 0: break
        time.sleep(.25)
    else: raise RuntimeError('owned PG not ready')
    execute('/task6-native-fixture', 'migrate', '/etc/cloud-8021x/config.yaml', log='migrate')
    if options.sudo_regression:
        docker('cp', str(OUT / 'systemd.test'), NAME + ':/systemd.test')
        print(docker('exec', '-e', 'C8021X_SUDO_FIXTURE=task11-protocol', NAME, '/systemd.test', '-test.v', '-test.run', '^TestFreshDebianNativeAccountAllowsOnlyFixedLeaf$', log='sudo-regression'), end='', flush=True)
        docker('cp', str(ROOT / 'tests/native_radius_container.py'), NAME + ':/task6_native.py')
        docker('cp', str(ROOT / 'tests/runtime/task11-protocol/account_probe.py'), NAME + ':/account_probe.py')
        print(execute(PYTHON, '/account_probe.py', '--expect-success', log='r96-eap'), end='', flush=True)
        return
    if options.account_only:
        docker('cp', str(ROOT / 'tests/native_radius_container.py'), NAME + ':/task6_native.py')
        docker('cp', str(ROOT / 'tests/runtime/task11-protocol/account_probe.py'), NAME + ':/account_probe.py')
        print(execute(PYTHON, '/account_probe.py', log='account-validation'), end='', flush=True)
        return
    if not options.ca_only:
        mode('test')
        for name in ['ports', 'attested', 'expiry-missing', 'legacy', 'termination', 'sources', 'full', 'zero', 'sqltls']:
            mode(name)
        docker('stop', '--time', '5', PG)
        mode('outage')
        docker('start', PG)
        time.sleep(1)
        mode('replay-duplicate')
        mode('permissions')
    # Actual fixed executable, rendered fixture, real mTLS and independent PG DBs.
    for name in ['legacy.json', 'inventory.json', 'scep.test']:
        docker('cp', str(OUT / name), NAME + ':/' + name)
    stepca_hash = execute('sha256sum', '/usr/bin/step-ca').split()[0]
    (OUT / 'step-ca.sha256').write_text(stepca_hash + '\n')
    for database in ['badger', 'postgres']:
        env = ['-e', 'STEP_CA_BINARY=/usr/bin/step-ca', '-e', 'SCEP_RENDERED_CONFIG=/legacy.json', '-e', 'SCEP_INVENTORY_RENDERED_CONFIG=/inventory.json']
        if database == 'postgres':
            env += ['-e', 'SCEP_PG_LEGACY_DSN=postgresql://stepca:disposable-ca@localhost:55432/stepca?sslmode=verify-full&sslrootcert=/task6/certs/ca.pem', '-e', 'SCEP_PG_INVENTORY_DSN=postgresql://stepca:disposable-ca@localhost:55432/stepca_rsa?sslmode=verify-full&sslrootcert=/task6/certs/ca.pem']
        output = docker('exec', *env, NAME, '/scep.test', '-test.v', '-test.run', '^TestActualStepCASCEP$', log='scep-' + database)
        print(output, end='', flush=True)
    return 'PASS actual SCEP CA suite' if options.ca_only else 'PASS complete protocol suite for exact supplied application source '+SOURCE_SHA

def cleanup():
    failures=[]
    for kind,name in reversed(created):
        try:
            state=json.loads(docker(kind,'inspect',name))[0]
            owned=state.get('Config',{}).get('Labels',state.get('Labels',{})).get('cloud8021x.owner')==OWNER
            if not owned:
                raise RuntimeError('cleanup refuses unowned resource')
        except Exception as error:
            failures.append(f'{kind} {name}: ownership: {error}')
            continue
        if kind=='container':
            try:
                docker('logs',name,log='container-'+name)
                if name==NAME and execute('sh','-c','test -d /task6 && printf yes || true')=='yes':
                    docker('cp',NAME+':/task6',str(OUT/'native-artifacts'))
            except Exception as error:
                failures.append(f'{kind} {name}: evidence: {error}')
            # Evidence capture may fail on stopped/OOM fixtures. Removal is an
            # independent operation after the mandatory ownership check.
            try:
                docker('rm','-f',name)
            except Exception as error:
                failures.append(f'{kind} {name}: removal: {error}')
        else:
            try:
                docker('network','rm',name)
            except Exception as error:
                failures.append(f'{kind} {name}: removal: {error}')
    if failures:
        raise RuntimeError('fixture cleanup failed:\n'+'\n'.join(failures))

if __name__ == '__main__':
    try:
        completion=main()
    finally:
        cleanup()
    if completion:
        print(completion,flush=True)
