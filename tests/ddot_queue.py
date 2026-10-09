#!/usr/bin/env python3
"""Actual pinned DDOT crash/overflow test; Docker required, no host ports/real keys."""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import uuid
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = 'golang@sha256:e58d6f83b3416618d8bcac2b3dde1b7f7e3c4a77d25e88637f8bbae81536c48d'
VERSION = '1:7.84.2-1+campus1'

def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)

def capture_command(command, evidence, name, timeout):
    """Retain exact subprocess diagnostics before propagating failure; never retry."""
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        (evidence / (name + '.stdout')).write_bytes(error.stdout or b'')
        (evidence / (name + '.stderr')).write_bytes(error.stderr or b'')
        (evidence / (name + '.result.json')).write_text(json.dumps(
            {'returncode': None, 'timed_out': True, 'timeout_seconds': timeout}))
        raise
    (evidence / (name + '.stdout')).write_bytes(result.stdout)
    (evidence / (name + '.stderr')).write_bytes(result.stderr)
    (evidence / (name + '.result.json')).write_text(json.dumps(
        {'returncode': result.returncode, 'timed_out': False, 'timeout_seconds': timeout}))
    result.check_returncode()
    return result

parser = argparse.ArgumentParser()
parser.add_argument('--evidence', required=True)
parser.add_argument('--packages', required=True, help='actual rebuilt package directory with mandatory SHA256SUMS')
parser.add_argument('--architecture', choices=['amd64', 'arm64'], required=True)
parser.add_argument('--storage-full', action='store_true')
parser.add_argument('--full-config', action='store_true')
args = parser.parse_args()
packages = pathlib.Path(args.packages).resolve()
checksums = dict(line.split(maxsplit=1)[::-1] for line in (packages / 'SHA256SUMS').read_text().splitlines())
archives = []
for package in ['datadog-agent', 'datadog-agent-ddot']:
    filename = f'{package}_{VERSION}_{args.architecture}.deb'
    path = packages / filename
    assert path.is_file() and not path.is_symlink(), filename
    assert hashlib.sha256(path.read_bytes()).hexdigest() == checksums.get(filename), filename
    archives.append('/packages/' + filename)
evidence = pathlib.Path(args.evidence).resolve()
evidence.mkdir(parents=True, exist_ok=True)
name = 'cloud8021x-task10-ddot-' + uuid.uuid4().hex[:8]
with tempfile.TemporaryDirectory(prefix='cloud8021x-ddot-task7-') as tmp:
    tmp = pathlib.Path(tmp)
    template = (ROOT / 'internal/templates/ddot/collector.yaml.tmpl').read_text()
    rendered = template.replace('{{quote .QueueDirectory}}', '"/task7/queue"').replace(
        '{{quote .LogsEndpoint}}', '"http://127.0.0.1:18080/v1/logs"').replace('{{quote .Site}}', '"us5.datadoghq.com"').replace('{{.QueueBytes}}', '10485760' if args.storage_full else '4096')
    config = yaml.safe_load(rendered)
    business = config['exporters']['otlp_http/business']
    business['timeout'] = '1s'
    business['retry_on_failure']['max_interval'] = '2s'
    business['sending_queue']['num_consumers'] = 1
    business['compression'] = 'none'
    # Only ordinary export goes to debug in this offline fixture. Business uses
    # the exact product exporter type, protobuf, mapping and persistent queue.
    if not args.full_config:
        del config['exporters']['datadog/ordinary']
        config['exporters']['debug/ordinary'] = {'verbosity': 'basic'}
        for key, pipeline in config['service']['pipelines'].items():
            if key.endswith('/ordinary'):
                pipeline['exporters'] = ['debug/ordinary']
    (tmp / 'collector.yaml').write_text(yaml.safe_dump(config))
    (tmp / 'core.yaml').write_text('hostname: task7-export-worker\nsite: us5.datadoghq.com\napi_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nlogs_enabled: true\notelcollector:\n  enabled: true\n  converter:\n    features: [ddflare]\n')
    with (tmp / 'core.yaml').open('a') as core:
        core.write('auth_token_file_path: /opt/datadog-agent/run/auth_token\nipc_cert_file_path: /opt/datadog-agent/run/ipc_cert.pem\ndisable_file_logging: true\nlog_to_console: true\ncloud_provider_metadata: []\nremote_configuration:\n  enabled: false\napm_config:\n  enabled: false\nuse_dogstatsd: false\n')
    run('go', 'test', './internal/adapters/otlp', '-run', '^TestDDOTWire$', cwd=ROOT,
        env={**os.environ, 'C8021X_DDOT_EVIDENCE': str(tmp), 'C8021X_DDOT_GENERATE': '1'})
    shutil.copy(ROOT / 'tests/ddot_probe.py', tmp / 'probe.py')
    try:
        run('docker', 'run', '-d', '--name', name, '--network', 'none', '--memory', '768m',
            '--platform', 'linux/' + args.architecture, '-v', str(packages) + ':/packages:ro',
            '--label', 'cloud8021x.task=10', '--label', 'cloud8021x.disposable=true',
            *(['--tmpfs', '/task7/queue:rw,size=64k'] if args.storage_full else []),
            '--entrypoint', '/bin/sleep', IMAGE, 'infinity')
        inspect = subprocess.check_output(['docker', 'inspect', name], text=True)
        info = json.loads(inspect)[0]
        assert info['HostConfig']['NetworkMode'] == 'none' and not info['HostConfig']['PortBindings']
        (evidence / 'container.json').write_text(inspect)
        run('docker', 'exec', name, 'dpkg', '--install', *archives)
        run('docker', 'exec', name, 'useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'dd-agent')
        run('docker', 'exec', name, 'mkdir', '-p', '/task7/queue', '/task7/evidence', '/opt/datadog-agent/run')
        run('docker', 'cp', str(tmp) + '/.', name + ':/task7/')
        run('docker', 'exec', name, 'chown', '-R', 'dd-agent:dd-agent', '/task7/evidence', '/task7/queue', '/opt/datadog-agent/run')
        run('docker', 'exec', name, 'chmod', '0700', '/opt/datadog-agent/run')
        run('docker', 'exec', name, 'chmod', '0644', '/task7/input.json')
        result = capture_command(['docker', 'exec', '--user', 'dd-agent', name, '/opt/datadog-agent/embedded/bin/python',
                     '/task7/probe.py', *(['--storage-full'] if args.storage_full else [])], evidence, 'probe', timeout=900)
        print(result.stdout.decode(errors="replace"))
        run('docker', 'cp', name + ':/task7/evidence/.', str(evidence))
        effective = json.loads((evidence / 'effective.json').read_text())
        runtime = yaml.safe_load(effective['full_configuration'])
        pipeline = runtime['service']['pipelines']['logs/business']
        assert pipeline['processors'] == ['transform/business']
        assert pipeline['exporters'] == ['otlp_http/business']
        if args.full_config:
            assert runtime['exporters']['datadog/ordinary']['api']['site'] == 'us5.datadoghq.com'
        queue = runtime['exporters']['otlp_http/business']['sending_queue']
        assert queue['storage'] == 'file_storage/accounting' and queue['batch'] is None
        assert not queue['block_on_overflow'] and not queue['wait_for_result']
        assert runtime['extensions']['file_storage/accounting']['fsync'] is True
        retry = runtime['exporters']['otlp_http/business']['retry_on_failure']
        assert retry['max_elapsed_time'] == '0s' and retry['max_interval'] == '2s'
        if not args.storage_full:
            run('go', 'test', './internal/adapters/otlp', '-run', '^TestDDOTWire$', cwd=ROOT,
                env={**os.environ, 'C8021X_DDOT_EVIDENCE': str(evidence)})
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(error.stdout or '', error.stderr or '')
        run('docker', 'cp', name + ':/task7/evidence/.', str(evidence))
        raise
    finally:
        subprocess.run(['docker', 'rm', '-f', name], check=False, capture_output=True)
