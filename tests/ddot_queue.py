#!/usr/bin/env python3
"""Actual pinned DDOT crash/overflow test; Docker required, no host ports/real keys."""
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import uuid
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = 'datadog/agent@sha256:d8f8a5271388c6f8eca64afc6864f0dc4ccac4277ac08b9c53f511ad29ea4a86'

def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)

parser = argparse.ArgumentParser()
parser.add_argument('--evidence', required=True)
parser.add_argument('--storage-full', action='store_true')
parser.add_argument('--full-config', action='store_true')
args = parser.parse_args()
evidence = pathlib.Path(args.evidence).resolve()
evidence.mkdir(parents=True, exist_ok=True)
name = 'cloud8021x-task7-ddot-' + uuid.uuid4().hex[:8]
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
    run('go', 'test', './internal/adapters/otlp', '-run', '^TestDDOTWire$', cwd=ROOT,
        env={**os.environ, 'C8021X_DDOT_EVIDENCE': str(tmp), 'C8021X_DDOT_GENERATE': '1'})
    shutil.copy(ROOT / 'tests/ddot_probe.py', tmp / 'probe.py')
    try:
        run('docker', 'run', '-d', '--name', name, '--network', 'none', '--memory', '768m',
            '--label', 'cloud8021x.task=7', '--label', 'cloud8021x.disposable=true',
            *(['--tmpfs', '/task7/queue:rw,size=64k'] if args.storage_full else []),
            '--entrypoint', '/bin/sleep', IMAGE, 'infinity')
        inspect = subprocess.check_output(['docker', 'inspect', name], text=True)
        info = json.loads(inspect)[0]
        assert info['HostConfig']['NetworkMode'] == 'none' and not info['HostConfig']['PortBindings']
        (evidence / 'container.json').write_text(inspect)
        run('docker', 'exec', name, 'mkdir', '-p', '/task7/queue')
        run('docker', 'cp', str(tmp) + '/.', name + ':/task7/')
        result = run('docker', 'exec', name, '/opt/datadog-agent/embedded/bin/python',
                     '/task7/probe.py', *(['--storage-full'] if args.storage_full else []), capture_output=True)
        print(result.stdout)
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
    except subprocess.CalledProcessError as error:
        print(error.stdout or '', error.stderr or '')
        run('docker', 'cp', name + ':/task7/evidence/.', str(evidence))
        raise
    finally:
        subprocess.run(['docker', 'rm', '-f', name], check=False, capture_output=True)
