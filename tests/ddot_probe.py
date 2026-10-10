#!/usr/bin/env python3
"""Run INSIDE the labeled network-none Task 7 fixture, with synthetic keys only."""
import gzip
import http.server
import json
import os
import pathlib
import signal
import ssl
import sys
import subprocess
import threading
import time
import urllib.error
import urllib.request

assert os.geteuid() != 0, 'package lifecycle must work as dd-agent'
ROOT = pathlib.Path('/task7')
EVIDENCE = ROOT / 'evidence'
EVIDENCE.mkdir(exist_ok=True)
accepted = []
blocked = True
attempts = 0

class Sink(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global attempts
        body = self.rfile.read(int(self.headers['Content-Length']))
        if self.headers.get('Content-Encoding') == 'gzip':
            body = gzip.decompress(body)
        attempts += 1
        if blocked:
            self.send_response(503)
            self.end_headers()
            return
        assert self.path == '/v1/logs'
        assert self.headers['dd-api-key'] == 'a' * 32
        assert self.headers['Content-Type'] == 'application/x-protobuf'
        (EVIDENCE / f'export-{len(accepted)}.pb').write_bytes(body)
        accepted.append(body)
        self.send_response(200)
        self.send_header('Content-Type', 'application/x-protobuf')
        self.end_headers()
    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(('127.0.0.1', 18080), Sink)
threading.Thread(target=server.serve_forever, daemon=True).start()

def wait(check, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(.1)
    raise AssertionError('bounded wait expired')

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

def core_api_status(token, certificate, timeout):
    # Agent 7.84.2: server_cmd.go mounts /agent with IPC auth; internal/agent/
    # agent.go exposes GET /status/health using health.GetReady(). IPC generation
    # publishes token BEFORE cert (comp/core/ipc/impl/ipc.go); token alone races
    # the check command's ModuleReadOnly / single-attempt FetchIPCCert.
    context = ssl.create_default_context(cafile=str(certificate))
    request = urllib.request.Request('https://127.0.0.1:5001/agent/status/health',
                                     headers={'Authorization': 'Bearer ' + token.read_text().strip()})
    with urllib.request.urlopen(request, context=context, timeout=timeout) as response:
        assert response.status == 200, 'core API did not return success'
        return json.load(response)


def wait_core_api(process, token, certificate, evidence, seconds=30, probe=core_api_status):
    """Bounded authenticated readiness; report failures without exposing IPC secrets."""
    deadline = time.monotonic() + seconds
    report = {'outcome': 'waiting', 'attempts': []}
    try:
        while time.monotonic() < deadline:
            state = {'returncode': process.poll(), 'token_exists': token.exists(),
                     'certificate_exists': certificate.exists()}
            report['attempts'].append(state)
            if state['returncode'] is not None:
                report['outcome'] = 'exited'
                raise AssertionError('core Agent exited before readiness; see core.log/core-readiness.json')
            try:
                health = probe(token, certificate, timeout=min(1, max(.001, deadline - time.monotonic())))
                # pkg/status/health.Status serializes Healthy/Unhealthy arrays;
                # the handler returns 200 even when some components are unhealthy.
                state['health'] = health
                if (isinstance(health, dict) and isinstance(health.get('Healthy'), list)
                        and health['Healthy'] and 'Unhealthy' in health
                        and health['Unhealthy'] in (None, [])):
                    report['outcome'] = 'ready'
                    return
            except (OSError, ValueError) as error:
                state['error'] = type(error).__name__
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
        report['outcome'] = 'timeout'
        raise AssertionError('core Agent readiness deadline expired; see core.log/core-readiness.json')
    finally:
        (evidence / 'core-readiness.json').write_text(json.dumps(report, indent=2))

def post(body):
    req = urllib.request.Request('http://127.0.0.1:4319/v1/logs', data=body,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()

def ready():
    try:
        return post(b'{"resourceLogs":[]}')[0] == 200
    except OSError:
        return False

def start():
    log = open(EVIDENCE / 'ddot.log', 'ab', buffering=0)
    process = subprocess.Popen(['/opt/datadog-agent/embedded/bin/otel-agent', 'run',
                                '--core-config', '/task7/core.yaml', '--config',
                                '/task7/collector.yaml', '--sync-delay', '1s'],
                               stdout=log, stderr=subprocess.STDOUT,
                               env={**os.environ, 'DD_API_KEY': 'a' * 32, 'DD_APM_ENABLED': 'true'})
    wait(lambda: ready() if process.poll() is None else False)
    return process

core_log = open(EVIDENCE / 'core.log', 'ab', buffering=0)
core = subprocess.Popen(['/opt/datadog-agent/bin/agent/agent', 'run', '-c', '/task7/core.yaml'], stdout=core_log, stderr=subprocess.STDOUT)
process = None
try:
    wait_core_api(core, pathlib.Path('/opt/datadog-agent/run/auth_token'),
                  pathlib.Path('/opt/datadog-agent/run/ipc_cert.pem'), EVIDENCE)
    for check in ['cpu', 'disk', 'io', 'load', 'memory', 'network', 'uptime']:
        checked = capture_command(['/opt/datadog-agent/bin/agent/agent', 'check', check, '--check-rate', '--json', '-c', '/task7/core.yaml'], EVIDENCE, 'host-check-' + check, timeout=60)
        payload = json.loads(checked.stdout)
        (EVIDENCE / ('host-check-' + check + '.json')).write_bytes(checked.stdout)
        assert payload and payload[0].get('aggregator', {}).get('metrics'), (check, payload)
    process = start()
    headers = {}
    token = pathlib.Path('/opt/datadog-agent/run/auth_token')
    if token.exists():
        headers['Authorization'] = 'Bearer ' + token.read_text().strip()
    request = urllib.request.Request('https://127.0.0.1:7777/', headers=headers)
    with urllib.request.urlopen(request, context=ssl._create_unverified_context()) as response:
        effective = json.load(response)
    (EVIDENCE / 'effective.json').write_text(json.dumps(effective, indent=2))
    assert effective['version'] == '7.84.2+campus1', effective['version']
    assert effective['extension_version'] == 'v0.159.0', effective['extension_version']
    # The host-side harness parses this YAML and checks the effective pipeline.
    initial = (ROOT / 'input.json').read_bytes()
    if '--storage-full' in sys.argv:
        value = json.loads(initial)
        value['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0]['attributes'].append(
            {'key': 'fixture.padding', 'value': {'stringValue': 'x' * 60000}})
        oversized = json.dumps(value).encode()
        failed = None
        for _ in range(20):
            status, body = post(oversized)
            if status != 200 or json.loads(body or b'{}').get('partialSuccess'):
                failed = {'status': status, 'body': body.decode()}
                break
        assert failed, 'full storage acknowledged every handoff'
        wait(lambda: 'no space left on device' in (EVIDENCE / 'ddot.log').read_text())
        assert not accepted
        result = {'storage_failure': 'ENOSPC', 'failed_handoff': failed,
                  'queue_capacity_bytes': 10485760, 'filesystem_bytes': 65536}
        (EVIDENCE / 'result.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result))
        sys.exit(0)
    status, body = post(initial)
    assert status == 200 and not json.loads(body or b'{}').get('partialSuccess'), (status, body)
    wait(lambda: attempts > 0)
    assert not accepted
    # Keep sink unavailable through repeated bounded retries before hard kill.
    wait(lambda: attempts >= 3)
    acknowledged = 1
    overflow = None
    for i in range(100):
        status, body = post(initial)
        if status != 200 or json.loads(body or b'{}').get('partialSuccess'):
            overflow = {'status': status, 'body': body.decode()}
            break
        acknowledged += 1
    assert overflow, 'queue overflow falsely acknowledged'
    assert not accepted
    queue_files = [p for p in (ROOT / 'queue').iterdir() if p.is_file()]
    assert queue_files and sum(p.stat().st_size for p in queue_files) > 0
    process.kill()
    process.wait(timeout=5)
    # Restart the same actual DDOT binary/storage after SIGKILL; no daemon resend.
    blocked = False
    process = start()
    wait(lambda: len(accepted) >= acknowledged)
    # Count each initial request: the contract is at least once, never exactly once.
    assert all(b'radius-original-a' in b for b in accepted)
    result = {'version': effective['version'], 'collector': effective['extension_version'],
              'acknowledged_before_kill': acknowledged, 'received_after_restart': len(accepted),
              'blocked_sink_attempts': attempts, 'overflow': overflow,
              'queue_files': [p.name for p in queue_files], 'hard_kill': 'SIGKILL',
              'encoding': 'protobuf', 'no_daemon_resend': True}
    (EVIDENCE / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
finally:
    if process is not None and process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    server.shutdown()
    core.kill()
    core.wait(timeout=5)
