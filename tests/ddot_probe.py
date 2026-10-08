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
                               env={**os.environ, 'DD_API_KEY': 'a' * 32})
    wait(lambda: ready() if process.poll() is None else False)
    return process

process = start()
try:
    headers = {}
    token = ROOT / 'auth_token'
    if token.exists():
        headers['Authorization'] = 'Bearer ' + token.read_text().strip()
    request = urllib.request.Request('https://127.0.0.1:7777/', headers=headers)
    with urllib.request.urlopen(request, context=ssl._create_unverified_context()) as response:
        effective = json.load(response)
    (EVIDENCE / 'effective.json').write_text(json.dumps(effective, indent=2))
    assert effective['version'] == '7.82.0'
    assert effective['extension_version'] == 'v0.155.0'
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
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)
    server.shutdown()
