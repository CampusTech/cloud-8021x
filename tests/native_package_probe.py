"""Actual Debian package ABI, failed-close and original-receipt source proof gate.

Development-only; requires an explicitly opted-in disposable container. Never
installed on a RADIUS node. No PostgreSQL, production traffic or credentials.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import time

assert os.environ.get('C8021X_PACKAGE_FIXTURE') == 'task10'
assert Path('/.dockerenv').is_file()
ROOT = Path('/tmp/native-package-probe')
ROOT.mkdir()
DATA = ROOT / 'data'
DATA.mkdir()
shutil.chown(DATA, user='freerad', group='freerad')
(ROOT / 'dictionary').write_text('$INCLUDE /usr/share/freeradius/dictionary\n')
PROOF = Path('/var/lib/cloud-8021x-source-proof')
PROOF.mkdir(mode=0o755)
CONFIG = hashlib.sha256(b'fixture-config').hexdigest()
CLIENT = hashlib.sha256(b'fixture-client').hexdigest()
VERSION = '3.2.10+dfsg-2+trixie.campus4'
for package in ['freeradius', 'freeradius-common', 'freeradius-config', 'freeradius-utils', 'freeradius-rest', 'freeradius-postgresql', 'libfreeradius3']:
    version = subprocess.check_output(['dpkg-query', '-W', '-f=${Status} ${Version}', package], text=True)
    assert version == 'install ok installed ' + VERSION, (package, version)
for library in ['rlm_detail.so', 'rlm_expr.so', 'rlm_rest.so', 'rlm_sql_postgresql.so']:
    result = subprocess.run(['ldd', '/usr/lib/freeradius/' + library], capture_output=True, text=True, check=True)
    assert 'not found' not in result.stdout, result.stdout
    print('ABI', library, result.stdout, flush=True)


def publish(observed, address='127.0.0.1'):
    generation = hashlib.sha256(os.urandom(32)).hexdigest()
    marker = PROOF / generation / CONFIG / CLIENT / address
    marker.parent.mkdir(parents=True)
    marker.write_bytes(b'')
    os.utime(marker, (observed, observed))
    (PROOF / 'current').write_text(generation)
    return marker


def start(kind='static', destination=None, pause=False):
    destination = destination or DATA / 'detail'
    config = f'''prefix = /usr
exec_prefix = /usr
libdir = /usr/lib/freeradius
raddbdir = {ROOT}
radacctdir = {DATA}
logdir = {DATA}
run_dir = {DATA}
name = freeradius
max_request_time = 30
security {{
 user = freerad
 group = freerad
}}
log {{
 destination = stdout
}}
client fixture {{
 ipaddr = 127.0.0.1
 secret = fixture-secret
 c8021x_source_kind = {kind}
 c8021x_config = {CONFIG}
 c8021x_client_hash = {CLIENT}
 c8021x_max_age = 2
}}
modules {{
 expr {{
 }}
 detail accounting_detail {{
  filename = {destination}
  permissions = 0600
  header = "%t"
  locking = no
 }}
 exec fixture_pause {{
  wait = yes
  program = "/bin/sleep 3"
 }}
}}
server default {{
 listen {{
  type = acct
  ipaddr = 127.0.0.1
  port = 1913
 }}
 accounting {{
  {'fixture_pause' if pause else ''}
  if ("%{{source_fresh:}}" != "1") {{
   update control {{
    Response-Packet-Type := Do-Not-Respond
   }}
   return
  }}
  accounting_detail
  if (fail) {{
   update control {{
    Response-Packet-Type := Do-Not-Respond
   }}
  }}
 }}
}}
'''
    (ROOT / 'radiusd.conf').write_text(config)
    result = subprocess.run(['/usr/sbin/freeradius', '-XC', '-d', str(ROOT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    log = ROOT / f'server-{time.time_ns()}.log'
    stream = log.open('w')
    server = subprocess.Popen(['/usr/sbin/freeradius', '-X', '-d', str(ROOT)], stdout=stream, stderr=subprocess.STDOUT)
    for _ in range(100):
        if 'Ready to process requests' in log.read_text():
            return server, stream
        assert server.poll() is None, log.read_text()
        time.sleep(.02)
    raise AssertionError(log.read_text())


def stop(server, stream):
    server.terminate()
    server.wait(timeout=5)
    stream.close()


def packet(name, expected, timeout=1):
    payload = f'Acct-Status-Type = Start\nAcct-Session-Id = {name}\nUser-Name = fixture\nNAS-IP-Address = 127.0.0.1\n'
    result = subprocess.run(['radclient', '-r', '1', '-t', str(timeout), '127.0.0.1:1913', 'acct', 'fixture-secret'], input=payload, capture_output=True, text=True)
    assert (result.returncode == 0) == expected, (name, result.returncode, result.stdout, result.stderr)
    print('PASS', name, 'ACK' if expected else 'no ACK', flush=True)


server, stream = start()
try:
    packet('successful-native-close', True)
    assert (DATA / 'detail').stat().st_size > 0
finally:
    stop(server, stream)
server, stream = start(destination='/dev/full')
try:
    packet('failed-native-close', False)
finally:
    stop(server, stream)
server, stream = start(kind='dynamic')
try:
    original_pid = server.pid
    publish(int(time.time()))
    packet('fresh-original-source', True)
    time.sleep(2.1)
    packet('expired-original-source', False)
    publish(int(time.time()))
    packet('root-refresh-without-restart', True)
    publish(int(time.time()) + 60)
    packet('future-observation', False)
    publish(int(time.time()), '192.0.2.1')
    packet('wrong-original-source', False)
    marker = publish(int(time.time()))
    marker.chmod(0o666)
    packet('writable-proof', False)
    marker = publish(int(time.time()))
    marker.unlink()
    marker.symlink_to('/dev/null')
    packet('symlink-proof', False)
    assert server.pid == original_pid and server.poll() is None
finally:
    stop(server, stream)
# Slow processing must use the packet's original receipt, not wall time at lookup.
server, stream = start(kind='dynamic', pause=True)
try:
    publish(int(time.time()))
    packet('original-receipt-through-processing-delay', True, timeout=5)
finally:
    stop(server, stream)
print('PASS actual coherent Trixie native package ABI and packet contracts', flush=True)
