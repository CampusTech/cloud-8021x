#!/usr/bin/env python3
"""Read-only account/credential comparison on the recreated original RED input."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, '/')
import task6_native as native  # The host copies the unchanged original under this module name.

PYTHON = '/opt/datadog-agent/embedded/bin/python3'
proof = {'accounts': {}, 'files': {}, 'commands': {}}
for name in ['freerad', 'root']:
    import pwd
    user = pwd.getpwnam(name)
    shadow = next(line.split(':') for line in Path('/etc/shadow').read_text().splitlines() if line.split(':', 1)[0] == name)
    proof['accounts'][name] = {'uid': user.pw_uid, 'gid': user.pw_gid, 'shell': user.pw_shell,
                              'password_locked': shadow[1].startswith(('!', '*')),
                              'last_change_days': shadow[2], 'maximum_age_days': shadow[4],
                              'account_expire_days': shadow[7],
                              'account_expired': bool(shadow[7] and int(shadow[7]) < int(__import__('time').time()) // 86400)}
for filename in ['/etc/sudoers.d/task6-leaf', '/etc/sudoers.d/cloud-8021x', '/etc/cloud-8021x/config.yaml', '/usr/local/bin/cloud-8021x', '/etc/pam.d/sudo', '/etc/pam.d/common-account', '/usr/lib/sysusers.d/freeradius-common.conf']:
    path = Path(filename)
    if path.exists():
        proof['files'][filename] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': oct(path.stat().st_mode & 0o7777)}

status_code = "from pathlib import Path; print(''.join(line+'\\n' for line in Path('/proc/self/status').read_text().splitlines() if line.split(':',1)[0] in ['Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters']))"
result = subprocess.run(['runuser', '-u', 'freerad', '--', PYTHON, '-c', status_code], capture_output=True, text=True)
proof['commands']['runuser_credentials'] = {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}

leaf = Path('/run/radius-verified-leaves/fixture.pem')
shutil.copyfile(native.CERT / 'personal.pem', leaf)
leaf.chmod(0o600)
shutil.chown(leaf, user='freerad', group='freerad')
command = ['runuser', '-u', 'freerad', '--', '/usr/bin/sudo', '-n', '/usr/local/bin/cloud-8021x', '--config', str(native.CFG), 'radius', 'verify-leaf', str(leaf), 'a' * 64]
result = subprocess.run(command, capture_output=True, text=True)
proof['commands']['direct_same_fixed_helper'] = {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}

policy_log = open('/task6/account-policy.log', 'w')
policy = subprocess.Popen(['runuser', '-u', 'cloud8021x', '--', '/task6-native-fixture', 'serve', str(native.CFG)], stdout=policy_log, stderr=subprocess.STDOUT)
__import__('time').sleep(.4)
assert policy.poll() is None, Path('/task6/account-policy.log').read_text()
radius = native.start_radius()
try:
    proof['native_pid'] = radius.pid
    proof['native_credentials'] = '\n'.join(line for line in Path(f'/proc/{radius.pid}/status').read_text().splitlines() if line.split(':', 1)[0] in ['Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp', 'Seccomp_filters'])
    proof['native_argv'] = Path(f'/proc/{radius.pid}/cmdline').read_bytes().replace(b'\0', b' ').decode().strip()
    try:
        native.authenticate('account-validation-probe')
    except AssertionError as error:
        proof['commands']['native_same_fixed_helper'] = {'eap_accept': False, 'assertion': str(error)}
    else:
        proof['commands']['native_same_fixed_helper'] = {'eap_accept': True}
finally:
    radius.terminate(); radius.wait(timeout=3)
    policy.terminate(); policy.wait(timeout=3); policy_log.close()

Path('/task6/account-validation-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
print(json.dumps(proof, indent=2))

if '--expect-success' in sys.argv:
    assert proof['commands']['direct_same_fixed_helper']['exit'] == 0
    assert proof['commands']['native_same_fixed_helper']['eap_accept'], 'real EAP did not accept'
