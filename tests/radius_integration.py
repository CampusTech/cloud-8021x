"""Run real EAP-TLS, VLAN, and JSON identity tests in Debian 12 FreeRADIUS.

Requires Docker and Terraform. No cloud calls, host ports, or production secrets.
Certificate inventory mode also replays Access-Accept Class attributes through
real Accounting-Requests and checks that untrusted identities stay unattributed.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
import uuid

from render_startup import render

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--certificate-inventory', action='store_true',
                        help='Exercise exact DER fingerprints and authenticated accounting log identities')
    parser.add_argument('--source-discovery', action='store_true',
                        help='Exercise source freshness guards for real auth and accounting packets')
    parser.add_argument('--container', help='Reuse a disposable test container with dependencies installed')
    args = parser.parse_args()
    container = args.container or ('cloud8021x-vlan-' + uuid.uuid4().hex[:8])

    def docker(*command, **kwargs):
        return subprocess.run(['docker', *command], check=True, **kwargs)

    try:
        if not args.container:
            docker('run', '--name', container, '-d', 'debian:12-slim', 'sleep', 'infinity', stdout=subprocess.DEVNULL)
            docker('exec', container, 'sh', '-c',
                   'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq '
                   'freeradius freeradius-python3 freeradius-utils eapoltest openssl python3 >/tmp/install.log 2>&1')
        # Stop only FreeRADIUS in this test container, including a previous debug run.
        docker('exec', container, 'python3', '-c', '''import os,signal
for pid in os.listdir('/proc'):
    if pid.isdigit():
        try:
            if open('/proc/'+pid+'/comm').read().strip() == 'freeradius':
                os.kill(int(pid),signal.SIGTERM)
        except FileNotFoundError:
            pass
''')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            (path / 'startup.sh').write_text(render(certificate_inventory=args.certificate_inventory, source_discovery=args.source_discovery))
            docker('cp', str(path / 'startup.sh'), container + ':/tmp/startup.sh')
        docker('cp', str(ROOT / 'tests' / 'radius_container.py'), container + ':/tmp/radius_container.py')
        docker('exec', container, 'python3', '/tmp/radius_container.py',
               *(['--certificate-inventory'] if args.certificate_inventory else []),
               *(['--source-discovery'] if args.source_discovery else []))
    finally:
        if not args.container:
            docker('rm', '-f', container, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
