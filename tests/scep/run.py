#!/usr/bin/env python3
"""Run actual pinned step-ca SCEP integration without cloud credentials or Docker."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from render_startup import render

VERSION = '0.30.2'

def main():
    system = platform.system().lower()
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64'}.get(platform.machine())
    if system not in ('darwin', 'linux') or not arch:
        raise SystemExit('This integration runner supports macOS/Linux arm64/amd64.')
    asset = f'step-ca_{system}_{VERSION}_{arch}.tar.gz'
    base = f'https://github.com/smallstep/certificates/releases/download/v{VERSION}/'
    with tempfile.TemporaryDirectory(prefix='cloud8021x-scep-') as directory:
        directory = Path(directory)
        checksums = urllib.request.urlopen(base + 'checksums.txt', timeout=60).read().decode()
        checksum = next(line.split()[0] for line in checksums.splitlines() if line.split()[-1] == asset)
        archive = urllib.request.urlopen(base + asset, timeout=60).read()
        if hashlib.sha256(archive).hexdigest() != checksum:
            raise SystemExit('Upstream step-ca archive checksum mismatch')
        binary = directory / 'step-ca'
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
            member = next(item for item in tar.getmembers() if item.isfile() and Path(item.name).name == 'step-ca')
            binary.write_bytes(tar.extractfile(member).read())
        binary.chmod(0o700)
        fixtures = {}
        for mode in ('legacy', 'inventory'):
            script = render(smallstep=True, webhook=True, certificate_inventory=mode == 'inventory')
            if f'STEP_CA_VERSION="{VERSION}"' not in script:
                raise SystemExit('Runner version must match startup.sh pinned step-ca version')
            config = json.loads(script.split('<<CARSAJSON\n', 1)[1].split('\nCARSAJSON', 1)[0])
            templates = {}
            for match in re.finditer(r"cat > ([^\n]+) <<'([A-Z]+)'\n(.*?)\n\2\n", script, re.S):
                path = match[1].strip('"')
                if '/templates/' in path:
                    templates[path] = match[3]
            fixture = directory / (mode + '.json')
            fixture.write_text(json.dumps({'config': config, 'templates': templates}))
            fixtures[mode] = str(fixture)
        subprocess.run(['go', 'test', '-v', '-count=1', './...'], cwd=HERE, check=True,
                       env={**os.environ, 'STEP_CA_BINARY': str(binary),
                            'SCEP_RENDERED_CONFIG': fixtures['legacy'],
                            'SCEP_INVENTORY_RENDERED_CONFIG': fixtures['inventory']})

if __name__ == '__main__':
    main()
