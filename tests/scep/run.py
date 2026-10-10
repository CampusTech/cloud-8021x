#!/usr/bin/env python3
"""Run actual pinned step-ca SCEP integration without cloud credentials or Docker."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True,
                        help='locally built, security-scanned step-ca executable for this host')
    parser.add_argument('--sha256', required=True, help='mandatory SHA256 of that exact executable')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    checksum = hashlib.sha256(binary.read_bytes()).hexdigest()
    if len(args.sha256) != 64 or checksum != args.sha256:
        raise SystemExit('Pinned step-ca executable checksum mismatch')
    if not os.access(binary, os.X_OK):
        raise SystemExit('Pinned step-ca executable is not executable')
    print(f'Actual step-ca fixture: {binary.name} sha256={checksum}', flush=True)
    with tempfile.TemporaryDirectory(prefix='cloud8021x-scep-') as directory:
        directory = Path(directory)
        subprocess.run(['go', 'test', '-run', '^TestExportSCEPFixtures$',
                        './internal/adapters/stepca'], cwd=HERE.parent.parent, check=True,
                       env={**os.environ, 'C8021X_SCEP_FIXTURE_OUTPUT': str(directory)})
        fixtures = {mode: str(directory / (mode + '.json')) for mode in ('legacy', 'inventory')}
        subprocess.run(['go', 'test', '-v', '-count=1', './...'], cwd=HERE, check=True,
                       env={**os.environ, 'STEP_CA_BINARY': str(binary),
                            'SCEP_RENDERED_CONFIG': fixtures['legacy'],
                            'SCEP_INVENTORY_RENDERED_CONFIG': fixtures['inventory']})

if __name__ == '__main__':
    main()
