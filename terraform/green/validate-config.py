#!/usr/bin/env python3
"""Local Terraform runner only; invokes the reviewed Go strict validator, no cloud."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

try:
    request = json.loads(sys.stdin.read(2 * 1024 * 1024 + 1))
    if set(request) != {'config'} or not isinstance(request['config'], str) or len(request['config'].encode()) > 1024 * 1024:
        raise ValueError('bounded config required')
    validator = Path(sys.argv[1]).resolve(strict=True)
    if not validator.is_file() or not os.access(validator, os.X_OK):
        raise ValueError('reviewed local validator required')
    with tempfile.TemporaryDirectory(prefix='cloud8021x-config-validation-') as directory:
        config = Path(directory) / 'config.yaml'
        config.write_text(request['config'])
        config.chmod(0o600)
        result = subprocess.run([str(validator), 'config', 'validate', '--config', str(config)], capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('strict Go configuration validation failed')
    print(json.dumps({'validated': 'true'}))
except (OSError, ValueError, subprocess.SubprocessError, IndexError):
    print('strict nonsecret configuration validation refused; run the reviewed Go config validator locally for diagnostics', file=sys.stderr)
    sys.exit(1)
