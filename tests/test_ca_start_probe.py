"""The CA startup probe must inspect this start, not months of old logs."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CAStartProbeTests(unittest.TestCase):
    def run_probe(self, current_failure=False):
        script = (ROOT / 'scripts/startup.sh').read_text().split("<<'PROBE'\n", 1)[1].split('\nPROBE', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = {
                'curl': '#!/bin/sh\nexit 0\n',
                'systemctl': '''#!/bin/sh
case "$*" in
  *ActiveEnterTimestamp*) echo '2026-06-06 06:01:00 UTC';;
  *ExecMainStartTimestamp*) echo '2026-10-07 23:53:25 UTC';;
  *) exit 1;;
esac
''',
                'journalctl': '''#!/bin/sh
case "$*" in
 *2026-06-06*) echo 'old failed start does not have decrypter';;
 *) if [ "$CURRENT_FAILURE" = 1 ]; then echo 'current CA does not have decrypter'; fi;;
esac
''',
            }
            for name, contents in commands.items():
                p = root / name
                p.write_text(contents)
                p.chmod(0o755)
            return subprocess.run(['bash'], input=script, text=True, capture_output=True,
                                  env={**os.environ, 'PATH': str(root)+os.pathsep+os.environ['PATH'],
                                       'CURRENT_FAILURE': str(int(current_failure))})

    def test_healthy_restart_ignores_previous_invocation_failure(self):
        result = self.run_probe()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_current_invocation_failure_still_fails_probe(self):
        self.assertEqual(self.run_probe(current_failure=True).returncode, 1)
