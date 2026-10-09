# Historical parity fixture only; current deployment is tested by test_green_deployment.py.
"""Exercise the actual boot helper with a fake Secret Manager client."""
from pathlib import Path
import os
import stat
import subprocess
import tempfile
import unittest


STARTUP = (Path(__file__).resolve().parents[1] / 'tests/legacy/scripts/startup.sh').read_text()


class AccountingKeyTests(unittest.TestCase):
    def test_restore_after_tmpfs_loss_and_preserve_key_on_fetch_failure(self):
        helper = STARTUP.split("<< 'ACCOUNTKEYEOF'\n", 1)[1].split('\nACCOUNTKEYEOF', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / 'radius-accounting-key'
            helper = helper.replace('/run/radius-accounting-key', str(key)).replace('${project_id}', 'fixture')
            (root / 'restore.sh').write_text(helper)
            (root / 'gcloud').write_text('#!/bin/bash\nprintf "%s" "$FIXTURE_KEY"\nexit "$FIXTURE_STATUS"\n')
            (root / 'chown').write_text('#!/bin/bash\nexit 0\n')
            for executable in ('gcloud', 'chown'):
                (root / executable).chmod(0o700)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ['PATH'],
                       FIXTURE_KEY='k' * 64, FIXTURE_STATUS='0')

            def restore():
                return subprocess.run(['bash', str(root / 'restore.sh')], env=env,
                                      capture_output=True, text=True)

            self.assertEqual(restore().returncode, 0)
            self.assertEqual(key.read_text(), 'k' * 64)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            key.unlink()  # /run is empty after a reboot.
            self.assertEqual(restore().returncode, 0)
            for value, status in [('short', '0'), ('replacement' * 8, '1')]:
                env.update(FIXTURE_KEY=value, FIXTURE_STATUS=status)
                self.assertNotEqual(restore().returncode, 0)
                self.assertEqual(key.read_text(), 'k' * 64)
                self.assertEqual(list(root.glob('radius-accounting-key.*')), [])

    def test_freeradius_requires_boot_key_even_when_bootstrap_is_skipped(self):
        dependency = STARTUP.split("<< 'ACCOUNTKEYDEPEOF'\n", 1)[1].split('\nACCOUNTKEYDEPEOF', 1)[0]
        self.assertIn('Requires=radius-accounting-key.service', dependency)
        self.assertIn('After=radius-accounting-key.service', dependency)


if __name__ == '__main__':
    unittest.main()
