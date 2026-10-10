"""Development release test: actual executable bytes, architecture and SHA pins."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseArtifactsTests(unittest.TestCase):
    def test_both_architectures_unified_binary_and_mandatory_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(['bash', str(ROOT / 'scripts/build-release.sh'), directory],
                                    cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            outputs = Path(directory)
            checksums = {}
            for line in (outputs / 'SHA256SUMS').read_text().splitlines():
                digest, name = line.split()
                self.assertNotIn(name, checksums)
                checksums[name] = digest
            self.assertEqual(set(checksums), {'cloud-8021x-linux-amd64', 'cloud-8021x-linux-arm64'})
            self.assertEqual({path.name for path in outputs.iterdir()}, set(checksums) | {'SHA256SUMS'})
            for arch, machine in [('amd64', 62), ('arm64', 183)]:
                name = f'cloud-8021x-linux-{arch}'
                data = (outputs / name).read_bytes()
                self.assertEqual(data[:4], b'\x7fELF')
                self.assertEqual(int.from_bytes(data[18:20], 'little'), machine)
                self.assertEqual(checksums[name], hashlib.sha256(data).hexdigest())
                info = subprocess.check_output(['go', 'version', '-m', str(outputs / name)], text=True)
                self.assertIn('go1.27.2', info)
                self.assertIn('CGO_ENABLED=0', info)
            version = (ROOT / 'VERSION').read_text().strip()
            self.assertRegex(version, r'^\d+\.\d+\.\d+$')
            self.assertFalse((ROOT / 'webhook/VERSION').exists())
            self.assertFalse((ROOT / 'webhook/main.go').exists())
