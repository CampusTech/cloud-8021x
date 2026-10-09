"""Release transport preserves Debian names without forbidden Actions upload paths."""
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'scripts/artifact-transport.py'
NAME = 'datadog-agent_1:7.84.2-1+campus1_arm64.deb'


class ArtifactTransport(unittest.TestCase):
    def make_input(self, directory):
        directory.mkdir()
        (directory / NAME).write_bytes(b'exact archive fixture')
        digest = hashlib.sha256((directory / NAME).read_bytes()).hexdigest()
        (directory / 'SHA256SUMS').write_text(f'{digest}  {NAME}\n')

    def test_component_uploads_only_safe_transport_files(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/release.yml').read_text())
        for job in ['components', 'ca']:
            with self.subTest(job=job):
                steps = workflow['jobs'][job]['steps']
                upload = next(step for step in steps if step.get('uses', '').startswith('actions/upload-artifact@'))
                self.assertEqual(upload['with']['path'], 'transport/', 'raw Debian names with colons reach Actions upload validator')
                self.assertTrue(any('artifact-transport.py pack component transport/component.tar' in step.get('run', '') for step in steps))
        steps = workflow['jobs']['bundle']['steps']
        self.assertTrue(any('artifact-transport.py unpack' in step.get('run', '') for step in steps))

    def test_exact_colon_names_and_bytes_survive_roundtrip(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_input(root / 'input')
            archive = root / 'component.tar'
            subprocess.run([sys.executable, str(HELPER), 'pack', str(root / 'input'), str(archive)], check=True)
            self.assertFalse(any(':' in path.name for path in root.glob('component*')))
            output = root / 'output'
            subprocess.run([sys.executable, str(HELPER), 'unpack', str(archive), str(output)], check=True)
            self.assertEqual((output / NAME).read_bytes(), b'exact archive fixture')
            self.assertEqual((output / 'SHA256SUMS').read_bytes(), (root / 'input/SHA256SUMS').read_bytes())
            archive.write_bytes(archive.read_bytes() + b'tamper')
            rejected = root / 'rejected'
            result = subprocess.run([sys.executable, str(HELPER), 'unpack', str(archive), str(rejected)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(rejected.exists())

    def test_reject_unsafe_members_before_publishing_directory(self):
        for kind in ['traversal', 'absolute', 'symlink', 'hardlink', 'duplicate', 'oversized', 'unlisted']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / 'component.tar'
                with tarfile.open(archive, 'w') as contents:
                    member = tarfile.TarInfo({'traversal': '../escape', 'absolute': '/escape'}.get(kind, NAME))
                    if kind in ['symlink', 'hardlink']:
                        member.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
                        member.linkname = '/outside'
                    member.size = 0
                    contents.addfile(member, io.BytesIO())
                    if kind == 'duplicate':
                        contents.addfile(member, io.BytesIO())
                    if kind == 'oversized':
                        member = tarfile.TarInfo('huge')
                        member.size = (1 << 30) + 1
                        contents.fileobj.write(member.tobuf())
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                Path(str(archive) + '.sha256').write_text(digest + '  component.tar\n')
                output = root / 'output'
                result = subprocess.run([sys.executable, str(HELPER), 'unpack', str(archive), str(output)], capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
