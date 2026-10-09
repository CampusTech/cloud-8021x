"""Actual release-script VCS metadata from a clean PR-like merge checkout."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class ReleaseProvenanceTests(unittest.TestCase):
    def fixture(self, root):
        checkout = root / 'checkout'
        (checkout / 'scripts').mkdir(parents=True)
        (checkout / 'cmd/cloud-8021x').mkdir(parents=True)
        shutil.copyfile(ROOT / 'scripts/build-release.sh', checkout / 'scripts/build-release.sh')
        (checkout / 'scripts/build-release.sh').chmod(0o755)
        (checkout / 'go.mod').write_text('module example.test/release\n\ngo 1.27.2\n')
        (checkout / 'VERSION').write_text('3.0.0\n')
        (checkout / 'cmd/cloud-8021x/main.go').write_text('package main\nvar version string\nfunc main() { println(version) }\n')

        def git(*args):
            return subprocess.check_output(['git', '-C', str(checkout), *args], text=True, stderr=subprocess.DEVNULL).strip()

        git('init', '-b', 'main')
        git('config', 'user.name', 'Disposable release fixture')
        git('config', 'user.email', 'fixture@example.invalid')
        git('add', '.')
        git('commit', '-m', 'fixture base')
        git('checkout', '-b', 'feature')
        (checkout / 'feature.txt').write_text('reviewed feature\n')
        git('add', 'feature.txt')
        git('commit', '-m', 'fixture feature')
        feature = git('rev-parse', 'HEAD')
        git('checkout', 'main')
        (checkout / 'main.txt').write_text('base branch change\n')
        git('add', 'main.txt')
        git('commit', '-m', 'fixture base update')
        git('merge', '--no-ff', 'feature', '-m', 'synthetic PR merge')
        revision = git('rev-parse', 'HEAD')
        self.assertNotEqual(revision, feature)
        self.assertEqual(len(git('rev-list', '--parents', '-n', '1', 'HEAD').split()), 3)
        self.assertEqual(git('status', '--porcelain'), '')
        return checkout, revision

    def build(self, checkout, temporary):
        workflow = yaml.safe_load((ROOT / '.github/workflows/release.yml').read_text())
        job = workflow['jobs']['build']
        step = next(step for step in job['steps'] if step.get('name') == 'Build pinned application and byte-identical aliases')
        toolchain = subprocess.check_output(['go', 'env', 'GOROOT'], cwd=ROOT, text=True).strip()
        environment = {**os.environ, 'PATH': str(Path(toolchain) / 'bin') + os.pathsep + os.environ['PATH'],
                       'RUNNER_TEMP': str(temporary), 'GITHUB_ENV': str(temporary / 'github-env'), 'GOTOOLCHAIN': 'go1.27.2',
                       'GOMAXPROCS': '1', 'GOFLAGS': '-p=1', 'GOPROXY': 'off', 'GOSUMDB': 'off'}
        setup = next((step for step in job['steps'] if step.get('name') == 'Select external application output'), None)
        if setup is not None:
            subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', setup['run']], cwd=checkout, env=environment, check=True)
            environment.update(line.split('=', 1) for line in (temporary / 'github-env').read_text().splitlines())
        result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', step['run']], cwd=checkout,
                                env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        binaries = list(temporary.rglob('cloud-8021x-linux-*'))
        self.assertEqual(len(binaries), 2)
        checksums = dict(line.split()[::-1] for line in (binaries[0].parent / 'SHA256SUMS').read_text().splitlines())
        metadata = {}
        for binary in binaries:
            architecture = binary.name.rsplit('-', 1)[1]
            info = subprocess.check_output(['go', 'version', '-m', str(binary)], text=True)
            metadata[architecture] = info
            print(architecture, *(line.strip() for line in info.splitlines() if 'vcs.revision=' in line or 'vcs.modified=' in line), flush=True)
            self.assertIn(': go1.27.2\n', info)
            self.assertIn('CGO_ENABLED=0', info)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            self.assertEqual(checksums[binary.name], digest)
            alias = binary.with_name('acme-authz-webhook-linux-' + architecture)
            self.assertEqual(alias.read_bytes(), binary.read_bytes())
            self.assertEqual(checksums[alias.name], digest)
        return metadata

    def test_scan_checksum_and_upload_consume_the_external_output(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/release.yml').read_text())
        job = workflow['jobs']['build']
        steps = job['steps']
        setup = next(step for step in steps if step.get('name') == 'Select external application output')
        self.assertIn('RELEASE_OUTPUT=$RUNNER_TEMP/cloud-8021x-application-release', setup['run'])
        scan = next(step for step in steps if step.get('name') == 'Scan both actual release binaries')
        self.assertIn('"$RELEASE_OUTPUT/cloud-8021x-linux-$arch"', scan['run'])
        checksums = next(step for step in steps if step.get('name') == 'Verify all mandatory checksums')
        self.assertEqual(checksums['working-directory'], '${{ env.RELEASE_OUTPUT }}')
        upload = next(step for step in steps if step.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['with']['path'], '${{ env.RELEASE_OUTPUT }}/*')

    def test_clean_merge_revision_stays_clean_for_both_architectures(self):
        with tempfile.TemporaryDirectory(prefix='cloud8021x-release-provenance-') as directory:
            root = Path(directory)
            checkout, revision = self.fixture(root)
            metadata = self.build(checkout, root)
            for architecture, info in metadata.items():
                with self.subTest(architecture=architecture):
                    self.assertIn('vcs.revision=' + revision, info)
                    self.assertIn('vcs.modified=false', info, info)
                    self.assertNotIn('+dirty', info)
            self.assertEqual(subprocess.check_output(['git', '-C', str(checkout), 'status', '--porcelain'], text=True), '')

    def test_intentionally_dirty_source_is_not_reported_clean(self):
        with tempfile.TemporaryDirectory(prefix='cloud8021x-release-dirty-') as directory:
            root = Path(directory)
            checkout, revision = self.fixture(root)
            with (checkout / 'cmd/cloud-8021x/main.go').open('a') as source:
                source.write('// intentional uncommitted source change\n')
            for architecture, info in self.build(checkout, root).items():
                with self.subTest(architecture=architecture):
                    self.assertIn('vcs.revision=' + revision, info)
                    self.assertIn('vcs.modified=true', info)


if __name__ == '__main__':
    unittest.main()
