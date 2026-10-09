"""Fail-closed release input integrity, before invoking any archive metadata tool."""
import hashlib
import importlib.util
import os
import subprocess
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('bundle', Path(__file__).resolve().parents[1] / 'scripts/build-bundle.py')
bundle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bundle)


class InputIntegrity(unittest.TestCase):
    def test_complete_pinned_input_and_reject_tampered_or_unlisted_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data = b'package archive fixture'
            (root / 'native.deb').write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            (root / 'SHA256SUMS').write_text(digest + '  native.deb\n')
            self.assertEqual(bundle.verified_inputs(root), {'native.deb': digest})
            (root / 'native.deb').write_bytes(data + b'tamper')
            with self.assertRaises(ValueError):
                bundle.verified_inputs(root)
            (root / 'native.deb').write_bytes(data)
            (root / 'unexpected.deb').write_bytes(data)
            with self.assertRaises(ValueError):
                bundle.verified_inputs(root)

    def test_reject_missing_duplicate_traversal_and_symlink_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'native.deb').write_bytes(b'archive')
            digest = hashlib.sha256(b'archive').hexdigest()
            with self.assertRaises(ValueError):
                bundle.verified_inputs(root)
            for text in [f'{digest}  ../native.deb\n', f'{digest}  native.deb\n' * 2]:
                (root / 'SHA256SUMS').write_text(text)
                with self.assertRaises(ValueError):
                    bundle.verified_inputs(root)
            (root / 'linked.deb').symlink_to(root / 'native.deb')
            (root / 'SHA256SUMS').write_text(f'{digest}  linked.deb\n{digest}  native.deb\n')
            with self.assertRaises(ValueError):
                bundle.verified_inputs(root)


class NativeInputs(unittest.TestCase):
    def test_bootstrap_refuses_missing_bundle_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            marker = directory / 'called'
            docker = directory / 'docker'
            docker.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 1\n')
            docker.chmod(0o755)
            env = {**os.environ, 'PATH': str(directory) + os.pathsep + os.environ['PATH']}
            for script in ['test_bootstrap_native.sh', 'test_auth_retention.sh']:
                with self.subTest(script=script):
                    marker.unlink(missing_ok=True)
                    result = subprocess.run(['bash', str(bundle.ROOT / 'scripts' / script)], env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(marker.exists(), 'missing bundle reached Docker before mandatory input validation')

    def test_native_install_refuses_invalid_bundle_before_docker(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            marker = directory / 'called'
            docker = directory / 'docker'
            docker.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 1\n')
            docker.chmod(0o755)
            go = directory / 'go'
            go.write_text('#!/bin/sh\nexit 0\n')
            go.chmod(0o755)
            invalid = directory / 'incomplete-bundle'
            invalid.mkdir()
            env = {**os.environ, 'PATH': str(directory) + os.pathsep + os.environ['PATH']}
            result = subprocess.run(['bash', str(bundle.ROOT / 'tests/native_package_acceptance.sh'), 'arm64', str(invalid)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists(), 'unverified bundle reached Docker before mandatory input validation')

    def test_native_runner_refuses_missing_bundle_before_inspection(self):
        spec = importlib.util.spec_from_file_location('native_runner', bundle.ROOT / 'tests/native_radius_integration.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        from unittest.mock import patch
        with patch.dict(os.environ, {}, clear=True), patch.object(runner.subprocess, 'run') as command:
            with self.assertRaisesRegex(SystemExit, 'bundle|BUNDLE'):
                runner.run_native('explicit-owned-fixture', 'policy')
            command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
