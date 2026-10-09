"""Reboots and parallel deployments must not reuse another VM's monitoring identity."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/datadog_hostname.py'
sys.path.insert(0, str(ROOT / 'scripts'))
import datadog_hostname


class DatadogHostnameTests(unittest.TestCase):
    def test_replacement_persists_directory_after_file_and_closes_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'datadog.yaml'
            config.write_text('hostname: stale\n')
            config.chmod(0o640)
            original = config.stat()
            actions = []
            real_fsync, real_replace = os.fsync, os.replace
            def fsync(fd):
                actions.append('directory' if os.fstat(fd).st_mode & 0o170000 == 0o040000 else 'file')
                real_fsync(fd)
            def replace(source, target):
                actions.append('rename')
                real_replace(source, target)
            with patch('datadog_hostname.os.fsync', side_effect=fsync), \
                    patch('datadog_hostname.os.replace', side_effect=replace):
                datadog_hostname.configure(config, 'radius-primary', 'test-project', 'test')
            self.assertEqual(actions, ['file', 'rename', 'directory'])
            self.assertEqual(config.stat().st_mode, original.st_mode)
            self.assertEqual((config.stat().st_uid, config.stat().st_gid), (original.st_uid, original.st_gid))

    def test_directory_sync_failure_closes_descriptor_and_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'datadog.yaml'
            config.write_text('hostname: stale\n')
            directory_fds = []
            real_fsync = os.fsync
            def fsync(fd):
                if os.fstat(fd).st_mode & 0o170000 == 0o040000:
                    directory_fds.append(fd)
                    raise OSError('directory sync failed')
                real_fsync(fd)
            with patch('datadog_hostname.os.fsync', side_effect=fsync):
                with self.assertRaisesRegex(OSError, 'directory sync failed'):
                    datadog_hostname.configure(config, 'radius-primary', 'test-project', 'test')
            self.assertEqual(len(directory_fds), 1)
            with self.assertRaises(OSError):
                os.fstat(directory_fds[0])
            self.assertEqual(list(Path(directory).iterdir()), [config])

    def configure(self, config, *, project='canary-project-bb45', suffix='canary-bb45', dry_run=False):
        args = [sys.executable, str(SCRIPT), '--config', str(config), '--instance',
                'radius-primary', '--project', project, '--suffix', suffix]
        if dry_run:
            args.append('--dry-run')
        return subprocess.run(args, capture_output=True, text=True)

    def test_reboot_replaces_active_hostname_and_unsafe_aliases_once(self):
        source = ('api_key: SECRET-MUST-NOT-BE-PRINTED\n# hostname: old-template\n'
                  'hostname: radius-primary\n"hostname": old-active-copy\n'
                  'host_aliases:\n  - radius-primary\n  - stale-other-project\n'
                  '# host_aliases: []\nhost_aliases: [radius-primary]\n'
                  'logs_enabled: true\nproxy:\n  hostname: nested-value\n')
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'datadog.yaml'
            config.write_text(source)
            config.chmod(0o640)
            result = self.configure(config)
            self.assertEqual(result.returncode, 0, result.stderr)
            updated = config.read_text()
            self.assertEqual(updated.count('\nhostname:'), 1)
            self.assertIn('hostname: "radius-primary-canary-bb45"\n', updated)
            self.assertIn('host_aliases: ["radius-primary.canary-project-bb45"]\n', updated)
            self.assertNotIn('stale-other-project', updated)
            self.assertNotIn('old-active-copy', updated)
            self.assertIn('api_key: SECRET-MUST-NOT-BE-PRINTED\n', updated)
            self.assertIn('proxy:\n  hostname: nested-value\n', updated)
            self.assertEqual(config.stat().st_mode & 0o777, 0o640)
            self.assertEqual(config.stat().st_uid, os.getuid())
            self.assertNotIn('SECRET-MUST-NOT-BE-PRINTED', result.stdout + result.stderr)
            before = config.stat().st_mtime_ns
            self.assertEqual(self.configure(config).returncode, 0)
            self.assertEqual(config.read_text(), updated)
            self.assertEqual(config.stat().st_mtime_ns, before, 'idempotent reboot must not rewrite the file')

    def test_indentless_alias_sequence_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'datadog.yaml'
            config.write_text('host_aliases:\n- radius-primary\n- stale-alias\nlogs_enabled: true\n')
            result = self.configure(config)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('stale-alias', config.read_text())
            self.assertIn('logs_enabled: true', config.read_text())

    def test_dry_run_does_not_write_or_print_agent_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'datadog.yaml'
            source = 'api_key: SECRET-MUST-NOT-BE-PRINTED\nhostname: radius-primary\n'
            config.write_text(source)
            result = self.configure(config, dry_run=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(config.read_text(), source)
            self.assertNotIn('SECRET-MUST-NOT-BE-PRINTED', result.stdout + result.stderr)

    def test_invalid_suffix_fails_before_touching_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'datadog.yaml'
            source = 'hostname: radius-primary\n'
            config.write_text(source)
            for suffix in ('-canary', 'canary-', 'canary\nhostname: other', 'UPPER', 'a' * 64):
                with self.subTest(suffix=suffix):
                    self.assertNotEqual(self.configure(config, suffix=suffix).returncode, 0)
                    self.assertEqual(config.read_text(), source)

    def test_legacy_override_preserves_hostname_with_project_scoped_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'datadog.yaml'
            config.write_text('# hostname: <HOSTNAME>\n')
            result = self.configure(config, project='production-project', suffix='')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('hostname: "radius-primary"\n', config.read_text())
            self.assertIn('host_aliases: ["radius-primary.production-project"]', config.read_text())

    def test_invalid_encoding_does_not_print_secret_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'datadog.yaml'
            source = b'api_key: SECRET-MUST-NOT-BE-PRINTED\xff\n'
            config.write_bytes(source)
            result = self.configure(config)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(config.read_bytes(), source)
            self.assertNotIn('SECRET-MUST-NOT-BE-PRINTED', result.stdout + result.stderr)


@unittest.skipUnless(shutil.which('terraform'), 'Terraform required')
class DatadogHostnameTerraformTests(unittest.TestCase):
    def evaluate(self, project, suffix=None):
        source = (ROOT / 'datadog-hostname.tf').read_text()
        source = source.replace('google_project.this.project_id', json.dumps(project))
        source = source.replace('google_compute_instance.radius.name', '"radius-primary"')
        source = source.replace('google_compute_instance.radius_secondary.name', '"radius-secondary"')
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'main.tf').write_text(source)
            (Path(directory) / 'terraform.tfvars.json').write_text(json.dumps({'datadog_hostname_suffix': suffix}))
            result = subprocess.run(['terraform', '-chdir=' + directory, 'console'],
                                    input='jsonencode(local.datadog_radius_hosts)',
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(json.loads(result.stdout))

    def test_two_default_deployments_have_distinct_canonical_hostnames(self):
        first = self.evaluate('project-a-1111')
        second = self.evaluate('project-b-2222')
        self.assertEqual(first['radius-primary'], 'radius-primary-project-a-1111')
        self.assertEqual(second['radius-primary'], 'radius-primary-project-b-2222')
        self.assertTrue(set(first.values()).isdisjoint(second.values()))

    def test_explicit_canary_and_legacy_production_override(self):
        production = self.evaluate('production-project', '')
        canary = self.evaluate('canary-project', 'canary-bb45')
        self.assertEqual(production, {'radius-primary': 'radius-primary', 'radius-secondary': 'radius-secondary'})
        self.assertEqual(canary['radius-primary'], 'radius-primary-canary-bb45')
        self.assertTrue(set(production.values()).isdisjoint(canary.values()))

    def test_invalid_namespace_is_rejected_by_terraform(self):
        source = (ROOT / 'datadog-hostname.tf').read_text()
        source = source.replace('google_project.this.project_id', '"test-project"')
        source = source.replace('google_compute_instance.radius.name', '"radius-primary"')
        source = source.replace('google_compute_instance.radius_secondary.name', '"radius-secondary"')
        for suffix in ('-canary', 'canary-', 'UPPER', 'a' * 47, 'canary\nhostname: other'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / 'main.tf').write_text(source)
                (Path(directory) / 'terraform.tfvars.json').write_text(json.dumps({'datadog_hostname_suffix': suffix}))
                result = subprocess.run(['terraform', '-chdir=' + directory, 'console'],
                                        input='jsonencode(local.datadog_radius_hosts)',
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Datadog hostname suffix must', result.stderr)


if __name__ == '__main__':
    unittest.main()
