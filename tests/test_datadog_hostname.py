"""Fresh-install Terraform keeps each VM monitoring identity project-scoped."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


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
