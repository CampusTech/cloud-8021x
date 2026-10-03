import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('terraform'), 'Terraform is required for configuration validation')
class TerraformPolicyTests(unittest.TestCase):
    def test_broker_rate_limit_is_configurable_and_positive(self):
        source = (Path(__file__).resolve().parents[1] / 'variables.tf').read_text()
        match = re.search(r'variable "scep_broker_requests_per_minute" \{.*?\n\}', source, re.S)
        self.assertIsNotNone(match, 'Fleet needs a separate configurable broker rate limit')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'main.tf').write_text(match[0] + '\noutput "limit" { value = var.scep_broker_requests_per_minute }\n')
            for value, valid in [(None, True), (100, True), (1000, True), (5000, True),
                                 (0, False), (-1, False), (1000.5, False)]:
                with self.subTest(value=value):
                    (root / 'terraform.tfvars.json').write_text(json.dumps(
                        {} if value is None else {'scep_broker_requests_per_minute': value}))
                    result = subprocess.run(['terraform', '-chdir=' + directory, 'plan', '-input=false', '-no-color'],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)
                    if value is None:
                        self.assertRegex(result.stdout, r'limit\s*=\s*1000')

    def test_broker_does_not_share_ca_ban_policy(self):
        source = (Path(__file__).resolve().parents[1] / 'webhook.tf').read_text()
        backend = re.search(r'resource "google_compute_backend_service" "scep_broker" \{.*?\n\}', source, re.S)[0]
        self.assertRegex(backend, r'security_policy\s*=\s*google_compute_security_policy\.scep_broker\[0\]\.id')
        policy = re.search(r'resource "google_compute_security_policy" "scep_broker" \{.*?\n\}', source, re.S)
        self.assertIsNotNone(policy)
        self.assertRegex(policy[0], r'action\s*=\s*"throttle"')
        self.assertRegex(policy[0], r'exceed_action\s*=\s*"deny\(429\)"')
        self.assertRegex(policy[0], r'enforce_on_key\s*=\s*"IP"')
        self.assertRegex(policy[0], r'count\s*=\s*var\.scep_broker_requests_per_minute')
        self.assertRegex(policy[0], r'interval_sec\s*=\s*60')
        self.assertNotIn('ban_duration_sec', policy[0])
        self.assertNotIn('rate_based_ban', policy[0])

    def test_webhook_requires_smallstep_for_all_enablement_combinations(self):
        source = (Path(__file__).resolve().parents[1] / 'variables.tf').read_text()
        declarations = '\n'.join(re.search(r'variable "' + name + r'" \{.*?\n\}', source, re.S)[0]
                                 for name in ('enable_smallstep_ca', 'enable_acme_webhook'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'main.tf').write_text(declarations + '\noutput "enabled" { value = var.enable_acme_webhook }\n')
            for smallstep in (False, True):
                for webhook in (False, True):
                    with self.subTest(smallstep=smallstep, webhook=webhook):
                        (root / 'terraform.tfvars.json').write_text(json.dumps({
                            'enable_smallstep_ca': smallstep, 'enable_acme_webhook': webhook}))
                        result = subprocess.run(['terraform', '-chdir=' + directory, 'plan', '-input=false', '-no-color'],
                                                capture_output=True, text=True)
                        self.assertEqual(result.returncode == 0, not webhook or smallstep,
                                         result.stdout + result.stderr)
                        if webhook and not smallstep:
                            self.assertIn('enable_acme_webhook requires enable_smallstep_ca', result.stdout + result.stderr)

    def test_policy_validation_and_disabled_default(self):
        source = (Path(__file__).resolve().parents[1] / 'variables.tf').read_text()
        declaration = 'variable "radius_vlan_policy"' + source.split('variable "radius_vlan_policy"', 1)[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'main.tf').write_text('variable "radius_clients" { default = { nyc = {}, atl = {} } }\n' + declaration + '\noutput "policy" { value = var.radius_vlan_policy }\n')
            for value, valid in [
                (None, True),
                ({'group_vlans': {'staff': 100}}, True),
                ({'group_vlans': {'staff': 0}}, False),
                ({'group_vlans': {'staff': 4095}}, False),
                ({'group_vlans': {'staff': 100.5}}, False),
                ({'group_vlans': {}, 'fallback_vlan': 4094}, True),
                ({'group_vlans': {}, 'fallback_vlan': 4095}, False),
                ({'group_vlans': {}, 'cache_max_age': 60}, False),
                ({'group_vlans': {}, 'cache_max_age': 300}, False),
                ({'group_vlans': {}, 'cache_max_age': 600}, True),
                ({'group_vlans': {}, 'cache_max_age': 60, 'cache_file': '/run/custom.json'}, True),
                ({'group_vlans': {}, 'cache_file': 'relative.json'}, False),
                ({'group_vlans': {}, 'certificate_inventory': True, 'certificate_max_age': 86400}, True),
                ({'group_vlans': {}, 'certificate_inventory': True, 'certificate_max_age': 0}, False),
                ({'group_vlans': {}, 'certificate_max_age': 30.5}, False),
                ({'certificate_inventory': True, 'certificate_max_age': 600}, False),
                ({'certificate_inventory': True, 'certificate_max_age': 3600}, False),
                ({'certificate_inventory': True, 'certificate_max_age': 7199}, False),
                ({'certificate_inventory': True, 'certificate_max_age': 7200}, True),
                ({'certificate_inventory': True, 'certificate_max_age': 7200.5}, False),
                ({'locations': {'nyc': {'group_vlans': {'staff': 100}}, 'atl': {'group_vlans': {'staff': 120}}}}, True),
                ({'locations': {'nyc': {'dynamic_vlans': False}}}, True),
                ({'locations': {'nyc': {'dynamic_vlans': False, 'group_vlans': {}}}}, True),
                ({'locations': {'nyc': {'dynamic_vlans': False, 'group_vlans': {'staff': 100}}}}, False),
                ({'locations': {'nyc': {'dynamic_vlans': False, 'fallback_vlan': 100}}}, False),
                ({'locations': {'nyc': {'dynamic_vlans': 'invalid'}}}, False),
                ({'locations': {'nyc': {'group_vlans': {'staff': 4095}}}}, False),
                ({'locations': {'nyc': {'group_vlans': {}, 'fallback_vlan': 0}}}, False),
                ({'locations': {'': {'group_vlans': {'staff': 100}}}}, False),
                ({'locations': {' nyc ': {'group_vlans': {'staff': 100}}}}, False),
                ({'locations': {'typo-office': {'group_vlans': {'staff': 100}}}}, False),
            ]:
                with self.subTest(value=value):
                    (root / 'terraform.tfvars.json').write_text(json.dumps({'radius_vlan_policy': value}))
                    result = subprocess.run(['terraform', '-chdir=' + directory, 'plan', '-input=false', '-no-color'],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
