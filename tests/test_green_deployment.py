"""Offline deployment contract; synthetic providers, no cloud credentials or state."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class GreenDeployment(unittest.TestCase):
    def test_separate_state_has_no_shared_resource_owner(self):
        source = '\n'.join(p.read_text() for p in (ROOT / 'terraform/green').glob('*.tf'))
        resources = re.findall(r'resource\s+"([^"]+)"\s+"([^"]+)"', source)
        self.assertTrue(resources, 'isolated runnable green entrypoint missing')
        permitted = {'google_compute_instance', 'google_compute_disk', 'google_compute_address',
                     'google_compute_firewall', 'google_compute_instance_group', 'google_service_account',
                     'google_secret_manager_secret_iam_member', 'google_kms_crypto_key_iam_member',
                     'google_storage_bucket', 'google_storage_bucket_object', 'google_storage_bucket_iam_member',
                     'google_project_iam_member', 'google_project_iam_custom_role', 'terraform_data'}
        self.assertEqual(set(t for t, _ in resources) - permitted, set())
        self.assertNotRegex(source, r'resource\s+"google_.*(?:_iam_policy|_iam_binding|backend_service|sql_|network|subnetwork)"')
        self.assertNotIn('terraform_remote_state', source)
        self.assertNotIn('secret_data', source)
        for owner in ['google_compute_instance', 'google_compute_disk', 'google_compute_address', 'google_compute_instance_group']:
            self.assertIn('resource "' + owner + '"', source)

    def test_loader_is_bounded_verified_and_incoming_only(self):
        source = (ROOT / 'scripts/startup.sh').read_text()
        for forbidden in ('apt-get', 'pip install', 'python3', 'systemctl restart', '/etc/step-ca/', 'curl |', '| bash'):
            self.assertNotIn(forbidden, source)
        for required in ('sha256sum', 'Metadata-Flavor: Google', 'bootstrap', '--incoming', 'flock', 'mktemp', 'stat', 'manifest.json'):
            self.assertIn(required, source)
        self.assertLess(len(source.encode()), 16384)


class ActualTerraformContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import json
        import subprocess
        cls.subprocess = subprocess
        cls.json = json
        cls.module = ROOT / 'terraform/green'
        result = subprocess.run(['terraform', '-chdir=' + str(cls.module), 'test', '-var-file=tests/fixtures/fixture.tfvars.json', '-json', '-verbose'], text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        cls.events = [json.loads(line) for line in result.stdout.splitlines()]
        cls.plans = {e['@testrun']: e['test_plan'] for e in cls.events if e['type'] == 'test_plan'}

    def test_creates_only_green_and_existing_state_is_noop(self):
        created = self.plans['new_green_plan']['resource_changes']
        self.assertGreater(len(created), 40)
        for resource in created:
            if resource['mode'] != 'managed':
                continue
            self.assertEqual(resource['change']['actions'], ['create'], resource['address'])
            if resource['type'] in {'google_compute_instance', 'google_compute_disk', 'google_compute_address', 'google_compute_instance_group', 'google_compute_firewall'}:
                self.assertTrue(resource['change']['after']['name'].startswith('green-test-'), resource['address'])
        self.assertTrue(all(r['change']['actions'] == ['no-op'] for r in self.plans['existing_green_state_plan']['resource_changes']))

    def test_peer_health_allows_only_both_protocols_between_green_accounts(self):
        # The seeded synthetic state resolves the service-account email, unknown
        # during the initial creation plan. No real state is read.
        changes = {r['address']: r['change']['after'] for r in self.plans['existing_green_state_plan']['resource_changes']}
        peer = changes['google_compute_firewall.peer']
        self.assertEqual({(a['protocol'], tuple(a['ports'])) for a in peer['allow']},
                         {('udp', ('18121',)), ('tcp', ('18122',))})
        account = changes['google_service_account.green']['email']
        self.assertTrue(account)
        self.assertEqual(peer['source_service_accounts'], [account])
        self.assertEqual(peer['target_service_accounts'], [account])
        for key in ('source_ranges', 'destination_ranges', 'source_tags', 'target_tags'):
            self.assertFalse(peer.get(key), key)

    def test_exact_serialized_yaml_passes_strict_go_validator(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix='cloud8021x-green-config-') as directory:
            validator = pathlib.Path(directory) / 'cloud-8021x'
            built = self.subprocess.run(['go', 'build', '-o', str(validator), './cmd/cloud-8021x'], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for role, content in self.plans['new_green_plan']['output_changes']['rendered_config']['after'].items():
                path = pathlib.Path(directory) / (role + '.yaml')
                path.write_text(content)
                result = self.subprocess.run([str(validator), 'config', 'validate', '--config', str(path)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                checked = self.subprocess.run(['python3', str(self.module / 'validate-config.py'), str(validator)], input=self.json.dumps({'config':content}), text=True, capture_output=True)
                self.assertEqual(checked.returncode,0,checked.stderr)
                self.assertEqual(self.json.loads(checked.stdout), {'validated':'true'})
                path.write_text(content + '\nunknown_injected_field: true\n')
                result = self.subprocess.run([str(validator), 'config', 'validate', '--config', str(path)], text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                checked = self.subprocess.run(['python3', str(self.module / 'validate-config.py'), str(validator)], input=self.json.dumps({'config':path.read_text()}), text=True, capture_output=True)
                self.assertNotEqual(checked.returncode,0)
                self.assertNotIn('unknown_injected_field', checked.stdout+checked.stderr)


    def test_tampered_artifact_pin_refused(self):
        import tempfile
        values = self.json.loads((self.module / 'tests/fixtures/fixture.tfvars.json').read_text())
        values['application_sha256'] = '0' * 64
        with tempfile.TemporaryDirectory(prefix='cloud8021x-green-refusal-') as directory:
            path = pathlib.Path(directory) / 'invalid.tfvars.json'
            path.write_text(self.json.dumps(values))
            result = self.subprocess.run(['terraform', '-chdir=' + str(self.module), 'test', '-var-file=' + str(path), '-no-color'], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('independent deployment pin', result.stdout + result.stderr)

if __name__ == "__main__":
    unittest.main()
