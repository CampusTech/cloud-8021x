"""Validate the actual source configuration declarations without cloud access."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('terraform'), 'Terraform required')
class SourceConfigTests(unittest.TestCase):
    def test_static_discovered_and_combined_sources_and_invalid_inputs(self):
        source = (ROOT / 'variables.tf').read_text()
        declaration = re.search(r'variable "radius_clients" \{.*?\n\}', source, re.S)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'main.tf').write_text(declaration + '\nvariable "unifi_api_key" { default = "" }\n'
                                         + 'output "clients" { value = var.radius_clients }\n')
            for clients, api_key, valid in [
                ({'nyc': {'cidrs': ['198.51.100.0/24']}}, '', True),
                ({'nyc': {'unifi_host_id': 'gateway-id'}}, 'fixture', True),
                ({'nyc': {'cidrs': ['10.42.0.0/16'], 'unifi_host_id': 'gateway-id'}}, 'fixture', True),
                ({'nyc': {'unifi_host_id': 'gateway-id'}}, '', False),
                ({'nyc': {}}, 'fixture', False),
                ({'nyc': {'unifi_host_id': ''}}, 'fixture', False),
                ({'nyc': {'unifi_host_id': ' gateway-id'}}, 'fixture', False),
                ({'nyc': {'cidrs': ['0.0.0.0/0']}}, '', False),
                ({'nyc': {'cidrs': ['bad-cidr']}}, '', False),
                ({'nyc\n}': {'cidrs': ['10.0.0.0/24']}}, '', False),
                ({'nyc': {'unifi_host_id': 'same'}, 'atl': {'unifi_host_id': 'same'}}, 'fixture', False),
            ]:
                with self.subTest(clients=clients, key_present=bool(api_key)):
                    (root / 'terraform.tfvars.json').write_text(json.dumps({'radius_clients': clients, 'unifi_api_key': api_key}))
                    result = subprocess.run(['terraform', '-chdir=' + directory, 'plan', '-input=false', '-no-color'],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)

    def test_discovery_template_has_guard_and_boot_secret_dependency(self):
        from render_startup import render
        script = render(source_discovery=True)
        self.assertIn('Requires=radius-source-secrets.service', script)
        self.assertIn('After=radius-source-secrets.service', script)
        self.assertIn('radius_source_check {', script)
        self.assertIn('OnUnitActiveSec=1min', script)
        self.assertIn('$INCLUDE /etc/freeradius/3.0/clients-discovered.conf', script)
        self.assertNotIn('radius_source_check {', render(source_discovery=False))

    def test_discovery_secret_outage_does_not_block_static_radius_at_boot(self):
        from render_startup import render
        script = render(source_discovery=True)
        secret_unit = script.split("<< 'SOURCESECRETSUNITEOF'\n", 1)[1].split('\nSOURCESECRETSUNITEOF', 1)[0]
        self.assertNotIn('Before=freeradius.service', secret_unit)
        self.assertNotIn("<< 'SOURCEDEPENDENCYEOF'", script)
        self.assertIn('systemctl restart radius-source-secrets.service ||', script)


if __name__ == '__main__':
    unittest.main()
