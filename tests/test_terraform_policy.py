import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('terraform'), 'Terraform is required for configuration validation')
class TerraformPolicyTests(unittest.TestCase):
    def test_policy_validation_and_disabled_default(self):
        source = (Path(__file__).resolve().parents[1] / 'variables.tf').read_text()
        declaration = 'variable "radius_vlan_policy"' + source.split('variable "radius_vlan_policy"', 1)[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'main.tf').write_text(declaration + '\noutput "policy" { value = var.radius_vlan_policy }\n')
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
            ]:
                with self.subTest(value=value):
                    (root / 'terraform.tfvars.json').write_text(json.dumps({'radius_vlan_policy': value}))
                    result = subprocess.run(['terraform', '-chdir=' + directory, 'plan', '-input=false', '-no-color'],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, valid, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
