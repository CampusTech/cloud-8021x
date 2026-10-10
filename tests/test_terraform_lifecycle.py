#!/usr/bin/env python3
"""Offline Google-provider plans over synthetic state; never applies or refreshes."""
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstanceLifecycle(unittest.TestCase):
    def test_existing_disks_survive_image_change(self):
        source = (ROOT / 'compute.tf').read_text()
        nodes = dict(re.findall(r'resource "google_compute_instance" "(radius(?:_secondary)?)" \{(.*?)(?=\nresource |\Z)', source, re.S))
        self.assertEqual(set(nodes), {'radius', 'radius_secondary'})
        with tempfile.TemporaryDirectory(prefix='cloud8021x-tf-lifecycle-') as directory:
            fixture = Path(directory)
            config = {
                'terraform': {'required_providers': {'google': {
                    'source': 'hashicorp/google', 'version': '= 5.45.2'}}},
                'provider': {'google': {'project': 'cloud8021x-disposable-fixture',
                                        'access_token': 'synthetic-never-used'}},
                'variable': {'image': {'default': 'debian-cloud/debian-12'},
                             'disk_size': {'default': 20}},
                'resource': {'google_compute_instance': {}},
            }
            for name, node in nodes.items():
                value = {'name': 'radius-primary' if name == 'radius' else 'radius-secondary', 'project': 'cloud8021x-disposable-fixture',
                         'zone': 'us-central1-a', 'machine_type': 'e2-small',
                         'boot_disk': [{'initialize_params': [{'image': '${var.image}',
                                         'size': '${var.disk_size}', 'type': 'pd-balanced'}]}],
                         'network_interface': [{'network': 'default'}]}
                lifecycle = re.search(r'\blifecycle\s*\{([^{}]*)\}', node, re.S)
                # Let Terraform parse the exact lifecycle block from production.
                if lifecycle:
                    (fixture / (name + '.tf')).write_text(
                        'resource "google_compute_instance" "' + name + '" {\n' +
                        'lifecycle {' + lifecycle[1] + '}\n}\n')
                    # Separate override file combines the real lifecycle with
                    # synthetic resource attributes, avoiding any cloud inputs.
                    (fixture / (name + '.tf')).rename(fixture / (name + '_override.tf'))
                config['resource']['google_compute_instance'][name] = value
            (fixture / 'main.tf.json').write_text(json.dumps(config))

            def run(*args, success=True):
                # No credential discovery, backend, refresh or apply. The token
                # above is deliberately invalid and the fixture has no data sources.
                result = subprocess.run(['terraform', '-chdir=' + directory, *args],
                                        text=True, capture_output=True,
                                        env={**os.environ, 'TF_IN_AUTOMATION': '1'})
                if success:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result

            def plan(name, *args, success=True):
                result = run('plan', '-refresh=false', '-input=false', '-out=' + name,
                             *args, success=success)
                if result.returncode:
                    return result
                return json.loads(run('show', '-json', name).stdout)

            run('init', '-backend=false', '-input=false')
            schema = json.loads(run('providers', 'schema', '-json').stdout)
            version = schema['provider_schemas']['registry.terraform.io/hashicorp/google'][
                'resource_schemas']['google_compute_instance']['version']
            created = plan('create.tfplan')
            resources = []
            for resource in created['planned_values']['root_module']['resources']:
                attributes = resource['values']
                attributes['id'] = 'projects/cloud8021x-disposable-fixture/zones/us-central1-a/instances/' + attributes['name']
                attributes['instance_id'] = '123456789' if resource['name'] == 'radius' else '987654321'
                attributes['guest_accelerator'] = []
                attributes['boot_disk'][0]['source'] = 'projects/cloud8021x-disposable-fixture/zones/us-central1-a/disks/' + attributes['name']
                resources.append({'mode': 'managed', 'type': 'google_compute_instance',
                                  'name': resource['name'],
                                  'provider': 'provider["registry.terraform.io/hashicorp/google"]',
                                  'instances': [{'schema_version': version, 'attributes': attributes,
                                                 'sensitive_attributes': []}]})
            (fixture / 'terraform.tfstate').write_text(json.dumps({
                'version': 4, 'terraform_version': '1.14.5', 'serial': 1,
                'lineage': '79f163c7-6d38-40ae-a03a-b2df9aff8031',
                'outputs': {}, 'resources': resources}))
            baseline = plan('baseline.tfplan')
            self.assertTrue(all('delete' not in r['change']['actions'] for r in baseline['resource_changes']))
            changed = plan('image.tfplan', '-var=image=debian-cloud/debian-13')
            for resource in changed['resource_changes']:
                self.assertNotIn('delete', resource['change']['actions'],
                                 'image-only update would destroy ' + resource['address'])
                self.assertEqual(resource['change']['after']['boot_disk'][0]['initialize_params'][0]['image'],
                                 'debian-cloud/debian-12', 'image drift must not pretend to upgrade the disk')
            resized = plan('resize.tfplan', '-var=disk_size=30', success=False)
            # This provider treats boot initialization disk size as replacement;
            # it must be visible and blocked, never hidden by whole-disk ignore.
            self.assertIsInstance(resized, subprocess.CompletedProcess)
            self.assertIn('prevent_destroy', resized.stderr)
            for node in nodes.values():
                self.assertRegex(node, r'image\s*=\s*"debian-cloud/debian-13"')
                self.assertRegex(node, r'prevent_destroy\s*=\s*true')
                self.assertRegex(node, r'ignore_changes\s*=\s*\[boot_disk\[0\]\.initialize_params\[0\]\.image\]')



if __name__ == '__main__':
    unittest.main()
