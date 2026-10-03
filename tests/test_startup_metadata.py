"""Exercise deployed metadata selection at the GCE UTF-8 byte boundary."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from render_startup import render

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('terraform'), 'Terraform required')
class StartupMetadataTests(unittest.TestCase):
    def test_private_object_transport_is_readable_before_both_instances_boot(self):
        transport = (ROOT / 'startup-transport.tf').read_text()
        compute = (ROOT / 'compute.tf').read_text()
        bucket = transport.split('resource "google_storage_bucket" "startup_scripts" {', 1)[1].split('\n}', 1)[0]
        obj = transport.split('resource "google_storage_bucket_object" "startup_script" {', 1)[1].split('\n}', 1)[0]
        reader = transport.split('resource "google_storage_bucket_iam_member" "startup_script_reader" {', 1)[1].split('\n}', 1)[0]
        self.assertRegex(bucket, r'uniform_bucket_level_access\s*=\s*true')
        self.assertRegex(bucket, r'public_access_prevention\s*=\s*"enforced"')
        self.assertIn('google_project_service.apis["storage.googleapis.com"]', bucket)
        self.assertIn('"storage.googleapis.com"', (ROOT / 'main.tf').read_text())
        for resource in (bucket, obj, reader):
            self.assertNotRegex(resource, r'\b(?:count|for_each)\s*=', 'transport resources must plan when rendered size is unknown')
        self.assertIn('sha256(local.startup_script)', obj)
        self.assertRegex(obj, r'content\s*=\s*local.startup_script')
        self.assertRegex(obj, r'create_before_destroy\s*=\s*true')
        self.assertIn('"roles/storage.objectViewer"', reader)
        self.assertIn('"serviceAccount:${google_service_account.radius.email}"', reader)
        for name in ('radius', 'radius_secondary'):
            instance = compute.split('resource "google_compute_instance" "' + name + '" {', 1)[1].split('\n}', 1)[0]
            dependencies = instance.split('depends_on = [', 1)[1]
            self.assertIn('google_storage_bucket_iam_member.startup_script_reader', dependencies)

    def test_metadata_transport_respects_utf8_limit_on_both_instances(self):
        compute = (ROOT / 'compute.tf').read_text()
        transport = ROOT / 'startup-transport.tf'
        # Evaluate the production selection expressions with a fake object URL;
        # no provider, credentials, state, or network calls are needed.
        selection = ''
        if transport.exists():
            selection = transport.read_text().split('# BEGIN METADATA SELECTION\n')[1].split('# END METADATA SELECTION')[0]
            selection = selection.replace('google_storage_bucket_object.startup_script.bucket', '"fixture-bucket"')
            selection = selection.replace('google_storage_bucket_object.startup_script.name', '"startup-fixture.sh"')
        metadata = re.findall(r'\n  metadata\s*=\s*(local\.startup_metadata|\{\s*startup-script\s*=\s*local\.startup_script\s*\})', compute)
        self.assertEqual(len(metadata), 2, 'both VMs must share guarded metadata selection')
        sources = ('a' * 262143, 'a' * 262144, 'a' * 262145, 'é' * 131072, 'é' * 131073,
                   render(smallstep=True, webhook=True, certificate_inventory=True, source_discovery=True))
        for source in sources:
            with self.subTest(bytes=len(source.encode())):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'main.tf').write_text('variable "script" { type = string }\nlocals { startup_script = var.script }\n' + selection)
                    (root / 'terraform.tfvars.json').write_text(json.dumps({'script': source}))
                    for expression in metadata:
                        result = subprocess.run(['terraform', '-chdir=' + directory, 'console'],
                                                input='jsonencode(' + ' '.join(expression.split()) + ')', text=True,
                                                capture_output=True, check=True)
                        value = json.loads(json.loads(result.stdout))
                        if len(source.encode()) <= 262144:
                            self.assertEqual(value, {'startup-script': source})
                        else:
                            self.assertEqual(value, {'startup-script-url': 'gs://fixture-bucket/startup-fixture.sh'})


if __name__ == '__main__':
    unittest.main()
