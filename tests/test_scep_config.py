"""Check the generated CA configuration cannot fall back to a shared password."""
import json
import os
import subprocess
import tempfile
from pathlib import Path
import unittest

from render_startup import render


class SCEPConfigTests(unittest.TestCase):
    def test_bootstrap_blocks_removing_enforcement_after_neutral_issuance(self):
        script = render()
        self.assertTrue('# BEGIN CERTIFICATE DOWNGRADE GUARD' in script, 'missing downgrade guard')
        guard = script.split('# BEGIN CERTIFICATE DOWNGRADE GUARD\n', 1)[1].split('# END CERTIFICATE DOWNGRADE GUARD', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'marker'
            guard = guard.replace('/var/lib/cloud-8021x/fingerprint-enforced', str(marker))
            self.assertEqual(subprocess.run(['bash'], input=guard, text=True, capture_output=True).returncode, 0)
            marker.touch()
            self.assertNotEqual(subprocess.run(['bash'], input=guard, text=True, capture_output=True).returncode, 0)

    def test_inventory_template_replaces_untrusted_subject(self):
        script = render(smallstep=True, webhook=True, certificate_inventory=True)
        template = script.split("<<'SCEPTPLEOF'\n", 1)[1].split('\nSCEPTPLEOF', 1)[0]
        self.assertIn('"commonName": "cloud-8021x-inventory"', template)
        self.assertNotIn('.Subject.CommonName', template)

    def test_issuance_always_requires_identity_binding_webhook(self):
        for enabled in (False, True):
            with self.subTest(webhook_enabled=enabled):
                script = render(smallstep=True, webhook=enabled)
                content = script.split('<<CARSAJSON\n', 1)[1].split('\nCARSAJSON', 1)[0]
                result = subprocess.run(['bash', '-c', 'cat <<CAJSON\n' + content + '\nCAJSON'],
                                        env={**os.environ, 'SMALLSTEP_SCEP_CHALLENGE': 'retired-password',
                                             'ACME_WEBHOOK_SECRET_B64': 'c2VjcmV0'},
                                        text=True, capture_output=True, check=True)
                config = json.loads(result.stdout)
                provisioner = config['authority']['provisioners'][0]
                self.assertNotIn('challenge', provisioner, 'shared-password issuance must be removed')
                gates = provisioner.get('options', {}).get('webhooks', [])
                self.assertEqual(len(gates), 1, 'even a disabled service must fail closed')
                self.assertEqual(gates[0]['kind'], 'SCEPCHALLENGE')
                self.assertTrue(gates[0]['url'].endswith('/scep-challenge'))
                self.assertTrue(gates[0]['url'].startswith('https://'))

    def test_acme_authorization_hook_is_in_supported_options_field(self):
        script = render(smallstep=True, webhook=True)
        content = script.split('<<CAJSON\n', 1)[1].split('\nCAJSON', 1)[0]
        result = subprocess.run(['bash', '-c', 'cat <<CAJSON\n' + content + '\nCAJSON'],
                                text=True, capture_output=True, check=True)
        provisioner = json.loads(result.stdout)['authority']['provisioners'][0]
        self.assertNotIn('webhooks', provisioner, 'step-ca ignores this field')
        self.assertEqual(provisioner['options']['webhooks'][0]['kind'], 'AUTHORIZING')
        self.assertIn('templateFile', provisioner['options']['x509'])
