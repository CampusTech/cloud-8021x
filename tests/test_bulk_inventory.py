"""Execute the deployed Fleet bulk script body against controlled HTTP responses."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from inventory_policy import certificate_readiness


class BulkInventoryTests(unittest.TestCase):
    def test_failed_page_keeps_previous_complete_snapshot(self):
        self.run_bulk(fail_page=True)

    def test_success_replaces_snapshot_with_byod_and_removes_old_device(self):
        self.run_bulk(fail_page=False)

    def test_bulk_publishes_exact_certificate_bindings_and_readiness(self):
        self.run_bulk(fail_page=False, certificates=True)

    def test_collector_failure_does_not_starve_legacy_policy_or_enrichment(self):
        for error in (urllib.error.HTTPError('https://inventory.example', 403, 'Forbidden', {}, None),
                      TimeoutError('collector timeout'), ValueError('invalid command identity')):
            with self.subTest(error=type(error).__name__):
                self.run_bulk(False, certificates=True, enforced=False, collector_error=error)

    def test_collector_failure_preserves_enforced_policy_but_refreshes_enrichment(self):
        self.run_bulk(False, certificates=True, enforced=True, collector_error=TimeoutError('collector timeout'))

    def test_invalid_config_never_downgrades_policy_but_refreshes_enrichment(self):
        for value in ('{', '[]', '"invalid"', 'false', '{"certificate_inventory":"false"}'):
            with self.subTest(config=value):
                self.run_bulk(False, certificates=True, config_text=value)

    def test_null_policy_supports_collection_before_enforcement(self):
        self.run_bulk(False, certificates=True, enforced=False, config_text='null')

    def test_null_policy_collection_failure_preserves_legacy_or_sticky_enforcement(self):
        for marker in (False, True):
            with self.subTest(marker=marker):
                self.run_bulk(False, certificates=True, enforced=False, config_text='null',
                              marker=marker, collector_error=TimeoutError('collector timeout'))

    def test_readiness_failure_still_publishes_collected_certificate_policy(self):
        self.run_bulk(False, certificates=True, report_error=ValueError('test-token'))

    def test_sticky_enforcement_marker_prevents_legacy_fallback_after_collection_failure(self):
        self.run_bulk(False, certificates=True, enforced=False, marker=True,
                      collector_error=TimeoutError('test-token'))

    def run_bulk(self, fail_page, certificates=False, enforced=True, collector_error=None,
                 config_text=None, report_error=None, marker=False):
        text = (ROOT / 'scripts/startup.sh').read_text().split("<< 'FLEETCACHEEOF'\n", 1)[1].split('\nFLEETCACHEEOF', 1)[0]
        body = text.split("python3 << 'PYEOF'\n", 1)[1].split('\nPYEOF', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            credentials = base / 'credentials.json'
            credentials.write_text(json.dumps({'url': 'https://inventory.example', 'token': 'test-token'}))
            policy = base / 'policy.json'
            previous = '{"version":1,"updated_at":1,"identities":{"old":{}}}'
            policy.write_text(previous)
            (base / 'collect-certificates').write_text(str(certificates).lower())
            (base / 'client-ca-file').write_text('smallstep-ca.pem')
            (base / 'config.json').write_text(json.dumps({'certificate_inventory': enforced,
                'certificate_max_age': 86400, 'cache_max_age': 3600, 'group_vlans': {'fleet:4': 200}}))
            if config_text is not None:
                (base / 'config.json').write_text(config_text)
            if marker:
                (base / 'fingerprint-enforced').touch()
            body = body.replace('/run/fleet-credentials.json', str(credentials)).replace(
                '/etc/freeradius/3.0/fleet-device-cache.json', str(base / 'enrichment.json')).replace(
                '/etc/freeradius/3.0/device-policy-cache.json', str(policy)).replace(
                '/var/lib/cloud-8021x', str(base)).replace('/etc/freeradius/3.0/vlan-policy.json', str(base / 'config.json'))
            hosts = [{'id': i, 'hardware_serial': '', 'uuid': 'enrollment-' + str(i),
                      'team_id': 4, 'platform': 'ios', 'mdm': {'enrollment_status': 'On (manual)'}} for i in range(100)]
            hosts[0].update({'display_name': 'Personal phone', 'hardware_model': 'iPhone',
                             'device_mapping': [{'email': 'owner@example.com'}]})

            def respond(req, timeout):
                self.assertEqual(req.get_header('Authorization'), 'Bearer test-token')
                if 'page=0&' in req.full_url:
                    return io.BytesIO(json.dumps({'hosts': hosts}).encode())
                if fail_page:
                    raise OSError('upstream unavailable')
                return io.BytesIO(b'{"hosts":[]}')

            fp = 'ab' * 32
            observation = {'enrollment-0': {'fingerprints': [fp], 'observed_at': int(time.time()) - 10,
                                           'trust_verified': True, 'expires_at': {fp: time.time() + 86400}}}
            errors = io.StringIO()
            with patch('fleet_certificates.refresh', return_value=observation, side_effect=collector_error) as refresh, patch('inventory_policy.certificate_readiness', wraps=certificate_readiness, side_effect=report_error), patch('urllib.request.urlopen', side_effect=respond), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                if fail_page:
                    with self.assertRaises(SystemExit):
                        exec(compile(body, 'fleet-bulk-script', 'exec'), {})
                    self.assertEqual(policy.read_text(), previous)
                else:
                    exec(compile(body, 'fleet-bulk-script', 'exec'), {})
                    enrichment = json.loads((base / 'enrichment.json').read_text())
                    self.assertEqual(enrichment['enrollment-0']['email'], 'owner@example.com')
                    self.assertNotIn('test-token', errors.getvalue())
                    if config_text is not None and config_text != 'null':
                        refresh.assert_not_called()
                        self.assertEqual(policy.read_text(), previous)
                        return
                    if collector_error:
                        refresh.assert_called_once()
                        self.assertFalse((base / 'certificate-readiness.json').exists())
                        if enforced or marker:
                            self.assertEqual(policy.read_text(), previous)
                        else:
                            snapshot = json.loads(policy.read_text())
                            self.assertNotIn('old', snapshot['identities'])
                            self.assertEqual(len(snapshot['identities']), 100)
                            self.assertEqual(snapshot['version'], 1)
                            self.assertNotIn('certificates', snapshot)
                        return
                    data = json.loads(policy.read_text())
                    self.assertNotIn('old', data['identities'])
                    self.assertEqual(data['identities']['enrollment-0'],
                                     {'device_id': 'fleet:0', 'groups': ['fleet:4'], 'enrolled': True})
                    self.assertEqual(len(data['identities']), 100)
                    self.assertEqual(data['devices']['fleet:0'], {
                        'serial': '', 'device_name': 'Personal phone',
                        'device_model': 'iPhone', 'device_owner': 'owner@example.com'})
                    self.assertEqual(data['devices']['fleet:1'], {
                        'serial': '', 'device_name': '', 'device_model': '', 'device_owner': ''})
                    if certificates:
                        refresh.assert_called_once()
                        self.assertEqual(data['version'], 2)
                        self.assertEqual(data['certificates'][fp]['device_id'], 'fleet:0')
                        self.assertEqual(data['certificates'][fp]['observed_at'], observation['enrollment-0']['observed_at'])
                        if report_error:
                            self.assertFalse((base / 'certificate-readiness.json').exists())
                            return
                        report = json.loads((base / 'certificate-readiness.json').read_text())
                        self.assertEqual(report['ready_count'], 0 if config_text == 'null' else 1)
                        self.assertFalse(report['ready'])


if __name__ == '__main__':
    unittest.main()
