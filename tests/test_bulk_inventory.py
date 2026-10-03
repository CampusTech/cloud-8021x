"""Execute the deployed Fleet bulk script body against controlled HTTP responses."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


class BulkInventoryTests(unittest.TestCase):
    def test_failed_page_keeps_previous_complete_snapshot(self):
        self.run_bulk(fail_page=True)

    def test_success_replaces_snapshot_with_byod_and_removes_old_device(self):
        self.run_bulk(fail_page=False)

    def test_bulk_publishes_exact_certificate_bindings_and_readiness(self):
        self.run_bulk(fail_page=False, certificates=True)

    def run_bulk(self, fail_page, certificates=False):
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
            (base / 'config.json').write_text(json.dumps({'certificate_inventory': True,
                'certificate_max_age': 86400, 'cache_max_age': 3600, 'group_vlans': {'fleet:4': 200}}))
            body = body.replace('/run/fleet-credentials.json', str(credentials)).replace(
                '/etc/freeradius/3.0/fleet-device-cache.json', str(base / 'enrichment.json')).replace(
                '/etc/freeradius/3.0/device-policy-cache.json', str(policy)).replace(
                '/var/lib/cloud-8021x', str(base)).replace('/etc/freeradius/3.0/vlan-policy.json', str(base / 'config.json'))
            hosts = [{'id': i, 'hardware_serial': '', 'uuid': 'enrollment-' + str(i),
                      'team_id': 4, 'platform': 'ios', 'mdm': {'enrollment_status': 'On (manual)'}} for i in range(100)]

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
            with patch('fleet_certificates.refresh', return_value=observation) as refresh, patch('urllib.request.urlopen', side_effect=respond), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                if fail_page:
                    with self.assertRaises(SystemExit):
                        exec(compile(body, 'fleet-bulk-script', 'exec'), {})
                    self.assertEqual(policy.read_text(), previous)
                else:
                    exec(compile(body, 'fleet-bulk-script', 'exec'), {})
                    data = json.loads(policy.read_text())
                    self.assertNotIn('old', data['identities'])
                    self.assertEqual(data['identities']['enrollment-0'],
                                     {'device_id': 'fleet:0', 'groups': ['fleet:4'], 'enrolled': True})
                    self.assertEqual(len(data['identities']), 100)
                    if certificates:
                        refresh.assert_called_once()
                        self.assertEqual(data['version'], 2)
                        self.assertEqual(data['certificates'][fp]['device_id'], 'fleet:0')
                        self.assertEqual(data['certificates'][fp]['observed_at'], observation['enrollment-0']['observed_at'])
                        report = json.loads((base / 'certificate-readiness.json').read_text())
                        self.assertEqual(report['ready_count'], 1)
                        self.assertFalse(report['ready'])


if __name__ == '__main__':
    unittest.main()
