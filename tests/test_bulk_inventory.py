"""Execute the deployed Fleet bulk script body against controlled HTTP responses."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


class BulkInventoryTests(unittest.TestCase):
    def test_failed_page_keeps_previous_complete_snapshot(self):
        self.run_bulk(fail_page=True)

    def test_success_replaces_snapshot_with_byod_and_removes_old_device(self):
        self.run_bulk(fail_page=False)

    def run_bulk(self, fail_page):
        text = (ROOT / 'scripts/startup.sh').read_text().split("<< 'FLEETCACHEEOF'\n", 1)[1].split('\nFLEETCACHEEOF', 1)[0]
        body = text.split("python3 << 'PYEOF'\n", 1)[1].split('\nPYEOF', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            credentials = base / 'credentials.json'
            credentials.write_text(json.dumps({'url': 'https://inventory.example', 'token': 'test-token'}))
            policy = base / 'policy.json'
            previous = '{"version":1,"updated_at":1,"identities":{"old":{}}}'
            policy.write_text(previous)
            body = body.replace('/run/fleet-credentials.json', str(credentials)).replace(
                '/etc/freeradius/3.0/fleet-device-cache.json', str(base / 'enrichment.json')).replace(
                '/etc/freeradius/3.0/device-policy-cache.json', str(policy))
            hosts = [{'id': i, 'hardware_serial': '', 'uuid': 'enrollment-' + str(i),
                      'team_id': 4, 'mdm': {'enrollment_status': 'On (manual)'}} for i in range(100)]

            def respond(req, timeout):
                self.assertEqual(req.get_header('Authorization'), 'Bearer test-token')
                if 'page=0&' in req.full_url:
                    return io.BytesIO(json.dumps({'hosts': hosts}).encode())
                if fail_page:
                    raise OSError('upstream unavailable')
                return io.BytesIO(b'{"hosts":[]}')

            with patch('urllib.request.urlopen', side_effect=respond), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
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


if __name__ == '__main__':
    unittest.main()
