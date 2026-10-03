"""Fleet script transport fixtures bind machine identities to current enrollment."""
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fleet_certificates


class WindowsCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state.json'
        self.ca = Path(self.tmp.name) / 'ca.pem'
        self.ca.write_text('test trust')
        self.now = 1700000000
        self.hosts = [{'id': 7, 'uuid': 'win-A', 'platform': 'windows',
                       'scripts_enabled': True, 'last_mdm_enrolled_at': None,
                       'last_enrolled_at': '2023-01-01T00:00:00Z',
                       'mdm': {'enrollment_status': 'On'}}]
        self.posts = []
        self.results = {}
        self.trust = patch('fleet_certificates._trusted', return_value=self.now + 10000)
        self.trust.start()
        self.addCleanup(self.trust.stop)

    def api(self, method, path, body=None):
        if method == 'POST':
            self.assertEqual(path, '/api/v1/fleet/scripts/run')
            self.assertEqual(body['host_id'], 7)
            self.posts.append(body)
            return {'host_id': 7, 'execution_id': 'exec-' + str(len(self.posts))}
        if '/hosts/' in path:
            return {'host': self.hosts[0]}
        return self.results.get(path.rsplit('/', 1)[1], {'exit_code': None})

    def refresh(self, request=None, **options):
        return fleet_certificates.refresh('https://fleet.example', 'secret', self.hosts,
            self.path, self.now, request=request or self.api, ca_file=self.ca, **options)

    def row(self, n=1, certs=None, **changes):
        if certs is None:
            certs = [base64.b64encode(b'der').decode()]
        result = {'host_id': 7, 'execution_id': 'exec-' + str(n), 'exit_code': 0,
                  'script_contents': self.posts[n-1]['script_contents'],
                  'created_at': datetime.fromtimestamp(self.now, timezone.utc).isoformat(),
                  'output': json.dumps({'version': 1, 'certificates': certs})}
        result.update(changes)
        return result

    def test_windows_hashes_exact_der_and_uses_script_request_time(self):
        self.assertEqual(self.refresh(), {})
        self.assertEqual(len(self.posts), 1)
        self.results['exec-1'] = self.row()
        self.now += 10
        observed = self.refresh()['win-A']
        self.assertEqual(observed['fingerprints'], [hashlib.sha256(b'der').hexdigest()])
        self.assertEqual(observed['observed_at'], 1700000000)
        self.assertTrue(observed['trust_verified'])

    def test_wrong_host_script_execution_output_or_time_never_authorizes(self):
        for changes in ({'host_id': 8}, {'execution_id': 'other'}, {'script_contents': 'forged'},
                        {'exit_code': 1}, {'exit_code': False}, {'output': '{truncated'},
                        {'output': '{"version":1,"certificates":["bad base64"]}'},
                        {'created_at': '2020-01-01T00:00:00Z'},
                        {'created_at': '2099-01-01T00:00:00Z'}):
            with self.subTest(changes=changes):
                self.path.unlink(missing_ok=True)
                self.posts.clear()
                self.results.clear()
                self.refresh()
                self.results['exec-1'] = self.row(**changes)
                self.assertEqual(self.refresh(), {})

    def test_missing_agent_or_disabled_scripts_does_not_enqueue(self):
        for value in (None, False):
            self.hosts[0]['scripts_enabled'] = value
            self.assertEqual(self.refresh(), {})
            self.assertEqual(self.posts, [])

    def test_offline_and_lost_post_response_queue_are_bounded(self):
        for lose in (False, True):
            self.path.unlink(missing_ok=True)
            self.posts.clear()
            def api(method, path, body=None):
                result = self.api(method, path, body)
                if method == 'POST' and lose:
                    raise OSError('lost response')
                return result
            for _ in range(10):
                try:
                    self.refresh(request=api, pending_ttl=60)
                except OSError:
                    pass
                self.now += 61
            self.assertEqual(len(self.posts), 2)

    def test_stale_reenrolled_and_untrusted_certificates_fail_closed(self):
        self.refresh()
        self.results['exec-1'] = self.row()
        self.assertTrue(self.refresh())
        self.now += 86401
        self.assertEqual(self.refresh(), {})
        self.hosts[0]['last_enrolled_at'] = datetime.fromtimestamp(self.now, timezone.utc).isoformat()
        self.assertEqual(self.refresh(), {})

    def test_no_trust_and_expired_der_cannot_authorize(self):
        self.refresh()
        self.results['exec-1'] = self.row()
        with patch('fleet_certificates._trusted', return_value=None):
            self.assertEqual(self.refresh()['win-A']['fingerprints'], [])
        self.now += 3601
        self.refresh()
        self.results['exec-2'] = self.row(2)
        with patch('fleet_certificates._trusted', return_value=self.now - 1):
            self.assertEqual(self.refresh()['win-A']['fingerprints'], [])

    def test_duplicate_oversized_and_unexpected_schema_fail_closed(self):
        self.refresh()
        for output in ('{"version":1,"version":1,"certificates":[]}',
                       '{"version":true,"certificates":[]}',
                       '{"version":1,"certificates":[],"host_id":7}',
                       json.dumps({'version': 1, 'certificates': ['ZGVy', 'ZGVy']}),
                       ' ' * 9003):
            row = self.row(output=output)
            command = json.loads(self.path.read_text())['commands'][0]
            with self.subTest(output=output[:80]), self.assertRaises(ValueError):
                fleet_certificates._windows_observation(row, command, 7, 1600000000,
                                                        self.now, 86400, self.ca)

    def test_host_reenrollment_discards_cached_identity_and_old_execution(self):
        self.refresh()
        self.results['exec-1'] = self.row()
        self.assertTrue(self.refresh())
        self.hosts[0]['last_enrolled_at'] = '2023-11-14T00:00:00Z'
        self.assertEqual(self.refresh(), {})
        self.assertEqual(len(self.posts), 2)
        self.results['exec-2'] = self.row(2)
        self.assertTrue(self.refresh())
        self.hosts[0]['mdm']['enrollment_status'] = 'Off'
        self.assertEqual(self.refresh(), {})

    def test_empty_success_and_expiry_replace_cached_identity(self):
        self.refresh()
        self.results['exec-1'] = self.row()
        self.assertTrue(self.refresh()['win-A']['fingerprints'])
        self.now += 3601
        self.refresh()
        self.results['exec-2'] = self.row(2, certs=[])
        self.assertEqual(self.refresh()['win-A']['fingerprints'], [])
        self.now += 3601
        self.refresh()
        self.results['exec-3'] = self.row(3)
        self.assertTrue(self.refresh()['win-A']['fingerprints'])
        self.now += 3601
        self.assertEqual(self.refresh()['win-A']['fingerprints'], [])

    def test_duplicate_host_and_missing_enrollment_never_enqueue(self):
        self.hosts.append({**self.hosts[0], 'id': 8})
        self.assertEqual(self.refresh(), {})
        self.assertEqual(self.posts, [])
        self.hosts.pop()
        del self.hosts[0]['last_enrolled_at']
        self.assertEqual(self.refresh(), {})
        self.assertEqual(self.posts, [])

    def test_without_ca_no_fingerprint_is_exposed(self):
        options = dict(request=self.api)
        fleet_certificates.refresh('https://fleet.example', 'secret', self.hosts,
                                  self.path, self.now, **options)
        self.results['exec-1'] = self.row()
        observations = fleet_certificates.refresh('https://fleet.example', 'secret', self.hosts,
                                                  self.path, self.now, **options)
        self.assertEqual(observations['win-A']['fingerprints'], [])
        self.assertFalse(fleet_certificates.readiness(self.hosts, observations, self.now)['ready'])

    def test_script_update_invalidates_observation_and_execution_binding(self):
        self.refresh()
        self.results['exec-1'] = self.row()
        self.assertTrue(self.refresh())
        changed = Path(self.tmp.name) / 'script.ps1'
        changed.write_text(fleet_certificates.WINDOWS_SCRIPT.read_text() + '\n# v2\n')
        with patch.object(fleet_certificates, 'WINDOWS_SCRIPT', changed):
            self.assertEqual(self.refresh(), {})

    def test_second_precision_server_timestamp_accepts_fractional_client_clock(self):
        self.now += 0.125
        self.refresh()
        self.results['exec-1'] = self.row(created_at='2023-11-14T22:13:20Z')
        self.assertIn('win-A', self.refresh())

    def test_missing_execution_is_confirmed_absent_and_retried_on_cadence(self):
        self.refresh()
        def missing(method, path, body=None):
            if '/scripts/results/' in path:
                raise urllib.error.HTTPError(path, 404, 'Not Found', {}, None)
            return self.api(method, path, body)
        self.assertEqual(self.refresh(request=missing), {})
        self.assertEqual(len(self.posts), 1)
        self.now += 3601
        self.refresh()
        self.assertEqual(len(self.posts), 2)

    def test_invalid_or_missing_host_enrollment_timestamp_cannot_use_mdm_fallback(self):
        self.hosts[0]['last_mdm_enrolled_at'] = '2023-01-01T00:00:00Z'
        for timestamp in (None, '', 'invalid', '2023-01-01T00:00:00',
                          '0001-01-01T00:00:00Z', '2099-01-01T00:00:00Z'):
            with self.subTest(timestamp=timestamp):
                self.hosts[0]['last_enrolled_at'] = timestamp
                self.assertEqual(self.refresh(), {})
                self.assertEqual(self.posts, [])

    def test_script_is_readonly_machine_identity_inventory(self):
        self.refresh()
        script = self.posts[0]['script_contents']
        self.assertIn('LocalMachine', script)
        self.assertIn('HasPrivateKey', script)
        self.assertIn('RawData', script)
        self.assertIn('IsSystem', script)
        self.assertNotIn('CurrentUser', script)
        self.assertNotIn('Export-PfxCertificate', script)


if __name__ == '__main__':
    unittest.main()
