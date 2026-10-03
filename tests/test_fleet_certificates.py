"""Authenticated Fleet result fixtures exercise persisted asynchronous collection."""
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import sys
import subprocess
import time
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))


class CollectorTests(unittest.TestCase):
    def test_host_deleted_during_refresh_drops_cached_identity_and_continues(self):
        self.refresh()
        self.results['cmd-1'] = [self.row()]
        self.assertIn('host-A', self.refresh())
        self.hosts.append({**self.hosts[0], 'id': 8, 'uuid': 'host-B'})
        response = io.BytesIO(b'host removed')
        original_api = self.api
        def request(method, path, body=None):
            if path == '/api/v1/fleet/hosts/7':
                raise urllib.error.HTTPError(path, 404, 'Not Found', {}, response)
            return original_api(method, path, body)
        self.api = request
        self.assertEqual(self.refresh(), {})
        self.assertTrue(response.closed)
        state = json.loads(self.path.read_text())
        self.assertNotIn('host-A', state['hosts'])
        self.assertIn('host-B', state['hosts'])
        self.assertEqual(state['commands'][0]['hosts'].keys(), {'host-B'})

    def test_host_detail_other_errors_remain_visible_and_preserve_state(self):
        self.refresh()
        before = self.path.read_bytes()
        for code in (401, 403, 429, 500):
            with self.subTest(code=code):
                response = io.BytesIO(b'failure')
                error = urllib.error.HTTPError('https://fleet.example', code, 'failure', {}, response)
                with patch.object(self, 'api', side_effect=error):
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        self.refresh()
                self.assertIs(raised.exception, error)
                self.assertTrue(response.closed)
                self.assertEqual(self.path.read_bytes(), before)
        with patch.object(self, 'api', side_effect=OSError('connection failed')):
            with self.assertRaises(OSError):
                self.refresh()
        self.assertEqual(self.path.read_bytes(), before)

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('fleet_certificates'),
                             'Fleet certificate collector must exist')
        import fleet_certificates
        self.collector = fleet_certificates
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state.json'
        self.hosts = [{'id': 7, 'uuid': 'host-A', 'platform': 'darwin',
                       'last_mdm_enrolled_at': '2023-01-01T00:00:00Z',
                       'mdm': {'enrollment_status': 'On (personal)'}}]
        self.calls = []
        self.results = {}
        self.counter = 0
        self.uuid_patch = patch('uuid.uuid4',
                                side_effect=self.next_uuid)
        self.uuid_patch.start()
        self.addCleanup(self.uuid_patch.stop)
        self.next_command = 0
        self.now = 1700000000

    def next_uuid(self):
        self.next_command = max(self.next_command, self.counter) + 1
        return 'cmd-' + str(self.next_command)

    def api(self, method, path, body=None):
        self.calls.append((method, path, body))
        if method == 'POST':
            command = plistlib.loads(base64.b64decode(body['command']))
            self.assertTrue(command.get('CommandUUID'))
            self.counter = int(command['CommandUUID'].split('-')[-1])
            self.assertEqual(command['Command'], {'RequestType': 'CertificateList',
                                                  'ManagedOnly': True})
            return {'command_uuid': 'cmd-' + str(self.counter), 'request_type': 'CertificateList'}
        if path.startswith('/api/v1/fleet/hosts/'):
            host_id = int(path.rsplit('/', 1)[1])
            return {'host': next(h for h in self.hosts if h['id'] == host_id)}
        command = path.split('=')[1]
        if int(command.split('-')[-1]) > self.counter:
            raise urllib.error.HTTPError(path, 404, 'Not Found', {}, None)
        return {'results': self.results.get(command, [])}

    def refresh(self, **kwargs):
        return self.collector.refresh('https://fleet.example', 'secret', self.hosts,
                                      self.path, self.now, request=self.api, **kwargs)

    def row(self, certificates=None, **changes):
        certs = [{'Data': b'\x30\x03abc', 'IsIdentity': True}] if certificates is None else certificates
        payload = {'CommandUUID': 'cmd-1', 'Status': 'Acknowledged', 'UDID': 'host-A',
                   'CertificateList': certs}
        row = {'host_uuid': 'host-A', 'command_uuid': 'cmd-1',
               'request_type': 'CertificateList', 'status': 'Acknowledged',
               'updated_at': datetime.fromtimestamp(self.now, timezone.utc).isoformat(),
               'result': base64.b64encode(plistlib.dumps(payload)).decode()}
        row.update(changes)
        return row

    def test_observation_hashes_exact_der_identity_only_and_never_refreshes_poll_time(self):
        self.assertEqual(self.refresh(), {})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.results['cmd-1'] = [self.row([{'Data': b'\x30\x03abc', 'IsIdentity': True},
                                         {'Data': b'root', 'IsIdentity': False}])]
        self.now += 10
        observed = self.refresh()
        self.assertEqual(observed, {'host-A': {'fingerprints': [hashlib.sha256(b'\x30\x03abc').hexdigest()],
                                              'observed_at': 1700000000, 'trust_verified': False}})
        self.now += 100
        self.assertEqual(self.refresh(), observed)
        self.now += 86401
        self.assertEqual(self.refresh(), {})

    def test_second_precision_server_timestamp_accepts_fractional_client_clock(self):
        self.now += 0.125
        self.refresh()
        self.results['cmd-1'] = [self.row(updated_at='2023-11-14T22:13:20Z')]
        self.assertIn('host-A', self.refresh())

    def test_empty_success_replaces_old_identity(self):
        self.refresh()
        self.results['cmd-1'] = [self.row()]
        self.refresh()
        self.now += 3601
        self.refresh()
        self.results['cmd-2'] = [self.row([], command_uuid='cmd-2', result=base64.b64encode(
            plistlib.dumps({'CommandUUID': 'cmd-2', 'Status': 'Acknowledged', 'UDID': 'host-A',
                           'CertificateList': []})).decode())]
        self.assertEqual(self.refresh()['host-A']['fingerprints'], [])

    def test_cross_host_wrong_command_type_and_unacknowledged_results_fail_closed(self):
        for changes in ({'host_uuid': 'other'}, {'command_uuid': 'other'},
                        {'request_type': 'ProfileList'}, {'status': 'Error'},
                        {'result': 'not a plist'},
                        {'updated_at': '2020-01-01T00:00:00Z'},
                        {'updated_at': '2099-01-01T00:00:00Z'}):
            with self.subTest(changes=changes):
                self.path.unlink(missing_ok=True)
                self.counter = 0
                self.next_command = 0
                self.results.clear()
                self.refresh()
                self.results['cmd-1'] = [self.row(**changes)]
                self.assertEqual(self.refresh(), {})

    def test_user_enrollment_id_matches_host_uuid_without_udid(self):
        self.refresh()
        row = self.row()
        payload = plistlib.loads(base64.b64decode(row['result']))
        payload['EnrollmentID'] = payload.pop('UDID')
        row['result'] = base64.b64encode(plistlib.dumps(payload)).decode()
        self.results['cmd-1'] = [row]
        self.assertIn('host-A', self.refresh())

    def test_inner_result_identity_and_command_are_validated(self):
        for key, value in [('UDID', 'other'), ('CommandUUID', 'other'), ('Status', 'Error')]:
            self.path.unlink(missing_ok=True)
            self.counter = 0
            self.next_command = 0
            self.results.clear()
            self.refresh()
            row = self.row()
            payload = plistlib.loads(base64.b64decode(row['result']))
            payload[key] = value
            row['result'] = base64.b64encode(plistlib.dumps(payload)).decode()
            self.results['cmd-1'] = [row]
            self.assertEqual(self.refresh(), {})

    def test_duplicate_host_rows_and_uuids_are_suppressed(self):
        self.refresh()
        self.results['cmd-1'] = [self.row(), self.row()]
        self.assertEqual(self.refresh(), {})
        self.hosts.append({**self.hosts[0], 'id': 8})
        self.assertEqual(self.refresh(), {})

    def test_removed_unenrolled_and_reenrolled_hosts_lose_observation(self):
        for change in ('removed', 'off', 'reenrolled'):
            self.setUp()
            self.refresh()
            self.results['cmd-1'] = [self.row()]
            self.assertTrue(self.refresh())
            if change == 'removed':
                self.hosts.clear()
            elif change == 'off':
                self.hosts[0]['mdm']['enrollment_status'] = 'Off'
            else:
                self.hosts[0]['last_mdm_enrolled_at'] = '2023-11-14T00:00:00Z'
            self.assertEqual(self.refresh(), {})

    def test_offline_expiry_retries_once_without_unbounded_queue(self):
        self.refresh(pending_ttl=60)
        for _ in range(10):
            self.now += 61
            self.refresh(pending_ttl=60)
        self.assertEqual(self.counter, 2)

    def test_batches_bound_creation_and_separate_apple_platforms(self):
        self.hosts = [{**self.hosts[0], 'id': i, 'uuid': 'h-' + str(i),
                       'platform': 'ios' if i % 2 else 'darwin'} for i in range(250)]
        self.refresh(batch_size=25, max_batches=2)
        posted = [call[2]['host_uuids'] for call in self.calls if call[0] == 'POST']
        self.assertEqual(len(posted), 2)
        self.assertTrue(all(len(batch) == 25 for batch in posted))
        by_uuid = {h['uuid']: h for h in self.hosts}
        self.assertTrue(all(len({by_uuid[u]['platform'] for u in batch}) == 1 for batch in posted))

    def test_real_der_chain_filters_unrelated_identities_and_expires_without_new_poll(self):
        root = Path(self.tmp.name)
        def openssl(*args):
            return subprocess.run(['openssl', *args], cwd=root, check=True,
                                  capture_output=True).stdout
        openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1',
                '-subj', '/CN=Trusted Test CA')
        openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=untrusted-name')
        (root / 'extensions').write_text('basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n')
        openssl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                '-set_serial', '1', '-days', '1', '-extfile', 'extensions', '-out', 'leaf.pem')
        der = openssl('x509', '-in', 'leaf.pem', '-outform', 'DER')
        self.now = int(time.time())
        options = {'ca_file': root / 'ca.pem', 'max_age': 172800, 'cadence': 172800}
        self.refresh(**options)
        self.results['cmd-1'] = [self.row([{'Data': der, 'IsIdentity': True},
                                         {'Data': b'unrelated', 'IsIdentity': True}])]
        observations = self.refresh(**options)
        self.assertEqual(observations['host-A']['fingerprints'], [hashlib.sha256(der).hexdigest()])
        self.assertTrue(self.collector.readiness(self.hosts, observations, self.now)['ready'])
        self.now += 86401
        self.assertFalse(self.collector.readiness(self.hosts, observations, self.now,
                                                 max_age=172800)['ready'])
        self.assertEqual(self.refresh(**options)['host-A']['fingerprints'], [])

    def test_state_does_not_reuse_certificates_from_another_fleet_server(self):
        self.refresh()
        self.results['cmd-1'] = [self.row()]
        self.assertTrue(self.refresh())
        self.assertEqual(self.collector.refresh('https://other-fleet.example', 'secret',
            self.hosts, self.path, self.now, request=self.api), {})

    def test_lost_enqueue_response_still_bounds_server_side_offline_queue(self):
        def lose_response(method, path, body=None):
            response = self.api(method, path, body)
            if method == 'POST':
                raise OSError('connection lost after Fleet queued command')
            return response
        for _ in range(10):
            try:
                self.collector.refresh('https://fleet.example', 'secret', self.hosts,
                    self.path, self.now, request=lose_response, pending_ttl=60)
            except OSError:
                pass
            self.now += 61
        self.assertEqual(self.counter, 2)

    def test_api_failure_after_enqueue_preserves_outstanding_command_budget(self):
        self.hosts = [{**self.hosts[0], 'id': i, 'uuid': 'h-' + str(i)} for i in range(3)]
        def fail_second(method, path, body=None):
            if method == 'POST' and self.counter == 1:
                raise OSError('Fleet unreachable')
            return self.api(method, path, body)
        with self.assertRaises(OSError):
            self.collector.refresh('https://fleet.example', 'secret', self.hosts,
                self.path, self.now, request=fail_second, batch_size=1, max_batches=2)
        self.now += 61
        self.refresh(batch_size=1, max_batches=2, cadence=60)
        posted = [call[2]['host_uuids'][0] for call in self.calls if call[0] == 'POST']
        self.assertEqual(len(set(posted)), 3)
        self.assertEqual(len(posted), 3)

    def test_missing_current_mdm_enrollment_timestamp_cannot_reuse_cached_identity(self):
        self.refresh()
        self.results['cmd-1'] = [self.row()]
        self.assertTrue(self.refresh())
        del self.hosts[0]['last_mdm_enrolled_at']
        self.assertEqual(self.refresh(), {})

    def test_readiness_requires_enrollment_supported_platform_and_fresh_identity(self):
        self.hosts += [{**self.hosts[0], 'id': 8, 'uuid': 'windows', 'platform': 'windows',
                       'scripts_enabled': False},
                       {**self.hosts[0], 'id': 9, 'uuid': 'missing'}]
        observations = {'host-A': {'fingerprints': ['a' * 64], 'observed_at': self.now, 'trust_verified': True,
                                    'expires_at': {'a' * 64: self.now + 1000}}}
        report = self.collector.readiness(self.hosts, observations, self.now)
        self.assertFalse(report['ready'])
        self.assertEqual(report['ready_count'], 1)
        self.assertEqual({r['uuid']: r['reason'] for r in report['hosts']},
                         {'host-A': 'ready', 'windows': 'fleet_scripts_unavailable',
                          'missing': 'no_certificate_observation'})


if __name__ == '__main__':
    unittest.main()
