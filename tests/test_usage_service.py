"""Persistent monitoring is isolated from authentication and its credentials."""
import contextlib
import base64
import io
import json
from pathlib import Path
import sys
import tempfile
import subprocess
from render_startup import render
import unittest
from unittest.mock import patch
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import radius_usage_service


SECRET = 'projects/test-project/secrets/radius-usage-credentials/versions/latest'


class UsageServiceTests(unittest.TestCase):
    def test_disabled_bootstrap_stops_only_its_managed_collector_and_keeps_state(self):
        script = render()
        block = script.split('# Usage collection is independent of authentication.', 1)[1].split('\n', 1)[1].split('# Restart Datadog Agent', 1)[0]
        for contents, managed in ((radius_usage_service.MARKER, True),
                                  ('# somebody else owns this', False),
                                  (radius_usage_service.MARKER + ' not actually managed', False)):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                unit = root / 'radius-usage-collector.service'
                unit.write_text(contents)
                checkpoint = root / 'checkpoint.json'
                checkpoint.write_text('preserve')
                code = root / 'radius_usage_service.py'
                code.write_text('preserve code')
                trace = root / 'commands'
                body = block.replace('/etc/systemd/system/radius-usage-collector.service', str(unit))
                prelude = f'systemctl() {{ echo "$*" >> "{trace}"; }}\n'
                subprocess.run(['bash', '-e', '-c', prelude + body], check=True)
                self.assertEqual(checkpoint.read_text(), 'preserve')
                self.assertEqual(code.read_text(), 'preserve code')
                self.assertEqual(unit.read_text(), contents)
                commands = trace.read_text() if trace.exists() else ''
                if managed:
                    self.assertEqual(commands, 'disable --now radius-usage-collector.service\n')
                else:
                    self.assertEqual(commands, '')

    def test_install_rejects_shared_state_directory_without_changing_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original_mode = root.stat().st_mode & 0o777
            (root / 'unrelated-service-state').write_text('preserve')
            with patch('radius_usage_service.socket.gethostname', return_value='radius-primary'), \
                    patch('radius_usage_service.os.geteuid', return_value=0), \
                    patch('radius_usage_service.subprocess.run') as command:
                result = radius_usage_service.main([
                    'install', '--secret', SECRET, '--install-dir', str(root / 'code'),
                    '--state', str(root / 'checkpoint.json'),
                    '--unit-path', str(root / 'radius-usage-collector.service')])
            self.assertEqual(result, 1)
            self.assertEqual(root.stat().st_mode & 0o777, original_mode)
            self.assertFalse((root / 'code').exists())
            command.assert_not_called()

    def test_install_rejects_shared_code_directory_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = root / 'code'
            code.mkdir(mode=0o700)
            (code / 'unrelated-script.py').write_text('preserve')
            with patch('radius_usage_service.socket.gethostname', return_value='radius-primary'), \
                    patch('radius_usage_service.os.geteuid', return_value=0), \
                    patch('radius_usage_service.subprocess.run') as command:
                result = radius_usage_service.main([
                    'install', '--secret', SECRET, '--install-dir', str(code),
                    '--state', str(root / 'state' / 'checkpoint.json'),
                    '--unit-path', str(root / 'radius-usage-collector.service')])
            self.assertEqual(result, 1)
            self.assertEqual(code.stat().st_mode & 0o777, 0o700)
            self.assertFalse((root / 'state').exists())
            command.assert_not_called()

    def test_permanent_runner_keeps_heartbeats_alive_when_no_site_has_traffic(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            posted = []
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': []}
                posted.extend(payload)
                return {}
            with patch('radius_usage_service.socket.gethostname', return_value='radius-primary'), \
                    patch('radius_usage_service.os.geteuid', return_value=0), \
                    patch('radius_usage_service.load_credentials', return_value={'api_key':'api', 'app_key':'app'}), \
                    patch('radius_usage_service.time.time', side_effect=lambda: 1791374420 + 120 * len(posted)), \
                    patch('radius_usage_service.time.sleep', side_effect=[None, KeyboardInterrupt]), \
                    patch('radius_usage_service.radius_usage_collector.request_json', side_effect=http):
                with self.assertRaises(KeyboardInterrupt):
                    radius_usage_service.main(['run', '--secret', SECRET, '--state', str(state)])
            self.assertEqual(len(posted), 2)
            self.assertTrue(all(item['event'] == 'Collection-Heartbeat' for item in posted))
            self.assertTrue(all(item['source_records'] == 0 for item in posted))
            self.assertEqual([item['timestamp'] for item in posted],
                             ['2026-10-07T12:00:20Z', '2026-10-07T12:02:20Z'])
            self.assertEqual([item['through'] for item in posted],
                             ['2026-10-07T11:58:20Z', '2026-10-07T12:00:20Z'])
            self.assertEqual(json.loads(state.read_text())['pending'], [])

    def test_install_preserves_checkpoint_and_restarts_only_its_own_service(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'state' / 'checkpoint.json'
            state.parent.mkdir()
            state.write_bytes(b'preserve uncertain pending delivery exactly')
            for suffix in ('.lock', '.runner.lock'):
                state.with_name(state.name + suffix).touch()
            # A normal reinstall encounters the Python cache from the running unit.
            code = root / 'code'
            (code / '__pycache__').mkdir(parents=True)
            (code / '__pycache__' / 'radius_usage.cpython-313.pyc').write_bytes(b'cached')
            with patch('radius_usage_service.socket.gethostname', return_value='radius-primary'), \
                    patch('radius_usage_service.os.geteuid', return_value=0), \
                    patch('radius_usage_service.subprocess.run') as command:
                result = radius_usage_service.main([
                    'install', '--secret', SECRET, '--install-dir', str(root / 'code'),
                    '--state', str(state), '--unit-path', str(root / 'radius-usage-collector.service')])
            self.assertEqual(result, 0)
            self.assertEqual(state.read_bytes(), b'preserve uncertain pending delivery exactly')
            self.assertEqual(state.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual([call.args[0] for call in command.call_args_list], [
                ['systemctl', 'daemon-reload'], ['systemctl', 'enable', 'radius-usage-collector.service'],
                ['systemctl', 'restart', 'radius-usage-collector.service']])
            self.assertTrue((root / 'code' / 'radius_usage_service.py').exists())

    def test_secondary_host_refuses_install_and_run_before_secret_access(self):
        with patch('radius_usage_service.socket.gethostname', return_value='radius-secondary'), \
                patch('radius_usage_service.load_credentials') as credentials, \
                patch('radius_usage_service.subprocess.run') as command:
            for action in ('install', 'run'):
                self.assertEqual(radius_usage_service.main([action, '--secret', SECRET, '--dry-run']), 1)
            credentials.assert_not_called()
            command.assert_not_called()

    def test_permanent_runner_restarts_do_not_send_ambiguous_usage_or_health(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            events = [
                {'attributes': {'timestamp': '2026-10-07T12:00:00Z', 'host': 'radius-primary',
                 'attributes': {'event': 'Acct-Start', 'src_ip': '203.0.113.1', 'nas_ip': '10.0.0.2',
                                'calling_station': 'aa:bb:cc:dd:ee:ff', 'session_id': 'a',
                                'session_time': 0, 'input_bytes': 0, 'output_bytes': 0}}},
                {'attributes': {'timestamp': '2026-10-07T12:00:10Z', 'host': 'radius-primary',
                 'attributes': {'event': 'Acct-Update', 'src_ip': '203.0.113.1', 'nas_ip': '10.0.0.2',
                                'calling_station': 'aa:bb:cc:dd:ee:ff', 'session_id': 'a',
                                'session_time': 10, 'input_bytes': 100, 'output_bytes': 200}}}]
            requests = Mock(side_effect=[{'data': events}, RuntimeError('secret-api')])
            arguments = ['run', '--secret', SECRET, '--state', str(state), '--settle-seconds', '0']
            with patch('radius_usage_service.socket.gethostname', return_value='radius-primary'), \
                    patch('radius_usage_service.os.geteuid', return_value=0), \
                    patch('radius_usage_service.load_credentials', return_value={'api_key':'api', 'app_key':'app'}), \
                    patch('radius_usage_service.time.time', return_value=1791374420), \
                    patch('radius_usage_service.radius_usage_collector.request_json', requests):
                self.assertEqual(radius_usage_service.main(arguments), 1)
                saved = json.loads(state.read_text())
                self.assertTrue(saved['uncertain'])
                self.assertEqual(len(saved['pending']), 1)
                requests.reset_mock()
                self.assertEqual(radius_usage_service.main(arguments), 1)
                requests.assert_not_called()
                self.assertEqual(json.loads(state.read_text()), saved)

    def test_secret_access_uses_vm_identity_and_never_exposes_key_on_failure(self):
        credential = {'api_key': 'secret-api', 'app_key': 'secret-app'}
        requests = []
        def open_request(request, timeout):
            requests.append(request)
            payload = ({'access_token': 'vm-token'} if len(requests) == 1 else
                       {'payload': {'data': base64.b64encode(json.dumps(credential).encode()).decode()}})
            response = Mock()
            response.read.return_value = json.dumps(payload).encode()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=None)
            return response
        opener = Mock(open=Mock(side_effect=open_request))
        with patch('radius_usage_service.build_opener', return_value=opener):
            self.assertEqual(radius_usage_service.load_credentials(SECRET), credential)
        self.assertEqual(requests[0].get_header('Metadata-flavor'), 'Google')
        self.assertEqual(requests[1].full_url, 'https://secretmanager.googleapis.com/v1/' + SECRET + ':access')
        self.assertEqual(requests[1].get_header('Authorization'), 'Bearer vm-token')
        with patch('radius_usage_service.build_opener', side_effect=RuntimeError('secret-api')):
            with self.assertRaisesRegex(RuntimeError, '^Usage credential retrieval failed$'):
                radius_usage_service.load_credentials(SECRET)

    def test_dry_run_renders_permanent_primary_only_unit_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('radius_usage_service.socket.gethostname', return_value='radius-primary'), \
                    patch('radius_usage_service.subprocess.run') as command, \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                result = radius_usage_service.main([
                    'install', '--secret', SECRET, '--dry-run',
                    '--source-hosts', 'radius-primary-project', 'radius-secondary-project',
                    '--collector-id', 'radius-primary-project',
                    '--install-dir', str(root / 'code'), '--state', str(root / 'state' / 'checkpoint.json'),
                    '--unit-path', str(root / 'radius-usage-collector.service')])
            self.assertEqual(result, 0)
            self.assertEqual(list(root.iterdir()), [])
            command.assert_not_called()
            unit = output.getvalue()
            self.assertIn('Restart=always', unit)
            self.assertIn('RestartSec=120', unit)
            self.assertIn('User=root', unit)
            self.assertIn('UMask=0077', unit)
            self.assertIn('ProtectSystem=strict', unit)
            self.assertIn('--secret', unit)
            self.assertIn('radius-primary', unit)
            self.assertIn('"--source-hosts" "radius-primary-project" "radius-secondary-project"', unit)
            self.assertIn('"--primary-host" "radius-primary"', unit)
            self.assertNotIn('radiusd', unit)
            self.assertNotIn('freeradius.service', unit)


if __name__ == '__main__':
    unittest.main()
