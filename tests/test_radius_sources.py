"""Trusted site discovery never infers an office from RADIUS packet claims."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


class SourceTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('radius_sources', ROOT / 'scripts/radius_sources.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.now = 1700000000
        self.clients = {'nyc': {'cidrs': ['10.20.0.0/16'], 'unifi_host_id': 'gateway-nyc'},
                        'atl': {'cidrs': [], 'unifi_host_id': 'gateway-atl'}}
        self.hosts = [self.host('gateway-nyc', '8.8.4.4'), self.host('gateway-atl', '1.1.1.1')]

    def host(self, identifier, address):
        return {'id': identifier, 'ipAddress': address,
                'updatedAt': datetime.fromtimestamp(self.now, timezone.utc).isoformat()}

    def test_exact_host_ids_discover_wan_and_ignore_unmapped_hosts(self):
        self.hosts.append(self.host('someone-else', '9.9.9.9'))
        self.assertEqual(self.module.discover(self.clients, self.hosts, self.now),
                         {'nyc': ['8.8.4.4/32'], 'atl': ['1.1.1.1/32']})

    def test_wan_change_replaces_old_address_and_all_active_public_wans_are_allowed(self):
        self.hosts[0]['ipAddress'] = '8.8.8.8'
        self.hosts[0]['reportedState'] = {'wans': [{'ipv4': '8.8.4.4'}, {'ipv4': '10.0.0.1'}]}
        self.assertEqual(self.module.discover(self.clients, self.hosts, self.now)['nyc'],
                         ['8.8.4.4/32', '8.8.8.8/32'])

    def test_missing_duplicate_private_or_malformed_hosts_fail_closed(self):
        for hosts in ([], self.hosts + [self.hosts[0]],
                      [dict(self.hosts[0], ipAddress='10.0.0.1'), self.hosts[1]],
                      [dict(self.hosts[0], ipAddress='injected\nclient'), self.hosts[1]]):
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                self.module.discover(self.clients, hosts, self.now)

    def test_unchanged_host_modification_time_is_not_a_heartbeat(self):
        self.hosts[0]['updatedAt'] = '2020-01-01T00:00:00Z'
        self.assertEqual(self.module.discover(self.clients, self.hosts, self.now)['nyc'],
                         ['8.8.4.4/32'])

    def test_malformed_optional_wan_shapes_raise_value_error(self):
        for state in (None, [], 'unexpected', 7, {'wans': None}, {'wans': {}},
                      {'wans': 'unexpected'}, {'wans': [None]}, {'wans': [[]]},
                      {'wans': ['unexpected']}, {'wans': [{'ipv4': 134744072}]},
                      {'wans': [{'ipv4': False}]}, {'wans': [{'ipv4': None}]}):
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.module.discover(self.clients,
                    [dict(self.hosts[0], reportedState=state), self.hosts[1]], self.now)

    def test_non_string_primary_ip_cannot_be_coerced_or_hidden_by_valid_wan(self):
        for address in (134744072, False, 0, ['8.8.8.8'], {'ipv4': '8.8.8.8'}):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.module.discover(self.clients,
                    [dict(self.hosts[0], ipAddress=address,
                          reportedState={'wans': [{'ipv4': '8.8.8.8'}]}), self.hosts[1]], self.now)

    def test_omitted_optional_wan_fields_remain_supported(self):
        for state in ({}, {'wans': []}, {'wans': [{}]}):
            with self.subTest(state=state):
                sources = self.module.discover(self.clients,
                    [dict(self.hosts[0], reportedState=state), self.hosts[1]], self.now)
                self.assertEqual(sources['nyc'], ['8.8.4.4/32'])

    def test_site_overlap_is_rejected_including_static_cidr(self):
        for mutation in ('dynamic', 'static', 'duplicate_id'):
            clients = json.loads(json.dumps(self.clients))
            hosts = json.loads(json.dumps(self.hosts))
            if mutation == 'dynamic':
                hosts[1]['ipAddress'] = hosts[0]['ipAddress']
            elif mutation == 'static':
                clients['atl']['cidrs'] = ['8.8.4.0/24']
            else:
                clients['atl']['unifi_host_id'] = 'gateway-nyc'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.module.discover(clients, hosts, self.now)

    def test_source_check_uses_site_and_ip_with_expiring_snapshot(self):
        state = {'updated_at': self.now, 'host_ids': {'nyc': 'gateway-nyc', 'atl': 'gateway-atl'}, 'sources': {'nyc': ['8.8.4.4/32'], 'atl': ['1.1.1.1/32']}}
        check = self.module.allowed
        self.assertTrue(check(self.clients, state, 'nyc', '8.8.4.4', self.now))
        self.assertTrue(check(self.clients, state, 'nyc', '10.20.35.99', self.now + 10000))
        self.assertFalse(check(self.clients, state, 'atl', '8.8.4.4', self.now))
        self.assertFalse(check(self.clients, state, 'nyc', '8.8.4.4', self.now + 900))
        self.assertFalse(check(self.clients, state, 'nyc', '8.8.4.4', self.now - 1))
        self.assertFalse(check(self.clients, {}, 'nyc', '8.8.4.4', self.now))

    def test_paginated_host_fetch_and_redirects_not_followed(self):
        calls = []
        def request(url, headers):
            calls.append((url, headers))
            return {'data': [self.hosts[len(calls)-1]], 'nextToken': 'next token' if len(calls) == 1 else None}
        self.assertEqual(self.module.fetch_hosts('fixture-key', request=request), self.hosts)
        self.assertIn('nextToken=next+token', calls[1][0])
        self.assertEqual(calls[0][1]['X-API-Key'], 'fixture-key')
        def loop(url, headers):
            return {'data': [], 'nextToken': 'loop'}
        with self.assertRaises(ValueError):
            self.module.fetch_hosts('fixture-key', request=loop)

    def test_render_injection_is_rejected_and_no_global_default_sources(self):
        rendered = self.module.render_clients({'nyc': ['8.8.4.4/32']}, {'nyc': 'a' * 48})
        self.assertIn('shortname = nyc', rendered)
        self.assertIn('ipaddr = 8.8.4.4/32', rendered)
        self.assertEqual(self.module.render_clients({}, {}), '')
        for name, secret in [('nyc\n}', 'a' * 48), ('nyc', 'bad\nsecret')]:
            with self.assertRaises(ValueError):
                self.module.render_clients({name: ['8.8.4.4/32']}, {name: secret})


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('radius_sources', ROOT / 'scripts/radius_sources.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.client_file = root / 'clients.conf'
        self.state_file = root / 'state.json'
        self.config = {'project': 'fixture-project', 'clients': {
            'nyc': {'cidrs': [], 'unifi_host_id': 'gateway-nyc'}}}
        self.secrets = {'nyc': 'A' * 48}
        self.old_sources = {'nyc': ['8.8.4.4/32']}
        self.new_sources = {'nyc': ['8.8.8.8/32']}
        self.old_content = self.module.render_clients(self.old_sources, self.secrets)
        self.client_file.write_text(self.old_content)
        self.old_state = {'updated_at': 100, 'sources': self.old_sources,
                          'host_ids': {'nyc': 'gateway-nyc'}}
        self.state_file.write_text(json.dumps(self.old_state))
        self.commands = []
        self.firewalls = []

    def process(self, command, **kwargs):
        self.commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    def firewall(self, project, node, sources):
        # Readiness must remain old until the cloud firewall has converged.
        self.assertEqual(json.loads(self.state_file.read_text()), self.old_state)
        self.firewalls.append((project, node, sources))

    def reconcile(self, sources=None, **changes):
        arguments = dict(secrets=self.secrets, client_file=self.client_file,
                         state_file=self.state_file, run=self.process,
                         firewall=self.firewall, node='radius-primary')
        arguments.update(changes)
        return self.module.reconcile(self.config, self.new_sources if sources is None else sources,
                                     200, **arguments)

    def test_failed_config_validation_restores_previous_clients_and_state(self):
        def process(command, **kwargs):
            self.commands.append(command)
            if command == ['freeradius', '-XC']:
                self.assertIn('8.8.8.8/32', self.client_file.read_text())
                raise subprocess.CalledProcessError(1, command)
            self.assertEqual(self.client_file.read_text(), self.old_content)
            return subprocess.CompletedProcess(command, 0)
        with self.assertRaises(subprocess.CalledProcessError):
            self.reconcile(run=process)
        self.assertEqual(self.client_file.read_text(), self.old_content)
        self.assertEqual(json.loads(self.state_file.read_text()), self.old_state)
        self.assertEqual(self.firewalls, [])

    def test_failed_service_restart_restores_previous_clients_and_state(self):
        def process(command, **kwargs):
            self.commands.append(command)
            if command == ['systemctl', 'restart', 'freeradius'] and kwargs['check']:
                raise subprocess.CalledProcessError(1, command)
            if command == ['systemctl', 'restart', 'freeradius']:
                self.assertEqual(self.client_file.read_text(), self.old_content)
            return subprocess.CompletedProcess(command, 0)
        with self.assertRaises(subprocess.CalledProcessError):
            self.reconcile(run=process)
        self.assertEqual(self.client_file.read_text(), self.old_content)
        self.assertEqual(json.loads(self.state_file.read_text()), self.old_state)
        self.assertEqual(self.firewalls, [])

    def test_failed_firewall_does_not_refresh_discovery_or_admit_new_source(self):
        def firewall(project, node, sources):
            raise RuntimeError('cloud firewall unavailable')
        with self.assertRaisesRegex(RuntimeError, 'cloud firewall unavailable'):
            self.reconcile(firewall=firewall)
        state = json.loads(self.state_file.read_text())
        self.assertEqual(state, self.old_state)
        self.assertFalse(self.module.allowed(self.config['clients'], state, 'nyc', '8.8.8.8', 200))
        self.assertFalse(self.module.allowed(self.config['clients'], state, 'nyc', '8.8.4.4', 1000))
        # The retry converges the cloud and publishes readiness without restarting again.
        self.commands.clear()
        self.assertFalse(self.reconcile())
        self.assertEqual(self.commands, [])
        state = json.loads(self.state_file.read_text())
        self.assertTrue(self.module.allowed(self.config['clients'], state, 'nyc', '8.8.8.8', 200))

    def test_unchanged_clients_refresh_freshness_without_restart(self):
        self.assertFalse(self.reconcile(self.old_sources))
        self.assertEqual(self.commands, [])
        self.assertEqual(self.client_file.read_text(), self.old_content)
        self.assertEqual(self.firewalls, [('fixture-project', 'radius-primary', self.old_sources)])
        self.assertEqual(json.loads(self.state_file.read_text()), {**self.old_state, 'updated_at': 200})

    def test_changed_ip_replaces_old_client_firewall_and_authorization(self):
        self.assertTrue(self.reconcile())
        self.assertNotIn('8.8.4.4', self.client_file.read_text())
        self.assertIn('8.8.8.8/32', self.client_file.read_text())
        self.assertEqual(self.commands, [['freeradius', '-XC'], ['systemctl', 'restart', 'freeradius']])
        self.assertEqual(self.firewalls, [('fixture-project', 'radius-primary', self.new_sources)])
        state = json.loads(self.state_file.read_text())
        self.assertEqual(state, {**self.old_state, 'updated_at': 200, 'sources': self.new_sources})
        self.assertFalse(self.module.allowed(self.config['clients'], state, 'nyc', '8.8.4.4', 200))
        self.assertTrue(self.module.allowed(self.config['clients'], state, 'nyc', '8.8.8.8', 200))

    def test_discovered_ip_inside_static_range_does_not_duplicate_client(self):
        self.config['clients']['nyc']['cidrs'] = ['8.8.8.0/24']
        self.assertTrue(self.reconcile())
        self.assertEqual(self.client_file.read_text(), '')
        state = json.loads(self.state_file.read_text())
        self.assertTrue(self.module.allowed(self.config['clients'], state, 'nyc', '8.8.8.8', 2000))


if __name__ == '__main__':
    unittest.main()
