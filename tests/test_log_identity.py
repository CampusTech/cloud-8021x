"""Serial-free logging must not infer owners from client-selected usernames."""
from pathlib import Path
import json
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import radius_identity
import radius_log


def lookup_module():
    source = (ROOT / 'scripts/startup.sh').read_text().split("<< 'PYMODEOF'\n", 1)[1].split('\nPYMODEOF', 1)[0]
    module = types.ModuleType('lookup_fixture')
    radiusd = types.SimpleNamespace(RLM_MODULE_OK=2, RLM_MODULE_UPDATED=8, RLM_MODULE_NOOP=7,
                                    RLM_MODULE_FAIL=1, L_ERR=3, L_INFO=1, radlog=lambda *a: None)
    config = types.SimpleNamespace(REWRITE_USERNAME_SEPARATOR=' - ', CERTIFICATE_INVENTORY=True)
    with patch.dict(sys.modules, {'radiusd': radiusd, 'radius_lookups_config': config}):
        exec(compile(source, 'radius_lookups.py', 'exec'), module.__dict__)
    return module


class LogIdentityTests(unittest.TestCase):
    def test_accounting_parses_ssid_even_without_verified_device_identity(self):
        module = lookup_module()
        cases = [('AA-BB-CC-DD-EE-FF:Campus', 'Campus'),
                 ('AA:BB:CC:DD:EE:FF:Campus', 'Campus'),
                 ('AA:BB:CC:DD:EE:FF:Campus:IT', 'Campus:IT'),
                 ('AA-BB-CC-DD-EE-FF', ''), ('', '')]
        for certificate_inventory in (False, True):
            for called_station, expected_ssid in cases:
                with self.subTest(certificate_inventory=certificate_inventory,
                                  called_station=called_station):
                    request = {'request': (('Acct-Status-Type', 'Interim-Update'),
                                           ('Called-Station-Id', called_station))}
                    with patch.object(radius_identity, 'enrich', return_value=[]), \
                            patch.object(module, 'CERTIFICATE_INVENTORY', certificate_inventory), \
                            patch.object(module, '_ap_lookup', return_value=None):
                        result = module.accounting(request)
                    attrs = dict(result[1]['reply']) if isinstance(result, tuple) else {}
                    self.assertEqual(attrs.get('Login-LAT-Port', ''), expected_ssid)
                    if certificate_inventory:
                        record = json.loads(attrs['Tmp-String-4'].replace(chr(92) * 2, chr(92)))
                        self.assertEqual(record['ssid'], expected_ssid)
                        self.assertFalse(record['identity_verified'])

    def test_accounting_counters_include_gigawords_after_four_gib(self):
        request = {'request': (('Acct-Status-Type', 'Interim-Update'),
                               ('Acct-Input-Octets', '37'), ('Acct-Input-Gigawords', '2'),
                               ('Acct-Output-Octets', '91'), ('Acct-Output-Gigawords', '3'),
                               ('Acct-Session-Time', '600'))}
        record = json.loads(radius_log.record(request, (), accounting=True))
        self.assertEqual(record['input_bytes'], (2 << 32) + 37)
        self.assertEqual(record['counter_bits'], 64)
        self.assertEqual(record['output_bytes'], (3 << 32) + 91)
        self.assertEqual(record['session_time'], 600)

    def test_accounting_counters_without_gigawords_remain_octets(self):
        request = {'request': (('Acct-Input-Octets', '4294967295'),
                               ('Acct-Output-Octets', '123'))}
        record = json.loads(radius_log.record(request, (), accounting=True))
        self.assertEqual(record['input_bytes'], 4294967295)
        self.assertEqual(record['output_bytes'], 123)
        self.assertEqual(record['session_time'], 0)

    def test_accounting_missing_octets_default_to_zero(self):
        request = {'request': (('Acct-Input-Gigawords', '2'),)}
        record = json.loads(radius_log.record(request, (), accounting=True))
        self.assertEqual(record['input_bytes'], 2 << 32)
        self.assertEqual(record['output_bytes'], 0)

    def test_accounting_invalid_counter_components_default_independently(self):
        for invalid in ('bad', '', None, '-1', float('inf')):
            for component in ('Octets', 'Gigawords'):
                with self.subTest(invalid=invalid, component=component):
                    incoming = {'Acct-Input-Octets': '37', 'Acct-Input-Gigawords': '2',
                                'Acct-Output-Octets': '91', 'Acct-Output-Gigawords': '3',
                                'Acct-Session-Time': invalid}
                    incoming[f'Acct-Input-{component}'] = invalid
                    incoming[f'Acct-Output-{component}'] = invalid
                    record = json.loads(radius_log.record(
                        {'request': tuple(incoming.items())}, (), accounting=True))
                    self.assertEqual(record['input_bytes'], (2 << 32) if component == 'Octets' else 37)
                    self.assertEqual(record['output_bytes'], (3 << 32) if component == 'Octets' else 91)
                    self.assertEqual(record['session_time'], 0)

    def test_expiry_metrics_count_distinct_serial_free_devices(self):
        events = [
            {'device_id': 'fleet:7', 'serial': '', 'cert_issuer': 'Smallstep WiFi', 'cert_expiration': '271001000000Z'},
            {'device_id': 'fleet:8', 'serial': '', 'cert_issuer': 'Smallstep WiFi', 'cert_expiration': '271002000000Z'},
            {'serial': 'OLD-MAC-SERIAL', 'cert_issuer': 'Smallstep WiFi', 'cert_expiration': '271003000000Z'},
            {'device_id': '', 'serial': 'unverified-claim', 'cert_issuer': 'Smallstep WiFi', 'cert_expiration': '271004000000Z'},
        ]
        pairs = list(radius_log.expiry_pairs(map(json.dumps, events), 'Smallstep'))
        self.assertEqual(len(pairs), 3)
        self.assertEqual(len({key for key, _ in pairs}), 3)

    def test_verified_serial_free_auth_and_accounting_emit_valid_json(self):
        module = lookup_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'key').write_bytes(b'k' * 64)
            (root / 'cache').write_text(json.dumps({'updated_at': time.time(), 'devices': {
                'fleet:7': {'serial': '', 'device_owner': 'owner"@example.com',
                            'device_name': 'Personal\niPhone', 'device_model': 'iPhone'}}}))
            (root / 'config').write_text(json.dumps({'cache_file': str(root / 'cache'), 'cache_max_age': 3600,
                'locations': {'nyc': {'vlan_names': {'210': 'Guest "BYOD"'}}}}))
            token = radius_identity.issue(b'k' * 64, 'fleet:7', 'ab' * 32, 210,
                                          'nyc', 'aa:bb:cc:dd:ee:ff', time.time())
            with patch.object(radius_identity, 'KEY_FILE', str(root / 'key')), \
                    patch.object(radius_identity, 'CONFIG_FILE', str(root / 'config')):
                for accounting in (False, True):
                    request = {'request': (('User-Name', 'victim"\nidentity'),
                                           ('Calling-Station-Id', 'aa:bb:cc:dd:ee:ff'),
                                           ('Acct-Status-Type', 'Start')),
                               'config': (('Tmp-String-1', 'nyc'), ('Tmp-String-5', 'Access-Accept')),
                               'reply': ()}
                    request['request' if accounting else 'reply'] += (('Class', token),)
                    result = (module.accounting if accounting else module.post_auth)(request)
                    output = dict(result[1]['reply'])['Tmp-String-4']
                    self.assertNotIn('\n', output)
                    record = json.loads(output.replace(chr(92) * 2, chr(92)))
                    self.assertEqual(record['device_id'], 'fleet:7')
                    self.assertEqual(record['serial'], '')
                    self.assertEqual(record['device_name'], 'Personal\niPhone')
                    self.assertEqual(record['device_owner'], 'owner"@example.com')
                    self.assertEqual(record['certificate_fingerprint'], 'ab' * 32)
                    self.assertEqual(record['vlan_id'], '210')
                    self.assertEqual(record.get('vlan_name'), 'Guest "BYOD"')
                    self.assertEqual(record['event'], 'Acct-Start' if accounting else 'Access-Accept')

    def test_missing_or_blank_owner_has_display_fallback_without_verifying_identity(self):
        missing = object()
        for owner in (missing, None, '', '   ', '\t', 42, False, [], {}):
            with self.subTest(owner=owner):
                enrichment = () if owner is missing else (('Reply-Message', owner),)
                value = json.loads(radius_log.record({'request': (), 'config': ()}, enrichment))
                self.assertEqual(value['device_owner'], 'N/A')
                self.assertFalse(value['identity_verified'])
                self.assertEqual(value['device_id'], '')

    def test_verified_device_without_owner_has_display_fallback(self):
        for accounting in (False, True):
            with self.subTest(accounting=accounting):
                value = json.loads(radius_log.record(
                    {'request': (), 'config': ()}, (('Tmp-String-2', 'fleet:7'),), accounting))
                self.assertEqual(value['device_owner'], 'N/A')
                self.assertTrue(value['identity_verified'])
                self.assertEqual(value['device_id'], 'fleet:7')

    def test_nonblank_owner_is_preserved_exactly(self):
        owner = ' owner"@example.com '
        value = json.loads(radius_log.record(
            {'request': (), 'config': ()}, (('Reply-Message', owner), ('Tmp-String-2', 'fleet:7'))))
        self.assertEqual(value['device_owner'], owner)
        self.assertTrue(value['identity_verified'])

    def test_reject_json_does_not_inherit_unverified_reply_metadata(self):
        request = {'request': (('User-Name', 'victim'), ('Module-Failure-Message', 'denied"\nreason')),
                   'reply': (('Tmp-String-2', 'victim-id'), ('Reply-Message', 'victim@example.com'),
                             ('Tunnel-Private-Group-Id', '5'), ('Tmp-String-7', 'Forged Secure')),
                   'config': (('Tmp-String-5', 'Access-Reject'),)}
        record = json.loads(radius_log.record(request, ()))
        self.assertEqual(record['event'], 'Access-Reject')
        self.assertFalse(record['identity_verified'])
        self.assertEqual(record['device_owner'], 'N/A')
        self.assertEqual(record['device_id'], '')
        self.assertEqual(record['vlan_id'], '')
        self.assertEqual(record.get('vlan_name'), '')
        self.assertEqual(record['reject_reason'], 'denied"\nreason')

    def test_fingerprint_mode_never_attributes_claimed_username_without_verified_binding(self):
        module = lookup_module()
        request = {'request': (('User-Name', 'VICTIM-SERIAL'),)}
        with patch.object(module, '_get_cached_device', return_value={
                'email': 'victim@example.com', 'device_name': 'Victim laptop'}) as lookup:
            for handler in (module.post_auth, module.accounting):
                with self.subTest(handler=handler.__name__):
                    result = handler(request)
                    attrs = dict(result[1].get('reply', ())) if isinstance(result, tuple) else {}
                    self.assertNotIn('Reply-Message', attrs)
                    self.assertNotIn('Filter-Id', attrs)
            lookup.assert_not_called()


if __name__ == '__main__':
    unittest.main()
