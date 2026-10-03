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
            (root / 'config').write_text(json.dumps({'cache_file': str(root / 'cache'), 'cache_max_age': 3600}))
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
                    self.assertEqual(record['event'], 'Acct-Start' if accounting else 'Access-Accept')

    def test_reject_json_does_not_inherit_unverified_reply_metadata(self):
        request = {'request': (('User-Name', 'victim'), ('Module-Failure-Message', 'denied"\nreason')),
                   'reply': (('Tmp-String-2', 'victim-id'), ('Reply-Message', 'victim@example.com')),
                   'config': (('Tmp-String-5', 'Access-Reject'),)}
        record = json.loads(radius_log.record(request, ()))
        self.assertEqual(record['event'], 'Access-Reject')
        self.assertFalse(record['identity_verified'])
        self.assertEqual(record['device_owner'], '')
        self.assertEqual(record['device_id'], '')
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
