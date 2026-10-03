"""Logging accepts only server-issued bindings from the correct packet context."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))


class RadiusIdentityTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((SCRIPTS / 'radius_identity.py').exists(), 'verified identity module missing')
        spec = importlib.util.spec_from_file_location('radius_identity', SCRIPTS / 'radius_identity.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.module.KEY_FILE = str(root / 'key')
        self.key = b'A' * 64
        Path(self.module.KEY_FILE).write_bytes(self.key)
        self.module.CONFIG_FILE = str(root / 'config.json')
        self.cache = root / 'inventory.json'
        Path(self.module.CONFIG_FILE).write_text(json.dumps({'cache_file': str(self.cache), 'cache_max_age': 3600}))
        self.now = int(time.time())
        self.fp = 'a1' * 32
        self.device = 'fleet:01234567-89ab-cdef-0123-456789abcdef'
        self.inventory = {'updated_at': self.now, 'devices': {self.device: {
            'serial': 'ACTUAL-SERIAL', 'device_name': 'Actual laptop',
            'device_owner': 'actual@example.com', 'device_model': 'MacBook Pro'}}}
        self.cache.write_text(json.dumps(self.inventory))

    def issue(self, **changes):
        args = dict(key=self.key, device_id=self.device, fingerprint=self.fp, vlan=120,
                    location='nyc', calling_station='AA-BB-CC-DD-EE-FF', now=self.now)
        args.update(changes)
        return self.module.issue(**args)

    def request(self, token, accounting=False, location='nyc', station='aa:bb:cc:dd:ee:ff'):
        packet = {'request': (('User-Name', 'VICTIM-SERIAL'),
                              ('TLS-Client-Cert-Common-Name', 'VICTIM-SERIAL'),
                              ('Calling-Station-Id', station)),
                  'config': (('Tmp-String-1', location),), 'reply': ()}
        source = 'request' if accounting else 'reply'
        packet[source] += (('Class', token),)
        return packet

    def test_verified_binding_uses_inventory_device_not_claimed_identity(self):
        for accounting in (False, True):
            with self.subTest(accounting=accounting):
                attrs = dict(self.module.enrich(self.request(self.issue(), accounting), accounting=accounting))
                self.assertEqual(attrs, {'Tmp-String-2': self.device, 'Tmp-String-3': self.fp,
                    'Tunnel-Private-Group-Id': '120', 'Login-LAT-Service': 'ACTUAL-SERIAL',
                    'Filter-Id': 'Actual laptop', 'Reply-Message': 'actual@example.com',
                    'Login-LAT-Node': 'MacBook Pro'})

    def test_optout_binding_preserves_verified_identity_without_vlan_attribute(self):
        token = self.issue(vlan=None)
        for accounting in (False, True):
            with self.subTest(accounting=accounting):
                attrs = dict(self.module.enrich(self.request(token, accounting), accounting=accounting))
                self.assertEqual(attrs, {'Tmp-String-2': self.device, 'Tmp-String-3': self.fp,
                    'Login-LAT-Service': 'ACTUAL-SERIAL', 'Filter-Id': 'Actual laptop',
                    'Reply-Message': 'actual@example.com', 'Login-LAT-Node': 'MacBook Pro'})
        self.cache.unlink()
        self.assertEqual(dict(self.module.enrich(self.request(token))), {
            'Tmp-String-2': self.device, 'Tmp-String-3': self.fp})
        self.assertEqual(self.module.enrich(self.request(token, location='atl')), ())
        self.assertEqual(self.module.enrich(self.request(token, station='11:22:33:44:55:66')), ())

    def test_class_wire_hex_and_mac_normalization(self):
        token = self.issue()
        self.assertLessEqual(len(token.encode()), 253)
        self.assertNotEqual(token, self.issue())
        self.assertTrue(self.module.enrich(self.request('0x' + token.encode().hex())))
        for station in ('AABBCCDDEEFF', 'aabb.ccdd.eeff', 'AA:BB:CC:DD:EE:FF'):
            self.assertTrue(self.module.enrich(self.request(token, station=station)))

    def test_forged_expired_future_wrong_key_and_wrong_context_do_not_attribute(self):
        token = self.issue()
        for invalid in (token[:-8] + 'AAAAAAAA', self.issue(key=b'B' * 64),
                        self.issue(now=self.now - 30 * 86400), self.issue(now=self.now + 60),
                        'arbitrary', '0x00', 'c8021x.2.' + token.split('.')[-1]):
            with self.subTest(token=invalid):
                self.assertEqual(self.module.enrich(self.request(invalid)), ())
        for field in ({'location': 'sac'}, {'location': ''}, {'station': '11:22:33:44:55:66'}, {'station': ''}):
            self.assertEqual(self.module.enrich(self.request(token, **field)), ())

    def test_only_correct_packet_list_and_single_class_or_context_are_accepted(self):
        token = self.issue()
        self.assertEqual(self.module.enrich(self.request(token, accounting=True)), ())
        self.assertEqual(self.module.enrich(self.request(token), accounting=True), ())
        for attr, source in (('Class', 'reply'), ('Tmp-String-1', 'config'), ('Calling-Station-Id', 'request')):
            packet = self.request(token)
            packet[source] += ((attr, 'anything'),)
            self.assertEqual(self.module.enrich(packet), ())
        packet = self.request(token)
        packet['config'] = ()
        packet['request'] += (('Tmp-String-1', 'nyc'),)
        self.assertEqual(self.module.enrich(packet), ())

    def test_missing_metadata_retains_signed_fields_without_fabricating_serial(self):
        for inventory in ({'updated_at': self.now - 3600, 'devices': self.inventory['devices']},
                          {'updated_at': self.now, 'devices': {}},
                          {'updated_at': self.now, 'devices': {self.device: {'serial': ''}}}):
            self.cache.write_text(json.dumps(inventory))
            self.assertEqual(dict(self.module.enrich(self.request(self.issue()))), {
                'Tmp-String-2': self.device, 'Tmp-String-3': self.fp, 'Tunnel-Private-Group-Id': '120'})
        self.cache.unlink()
        self.assertEqual(len(self.module.enrich(self.request(self.issue()))), 3)

    def test_missing_or_short_key_does_not_attribute(self):
        token = self.issue()
        Path(self.module.KEY_FILE).write_bytes(b'short')
        self.assertEqual(self.module.enrich(self.request(token)), ())
        Path(self.module.KEY_FILE).unlink()
        self.assertEqual(self.module.enrich(self.request(token)), ())

    def test_issuance_rejects_unsafe_fields_and_oversize_class(self):
        for change in ({'key': b'short'}, {'device_id': ''}, {'device_id': 'a' * 97},
                       {'fingerprint': 'invalid'}, {'vlan': 0}, {'vlan': True},
                       {'location': ''}, {'calling_station': ''}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.issue(**change)
        self.assertLessEqual(len(self.issue(device_id='a' * 96)), 253)


if __name__ == '__main__':
    unittest.main()
