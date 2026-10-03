import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from device_policy import snapshot
import inventory_policy


class InventoryTests(unittest.TestCase):
    def test_certificate_coverage_does_not_imply_vlan_readiness(self):
        host = {'id': 7, 'uuid': 'byod', 'platform': 'ios', 'team_id': 4,
                'mdm': {'enrollment_status': 'On (personal)'}}
        fp = 'ab' * 32
        device = {**inventory_policy.fleet_device(host), 'certificate_fingerprints': [fp],
                  'certificates_observed_at': 100}
        obs = {'byod': {'fingerprints': [fp], 'observed_at': 100, 'trust_verified': True,
                        'expires_at': {fp: 10000}}}
        config = {'group_vlans': {}, 'cache_max_age': 3600, 'certificate_max_age': 86400,
                  'certificate_inventory': True}
        self.assertTrue(hasattr(inventory_policy, 'certificate_readiness'))
        report = inventory_policy.certificate_readiness([host], [device], obs, config, 101)
        self.assertFalse(report['ready'])
        self.assertEqual(report['hosts'][0]['reason'], 'no_vlan_assignment')
        config['group_vlans'] = {'fleet:4': 200}
        report = inventory_policy.certificate_readiness([host], [device], obs, config, 101)
        self.assertTrue(report['ready'])
        self.assertEqual(report['hosts'][0]['vlan'], 200)

    def test_fleet_byod_without_serial(self):
        device = inventory_policy.fleet_device({'id': 7, 'hardware_serial': '',
            'uuid': '01234567-89AB-CDEF-0123-456789ABCDEF', 'team_id': 4,
            'mdm': {'enrollment_status': 'On (personal)'}})
        cache = snapshot([device], 100)
        self.assertEqual(cache['identities'], {'01234567-89ab-cdef-0123-456789abcdef':
            {'device_id': 'fleet:7', 'groups': ['fleet:4'], 'enrolled': True}})

    def test_fleet_current_and_legacy_group_fields(self):
        for fields in ({'fleet_id': 8}, {'team_id': 8}):
            host = {'id': 1, 'hardware_serial': 'SERIAL', 'uuid': 'enrollment',
                    'mdm': {'enrollment_status': 'Off'}, **fields}
            record = inventory_policy.fleet_device(host)
            self.assertEqual(record['groups'], ['fleet:8'])
            self.assertFalse(record['enrolled'])
            self.assertEqual(record['identities'], ['SERIAL', 'enrollment'])
        host['fleet_id'] = 9
        self.assertEqual(inventory_policy.fleet_device(host)['groups'], ['fleet:9'])

    def test_unassigned_fleet_is_explicit_zero(self):
        self.assertEqual(inventory_policy.fleet_device({'id': 1})['groups'], ['fleet:0'])

    def test_jamf_site_and_udid_are_normalized(self):
        device = inventory_policy.jamf_device({'id': '2', 'udid': 'enrollment',
            'hardware': {'serialNumber': 'SERIAL'},
            'general': {'site': {'id': '3'}, 'remoteManagement': {'managed': True}}})
        self.assertEqual(device, {'device_id': 'jamf:2', 'identities': ['SERIAL', 'enrollment'],
                                 'groups': ['jamf:site:3'], 'enrolled': True})

    def test_duplicate_identities_are_denied_even_after_third_record(self):
        devices = [{'device_id': str(i), 'identities': ['same'], 'groups': ['staff'],
                    'enrolled': True} for i in range(3)]
        self.assertIsNone(snapshot(devices, 100)['identities']['same'])

    def test_atomic_publish_replaces_removed_hosts(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'inventory.json'
            dest.write_text('{"identities":{"removed":{}}}')
            inventory_policy.publish(dest, [], 100)
            self.assertEqual(json.loads(dest.read_text()),
                             {'version': 1, 'updated_at': 100, 'identities': {}})


if __name__ == '__main__':
    unittest.main()
