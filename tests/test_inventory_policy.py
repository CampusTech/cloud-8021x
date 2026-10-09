# Historical parity fixture only; current deployment is tested by test_green_deployment.py.
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/legacy/scripts'))
from device_policy import snapshot
import inventory_policy


class InventoryTests(unittest.TestCase):
    def test_serial_free_fleet_metadata_is_keyed_by_stable_device_id(self):
        device = inventory_policy.fleet_device({'id': 7, 'uuid': 'byod-enrollment',
            'hardware_serial': None, 'display_name': 'Personal iPhone',
            'hardware_model': 'iPhone', 'device_mapping': [{'email': 'owner@example.com'}],
            'mdm': {'enrollment_status': 'On (personal)'}})
        data = snapshot([device], 100)
        self.assertEqual(data['devices']['fleet:7'], {
            'serial': '', 'device_name': 'Personal iPhone', 'device_model': 'iPhone',
            'device_owner': 'owner@example.com'})

    def test_fleet_nullable_enrollment_status_does_not_abort_inventory(self):
        for mdm, expected in [(None, False), ({}, False),
                              ({'enrollment_status': None}, False),
                              ({'enrollment_status': ''}, False),
                              ({'enrollment_status': 'Off'}, False),
                              ({'enrollment_status': 'On (personal)'}, True),
                              ({'enrollment_status': 'On (automatic)'}, True)]:
            with self.subTest(mdm=mdm):
                devices = [inventory_policy.fleet_device({'id': 1, 'uuid': 'first', 'mdm': mdm}),
                           inventory_policy.fleet_device({'id': 2, 'uuid': 'second',
                               'mdm': {'enrollment_status': 'On'}})]
                identities = snapshot(devices, 100)['identities']
                self.assertEqual(identities['first']['enrolled'], expected)
                self.assertTrue(identities['second']['enrolled'])

    def test_fleet_metadata_handles_null_fields_and_missing_owner(self):
        host = {'id': 7, 'uuid': 'enrollment', 'hardware_serial': None,
                'display_name': None, 'computer_name': None, 'hostname': None,
                'hardware_model': None, 'device_mapping': None, 'end_users': None}
        self.assertEqual(inventory_policy.fleet_device(host)['metadata'], {
            'serial': '', 'device_name': '', 'device_model': '', 'device_owner': ''})

    def test_fleet_metadata_uses_name_and_owner_fallbacks(self):
        host = {'id': 7, 'hardware_serial': 'SERIAL', 'display_name': None,
                'computer_name': 'Computer', 'hostname': 'hostname',
                'hardware_model': 'MacBook', 'device_mapping': [{'email': None}],
                'end_users': [{'idp_username': 'owner@example.com'}]}
        metadata = inventory_policy.fleet_device(host)['metadata']
        self.assertEqual(metadata, {'serial': 'SERIAL', 'device_name': 'Computer',
                                   'device_model': 'MacBook', 'device_owner': 'owner@example.com'})
        host['computer_name'] = None
        host['device_mapping'] = [{'email': 'assigned@example.com'}]
        metadata = inventory_policy.fleet_device(host)['metadata']
        self.assertEqual(metadata['device_name'], 'hostname')
        self.assertEqual(metadata['device_owner'], 'assigned@example.com')

    def test_metadata_conflicting_device_ids_stay_ambiguous(self):
        first = inventory_policy.fleet_device({'id': 7, 'uuid': 'one', 'display_name': 'First'})
        other = inventory_policy.fleet_device({'id': 7, 'uuid': 'two', 'display_name': 'Other'})
        data = snapshot([first, other, first], 100)
        self.assertIsNone(data['devices']['fleet:7'])
        self.assertEqual(data['identities']['one'], {
            'device_id': 'fleet:7', 'groups': ['fleet:0'], 'enrolled': False})

    def test_metadata_identical_device_ids_are_not_ambiguous(self):
        device = inventory_policy.fleet_device({'id': 7, 'uuid': 'one', 'display_name': 'First'})
        self.assertEqual(snapshot([device, device], 100)['devices']['fleet:7'], device['metadata'])

    def test_snapshot_metadata_rejects_invalid_values_without_changing_policy(self):
        device = inventory_policy.fleet_device({'id': 7, 'uuid': 'one'})
        for metadata in (None, [], {}, {**device['metadata'], 'device_name': 7},
                         {**device['metadata'], 'device_name': 'x' * 1025}):
            with self.subTest(metadata=metadata):
                data = snapshot([{**device, 'metadata': metadata}, device], 100)
                self.assertIsNone(data['devices']['fleet:7'])
                self.assertEqual(data['identities']['one'], {
                    'device_id': 'fleet:7', 'groups': ['fleet:0'], 'enrolled': False})

    def test_snapshot_without_metadata_preserves_legacy_schema(self):
        device = {'device_id': 'legacy:1', 'identities': ['serial'],
                  'groups': [], 'enrolled': True}
        self.assertEqual(snapshot([device], 100), {'version': 1, 'updated_at': 100,
            'identities': {'serial': {'device_id': 'legacy:1', 'groups': [], 'enrolled': True}}})

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
        config['locations'] = {'nyc': {'group_vlans': {'fleet:4': 210}},
                               'atl': {'group_vlans': {'fleet:4': 220}}}
        report = inventory_policy.certificate_readiness([host], [device], obs, config, 101)
        self.assertTrue(report['ready'])
        self.assertEqual(report['hosts'][0]['locations'], {
            'nyc': {'reason': 'ready', 'vlan': 210}, 'atl': {'reason': 'ready', 'vlan': 220}})
        config['locations']['atl'] = {'dynamic_vlans': False}
        report = inventory_policy.certificate_readiness([host], [device], obs, config, 101)
        self.assertTrue(report['ready'])
        self.assertEqual(report['hosts'][0]['locations']['atl'], {
            'reason': 'ready', 'vlan': None, 'dynamic_vlans': False})
        config['locations']['atl'] = {'group_vlans': {}}
        config['locations']['atl']['group_vlans'] = {}
        report = inventory_policy.certificate_readiness([host], [device], obs, config, 101)
        self.assertFalse(report['ready'])
        self.assertEqual(report['hosts'][0]['locations']['atl']['reason'], 'no_vlan_assignment')

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
