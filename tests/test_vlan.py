"""Exercise policy decisions, including the RADIUS reply contract UniFi consumes."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
sys.modules['radiusd'] = types.SimpleNamespace(
    RLM_MODULE_REJECT=0, RLM_MODULE_FAIL=1, RLM_MODULE_OK=2,
    RLM_MODULE_UPDATED=8, L_ERR=3, L_INFO=6, radlog=lambda *args: None)


class VLANTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = Path(self.tmp.name) / 'policy.json'
        self.config = Path(self.tmp.name) / 'config.json'
        self.policy = {'group_vlans': {'staff': 100, 'byod': 200},
                       'fallback_vlan': None, 'cache_max_age': 3600,
                       'cache_file': str(self.cache)}
        self.config.write_text(json.dumps(self.policy))
        spec = importlib.util.spec_from_file_location('radius_vlan', SCRIPTS / 'radius_vlan.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.module.CONFIG_FILE = str(self.config)
        self.write_cache()

    def write_cache(self, groups=None, enrolled=True, age=0):
        self.cache.write_text(json.dumps({'version': 1, 'updated_at': time.time() - age,
            'identities': {'personal-enrollment-id': {'device_id': '42',
                'groups': ['byod'] if groups is None else groups, 'enrolled': enrolled},
                'STAFFSERIAL': {'device_id': '1', 'groups': ['staff'], 'enrolled': True}}}))

    def request(self, identity='personal-enrollment-id', resumed=False):
        attrs = [('User-Name', 'STAFFSERIAL')]
        if identity is not None:
            attrs.append(('TLS-Client-Cert-Common-Name', identity))
        if resumed:
            attrs.append(('EAP-Session-Resumed', '1'))
        return {'request': tuple(attrs)}

    def assert_vlan(self, vlan, request=None):
        result = self.module.authorize(self.request() if request is None else request)
        self.assertEqual(result[0], 8)
        self.assertEqual(dict(result[1]['reply']), {
            'Tunnel-Type': '13', 'Tunnel-Medium-Type': '6',
            'Tunnel-Private-Group-Id': str(vlan)})

    def test_byod_certificate_overrides_spoofed_outer_identity(self):
        self.assert_vlan(200)

    def test_existing_windows_certificate(self):
        self.assert_vlan(100, self.request('STAFFSERIAL Campus WiFi'))

    def test_same_fleet_uses_authenticated_office_mapping(self):
        self.policy['locations'] = {
            'nyc': {'group_vlans': {'byod': 200}},
            'atl': {'group_vlans': {'byod': 220}},
        }
        self.config.write_text(json.dumps(self.policy))
        for location, vlan in [('nyc', 200), ('atl', 220)]:
            request = self.request(resumed=True)
            request['request'] += (('Tmp-String-1', location), ('NAS-Identifier', 'nyc'))
            self.assert_vlan(vlan, request)

    def test_location_mode_rejects_unknown_missing_or_duplicate_context(self):
        self.policy['locations'] = {'nyc': {'group_vlans': {'byod': 210}}}
        self.policy['fallback_vlan'] = 999
        self.config.write_text(json.dumps(self.policy))
        for attrs in ((), (('Tmp-String-1', 'unknown'),),
                      (('NAS-Identifier', 'nyc'),),
                      (('Tmp-String-1', 'nyc'), ('Tmp-String-1', 'nyc'))):
            request = self.request()
            request['request'] += attrs
            self.assertEqual(self.module.authorize(request), 0)

    def test_location_rules_do_not_inherit_global_vlans(self):
        self.policy['locations'] = {'nyc': {'group_vlans': {}, 'fallback_vlan': 230}}
        self.config.write_text(json.dumps(self.policy))
        request = self.request()
        request['request'] += (('Tmp-String-1', 'nyc'),)
        self.assert_vlan(230, request)
        self.policy['locations']['nyc'].pop('fallback_vlan')
        self.config.write_text(json.dumps(self.policy))
        self.assertEqual(self.module.authorize(request), 0)

    def test_untrusted_username_cannot_replace_missing_certificate(self):
        self.assertEqual(self.module.authorize(self.request(None)), 0)

    def test_reauthentication_uses_current_membership(self):
        self.assert_vlan(200)
        self.write_cache(groups=['staff'])
        self.assert_vlan(100, self.request(resumed=True))

    def test_unknown_stale_unenrolled_and_ambiguous_deny(self):
        for kwargs in ({'age': 3601}, {'enrolled': False}, {'groups': []},
                       {'groups': ['staff', 'byod']}, {'age': -60}):
            with self.subTest(kwargs=kwargs):
                self.write_cache(**kwargs)
                self.assertEqual(self.module.authorize(self.request()), 0)
        self.assertEqual(self.module.authorize(self.request('unknown')), 0)

    def test_fallback_only_for_known_enrolled_unmapped_device(self):
        self.policy['fallback_vlan'] = 999
        self.config.write_text(json.dumps(self.policy))
        self.write_cache(groups=[])
        self.assert_vlan(999)
        self.assertEqual(self.module.authorize(self.request('unknown')), 0)
        self.write_cache(enrolled=False)
        self.assertEqual(self.module.authorize(self.request()), 0)

    def test_invalid_cache_or_config_denies(self):
        for content in ('{', '{}', 'null'):
            self.cache.write_text(content)
            self.assertEqual(self.module.authorize(self.request()), 0)
        self.write_cache()
        for vlan in (0, 4095, 1.5, True, '100'):
            self.policy['group_vlans']['byod'] = vlan
            self.config.write_text(json.dumps(self.policy))
            self.assertEqual(self.module.authorize(self.request()), 0)


if __name__ == '__main__':
    unittest.main()
