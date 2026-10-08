"""Controller names are cached per trusted office and never affect assignment."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))


class VlanNameTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('vlan_names', SCRIPTS / 'vlan_names.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name) / 'cache.json'
        self.sources = {'nyc': {'unifi_host_id': 'console:123', 'unifi_site_id': 'site-nyc'},
                        'atl': {'meraki_network_id': 'N_123'}}

    def page(self, data, offset=0, total=None):
        data = [dict(item, id=item.get('id', 'network-' + str(offset + index)))
                for index, item in enumerate(data)]
        return {'data': data, 'offset': offset, 'count': len(data),
                'totalCount': len(data) if total is None else total, 'limit': 200}

    def test_unifi_paginates_sites_and_networks_and_uses_exact_site(self):
        calls = []
        def request(url, headers):
            calls.append((url, headers))
            if '/sites?' in url:
                return self.page([{'id': 'wrong'}], total=2) if 'offset=0' in url else self.page([{'id': 'site-nyc'}], 1, 2)
            return self.page([{'vlanId': 5, 'name': 'Secure'}], total=2) if 'offset=0' in url else self.page([{'vlanId': 6, 'name': 'Guest'}], 1, 2)
        self.assertEqual(self.module.fetch_unifi(self.sources['nyc'], 'secret', request), {'5': 'Secure', '6': 'Guest'})
        self.assertEqual(len(calls), 4)
        self.assertIn('console%3A123/proxy/network/integration/v1/sites', calls[0][0])
        self.assertIn('/sites/site-nyc/networks', calls[2][0])
        self.assertEqual(calls[0][1]['X-API-Key'], 'secret')

    def test_unifi_selects_single_site_only_and_rejects_missing_pinned_site(self):
        for source, sites in [({'unifi_host_id': 'console'}, [{'id': 'a'}, {'id': 'b'}]),
                              (self.sources['nyc'], [{'id': 'other'}])]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.module.fetch_unifi(source, 'secret', lambda u, h: self.page(sites))
        pages = iter([self.page([{'id': 'one'}]), self.page([{'vlanId': 5, 'name': 'Secure'}])])
        self.assertEqual(self.module.fetch_unifi({'unifi_host_id': 'console'}, 'secret', lambda u, h: next(pages)), {'5': 'Secure'})

    def test_unifi_incomplete_or_repeated_pagination_is_rejected(self):
        for response in [self.page([], total=2), self.page([{'id': 'one'}], total=2),
                         {'data': []}, self.page([], offset=99), self.page([], total=True)]:
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.module.fetch_unifi({'unifi_host_id': 'console'}, 'secret', lambda u, h: response)

    def test_meraki_reads_appliance_and_named_vlan_profiles_without_using_ssid_names(self):
        calls = []
        def request(url, headers):
            calls.append(url)
            return ([{'id': '5', 'name': 'Secure'}] if url.endswith('/appliance/vlans') else
                    [{'vlanNames': [{'vlanId': '6', 'name': 'Guest'}]}])
        self.assertEqual(self.module.fetch_meraki(self.sources['atl'], 'secret', request), {'5': 'Secure', '6': 'Guest'})
        self.assertTrue(all('/networks/N_123/' in u for u in calls))

    def test_meraki_wireless_only_network_can_use_vlan_profiles(self):
        def request(url, headers):
            if url.endswith('/appliance/vlans'):
                raise HTTPError(url, 404, 'no appliance', {}, None)
            return [{'vlanNames': [{'vlanId': '4', 'name': 'Conferencing'}]}]
        self.assertEqual(self.module.fetch_meraki(self.sources['atl'], 'secret', request), {'4': 'Conferencing'})

    def test_meraki_disabled_appliance_vlans_can_use_vlan_profiles(self):
        calls = []
        def request(url, headers):
            calls.append(url)
            if url.endswith('/appliance/vlans'):
                raise HTTPError(url, 400, 'VLANs are not enabled for this network', {}, None)
            return [{'vlanNames': [{'vlanId': '4', 'name': 'Conferencing'}]}]
        self.assertEqual(self.module.fetch_meraki(self.sources['atl'], 'secret', request), {'4': 'Conferencing'})
        self.assertEqual([url.rsplit('/', 1)[-1] for url in calls], ['vlans', 'vlanProfiles'])

    def test_meraki_vlan_profile_bad_request_is_not_optional(self):
        def request(url, headers):
            if url.endswith('/vlanProfiles'):
                raise HTTPError(url, 400, 'bad request', {}, None)
            return [{'id': 5, 'name': 'Secure'}]
        with self.assertRaises(HTTPError) as raised:
            self.module.fetch_meraki(self.sources['atl'], 'secret', request)
        self.assertEqual(raised.exception.code, 400)

    def test_meraki_permission_and_rate_limit_failures_do_not_publish_partial_results(self):
        for code in (403, 429, 500):
            def request(url, headers):
                if url.endswith('/vlanProfiles'):
                    raise HTTPError(url, code, 'failed', {}, None)
                return [{'id': 5, 'name': 'Secure'}]
            with self.subTest(code=code), self.assertRaises(HTTPError):
                self.module.fetch_meraki(self.sources['atl'], 'secret', request)

    def test_conflicting_ids_and_invalid_names_are_omitted(self):
        rows = [{'vlanId': 5, 'name': 'Secure'}, {'vlanId': 5, 'name': 'Other'},
                {'vlanId': 6, 'name': 'Guest "BYOD"'}, {'vlanId': True, 'name': 'Bad'},
                {'vlanId': '06', 'name': 'Bad'}, {'vlanId': 0, 'name': 'Bad'},
                {'vlanId': 4095, 'name': 'Bad'}, {'vlanId': 7, 'name': ' Bad '},
                {'vlanId': 8, 'name': 'Line\nBreak'}, {'vlanId': 9, 'name': 'x' * 129}]
        pages = iter([self.page([{'id': 'site-nyc'}]), self.page(rows)])
        self.assertEqual(self.module.fetch_unifi(self.sources['nyc'], 'key', lambda u, h: next(pages)), {'6': 'Guest "BYOD"'})

    def test_refresh_preserves_failed_site_and_updates_other_site_atomically(self):
        old = {'source': self.sources['nyc'], 'updated_at': 100, 'names': {'5': 'Old NYC'}}
        self.cache.write_text(json.dumps({'locations': {'nyc': old, 'removed': old}}))
        def fetch(source, credentials):
            if source == self.sources['nyc']:
                raise ValueError('unavailable')
            return {'5': 'ATL Secure'}
        self.module.refresh(self.sources, {}, self.cache, now=200, fetch=fetch)
        result = json.loads(self.cache.read_text())['locations']
        self.assertEqual(result, {'nyc': old, 'atl': {'source': self.sources['atl'], 'updated_at': 200, 'names': {'5': 'ATL Secure'}}})
        self.assertEqual(self.module.lookup(self.sources, 'nyc', 5, self.cache, now=200), 'Old NYC')
        self.assertEqual(self.module.lookup(self.sources, 'atl', 5, self.cache, now=200), 'ATL Secure')

    def test_successful_refresh_renames_and_deletions_replace_previous_snapshot(self):
        for names in ({'5': 'Old'}, {'5': 'Renamed'}, {}):
            self.module.refresh(self.sources, {}, self.cache, now=200, fetch=lambda s, c: names)
            self.assertEqual(self.module.lookup(self.sources, 'nyc', 5, self.cache, now=201), names.get('5', ''))

    def test_stale_future_corrupt_changed_source_and_unknown_office_never_mislabel(self):
        self.module.refresh(self.sources, {}, self.cache, now=200, fetch=lambda s, c: {'5': 'Secure'})
        for office, vlan, now, sources in [('other', 5, 201, self.sources), ('nyc', None, 201, self.sources),
                ('nyc', 5, 200 + self.module.MAX_AGE, self.sources), ('nyc', 5, 199, self.sources),
                ('nyc', 5, 201, {'nyc': {'unifi_host_id': 'changed'}})]:
            self.assertEqual(self.module.lookup(sources, office, vlan, self.cache, now=now), '')
        self.cache.write_text('invalid')
        self.assertEqual(self.module.lookup(self.sources, 'nyc', 5, self.cache, now=201), '')

    def test_signed_auth_and_accounting_use_api_name_over_manual_fallback(self):
        import radius_identity
        root = Path(self.temp.name)
        key = root / 'key'
        key.write_bytes(b'A' * 64)
        sources_path = root / 'sources.json'
        sources_path.write_text(json.dumps(self.sources))
        config = root / 'policy.json'
        config.write_text(json.dumps({'locations': {'nyc': {'vlan_names': {'5': 'Manual'}}}}))
        self.module.refresh(self.sources, {}, self.cache, now=200, fetch=lambda s, c: {'5': 'Controller name'})
        with patch.object(radius_identity, 'KEY_FILE', str(key)), patch.object(radius_identity, 'CONFIG_FILE', str(config)), \
             patch.object(self.module, 'CONFIG_FILE', sources_path), patch.object(self.module, 'CACHE_FILE', self.cache), \
             patch.object(radius_identity.time, 'time', return_value=201):
            token = radius_identity.issue(b'A' * 64, 'fleet:26', 'ab' * 32, 5, 'nyc', 'AABBCCDDEEFF', 200)
            for accounting in (False, True):
                packet = {'config': (('Tmp-String-1', 'nyc'),), 'request': (('Calling-Station-Id', 'AABBCCDDEEFF'),), 'reply': ()}
                packet['request' if accounting else 'reply'] += (('Class', token),)
                # Ensure the identity module uses this isolated collector instance.
                with patch.object(radius_identity, 'vlan_names', self.module):
                    self.assertEqual(dict(radius_identity.enrich(packet, accounting))['Tmp-String-7'], 'Controller name')
                    self.cache.unlink()
                    self.assertEqual(dict(radius_identity.enrich(packet, accounting))['Tmp-String-7'], 'Manual')
                    self.module.refresh(self.sources, {}, self.cache, now=200, fetch=lambda s, c: {'5': 'Controller name'})


if __name__ == '__main__':
    unittest.main()
