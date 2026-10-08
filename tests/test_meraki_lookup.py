"""Meraki RADIUS Called-Station-Id can use a hardware MAC, not a BSSID."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_log_identity import lookup_module

ROOT = Path(__file__).resolve().parents[1]
ROOM = {'ap_name': 'Room 102', 'site_name': 'MTI Wireless'}


class MerakiLookupTests(unittest.TestCase):
    def test_hardware_mac_enriches_auth_and_accounting_json(self):
        module = lookup_module()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / 'cache.json'
            cache.write_text(json.dumps({'by_bssid': {'FE9E28780630': ROOM},
                                         'by_mac': {'F89E28780630': ROOM}}))
            with patch.object(module, 'MERAKI_CACHE_FILE', str(cache)), \
                    patch.object(module, 'UNIFI_CACHE_FILE', str(Path(directory) / 'absent')):
                for called in ('F8-9E-28-78-06-30:Campus', 'f8:9e:28:78:06:30:Campus'):
                    for handler in (module.post_auth, module.accounting):
                        with self.subTest(called=called, handler=handler.__name__):
                            result = handler({'request': (('Called-Station-Id', called),
                                                          ('Acct-Status-Type', 'Start'))})
                            attrs = dict(result[1]['reply'])
                            record = json.loads(attrs['Tmp-String-4'].replace(chr(92) * 2, chr(92)))
                            self.assertEqual(record['ap_name'], 'Room 102')
                            self.assertEqual(record['site_name'], 'MTI Wireless')

    def test_existing_bssid_only_cache_still_works_without_offset_guesses(self):
        module = lookup_module()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / 'cache.json'
            cache.write_text(json.dumps({'by_bssid': {'FE9E28780630': ROOM}}))
            with patch.object(module, 'MERAKI_CACHE_FILE', str(cache)):
                self.assertEqual(module._meraki_lookup('FE-9E-28-78-06-30:Campus'), ROOM)
                self.assertIsNone(module._meraki_lookup('F8-9E-28-78-06-30:Campus'))


    def test_lookup_does_not_accept_malformed_prefix_or_cross_index_collision(self):
        module = lookup_module()
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / 'cache.json'
            cache.write_text(json.dumps({'by_bssid': {'F89E28780630': ROOM},
                'by_mac': {'F89E28780630': {'ap_name': 'Other', 'site_name': 'Other'}}}))
            with patch.object(module, 'MERAKI_CACHE_FILE', str(cache)):
                self.assertIsNone(module._meraki_lookup('F8-9E-28-78-06-30:Campus'))
                self.assertIsNone(module._meraki_lookup('ZZF8-9E-28-78-06-30:Campus'))
                self.assertIsNone(module._meraki_lookup('F8!9E28780630:Campus'))


def builder_module():
    import types
    source = (ROOT / 'scripts/startup.sh').read_text().split("<< 'MERAKICACHEEOF'\n", 1)[1].split('\nMERAKICACHEEOF', 1)[0]
    source = source.split("<< 'PYEOF'\n", 1)[1].split('\nPYEOF', 1)[0]
    module = types.ModuleType('meraki_cache_fixture')
    exec(compile(source, 'meraki_cache.py', 'exec'), module.__dict__)
    return module


def response(items, link=None):
    import io
    from email.message import Message
    stream = io.BytesIO(json.dumps(items).encode())
    stream.headers = Message()
    if link:
        stream.headers['Link'] = link
    return stream


def devices(mac='F8:9E:28:78:06:30', network='N_1'):
    return [{'serial': 'Q123', 'networkId': network, 'mac': mac, 'name': 'Inventory label'}]


def statuses(name='Room 102', site='MTI Wireless', network='N_1', bssid='FE:9E:28:78:06:30'):
    return [{'serial': 'Q123', 'name': name, 'network': {'id': network, 'name': site},
             'basicServiceSets': [{'bssid': bssid}]}]


class MerakiBuilderTests(unittest.TestCase):
    def test_joins_exact_hardware_mac_by_serial_and_network(self):
        cache = builder_module().build_cache(devices(), statuses())
        self.assertEqual(cache, {'by_bssid': {'FE9E28780630': ROOM},
                                 'by_mac': {'F89E28780630': ROOM}})

    def test_network_move_does_not_mislabel_hardware_mac(self):
        cache = builder_module().build_cache(devices(network='N_2'), statuses())
        self.assertEqual(cache['by_mac'], {})
        self.assertEqual(cache['by_bssid'], {'FE9E28780630': ROOM})

    def test_same_labels_do_not_hide_two_distinct_ap_identities(self):
        other = statuses()[0]
        other['serial'] = 'Q456'
        cache = builder_module().build_cache(devices() + [{
                    'serial': 'Q456', 'networkId': 'N_1', 'mac': 'F8:9E:28:78:06:30'}],
                    statuses() + [other])
        self.assertEqual(cache, {'by_bssid': {}, 'by_mac': {}})

    def test_invalid_mac_not_indexed(self):
        cache = builder_module().build_cache(devices(mac='GG:9E:28:78:06:30'),
                                             statuses(bssid='FE!9E28780630'))
        self.assertEqual(cache, {'by_mac': {}, 'by_bssid': {}})

    def test_conflicting_mac_identity_is_removed_even_if_seen_again(self):
        cache = builder_module().build_cache(devices(),
                statuses() + statuses(name='Other AP') + statuses())
        self.assertEqual(cache, {'by_mac': {}, 'by_bssid': {}})

    def test_cross_index_collision_is_removed(self):
        wireless = statuses() + [{'serial': 'Q456', 'name': 'Other AP',
                    'network': {'id': 'N_2', 'name': 'Other Site'},
                    'basicServiceSets': [{'bssid': 'F8:9E:28:78:06:30'}]}]
        cache = builder_module().build_cache(devices(), wireless)
        self.assertNotIn('F89E28780630', cache['by_mac'])
        self.assertNotIn('F89E28780630', cache['by_bssid'])
        self.assertEqual(cache['by_bssid']['FE9E28780630'], ROOM)

    def test_paginated_both_endpoints_refresh_atomically(self):
        from unittest.mock import Mock
        module = builder_module()
        opener = Mock()
        base = module.API + '/organizations/123'
        opener.open.side_effect = [
            response([], '<' + base + '/devices?startingAfter=x>; rel=next'),
            response(devices()),
            response({'items': []}, '<' + base + '/wireless/ssids/statuses/byDevice?startingAfter=x>; rel="next"'),
            response({'items': statuses()})]
        with tempfile.TemporaryDirectory() as directory:
            cred, cache = Path(directory) / 'creds', Path(directory) / 'cache'
            cred.write_text(json.dumps({'api_key': 'secret', 'org_id': '123'}))
            cache.write_text('old')
            with patch.object(module, 'build_opener', return_value=opener):
                module.refresh(str(cred), str(cache))
            self.assertEqual(json.loads(cache.read_text())['by_mac'], {'F89E28780630': ROOM})
            self.assertEqual(opener.open.call_count, 4)
            self.assertEqual(cache.stat().st_mode & 0o777, 0o644)
            self.assertEqual(set(p.name for p in Path(directory).iterdir()), {'creds', 'cache'})

    def test_partial_fetch_parse_and_page_limit_leave_old_cache_untouched(self):
        from unittest.mock import Mock
        import io
        from email.message import Message
        for failure in ('http', 'json', 'schema', 'bare_list', 'cap', 'cycle'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                module = builder_module()
                module.MAX_PAGES = 1
                opener = Mock()
                bad = io.BytesIO(b'not json'); bad.headers = Message()
                base = module.API + '/organizations/123/devices'
                effects = {
                    'http': [response(devices()), OSError('request failed')],
                    'json': [response(devices()), bad],
                    'schema': [response(devices()), response({'unexpected': []})],
                    'bare_list': [response(devices()), response(statuses())],
                    'cap': [response(devices(), '<' + base + '?startingAfter=x>; rel=next')],
                    'cycle': [response(devices(), '<' + base + '?perPage=500>; rel=next')],
                }
                opener.open.side_effect = effects[failure]
                cred, cache = Path(directory) / 'creds', Path(directory) / 'cache'
                cred.write_text(json.dumps({'api_key': 'secret', 'org_id': '123'}))
                cache.write_text('old')
                with patch.object(module, 'build_opener', return_value=opener), self.assertRaises(Exception):
                    module.refresh(str(cred), str(cache))
                self.assertEqual(cache.read_text(), 'old')
                self.assertEqual(set(p.name for p in Path(directory).iterdir()), {'creds', 'cache'})

    def test_unsafe_next_links_rejected_before_key_can_be_sent(self):
        from unittest.mock import Mock
        module = builder_module()
        initial = module.API + '/organizations/123/devices?perPage=500'
        unsafe = ['https://evil.example/api/v1/organizations/123/devices',
                  'http://api.meraki.com/api/v1/organizations/123/devices',
                  'https://api.meraki.com:444/api/v1/organizations/123/devices',
                  'https://user@api.meraki.com/api/v1/organizations/123/devices',
                  module.API + '/organizations/OTHER/devices',
                  initial + '#fragment']
        for url in unsafe:
            with self.subTest(url=url):
                opener = Mock()
                opener.open.return_value = response([], '<' + url + '>; rel=next')
                with self.assertRaises(ValueError):
                    module.fetch_pages(opener, initial, 'secret')
                self.assertEqual(opener.open.call_count, 1)

    def test_redirects_are_rejected(self):
        with self.assertRaises(ValueError):
            builder_module().NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.example')

    def test_cache_write_failure_keeps_old_cache_and_cleans_temporary(self):
        from unittest.mock import Mock
        module = builder_module()
        opener = Mock()
        opener.open.side_effect = [response(devices()), response({'items': statuses()})]
        with tempfile.TemporaryDirectory() as directory:
            cred, cache = Path(directory) / 'creds', Path(directory) / 'cache'
            cred.write_text(json.dumps({'api_key': 'secret', 'org_id': '123'}))
            cache.write_text('old')
            with patch.object(module, 'build_opener', return_value=opener), \
                    patch.object(module.os, 'replace', side_effect=OSError('failed')), self.assertRaises(OSError):
                module.refresh(str(cred), str(cache))
            self.assertEqual(cache.read_text(), 'old')
            self.assertEqual(set(p.name for p in Path(directory).iterdir()), {'creds', 'cache'})


    def test_generated_worker_subprocess_preserves_cache_on_failure(self):
        import subprocess
        import sys
        source = (ROOT / 'scripts/startup.sh').read_text().split("<< 'MERAKICACHEEOF'\n", 1)[1].split('\nMERAKICACHEEOF', 1)[0]
        source = source.split("<< 'PYEOF'\n", 1)[1].split('\nPYEOF', 1)[0]
        fixture = """
from io import BytesIO
from email.message import Message
from unittest.mock import Mock
opener = Mock()
responses = []
for body in TEST_BODIES:
    response = BytesIO(body.encode())
    response.headers = Message()
    responses.append(response)
opener.open.side_effect = responses
build_opener = lambda *args: opener
"""
        for fail in (False, True):
            with self.subTest(failure=fail), tempfile.TemporaryDirectory() as directory:
                cred, cache = Path(directory) / 'creds', Path(directory) / 'cache'
                cred.write_text(json.dumps({'api_key': 'secret', 'org_id': '123'}))
                cache.write_text('old')
                bodies = [json.dumps(devices()), 'broken JSON' if fail else json.dumps({'items': statuses()})]
                injected = 'TEST_BODIES = ' + repr(bodies) + '\n' + fixture
                script = source.replace("if __name__ == '__main__':", injected + "\nif __name__ == '__main__':")
                run = subprocess.run([sys.executable, '-c', script, str(cred), str(cache)], capture_output=True, text=True)
                self.assertEqual(run.returncode, 1 if fail else 0, run.stderr)
                if fail:
                    self.assertEqual(cache.read_text(), 'old')
                    self.assertNotIn('secret', run.stderr)
                else:
                    self.assertEqual(json.loads(cache.read_text())['by_mac'], {'F89E28780630': ROOM})


if __name__ == '__main__':
    unittest.main()
