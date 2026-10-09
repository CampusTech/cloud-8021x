"""A single downstream collector must checkpoint both-server accounting safely."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import radius_usage_collector


def sample(second, kind, value):
    r={'event':kind,'src_ip':'203.0.113.1','nas_ip':'10.0.0.2',
       'calling_station':'aa:bb:cc:dd:ee:ff','session_id':'a',
       'session_time':second,'input_bytes':value,'output_bytes':value*2}
    return {'attributes':{'timestamp':f'2026-10-07T12:00:{second:02d}Z',
                           'attributes':r,'tags':['host:radius-primary']}}


class CollectorTests(unittest.TestCase):
    def test_legacy_checkpoint_recovers_overlap_without_recrediting_seen_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            posted = []
            batches = [[sample(0, 'Acct-Start', 0), sample(10, 'Acct-Update', 100)],
                       [sample(10, 'Acct-Update', 100), sample(20, 'Acct-Stop', 150)],
                       [sample(20, 'Acct-Stop', 150)]]
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': batches.pop(0)}
                posted.extend(payload)
                return {}
            state = Path(directory) / 'state'
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
            collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:30Z')
            legacy = json.loads(state.read_text())
            legacy.pop('credit_start', None)
            state.write_text(json.dumps(legacy))
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
            collector.run_once('2026-10-07T12:00:30Z', '2026-10-07T12:01:00Z')
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
            collector.run_once('2026-10-07T12:01:00Z', '2026-10-07T12:02:00Z')
            self.assertEqual(sum(item['input_bytes'] for item in posted), 150)
            self.assertEqual(len(posted), 2)
            self.assertEqual(json.loads(state.read_text()).get('credit_start'), 1791373530)

    def test_credit_floor_is_validated_against_initialized_checkpoint(self):
        saved = {'version': 1, 'tracker': {'version': 1, 'sessions': []},
                 'through': 20, 'pending': [], 'uncertain': False,
                 'seeded': False, 'preview_id': None, 'credit_start': 10}
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            for through, floor in ((20, float('nan')), (20, float('inf')), (20, True),
                                   (20, 21), (20, None), (None, 10)):
                with self.subTest(through=through, floor=floor):
                    state.write_text(json.dumps({**saved, 'through': through, 'credit_start': floor}))
                    with self.assertRaises(ValueError):
                        radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=Mock())
            for floor in (10, 20):
                state.write_text(json.dumps({**saved, 'credit_start': floor}))
                radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=Mock())

    def test_uninitialized_checkpoint_preserves_first_collection_window(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as directory:
                state = Path(directory) / 'state'
                saved = {'version': 1, 'tracker': {'version': 1, 'sessions': []},
                         'through': None, 'pending': [], 'uncertain': False,
                         'seeded': False, 'preview_id': None}
                if not legacy:
                    saved['credit_start'] = None
                state.write_text(json.dumps(saved))
                posted = []
                def http(url, headers, payload):
                    if 'events/search' in url:
                        return {'data': [sample(0, 'Acct-Start', 0), sample(10, 'Acct-Update', 100)]}
                    posted.extend(payload)
                    return {}
                collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
                collector.run_once('2026-10-07T12:00:20Z', '2026-10-07T12:00:30Z')
                self.assertEqual(posted, [])
                self.assertEqual(json.loads(state.read_text()).get('credit_start'), 1791374420)

    def test_late_new_session_before_initial_window_is_not_backfilled(self):
        with tempfile.TemporaryDirectory() as directory:
            posted = []
            batches = [[], [sample(0, 'Acct-Start', 0), sample(10, 'Acct-Update', 100)],
                       [sample(10, 'Acct-Update', 100), sample(30, 'Acct-Update', 150)]]
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': batches.pop(0)}
                posted.extend(payload)
                return {}
            state = Path(directory) / 'state'
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
            collector.run_once('2026-10-07T12:00:20Z', '2026-10-07T12:00:30Z')
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
            collector.run_once('2026-10-07T12:00:30Z', '2026-10-07T12:00:40Z')
            self.assertEqual(posted, [])
            collector.run_once('2026-10-07T12:00:40Z', '2026-10-07T12:00:50Z')
            self.assertEqual(sum(item['input_bytes'] for item in posted), 50)

    def test_initial_and_seed_windows_exclude_prior_traffic_even_after_replay(self):
        for seeded in (False, True):
            with self.subTest(seeded=seeded), tempfile.TemporaryDirectory() as directory:
                posted = []
                initial = [sample(0, 'Acct-Start', 0), sample(10, 'Acct-Update', 100),
                           sample(20, 'Acct-Update', 150)]
                batches = [initial + [sample(40, 'Acct-Update', 200)]]
                if not seeded:
                    batches.insert(0, initial)
                def http(url, headers, payload):
                    if 'events/search' in url:
                        return {'data': batches.pop(0)}
                    posted.extend(payload)
                    return {}
                state = Path(directory) / 'state'
                collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
                if seeded:
                    collector.seed_once([radius_usage_collector.flatten(item) for item in initial],
                                        '2026-10-07T12:00:15Z', '2026-10-07T12:00:30Z')
                else:
                    collector.run_once('2026-10-07T12:00:15Z', '2026-10-07T12:00:30Z')
                self.assertEqual(sum(item['input_bytes'] for item in posted), 50)
                collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
                collector.run_once('2026-10-07T12:00:30Z', '2026-10-07T12:00:50Z')
                self.assertEqual(sum(item['input_bytes'] for item in posted), 100)
                self.assertEqual(len(posted), 2)

    def test_recovery_credits_unseen_reports_before_the_runner_window(self):
        def event(minute, value):
            item = sample(0, 'Acct-Update', value)
            item['attributes']['timestamp'] = f'2026-10-07T12:{minute:02d}:00Z'
            item['attributes']['attributes']['session_time'] = minute * 60
            return item
        with tempfile.TemporaryDirectory() as directory:
            posted = []
            batches = [[sample(0, 'Acct-Start', 0), event(2, 100)],
                       [event(2, 100), event(5, 200), event(15, 300)]]
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': batches.pop(0)}
                posted.extend(payload)
                return {}
            state = Path(directory) / 'state'
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
            collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:04:00Z')
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, http=http)
            collector.run_once('2026-10-07T12:10:00Z', '2026-10-07T12:20:00Z')
            self.assertEqual(sum(item['input_bytes'] for item in posted), 300)

    def test_late_indexed_stop_credits_overlap_once(self):
        with tempfile.TemporaryDirectory() as directory:
            posted = []
            batches = [[sample(0, 'Acct-Start', 0), sample(10, 'Acct-Update', 100)],
                       [sample(10, 'Acct-Update', 100), sample(20, 'Acct-Stop', 150)],
                       [sample(20, 'Acct-Stop', 150)]]
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': batches.pop(0)}
                posted.extend(payload)
                return {}
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'},
                                                        Path(directory) / 'state', http=http)
            collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:30Z')
            collector.run_once('2026-10-07T12:00:30Z', '2026-10-07T12:01:00Z')
            collector.run_once('2026-10-07T12:01:00Z', '2026-10-07T12:02:00Z')
            self.assertEqual(sum(item['input_bytes'] for item in posted), 150)
            self.assertEqual(len(posted), 2)

    def test_configured_canonical_hosts_are_searched_validated_and_restored(self):
        hosts = ('radius-primary-project', 'radius-secondary-project')
        event = sample(10, 'Acct-Update', 100)
        event['attributes']['tags'] = ['host:' + hosts[0]]
        self.assertEqual(radius_usage_collector.flatten(event, hosts=hosts)['host'], hosts[0])
        with self.assertRaises(ValueError):
            radius_usage_collector.flatten(sample(10, 'Acct-Update', 100), hosts=hosts)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            events = [sample(0, 'Acct-Start', 0), event]
            events[0]['attributes']['tags'] = ['host:' + hosts[0]]
            http = Mock(side_effect=[{'data': events}, HTTPError('https://test', 403, 'denied', {}, None)])
            collector = radius_usage_collector.Collector(
                {'api_key':'api', 'app_key':'app'}, state, http=http, hosts=hosts)
            with self.assertRaises(RuntimeError):
                collector.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertIn('host:"radius-primary-project"', http.call_args_list[0].args[2]['filter']['query'])
            restarted = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, hosts=hosts)
            self.assertEqual(restarted.pending[0]['hostname'], hosts[0])
            with self.assertRaises(ValueError):
                radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state)
            for invalid in ('radius-primary OR *', '-radius', 'radius..primary', 'radius/primary'):
                with self.assertRaises(ValueError):
                    radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'}, state, hosts=[invalid])

    def test_successful_quiet_pass_sends_heartbeat_after_durable_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            posted = []
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': []}
                saved = json.loads(state.read_text())
                self.assertFalse(saved['uncertain'])
                self.assertEqual(saved['pending'], [])
                self.assertEqual(saved['through'], radius_usage_collector.radius_usage.timestamp('2026-10-07T12:00:20Z'))
                self.assertNotIn('DD-APPLICATION-KEY', headers)
                posted.extend(payload)
                return {}
            collector = radius_usage_collector.Collector(
                {'api_key': 'api', 'app_key': 'app'}, state, http=http,
                heartbeat=True, collector_id='radius-primary')
            collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:20Z')
            self.assertEqual(len(posted), 1)
            heartbeat = posted[0]
            self.assertEqual(heartbeat['service'], 'radius-usage-collector')
            self.assertEqual(heartbeat['event'], 'Collection-Heartbeat')
            self.assertEqual(heartbeat['collector_id'], 'radius-primary')
            self.assertEqual(heartbeat['through'], '2026-10-07T12:00:20Z')
            self.assertEqual(heartbeat['source_records'], 0)
            self.assertEqual(heartbeat['intervals'], 0)
            self.assertNotIn('input_bytes', heartbeat)
            self.assertNotIn('output_bytes', heartbeat)

    def test_heartbeat_failure_preserves_clean_traffic_checkpoint_for_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'
            http = Mock(side_effect=[{'data': []}, URLError('lost heartbeat response')])
            collector = radius_usage_collector.Collector(
                {'api_key': 'api', 'app_key': 'app'}, state, http=http,
                heartbeat=True, collector_id='radius-primary')
            with self.assertRaisesRegex(RuntimeError, 'heartbeat intake failed'):
                collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:20Z')
            saved = json.loads(state.read_text())
            self.assertFalse(saved['uncertain'])
            self.assertEqual(saved['pending'], [])
            fresh = Mock(side_effect=[{'data': []}, {}])
            restarted = radius_usage_collector.Collector(
                {'api_key': 'api', 'app_key': 'app'}, state, http=fresh,
                heartbeat=True, collector_id='radius-primary')
            restarted.run_once('2026-10-07T12:00:20Z', '2026-10-07T12:00:40Z')
            self.assertEqual(fresh.call_args.args[2][0]['event'], 'Collection-Heartbeat')

    def test_heartbeat_never_announces_health_on_partial_search_or_dry_run(self):
        for dry_run, response in ((False, {'data': [], 'meta': {'warnings': ['timeout']}}),
                                  (True, {'data': []})):
            with self.subTest(dry_run=dry_run), tempfile.TemporaryDirectory() as directory:
                http = Mock(return_value=response)
                collector = radius_usage_collector.Collector(
                    {'api_key': 'api', 'app_key': 'app'}, Path(directory) / 'state', http=http,
                    heartbeat=True, collector_id='radius-primary', dry_run=dry_run)
                if dry_run:
                    collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:20Z')
                else:
                    with self.assertRaises(ValueError):
                        collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:20Z')
                self.assertEqual(http.call_count, 1)
                self.assertIn('events/search', http.call_args.args[0])

    def test_incremental_checkpoint_prevents_overlap_and_restart_double_count(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'state.json'
            batches=[[sample(0,'Acct-Start',0),sample(10,'Acct-Update',100)],
                     [sample(10,'Acct-Update',100),sample(20,'Acct-Stop',150)]]
            uploaded=[]
            def http(url,headers,payload):
                if 'events/search' in url:return {'data':batches.pop(0)}
                uploaded.extend(payload);return {}
            c=radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:15Z')
            c=radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:25Z')
            self.assertEqual(sum(r['input_bytes'] for r in uploaded),150)
            self.assertEqual(sum(r['output_bytes'] for r in uploaded),300)
            self.assertTrue(all(r['service']=='radius-usage' for r in uploaded))
            self.assertTrue(all(r['hostname']=='radius-primary' for r in uploaded))
            self.assertNotIn('api',state.read_text())
            self.assertNotIn('app',state.read_text())

    def test_missing_owner_defaults_to_na_without_claiming_verified_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted = []
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': [sample(0, 'Acct-Start', 0), sample(10, 'Acct-Stop', 100)]}
                emitted.extend(payload)
                return {}
            collector = radius_usage_collector.Collector({'api_key': 'api', 'app_key': 'app'},
                                                        Path(directory) / 'state', http=http)
            collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:20Z')
            self.assertEqual(emitted[0]['device_owner'], 'N/A')
            self.assertFalse(emitted[0]['identity_verified'])

    def test_verified_owner_display_fallback_and_exact_nonblank_preservation(self):
        missing = object()
        for owner in (missing, None, '', ' \t ', 42, False, [], {}, ' owner@example.com '):
            with self.subTest(owner=owner), tempfile.TemporaryDirectory() as directory:
                events = [sample(0, 'Acct-Start', 0), sample(10, 'Acct-Stop', 100)]
                for event in events:
                    attrs = event['attributes']['attributes']
                    attrs.update(identity_verified=True, device_id='fleet:7')
                    if owner is not missing:
                        attrs['device_owner'] = owner
                emitted = []
                def http(url, headers, payload):
                    if 'events/search' in url:
                        return {'data': events}
                    emitted.extend(payload)
                    return {}
                collector = radius_usage_collector.Collector({'api_key': 'api', 'app_key': 'app'},
                                                            Path(directory) / 'state', http=http)
                collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:20Z')
                expected = owner if isinstance(owner, str) and owner.strip() else 'N/A'
                self.assertEqual(emitted[0]['device_owner'], expected)
                self.assertTrue(emitted[0]['identity_verified'])
                self.assertEqual(emitted[0]['device_id'], 'fleet:7')

    def test_unverified_owner_claim_is_not_used_for_display(self):
        with tempfile.TemporaryDirectory() as directory:
            events = [sample(0, 'Acct-Start', 0), sample(10, 'Acct-Stop', 100)]
            for event in events:
                event['attributes']['attributes'].update(
                    identity_verified=False, device_id='forged', device_owner='victim@example.com')
            emitted = []
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': events}
                emitted.extend(payload)
                return {}
            collector = radius_usage_collector.Collector({'api_key': 'api', 'app_key': 'app'},
                                                        Path(directory) / 'state', http=http)
            collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:20Z')
            self.assertEqual(emitted[0]['device_owner'], 'N/A')
            self.assertFalse(emitted[0]['identity_verified'])
            self.assertNotIn('device_id', emitted[0])

    def test_unenriched_site_is_visible_in_all_sites_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            emitted=[]
            def http(url,headers,payload):
                if 'events/search' in url:return {'data':[sample(0,'Acct-Start',0),sample(10,'Acct-Stop',100)]}
                emitted.extend(payload);return {}
            c=radius_usage_collector.Collector({'api_key':'api','app_key':'app'},Path(directory)/'state.json',http=http)
            c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertEqual(emitted[0]['site_name'],'Unknown site')

    def test_dry_run_posts_no_logs_and_writes_no_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'state.json';calls=[]
            def http(url,headers,payload):
                calls.append(url);return {'data':[sample(0,'Acct-Start',0),sample(10,'Acct-Stop',100)]}
            c=radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http,dry_run=True)
            report=c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertEqual(report['upload_bytes'],100)
            self.assertFalse(state.exists())
            self.assertEqual(len(calls),1)

    def test_ambiguous_intake_response_does_not_auto_resend_or_lose_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory)/'state.json'
            source={'data':[sample(0,'Acct-Start',0),sample(10,'Acct-Update',100)]}
            http=Mock(side_effect=[source,URLError('response lost')])
            c=radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            with self.assertRaises(Exception):c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertTrue(state.exists())
            fresh_http=Mock()
            c=radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=fresh_http)
            with self.assertRaises(Exception):c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:30Z')
            fresh_http.assert_not_called()

    def test_pagination_includes_second_server_and_duplicate_is_counted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            a=sample(10,'Acct-Update',100);b=json.loads(json.dumps(a));b['attributes']['tags']=['host:radius-secondary']
            http=Mock(side_effect=[{'data':[sample(0,'Acct-Start',0),a], 'meta':{'page':{'after':'cursor'}}},
                                   {'data':[b,sample(20,'Acct-Stop',150)]},{}])
            c=radius_usage_collector.Collector({'api_key':'api','app_key':'app'},Path(directory)/'state.json',http=http)
            report=c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:25Z')
            self.assertEqual(report['upload_bytes'],150)
            self.assertEqual(http.call_args_list[1].args[2]['page']['cursor'],'cursor')

    def test_outer_timestamp_overrides_naive_json_time_and_ssid_is_enriched(self):
        with tempfile.TemporaryDirectory() as directory:
            events = [sample(0, 'Acct-Start', 0), sample(10, 'Acct-Update', 100)]
            for event in events:
                event['attributes']['attributes']['timestamp'] = '2026-10-07 12:00:00'
                event['attributes']['attributes']['called_station'] = 'AA:BB:CC:DD:EE:FF:Campus:Test'
            uploaded = []
            def http(url, headers, payload):
                if 'events/search' in url:
                    self.assertIn('host:"radius-primary"', payload['filter']['query'])
                    self.assertIn('host:"radius-secondary"', payload['filter']['query'])
                    self.assertEqual(payload['filter']['from'], '2026-10-06T00:00:00Z')
                    return {'data': events}
                self.assertNotIn('DD-APPLICATION-KEY', headers)
                uploaded.extend(payload)
                return {}
            collector = radius_usage_collector.Collector({'api_key':'api', 'app_key':'app'},
                                                        Path(directory)/'state', http=http, preview_id='draft')
            collector.run_once('2026-10-07T12:00:00Z', '2026-10-07T12:00:20Z')
            self.assertEqual(uploaded[0]['timestamp'], '2026-10-07T12:00:10Z')
            self.assertEqual(uploaded[0]['ssid'], 'Campus:Test')
            self.assertEqual(uploaded[0]['preview_id'], 'draft')
            self.assertEqual(uploaded[0]['counter_quality'], 'legacy_32bit')

    def test_partial_second_page_preserves_previous_checkpoint_and_posts_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            http = Mock(side_effect=[{'data':[sample(0,'Acct-Start',0),sample(10,'Acct-Update',100)]}, {}])
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'}, state, http=http)
            c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:15Z')
            before = state.read_bytes()
            c.http = Mock(side_effect=[{'data':[sample(20,'Acct-Stop',150)],'meta':{'page':{'after':'x'}}},
                                       {'data':[], 'meta':{'warnings':[{'code':'timeout'}]}}])
            with self.assertRaises(ValueError):
                c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:25Z')
            self.assertEqual(state.read_bytes(), before)
            self.assertEqual(c.http.call_count, 2)
            self.assertEqual(c.http.call_args_list[0].args[2]['filter']['from'], '2026-10-07T11:45:15Z')

    def test_repeated_cursor_aborts_without_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            http = Mock(side_effect=[{'data':[sample(0,'Acct-Start',0)],'meta':{'page':{'after':'x'}}},
                                     {'data':[], 'meta':{'page':{'after':'x'}}}])
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            with self.assertRaises(ValueError):
                c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:25Z')
            self.assertFalse(state.exists())

    def test_intake_attempt_persists_uncertain_outbox_before_send(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data':[sample(0,'Acct-Start',0),sample(10,'Acct-Update',100)]}
                saved = json.loads(state.read_text())
                self.assertTrue(saved['uncertain'])
                self.assertEqual(saved['pending'][0]['input_bytes'],100)
                self.assertEqual(state.stat().st_mode & 0o777, 0o600)
                raise KeyboardInterrupt()  # Simulate a process dying in the network call.
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            with self.assertRaises(KeyboardInterrupt):
                c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            next_http = Mock()
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=next_http)
            with self.assertRaises(RuntimeError):
                c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:30Z')
            next_http.assert_not_called()

    def test_definite_rate_limit_can_retry_but_not_send_twice_after_success(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            limited = HTTPError('https://example.test',429,'Too many requests', {'Retry-After':'0'},None)
            http = Mock(side_effect=[limited, {'data':[sample(0,'Acct-Start',0),sample(10,'Acct-Update',100)]},
                                     limited, {}])
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            with patch('radius_usage_collector.time.sleep') as sleep:
                report = c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertEqual(report['upload_bytes'],100)
            self.assertEqual(sleep.call_count,2)
            self.assertEqual(json.loads(state.read_text())['pending'],[])
            self.assertFalse(json.loads(state.read_text())['uncertain'])

    def test_definite_auth_rejection_leaves_safe_pending_outbox(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            http = Mock(side_effect=[{'data':[sample(0,'Acct-Start',0),sample(10,'Acct-Update',100)]},
                                     HTTPError('https://example.test',403,'Forbidden',{},None)])
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            with self.assertRaisesRegex(RuntimeError,'HTTP 403'):
                c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            saved = json.loads(state.read_text())
            self.assertFalse(saved['uncertain'])
            self.assertEqual(len(saved['pending']),1)

    def test_seed_can_bootstrap_cached_records_once_without_search(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            http = Mock(return_value={})
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            events = [radius_usage_collector.flatten(sample(0,'Acct-Start',0)),
                      radius_usage_collector.flatten(sample(10,'Acct-Update',100))]
            report = c.seed_once(events,'2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertEqual(report['upload_bytes'],100)
            self.assertEqual(http.call_count,1)
            self.assertIn('http-intake.logs.',http.call_args.args[0])
            with self.assertRaises(ValueError):
                c.seed_once(events,'2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')

    def test_malformed_checkpoint_and_different_preview_never_reset_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            for saved in ({'version':2}, {'version':1}):
                state.write_text(json.dumps(saved))
                before = state.read_bytes()
                with self.assertRaises(ValueError):
                    radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=Mock())
                self.assertEqual(state.read_bytes(),before)
            state.unlink()
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,
                  http=Mock(return_value={'data':[]}), preview_id='a')
            report = c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertFalse(report['data_available'])
            self.assertEqual(report['source_completeness'],'observed_only')
            with self.assertRaises(ValueError):
                radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,preview_id='b')

    def test_redirect_handler_never_forwards_credentials(self):
        handler = radius_usage_collector.NoRedirect()
        self.assertIsNone(handler.redirect_request(None,None,302,'redirect',{},'https://other.example'))

    def test_derived_session_time_alias_is_interval_duration_not_cumulative_age(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            uploaded = []
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data':[sample(0,'Acct-Start',0),sample(10,'Acct-Update',100),sample(20,'Acct-Stop',150)]}
                uploaded.extend(payload)
                return {}
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},state,http=http)
            c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:25Z')
            self.assertEqual([r['session_time'] for r in uploaded],[10,10])
            self.assertEqual([r['interval_seconds'] for r in uploaded],[10,10])
            self.assertEqual([r['source_session_time'] for r in uploaded],[10,20])
            self.assertEqual([r['upload_delta_bytes'] for r in uploaded],[100,50])

    def test_single_cli_runner_lease_stays_locked_between_collection_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)/'state'
            with radius_usage_collector.runner_lock(state):
                with self.assertRaises(RuntimeError):
                    with radius_usage_collector.runner_lock(state):
                        self.fail('Second runner acquired lease')
            with radius_usage_collector.runner_lock(state):
                pass

    def test_explicit_64bit_source_quality_is_not_guessed_from_low_word(self):
        with tempfile.TemporaryDirectory() as directory:
            events = [sample(0,'Acct-Start',0),sample(10,'Acct-Update',100)]
            for event in events:
                event['attributes']['attributes']['counter_bits'] = 64
            posted = []
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': events}
                posted.extend(payload)
                return {}
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},Path(directory)/'state',http=http)
            c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertEqual(posted[0]['counter_quality'],'full_64bit')
            self.assertEqual(posted[0]['counter_bits'],64)

    def test_empty_or_malformed_site_uses_unknown_without_guessing_office(self):
        for site in (None, '', '   ', {}, 5, False, ['NYC']):
            with self.subTest(site=site), tempfile.TemporaryDirectory() as directory:
                events = [sample(0,'Acct-Start',0),sample(10,'Acct-Stop',100)]
                for event in events:
                    event['attributes']['attributes']['site_name'] = site
                posted = []
                def http(url, headers, payload):
                    if 'events/search' in url:
                        return {'data': events}
                    posted.extend(payload)
                    return {}
                c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},Path(directory)/'state',http=http)
                c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
                self.assertEqual(posted[0]['site_name'],'Unknown site')

    def test_known_source_site_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            events = [sample(0,'Acct-Start',0),sample(10,'Acct-Stop',100)]
            for event in events:
                event['attributes']['attributes']['site_name'] = 'NYC'
            posted = []
            def http(url, headers, payload):
                if 'events/search' in url:
                    return {'data': events}
                posted.extend(payload)
                return {}
            c = radius_usage_collector.Collector({'api_key':'api','app_key':'app'},Path(directory)/'state',http=http)
            c.run_once('2026-10-07T12:00:00Z','2026-10-07T12:00:20Z')
            self.assertEqual(posted[0]['site_name'],'NYC')


if __name__=='__main__':unittest.main()
