"""Keep exported dashboard telemetry tied to its actual RADIUS sources."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

class DashboardTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.dashboard=json.loads((ROOT/'datadog-dashboard.json').read_text())
        self.widgets={w['definition'].get('title'):w['definition'] for g in self.dashboard['widgets'] for w in g['definition'].get('widgets',[])}

    def test_system_metrics_do_not_include_unrelated_datadog_hosts(self):
        checked=0
        for definition in self.widgets.values():
            for request in definition.get('requests',[]):
                for query in request.get('queries',[]):
                    if query.get('data_source')=='metrics' and ':system.' in query.get('query',''):
                        checked+=1
                        with self.subTest(widget=definition.get('title'),query=query['query']):
                            self.assertIn('host:radius-primary',query['query'])
                            self.assertIn('host:radius-secondary',query['query'])
                            self.assertIn('$host',query['query'])
        self.assertGreater(checked,5)

    def test_all_radius_metric_queries_exclude_canary_hosts(self):
        for definition in self.widgets.values():
            for request in definition.get('requests', []):
                for query in request.get('queries', []):
                    if query.get('data_source') == 'metrics' and ':freeradius.' in query.get('query', ''):
                        with self.subTest(widget=definition.get('title'), query=query['query']):
                            self.assertIn('host:radius-primary', query['query'])
                            self.assertIn('host:radius-secondary', query['query'])

    def test_log_tables_use_one_builtin_date_column_without_duplicate_fields(self):
        def streams(value):
            if isinstance(value, dict):
                if value.get('type') == 'log_stream':
                    yield value
                for child in value.values():
                    yield from streams(child)
            elif isinstance(value, list):
                for child in value:
                    yield from streams(child)
        checked = 0
        for filename in ('datadog-dashboard.json', 'datadog-smallstep-dashboard.json'):
            for widget in streams(json.loads((ROOT / filename).read_text())):
                checked += 1
                with self.subTest(dashboard=filename, widget=widget.get('title')):
                    columns = widget['columns']
                    # Datadog supplies Date itself; @timestamp selects a second
                    # custom field containing the same event time.
                    self.assertNotIn('@timestamp', columns)
                    self.assertEqual(columns.count('timestamp'), 1)
                    self.assertEqual(len(columns), len(set(columns)))
                    self.assertEqual(widget['sort'], {'column':'timestamp', 'order':'desc'})
        self.assertGreaterEqual(checked, 5)

    def test_queue_depth_does_not_turn_missing_telemetry_into_zero(self):
        widget=self.widgets['Queue Depths']
        for request in widget['requests']:
            for formula in request['formulas']:self.assertNotIn('default_zero',formula['formula'])
            for query in request['queries']:
                self.assertIn(' by {host}',query['query'])
                self.assertTrue(query['query'].startswith('max:'))

    def test_packet_activity_uses_real_request_counters(self):
        widget=next(w for title,w in self.widgets.items() if title and ('Packets Per Second' in title or 'requests / sec' in title))
        queries=[q['query'] for r in widget['requests'] for q in r['queries']]
        self.assertTrue(any('total_access_requests.count' in q for q in queries))
        self.assertTrue(any('total_acct_requests.count' in q for q in queries))
        for query in queries:
            self.assertNotIn('queue_pps',query)
            self.assertIn('.as_rate()',query)
            self.assertIn(' by {host}',query)

    def test_vm_uptime_is_separate_for_each_radius_server(self):
        widget=next(w for title,w in self.widgets.items() if title and ('System Uptime' in title or 'VM uptime' in title))
        self.assertEqual(widget['type'],'query_table')
        queries=[q for r in widget['requests'] for q in r['queries']]
        self.assertEqual(len(queries),1)
        self.assertIn(' by {host}',queries[0]['query'])
        self.assertEqual(queries[0]['aggregator'],'last')
        self.assertIn('hours',json.dumps(widget).lower())

    def test_vlan_names_preserve_id_and_unnamed_buckets(self):
        widget=self.widgets['Verified Devices Seen by VLAN']
        query=widget['requests'][0]['queries'][0]
        self.assertEqual(query['compute'],{'aggregation':'cardinality','metric':'@device_id'})
        groups=query['group_by']
        self.assertEqual([g['facet'] for g in groups],['@vlan_id','@vlan_name'])
        self.assertIs(groups[1].get('should_exclude_missing'),False)
        self.assertNotIn('missing',groups[1])

    def test_authenticator_popularity_keeps_one_bucket_per_site_and_ap(self):
        chart=self.widgets['Top authenticators — successful auth']
        query=chart['requests'][0]['queries'][0]
        groups=query['group_by']
        # The same AP must not split when optional raw packet identifiers are
        # absent in older events, or differ across its radios/SSIDs.
        events=[
            {'site_name':'NYC','ap_name':'Engineering'},
            {'site_name':'NYC','ap_name':'Engineering','called_station':'radio-a:Campus'},
            {'site_name':'NYC','ap_name':'Engineering','called_station':'radio-b:Campus'},
        ]
        buckets={tuple(event.get(group['facet'][1:],'') for group in groups) for event in events}
        self.assertEqual(len(buckets),1,'Optional packet identifiers split an already identified AP')
        self.assertIn('@event:Access-Accept',query['search']['query'])
        self.assertTrue(all(group.get('should_exclude_missing') is False for group in groups),
                        'Unidentified historical events must remain visible')

if __name__=='__main__':unittest.main()
