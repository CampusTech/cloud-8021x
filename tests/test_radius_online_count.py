"""Exercise the dashboard's health aggregation with known per-host samples."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def gauge_query(query, samples):
    """Evaluate the dashboard's simple gauge/count aggregation on fixtures."""
    match = re.search(r'(min|max|sum):([a-z_.]+)\{', query)
    aggregation, metric = match.groups()
    scoped_hosts = set(re.findall(r'host:([a-z0-9-]+)', query))
    values = [v for host, v in samples.get(metric, {}).items()
              if v is not None and (not scoped_hosts or host in scoped_hosts)]
    if ' by {host}' in query:
        return values
    if not values:
        return None
    return {'min': min, 'max': max, 'sum': sum}[aggregation](values)


def online_widget():
    dashboard = json.loads((ROOT / 'datadog-dashboard.json').read_text())
    overview = next(g for g in dashboard['widgets'] if g['definition']['title'] == 'Overview')
    return overview['definition']['widgets'][0]['definition']


def widget_value(samples):
    widget = online_widget()
    request = widget['requests'][0]
    values = {q['name']: gauge_query(q['query'], samples) for q in request['queries']}
    formula = request['formulas'][0]['formula']
    if formula in values:
        return values[formula]
    match = re.fullmatch(r'count_nonzero\((\w+)\)', formula)
    if match:
        host_values = values[match.group(1)]
        if not isinstance(host_values, list):
            raise AssertionError('Host counting requires grouping by host')
        return sum(value != 0 for value in host_values)
    # Reproduce the legacy binary-health formula, including its missing alias.
    match = re.fullmatch(r'default_zero\((\w+)\) \+ default_zero\((\w+)\)', formula)
    if match:
        return sum(values[name] or 0 for name in match.groups())
    raise AssertionError('Update this fixture evaluator for the new query semantics')


class RadiusOnlineCountTests(unittest.TestCase):
    def test_two_healthy_nodes_count_as_two(self):
        self.assertEqual(widget_value({'freeradius.up': {'radius-primary': 1, 'radius-secondary': 1}}), 2)

    def test_down_node_is_not_online(self):
        self.assertEqual(widget_value({'freeradius.up': {'radius-primary': 1, 'radius-secondary': 0}}), 1)

    def test_missing_node_is_not_online(self):
        self.assertEqual(widget_value({'freeradius.up': {'radius-primary': 1, 'radius-secondary': None}}), 1)

    def test_legacy_alias_cannot_double_count_same_hosts(self):
        values = {'radius-primary': 1, 'radius-secondary': 1}
        self.assertEqual(widget_value({'freeradius.up': values, 'freeradius.freeradius_up': values}), 2)

    def test_canary_and_unrelated_hosts_do_not_count(self):
        self.assertEqual(widget_value({'freeradius.up': {
            'radius-primary': 1, 'radius-secondary': 1,
            'radius-primary-canary': 1, 'unrelated': 1,
        }}), 2)

    def test_all_down_nodes_count_as_zero(self):
        self.assertEqual(widget_value({'freeradius.up': {'radius-primary': 0, 'radius-secondary': 0}}), 0)

    def test_current_health_does_not_follow_historical_dashboard_window(self):
        widget = online_widget()
        self.assertEqual(widget['title'], 'RADIUS servers online')
        self.assertEqual(widget['time'], {'live_span': '5m'})
        query = widget['requests'][0]['queries'][0]
        self.assertEqual(query['aggregator'], 'last')
        self.assertIn('.fill(last,60)', query['query'])

    def test_functions_use_formula_field_in_formula_and_functions_schema(self):
        request = online_widget()['requests'][0]
        for query in request['queries']:
            self.assertRegex(query['query'], r'^(min|max|sum|avg):')
        self.assertEqual(request['formulas'], [{'formula': 'count_nonzero(online)'}])
