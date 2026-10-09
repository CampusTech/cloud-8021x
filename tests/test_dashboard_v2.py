"""Keep the native companion reviewable without losing production dashboard fields."""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMPANION = ROOT / 'docs/generated/datadog-dashboard-v2.tf'
LOSSES = ROOT / 'docs/generated/datadog-dashboard-v2-losses.json'


def missing_flags(value, path='$'):
    """Match the official-provider loss report's full API property paths."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == 'should_exclude_missing':
                yield path + '.' + key, child
            yield from missing_flags(child, path + '.' + key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from missing_flags(child, f'{path}[{index}]')


class NativeCompanionSafetyTests(unittest.TestCase):
    def test_production_keeps_the_complete_json_managed_source(self):
        source = (ROOT / 'datadog.tf').read_text()
        self.assertIn('resource "datadog_dashboard_json" "radius"', source)
        self.assertIn('dashboard = jsonencode(local.dashboard_json)', source)
        self.assertIn('datadog_dashboard_json.radius[0].url', (ROOT / 'outputs.tf').read_text())
        for file in ROOT.glob('*.tf'):
            self.assertNotRegex(file.read_text(), r'resource\s+"datadog_dashboard_v2"')

    def test_generated_native_companion_is_outside_module_and_disabled(self):
        self.assertTrue(COMPANION.is_file(), 'Generate native companion with tools/dashboard sync')
        source = COMPANION.read_text()
        self.assertEqual(COMPANION.parent, ROOT / 'docs/generated')
        self.assertIn('GENERATED FILE', source)
        self.assertIn('DO NOT APPLY', source)
        self.assertRegex(source, r'(?m)^\s*count\s*=\s*0\s*$')
        self.assertIn('https://github.com/DataDog/terraform-provider-datadog/pull/4225', source)
        self.assertIn('group_definition {', source)
        self.assertIn('formula_expression', source)
        self.assertNotIn('jsonencode(', source)
        self.assertNotIn('jsondecode(', source)
        self.assertNotRegex(source, r'(?m)^\s*default\s*=')
        self.assertRegex(source, r'(?m)^\s*defaults\s*=')
        self.assertNotIn('"@timestamp"', source)

    def test_actual_provider_losses_cover_every_explicit_missing_bucket_flag(self):
        report = json.loads(LOSSES.read_text())
        dashboard = json.loads((ROOT / 'datadog-dashboard.json').read_text())
        self.assertTrue(report['deployment_blocked'])
        self.assertEqual(report['provider_version'], '4.25.0')
        self.assertEqual(report['upstream_dependency'],
                         'https://github.com/DataDog/terraform-provider-datadog/pull/4225')
        expected = dict(missing_flags(dashboard))
        recorded = {loss['path']: loss['source'] for loss in report['losses']
                    if loss['path'].endswith('.should_exclude_missing')}
        self.assertEqual(len(recorded), 24)
        self.assertEqual(recorded, expected)
        self.assertTrue(all(value is False for value in recorded.values()))
        self.assertEqual(len(report['losses']), 24, 'No other unsupported source properties may disappear')
        source = COMPANION.read_text()
        self.assertIn('grouped by site and AP name', source)
        for loss in report['losses']:
            self.assertIn(loss['path'], source)


if __name__ == '__main__':
    unittest.main()
