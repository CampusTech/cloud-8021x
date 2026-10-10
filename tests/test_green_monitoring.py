"""Retained safety queries must consume the fresh green producer contracts."""
from pathlib import Path
import re
import json
import os
import unittest

ROOT = Path(__file__).resolve().parents[1]

class GreenSafetyQueries(unittest.TestCase):
    def monitor(self, name):
        text = (ROOT / 'datadog-smallstep.tf').read_text()
        return re.search(r'resource "datadog_monitor" "' + name + r'" \{(.*?)^\}', text, re.S | re.M).group(1)

    def test_neutral_expiry_readiness_and_native_queries(self):
        contracts = {
            'radius_server_cert_expiry': ['cloud8021x.certificate.days_until_expiry', 'service:cloud-8021x', 'component:freeradius', 'cert:server'],
            'radius_client_cert_expiring': ['cloud8021x.client_certificate.expiring_soon', 'service:cloud-8021x', 'window:48h', 'scope:shared'],
            'stepca_cert_expiry': ['cloud8021x.certificate.days_until_expiry', 'component:step-ca', 'service:cloud-8021x', 'by {host,cert,ca_instance}'],
            'stepca_decrypter': ['cloud8021x.scep.decrypter_ready', 'service:cloud-8021x', 'ca_instance:rsa'],
            'radius_down': ['cloud8021x.backend.up', 'service:cloud-8021x', 'component:freeradius'],
            'stepca_health': ['instance:stepca_health'],
            'stepca_rsa_health': ['instance:stepca_rsa_health'],
        }
        for name, required in contracts.items():
            with self.subTest(monitor=name):
                source = self.monitor(name)
                for fragment in required:
                    self.assertIn(fragment, source)
        all_monitors = (ROOT / 'datadog-smallstep.tf').read_text()
        for retired in ['radius-cert-renew.sh', 'radius-cert-renew.timer', 'radius-client-cert-metrics.timer']:
            self.assertNotIn(retired, all_monitors)

@unittest.skipUnless(os.environ.get('C8021X_MONITORING_CONTRACT'), 'actual runtime-exported contract required')
class ActualFreshProducerContracts(unittest.TestCase):
    def test_actual_sdk_units_dimensions_and_service(self):
        directory = Path(os.environ['C8021X_MONITORING_CONTRACT'])
        output = json.loads((directory / 'neutral-metrics.json').read_text())
        attributes = lambda values: {a['Key']: a['Value']['Value'] for a in values}
        resource = attributes(output['Resource'])
        self.assertEqual(resource['service.name'], 'cloud-8021x')
        self.assertTrue(resource['host.name'].startswith('green-'))
        metrics = {m['Name']: m for scope in output['ScopeMetrics'] for m in scope['Metrics']}
        expiry = metrics['cloud8021x.certificate.days_until_expiry']
        self.assertEqual(expiry['Unit'], 'd')
        identities = {tuple(attributes(p['Attributes']).get(k) for k in ('component', 'cert', 'ca_instance')) for p in expiry['Data']['DataPoints']}
        self.assertEqual(identities, {('freeradius', 'server', 'ec'), ('step-ca', 'intermediate', 'ec'), ('step-ca', 'intermediate', 'rsa'), ('step-ca', 'decrypter', 'ec'), ('step-ca', 'decrypter', 'rsa')})
        client = metrics['cloud8021x.client_certificate.expiring_soon']
        self.assertEqual(client['Unit'], '{certificate}')
        for point in client['Data']['DataPoints']:
            tags = attributes(point['Attributes'])
            self.assertEqual(tags['window'], '48h')
            self.assertEqual(tags['scope'], 'shared')
            self.assertRegex(tags['cluster'], '^[0-9a-f]{64}$')
        ready = metrics['cloud8021x.scep.decrypter_ready']
        self.assertEqual(ready['Unit'], '1')
        for point in ready['Data']['DataPoints']:
            self.assertEqual(attributes(point['Attributes'])['ca_instance'], 'rsa')
        for name in ('radius_server_cert_expiry', 'radius_client_cert_expiring', 'stepca_cert_expiry', 'stepca_decrypter'):
            query = GreenSafetyQueries().monitor(name)
            self.assertTrue(any(metric in query for metric in metrics), name)

    def test_native_counter_queue_types_and_actual_queries(self):
        directory = Path(os.environ['C8021X_MONITORING_CONTRACT'])
        output = json.loads((directory / 'neutral-metrics.json').read_text())
        metrics = {m['Name']: m for scope in output['ScopeMetrics'] for m in scope['Metrics']}
        counters = ['total_access_requests', 'total_access_challenges', 'total_acct_requests', 'total_acct_responses', 'total_auth_duplicate_requests', 'total_auth_malformed_requests', 'total_auth_invalid_requests', 'total_auth_dropped_requests']
        queues = ['queue_len_auth', 'queue_len_acct', 'queue_len_internal']
        dashboard = json.loads((ROOT / 'datadog-dashboard.json').read_text())
        queries = []
        def visit(value):
            if isinstance(value, dict):
                if value.get('data_source') == 'metrics':
                    queries.append(value['query'])
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(dashboard)
        for name in counters + queues:
            metric = metrics['cloud8021x.radius.' + name]
            self.assertEqual(metric['Unit'], '{packet}')
            matched = [q for q in queries if 'cloud8021x.radius.' + name + '{' in q]
            self.assertTrue(matched, name)
            for query in matched:
                self.assertIn('component:freeradius', query)
                self.assertIn('service:cloud-8021x', query)
                self.assertIn('host:radius-primary', query)
                self.assertIn('host:radius-secondary', query)
                if name in counters:
                    self.assertTrue(metric['Data']['IsMonotonic'])
                    self.assertEqual(metric['Data']['Temporality'], 'CumulativeTemporality')
                    self.assertIn('.as_rate()', query)
                else:
                    self.assertNotIn('IsMonotonic', metric['Data'])
                    self.assertTrue(query.startswith('max:'))
                    self.assertNotIn('.as_rate()', query)
        self.assertFalse(any(':freeradius.' in query for query in queries), 'Retired exporter aliases remain')

    def test_actual_clean_node_native_configuration_covers_retained_queries(self):
        directory = Path(os.environ['C8021X_MONITORING_CONTRACT'])
        configs = json.loads((directory / 'native-monitoring.json').read_text())
        http = configs['/etc/datadog-agent/conf.d/http_check.d/cloud-8021x.yaml']
        for name in ('stepca-health', 'stepca-rsa-health'):
            self.assertIn('name: ' + name, http)
            monitor = 'stepca_health' if name == 'stepca-health' else 'stepca_rsa_health'
            self.assertIn('instance:' + name.replace('-', '_'), GreenSafetyQueries().monitor(monitor))
        self.assertIn('tls_verify: true', http)
        self.assertIn('tls_use_host_header: true', http)
        self.assertIn('allow_redirects: false', http)
        instances = [block for path, source in configs.items() if '/openmetrics.d/' in path for block in re.split(r'\n    - ', source)[1:]]
        for instance, port in [('ec', 9090), ('rsa', 9091)]:
            matching = [source for source in instances if 'ca_instance:' + instance in source and '127.0.0.1:' + str(port) in source]
            self.assertEqual(len(matching), 1, 'Each CA must have exactly one actual scrape instance')
            for required in ['namespace: smallstep', 'service:smallstep-ca', 'step_ca_x509_signed: x509.signed', 'step_ca_kms_errors: kms.errors']:
                self.assertIn(required, matching[0])
        process = configs['/etc/datadog-agent/conf.d/process.d/cloud-8021x.yaml']
        self.assertIn('name: freeradius', process)
        self.assertIn('name: step-ca', process)
        self.assertIn('process_name:freeradius', (ROOT / 'datadog-usage.tf').read_text())
        self.assertIn('uptime / 3600', (ROOT / 'datadog-usage.tf').read_text())

if __name__ == '__main__':
    unittest.main()
