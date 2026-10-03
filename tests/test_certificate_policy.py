"""Exact certificate authorization must never fall back to certificate CN."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import ssl
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import device_policy
import radius_identity

sys.modules['radiusd'] = types.SimpleNamespace(RLM_MODULE_REJECT=0, RLM_MODULE_UPDATED=8,
                                              L_ERR=3, radlog=lambda *args: None)


class CertificatePolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.fingerprint = 'a1' * 32
        self.device = {'device_id': 'fleet:1', 'identities': ['staff-serial'],
                       'groups': ['byod'], 'enrolled': True,
                       'certificate_fingerprints': [self.fingerprint],
                       'certificates_observed_at': self.now - 30}
        self.config = {'certificate_inventory': True, 'cache_max_age': 3600,
                       'group_vlans': {'byod': 200, 'staff': 100}, 'fallback_vlan': 999}

    def select(self, inventory=None, fingerprint=None):
        return device_policy.select_vlan(self.fingerprint if fingerprint is None else fingerprint,
            inventory if inventory is not None else device_policy.snapshot([self.device], self.now),
            self.config, self.now)

    def test_location_optout_retains_exact_certificate_and_inventory_checks(self):
        self.config['locations'] = {'nyc': {'dynamic_vlans': False}}
        inventory = device_policy.snapshot([self.device], self.now)
        self.assertIsNone(device_policy.select_vlan(self.fingerprint, inventory, self.config, self.now, 'nyc'))
        for location in (None, 'unknown'):
            with self.subTest(location=location), self.assertRaises(ValueError):
                device_policy.select_vlan(self.fingerprint, inventory, self.config, self.now, location)
        for change in ({'certificate_fingerprints': []}, {'enrolled': False},
                       {'certificates_observed_at': self.now - 3600}):
            invalid = device_policy.snapshot([dict(self.device, **change)], self.now)
            with self.subTest(change=change), self.assertRaises(ValueError):
                device_policy.select_vlan(self.fingerprint, invalid, self.config, self.now, 'nyc')
        for identity in ('staff-serial', 'b2' * 32):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                device_policy.select_vlan(identity, inventory, self.config, self.now, 'nyc')
        inventory['updated_at'] = self.now - 3600
        with self.assertRaises(ValueError):
            device_policy.select_vlan(self.fingerprint, inventory, self.config, self.now, 'nyc')

    def test_snapshot_binds_fingerprint_to_current_device(self):
        result = device_policy.snapshot([self.device], self.now)
        self.assertEqual(result['version'], 2)
        self.assertEqual(result['certificates'][self.fingerprint], {
            'device_id': 'fleet:1', 'groups': ['byod'], 'enrolled': True,
            'observed_at': self.now - 30})
        self.assertEqual(self.select(), 200)

    def test_fingerprint_mode_rejects_matching_cn_and_legacy_snapshot(self):
        with self.assertRaises(ValueError):
            self.select(fingerprint='staff-serial')
        legacy = dict(self.device)
        del legacy['certificate_fingerprints']
        with self.assertRaises(ValueError):
            self.select(device_policy.snapshot([legacy], self.now))

    def test_unknown_ambiguous_unenrolled_and_stale_certificates_rejected(self):
        for change in ({'certificate_fingerprints': []}, {'enrolled': False},
                       {'certificates_observed_at': self.now - 3600},
                       {'certificates_observed_at': self.now + 1},
                       {'certificates_observed_at': float('nan')}):
            with self.subTest(change=change):
                device = dict(self.device, **change)
                with self.assertRaises(ValueError):
                    self.select(device_policy.snapshot([device], self.now))
        other = dict(self.device, device_id='fleet:2')
        inv = device_policy.snapshot([self.device, other, self.device], self.now)
        self.assertIsNone(inv['certificates'][self.fingerprint])
        with self.assertRaises(ValueError):
            self.select(inv)

    def test_current_groups_rechecked_and_malformed_fingerprints_rejected(self):
        self.device['groups'] = ['staff']
        self.assertEqual(self.select(), 100)
        for fingerprint in ('', 'a1' * 31, 'G1' * 32, 7):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(ValueError):
                self.select(fingerprint=fingerprint)

    def test_legacy_mode_can_read_version_two(self):
        self.config['certificate_inventory'] = False
        self.assertEqual(self.select(fingerprint='staff-serial'), 200)

    def test_inventory_only_subject_cannot_authorize_after_downgrade(self):
        self.config['certificate_inventory'] = False
        self.device['identities'] = ['cloud-8021x-inventory']
        with self.assertRaises(ValueError):
            self.select(fingerprint='cloud-8021x-inventory')

    def test_certificate_handoff_is_single_use_and_not_a_client_attribute(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pem = root / 'leaf.pem'
            # PEM-to-DER conversion is sufficient here: FreeRADIUS already verifies X509.
            pem.write_text(ssl.DER_cert_to_PEM_cert(b'example verified leaf DER'))
            token = 'a' * 64
            digest = hashlib.sha256(b'example verified leaf DER').hexdigest()
            device_policy.record_certificate(str(pem), token, directory)
            self.assertEqual(device_policy.consume_certificate(token, directory), digest)
            with self.assertRaises((ValueError, FileNotFoundError)):
                device_policy.consume_certificate(token, directory)
            for bad in ('../leaf.pem', '', 'x' * 64):
                with self.assertRaises(ValueError):
                    device_policy.record_certificate(str(pem), bad, directory)

    def test_certificate_handoff_rejects_expiry_symlinks_and_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = 'c' * 64
            path = root / token
            pem = root / 'leaf.pem'
            pem.write_text(ssl.DER_cert_to_PEM_cert(b'leaf DER'))
            device_policy.record_certificate(str(pem), token, directory)
            with self.assertRaises(FileExistsError):
                device_policy.record_certificate(str(pem), token, directory)
            os.utime(path, (self.now - 121, self.now - 121))
            with self.assertRaises(ValueError):
                device_policy.consume_certificate(token, directory)
            path.symlink_to(pem)
            with self.assertRaises(OSError):
                device_policy.consume_certificate(token, directory)

    def test_snapshot_freshness_does_not_refresh_certificate_observation(self):
        self.config['certificate_max_age'] = 86400
        self.device['certificates_observed_at'] = self.now - 4000
        self.assertEqual(self.select(), 200)
        self.device['certificates_observed_at'] = self.now - 86400
        with self.assertRaises(ValueError):
            self.select()

    def test_optout_exact_authorization_issues_identity_binding_without_tunnel_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config.json'
            cache = root / 'cache.json'
            self.config['locations'] = {'nyc': {'dynamic_vlans': False}}
            self.device['metadata'] = {'serial': 'staff-serial', 'device_name': 'Laptop',
                                       'device_owner': 'owner@example.com', 'device_model': 'Mac'}
            config.write_text(json.dumps(dict(self.config, cache_file=str(cache))))
            cache.write_text(json.dumps(device_policy.snapshot([self.device], self.now)))
            spec = importlib.util.spec_from_file_location('radius_vlan', SCRIPTS / 'radius_vlan.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.CONFIG_FILE = str(config)
            module.CERTIFICATE_DIRECTORY = directory
            token = 'b' * 64
            (root / token).write_text(self.fingerprint)
            request = {'request': (('Tmp-String-0', token), ('Tmp-String-1', 'nyc'),
                                   ('Calling-Station-Id', 'AA-BB-CC-DD-EE-FF'),
                                   ('User-Name', 'untrusted-identity')),
                       'config': (('Tmp-String-1', 'nyc'),)}
            key = root / 'key'
            key.write_bytes(b'A' * 64)
            with patch.object(radius_identity, 'KEY_FILE', str(key)), \
                 patch.object(radius_identity, 'CONFIG_FILE', str(config)):
                result = module.authorize(request)
                self.assertEqual(result[0], 8)
                self.assertEqual(set(dict(result[1]['reply'])), {'Class'})
                for accounting in (False, True):
                    packet = dict(request, reply=result[1]['reply'])
                    if accounting:
                        packet['request'] += result[1]['reply']
                    attrs = dict(radius_identity.enrich(packet, accounting=accounting))
                    self.assertEqual(attrs, {'Tmp-String-2': 'fleet:1', 'Tmp-String-3': self.fingerprint,
                        'Login-LAT-Service': 'staff-serial', 'Filter-Id': 'Laptop',
                        'Reply-Message': 'owner@example.com', 'Login-LAT-Node': 'Mac'})
                self.assertEqual(module.authorize(request), 0)

    def test_radius_requires_server_session_binding_even_with_valid_cn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / 'config.json'
            cache = root / 'cache.json'
            config.write_text(json.dumps(dict(self.config, cache_file=str(cache))))
            cache.write_text(json.dumps(device_policy.snapshot([self.device], self.now)))
            spec = importlib.util.spec_from_file_location('radius_vlan', SCRIPTS / 'radius_vlan.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.CONFIG_FILE = str(config)
            module.CERTIFICATE_DIRECTORY = directory
            request = {'request': (('TLS-Client-Cert-Common-Name', 'staff-serial'),
                                   ('User-Name', 'staff-serial'),
                                   ('TLS-Client-Cert-Fingerprint', self.fingerprint))}
            self.assertEqual(module.authorize(request), 0)
            token = 'b' * 64
            (root / token).write_text(self.fingerprint)
            request['request'] += (('Tmp-String-0', token), ('Tmp-String-1', 'nyc'),
                                   ('Calling-Station-Id', 'AA-BB-CC-DD-EE-FF'),
                                   ('Class', 'client-selected-binding'))
            key = root / 'accounting-key'
            key.write_bytes(b'A' * 64)
            with patch.object(radius_identity, 'KEY_FILE', str(key)):
                result = module.authorize(request)
                self.assertEqual(result[0], 8)
                self.assertIn('Class', dict(result[1]['reply']))
                self.assertTrue(dict(result[1]['reply'])['Class'].startswith('c8021x.1.'))
                logged = dict(radius_identity.enrich(dict(request, reply=result[1]['reply'],
                                                        config=(('Tmp-String-1', 'nyc'),))))
                self.assertEqual(logged['Tmp-String-2'], 'fleet:1')
                self.assertEqual(logged['Tmp-String-3'], self.fingerprint)
                self.assertEqual(logged['Tunnel-Private-Group-Id'], '200')
                self.assertEqual(module.authorize(request), 0)
                (root / token).write_text(self.fingerprint)
                key.unlink()
                self.assertEqual(module.authorize(request), 0)
                config.write_text(json.dumps(dict(self.config, certificate_inventory=False,
                                                  cache_file=str(cache))))
                self.assertEqual(module.authorize(request)[0], 8)


if __name__ == '__main__':
    unittest.main()
