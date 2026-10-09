# Historical parity fixture only; current deployment is tested by test_green_deployment.py.
"""Attested identities require the pinned issuer and CA-controlled ACME marker."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
import tempfile
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier, ExtendedKeyUsageOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/legacy/scripts'))
import attested_acme
import device_policy


class AttestedACMETests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Wi-Fi CA')])
        self.issuer = (x509.CertificateBuilder().subject_name(self.name).issuer_name(self.name)
                       .public_key(self.key.public_key()).serial_number(1)
                       .not_valid_before(self.now - timedelta(days=1))
                       .not_valid_after(self.now + timedelta(days=365))
                       .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                       .sign(self.key, hashes.SHA256()))

    def certificate(self, *, provisioner=b'wifi-acme', kind=6, serial='SERIAL123',
                    san_serial='SERIAL123', signer=None, expired=False, ca=False):
        # Independent DER fixtures for Smallstep Extension and RFC 4043 identity.
        marker = bytes([2, 1, kind, 4, len(provisioner)]) + provisioner + b'\x04\x00'
        identifier = san_serial.encode()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, serial)])
        return (x509.CertificateBuilder().subject_name(name).issuer_name(self.name)
                .public_key(ec.generate_private_key(ec.SECP256R1()).public_key()).serial_number(2)
                .not_valid_before(self.now - timedelta(days=2))
                .not_valid_after(self.now + timedelta(days=-1 if expired else 90))
                .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.37476.9000.64.1'),
                                                         bytes([48, len(marker)]) + marker), False)
                .add_extension(x509.SubjectAlternativeName([x509.OtherName(
                    ObjectIdentifier('1.3.6.1.5.5.7.8.3'),
                    bytes([48, len(identifier) + 2, 12, len(identifier)]) + identifier)]), False)
                .sign(signer or self.key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))

    def identity(self, **kwargs):
        return attested_acme.identity(self.certificate(**kwargs),
            self.issuer.public_bytes(serialization.Encoding.PEM), 'wifi-acme')

    def test_attested_serial_needs_no_device_certificate_observation(self):
        self.assertEqual(self.identity(), 'SERIAL123')

    def test_untrusted_paths_cannot_claim_a_serial(self):
        for options in [dict(kind=8), dict(provisioner=b'other-acme'),
                        dict(san_serial='OTHER123'), dict(expired=True), dict(ca=True),
                        dict(signer=ec.generate_private_key(ec.SECP256R1()))]:
            with self.subTest(options=options):
                self.assertIsNone(self.identity(**options))

    def test_malformed_certificate_denies(self):
        self.assertIsNone(attested_acme.identity(b'not a certificate', b'bad issuer', 'wifi-acme'))

    def test_private_handoff_contains_verified_serial_and_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'leaf.pem').write_bytes(self.certificate())
            (root / 'issuer.pem').write_bytes(self.issuer.public_bytes(serialization.Encoding.PEM))
            token = 'c' * 64
            config = {'issuer_file': str(root / 'issuer.pem'), 'provisioner': 'wifi-acme'}
            device_policy.record_certificate(root / 'leaf.pem', token, directory, config)
            bound = device_policy.consume_certificate(token, directory, include_attestation=True)
            self.assertEqual(bound['attested_serial'], 'SERIAL123')
            self.assertEqual(len(bound['fingerprint']), 64)
            with self.assertRaises(FileNotFoundError):
                device_policy.consume_certificate(token, directory, include_attestation=True)
            # SCEP signed by the same issuer still cannot use this route.
            (root / 'leaf.pem').write_bytes(self.certificate(kind=8))
            device_policy.record_certificate(root / 'leaf.pem', token, directory, config)
            self.assertIsInstance(device_policy.consume_certificate(token, directory, include_attestation=True), str)
