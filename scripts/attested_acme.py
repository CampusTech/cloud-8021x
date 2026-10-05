"""Recognize this deployment's hardware-attested ACME certificates.

This is an additional identity check on the exact TLS-verified leaf. The pinned
issuer must serve a device-attest-01-only provisioner. A CN, issuer display name,
supervision flag, or caller-supplied RADIUS attribute alone grants nothing.
"""
from datetime import datetime, timezone
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier


def _der(tag, value):
    """Encode the short, fixed ASN.1 structures issued by Smallstep (not a parser)."""
    if len(value) >= 128:
        raise ValueError('attestation field too long')
    return bytes([tag, len(value)]) + value


def identity(leaf_pem, issuer_pem, provisioner):
    """Return a hardware serial only for the pinned attested issuance path."""
    try:
        leaf = x509.load_pem_x509_certificate(leaf_pem)
        issuer = x509.load_pem_x509_certificate(issuer_pem)
        key = issuer.public_key()
        # The built-in attested CA uses an EC signing key. SCEP uses another CA.
        if not isinstance(key, ec.EllipticCurvePublicKey) or leaf.issuer != issuer.subject:
            return None
        key.verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(leaf.signature_hash_algorithm))
        # Debian 12's cryptography predates the UTC-aware validity properties.
        now = datetime.now(timezone.utc)
        def valid(cert):
            if hasattr(cert, 'not_valid_before_utc'):
                return cert.not_valid_before_utc <= now < cert.not_valid_after_utc
            return cert.not_valid_before.replace(tzinfo=timezone.utc) <= now < cert.not_valid_after.replace(tzinfo=timezone.utc)
        if not all(valid(cert) for cert in (leaf, issuer)):
            return None
        if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return None
        try:
            if leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                return None
        except x509.ExtensionNotFound:
            pass
        if ExtendedKeyUsageOID.CLIENT_AUTH not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            return None
        names = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) != 1 or not re.fullmatch(r'[A-Za-z0-9]{1,64}', names[0].value):
            return None
        serial = names[0].value
        # Smallstep overwrites this extension during signing; CSR values cannot
        # choose a provisioner. TypeACME=6, credential ID is empty for ACME.
        expected = _der(48, b'\x02\x01\x06' + _der(4, provisioner.encode('ascii')) + b'\x04\x00')
        extension = leaf.extensions.get_extension_for_oid(ObjectIdentifier('1.3.6.1.4.1.37476.9000.64.1'))
        if extension.value.value != expected:
            return None
        permanent_ids = [name.value for name in leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(x509.OtherName)
            if name.type_id == ObjectIdentifier('1.3.6.1.5.5.7.8.3')]
        if permanent_ids != [_der(48, _der(12, serial.encode('ascii')))]:
            return None
        return serial
    except (ValueError, TypeError, AttributeError, UnicodeError, InvalidSignature, x509.ExtensionNotFound):
        return None
