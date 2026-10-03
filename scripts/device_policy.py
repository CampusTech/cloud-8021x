"""MDM-independent device identity and VLAN policy over an atomic inventory snapshot."""
import fcntl
import hashlib
import math
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import time
import uuid


def normalize_identity(value):
    if not isinstance(value, str):
        return ''
    value = value.strip()
    # Compatibility with the Windows certificates already issued by this project.
    if value.endswith(' Campus WiFi'):
        value = value[:-len(' Campus WiFi')].strip()
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return value


def snapshot(devices, now):
    identities = {}
    certificates = {}
    certificate_mode = False
    for device in devices:
        for alias in device['identities']:
            alias = normalize_identity(alias)
            if not alias:
                continue
            entry = {key: device[key] for key in ('device_id', 'groups', 'enrolled')}
            if alias in identities and identities[alias] != entry:
                # Never choose a winner when two devices claim the same identity.
                identities[alias] = None
            else:
                identities[alias] = entry
        if 'certificate_fingerprints' in device:
            certificate_mode = True
            for fingerprint in device['certificate_fingerprints']:
                fingerprint = normalize_fingerprint(fingerprint)
                entry = {key: device[key] for key in ('device_id', 'groups', 'enrolled')}
                entry['observed_at'] = device['certificates_observed_at']
                if fingerprint in certificates and certificates[fingerprint] != entry:
                    certificates[fingerprint] = None
                else:
                    certificates[fingerprint] = entry
    result = {'version': 2 if certificate_mode else 1, 'updated_at': now, 'identities': identities}
    if certificate_mode:
        result['certificates'] = certificates
    return result


def normalize_fingerprint(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise ValueError('invalid certificate SHA256 fingerprint')
    return value.lower()


def require_fresh(timestamp, now, ttl):
    age = now - timestamp
    if not math.isfinite(age) or not math.isfinite(ttl) or not 0 <= age < ttl or ttl <= 0:
        raise ValueError('inventory expired or timestamp invalid')


CERTIFICATE_DIRECTORY = '/run/radius-certificate-bindings'
CERTIFICATE_HANDOFF_TTL = 120


def certificate_path(token, directory):
    if not isinstance(token, str) or not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('invalid server certificate session token')
    return Path(directory) / token


def record_certificate(filename, token, directory=CERTIFICATE_DIRECTORY):
    """Called only by TLS verify with its verified leaf PEM and server session token."""
    destination = certificate_path(token, directory)
    with open(filename) as stream:
        der = ssl.PEM_cert_to_DER_cert(stream.read())
    fingerprint = hashlib.sha256(der).hexdigest()
    # Exclusive creation prevents replacing another authentication's binding.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(fingerprint)


def consume_certificate(token, directory=CERTIFICATE_DIRECTORY):
    """Consume the private handshake binding. Missing/expired/replayed bindings deny."""
    filename = certificate_path(token, directory)
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError('invalid or consumed certificate binding')
        os.unlink(filename)
        require_fresh(metadata.st_mtime, time.time(), CERTIFICATE_HANDOFF_TTL)
        return normalize_fingerprint(stream.read(65))


def valid_vlan(value):
    return type(value) is int and 1 <= value <= 4094


def select_vlan(identity, inventory, config, now):
    """Select from verified SHA256 in certificate mode, otherwise a legacy cert CN."""
    certificate_mode = config.get('certificate_inventory', False)
    if type(certificate_mode) is not bool:
        raise ValueError('invalid certificate inventory mode')
    if inventory['version'] not in ((2,) if certificate_mode else (1, 2)):
        raise ValueError('unsupported inventory version')
    require_fresh(inventory['updated_at'], now, config['cache_max_age'])
    if certificate_mode:
        identity = normalize_fingerprint(identity)
        device = inventory['certificates'].get(identity)
        if device:
            require_fresh(device['observed_at'], now,
                          config.get('certificate_max_age', config['cache_max_age']))
    else:
        identity = normalize_identity(identity)
        if not identity:
            raise ValueError('missing certificate identity')
        if identity == 'cloud-8021x-inventory':
            raise ValueError('inventory certificate requires fingerprint authorization')
        device = inventory['identities'].get(identity)
    if not device or device['enrolled'] is not True:
        raise ValueError('device unknown, ambiguous, or unenrolled')
    groups = device['groups']
    if not isinstance(groups, list) or any(not isinstance(g, str) for g in groups):
        raise ValueError('invalid device groups')
    rules = config['group_vlans']
    if not isinstance(rules, dict) or any(not valid_vlan(v) for v in rules.values()):
        raise ValueError('invalid VLAN rules')
    vlans = {rules[g] for g in groups if g in rules}
    if len(vlans) > 1:
        raise ValueError('conflicting VLAN rules')
    vlan = next(iter(vlans)) if vlans else config.get('fallback_vlan')
    if not valid_vlan(vlan):
        raise ValueError('device has no VLAN assignment')
    return vlan


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3:
            raise ValueError('expected verified certificate filename and server session token')
        record_certificate(sys.argv[1], sys.argv[2])
    except Exception as exc:
        print('certificate binding failed: ' + str(exc), file=sys.stderr)
        sys.exit(1)
