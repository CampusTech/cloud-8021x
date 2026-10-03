"""Verified certificate bindings for logs only; never an authorization source.

RADIUS Class survives accounting without trusting client-selected usernames.
A token authenticates the original device, fingerprint and VLAN, bound to the
trusted office and calling station. It intentionally carries no owner metadata.
"""
import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import struct
import time

from device_policy import normalize_fingerprint, require_fresh, valid_vlan

KEY_FILE = '/run/radius-accounting-key'
CONFIG_FILE = '/etc/freeradius/3.0/vlan-policy.json'
PREFIX = 'c8021x.1.'
MAX_AGE = 30 * 86400
_HEADER = struct.Struct('!Q12s32sH')
_DOMAIN = b'cloud-8021x/accounting-binding/v1\x00'


def read_key():
    with open(KEY_FILE, 'rb') as stream:
        key = stream.read(4097).strip()
    if not 32 <= len(key) <= 4096:
        raise ValueError('invalid accounting binding key')
    return key


def _context(location, calling_station):
    if not isinstance(location, str) or not location or len(location.encode()) > 255:
        raise ValueError('missing trusted RADIUS location')
    if not isinstance(calling_station, str) or not re.fullmatch(
            r'(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|'
            r'(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}|(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4})',
            calling_station):
        raise ValueError('missing or invalid calling station')
    station = bytes.fromhex(re.sub(r'[:.-]', '', calling_station))
    office = location.encode()
    return bytes([len(office)]) + office + station


def _encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def issue(key, device_id, fingerprint, vlan, location, calling_station, now):
    """Issue one <=253-octet Class value after exact certificate authorization."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError('invalid accounting binding key')
    if not isinstance(device_id, str) or not 1 <= len(device_id.encode()) <= 96:
        raise ValueError('invalid stable device ID')
    if not valid_vlan(vlan):
        raise ValueError('invalid VLAN')
    if not math.isfinite(now) or not 0 <= now < 2 ** 64:
        raise ValueError('invalid binding timestamp')
    fingerprint = bytes.fromhex(normalize_fingerprint(fingerprint))
    context = _context(location, calling_station)
    payload = _HEADER.pack(int(now), secrets.token_bytes(12), fingerprint, vlan) + device_id.encode()
    signature = hmac.new(key, _DOMAIN + context + payload, hashlib.sha256).digest()
    return PREFIX + _encode(payload + signature)


def _one(attributes, name):
    values = [value for key, value in attributes if key == name]
    if len(values) != 1:
        raise ValueError('missing or ambiguous binding context')
    return values[0]


def _verify(token, location, station, now):
    if not isinstance(token, str) or len(token) > 508:
        raise ValueError('invalid Class')
    if token.startswith('0x'):
        token = bytes.fromhex(token[2:]).decode('ascii')
    if not token.startswith(PREFIX) or len(token) > 253:
        raise ValueError('unknown Class namespace')
    encoded = token[len(PREFIX):]
    if not re.fullmatch(r'[A-Za-z0-9_-]+', encoded):
        raise ValueError('invalid Class encoding')
    raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    if _encode(raw) != encoded or not _HEADER.size + 1 + 32 <= len(raw) <= _HEADER.size + 96 + 32:
        raise ValueError('invalid Class payload')
    payload, signature = raw[:-32], raw[-32:]
    expected = hmac.new(read_key(), _DOMAIN + _context(location, station) + payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError('invalid Class signature')
    issued, _, fingerprint, vlan = _HEADER.unpack(payload[:_HEADER.size])
    require_fresh(issued, now, MAX_AGE)
    if not valid_vlan(vlan):
        raise ValueError('invalid Class VLAN')
    return payload[_HEADER.size:].decode('utf-8'), fingerprint.hex(), vlan


def enrich(request, accounting=False):
    """Return log attributes from reply Class (auth) or request Class (accounting).

    Invalid/missing binding returns no attributes. Missing/stale metadata retains
    only the signed stable ID, original fingerprint and original VLAN. Accounting
    updates may repeat a Class; it is not a single-use authentication credential.
    """
    try:
        source = request.get('request' if accounting else 'reply', ())
        token = _one(source, 'Class')
        # rlm_python3 names the server control list 'config'.
        location = _one(request.get('config', ()), 'Tmp-String-1')
        station = _one(request.get('request', ()), 'Calling-Station-Id')
        now = time.time()
        device_id, fingerprint, vlan = _verify(token, location, station, now)
    except (ValueError, TypeError, KeyError, OSError, OverflowError):
        return ()
    attributes = [('Tmp-String-2', device_id), ('Tmp-String-3', fingerprint),
                  ('Tunnel-Private-Group-Id', str(vlan))]
    try:
        with open(CONFIG_FILE) as stream:
            config = json.load(stream)
        with open(config['cache_file']) as stream:
            inventory = json.load(stream)
        require_fresh(inventory['updated_at'], now, config['cache_max_age'])
        device = inventory['devices'][device_id]
        for name, field in (('Login-LAT-Service', 'serial'), ('Filter-Id', 'device_name'),
                            ('Reply-Message', 'device_owner'), ('Login-LAT-Node', 'device_model')):
            value = device.get(field)
            if isinstance(value, str) and value:
                attributes.append((name, value))
    except (ValueError, TypeError, KeyError, OSError, AttributeError):
        pass
    return tuple(attributes)
