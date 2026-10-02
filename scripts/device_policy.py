"""MDM-independent device identity and VLAN policy over an atomic inventory snapshot."""
import math
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
    return {'version': 1, 'updated_at': now, 'identities': identities}


def valid_vlan(value):
    return type(value) is int and 1 <= value <= 4094


def select_vlan(identity, inventory, config, now):
    """Return a VLAN for a validated certificate CN, or raise ValueError to deny."""
    identity = normalize_identity(identity)
    if not identity:
        raise ValueError('missing certificate identity')
    if inventory['version'] != 1:
        raise ValueError('unsupported inventory version')
    age = now - inventory['updated_at']
    ttl = config['cache_max_age']
    if not math.isfinite(age) or not 0 <= age < ttl or ttl <= 0:
        raise ValueError('inventory expired or timestamp invalid')
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
