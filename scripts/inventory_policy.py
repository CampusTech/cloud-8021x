"""Inventory adapters publish the same device policy format for any RADIUS client."""
import json
import os
from pathlib import Path
import tempfile

from device_policy import select_vlan, snapshot


def certificate_readiness(hosts, devices, observations, config, now):
    """Report exact certificate coverage separately from a usable VLAN policy."""
    from fleet_certificates import readiness
    report = readiness(hosts, observations, now, config.get('certificate_max_age', 86400))
    report['updated_at'] = now
    report['policy_enforced'] = config.get('certificate_inventory') is True
    inventory = snapshot(devices, now)
    for row in report['hosts']:
        row['certificate_reason'] = row['reason']
        if row['reason'] != 'ready':
            continue
        locations = config.get('locations') or {}
        if locations:
            row['locations'] = {}
        for location in locations or [None]:
            result = {'reason': 'ready'}
            try:
                vlans = {select_vlan(fp, inventory, {**config, 'certificate_inventory': True}, now, location)
                         for fp in observations[row['uuid']]['fingerprints']}
                if len(vlans) != 1:
                    raise ValueError('ambiguous VLAN')
                result['vlan'] = next(iter(vlans))
                if result['vlan'] is None:
                    result['dynamic_vlans'] = False
            except (ValueError, KeyError, TypeError):
                result['reason'] = 'no_vlan_assignment'
                row['reason'] = 'no_vlan_assignment'
            if locations:
                row['locations'][location] = result
            else:
                row.update(result)
    report['ready_count'] = sum(row['reason'] == 'ready' for row in report['hosts'])
    report['ready'] = bool(report['hosts']) and report['ready_count'] == report['total']
    return report


def fleet_device(host):
    group_id = host.get('fleet_id', host.get('team_id')) or 0

    def text(value):
        return value if isinstance(value, str) else ''

    owner = ''
    for field, key in (('device_mapping', 'email'), ('end_users', 'idp_username')):
        records = host.get(field)
        if not isinstance(records, list):
            continue
        owner = next((text(record.get(key)) for record in records
                      if isinstance(record, dict) and text(record.get(key))), '')
        if owner:
            break
    return {
        'device_id': 'fleet:' + str(host['id']),
        'identities': [v for v in (host.get('hardware_serial'), host.get('uuid')) if v],
        'groups': ['fleet:' + str(group_id)],
        'enrolled': ((host.get('mdm') or {}).get('enrollment_status') or '').startswith('On'),
        'metadata': {
            'serial': text(host.get('hardware_serial')),
            'device_name': (text(host.get('display_name')) or text(host.get('computer_name'))
                            or text(host.get('hostname'))),
            'device_model': text(host.get('hardware_model')),
            'device_owner': owner,
        },
    }


def jamf_device(host):
    general = host.get('general') or {}
    hardware = host.get('hardware') or {}
    site_id = (general.get('site') or {}).get('id')
    return {
        'device_id': 'jamf:' + str(host['id']),
        'identities': [v for v in (hardware.get('serialNumber'), host.get('udid')) if v],
        'groups': ['jamf:site:' + str(site_id)] if site_id is not None else [],
        'enrolled': (general.get('remoteManagement') or {}).get('managed') is True,
    }


def publish(path, devices, now):
    """Called only after ALL inventory pages succeeded. Never publish partial results."""
    path = Path(path)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
            name = stream.name
            json.dump(snapshot(devices, now), stream)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
        os.replace(name, path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)
