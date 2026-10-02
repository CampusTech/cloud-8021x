"""Inventory adapters publish the same device policy format for any RADIUS client."""
import json
import os
from pathlib import Path
import tempfile

from device_policy import snapshot


def fleet_device(host):
    group_id = host.get('fleet_id', host.get('team_id')) or 0
    return {
        'device_id': 'fleet:' + str(host['id']),
        'identities': [v for v in (host.get('hardware_serial'), host.get('uuid')) if v],
        'groups': ['fleet:' + str(group_id)],
        'enrolled': (host.get('mdm') or {}).get('enrollment_status', '').startswith('On'),
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
