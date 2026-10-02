"""FreeRADIUS EAP-TLS certificate authorization policy. Never derive authorization from outer User-Name."""
import json
import time

import radiusd
from device_policy import select_vlan

CONFIG_FILE = '/etc/freeradius/3.0/vlan-policy.json'


def authorize(request):
    try:
        # FreeRADIUS 3.x restores TLS certificate attributes into request on
        # resumption. If it cannot restore them, deny; never fall back to EAP identity.
        names = [value for key, value in request.get('request', ())
                 if key == 'TLS-Client-Cert-Common-Name']
        if len(names) != 1:
            raise ValueError('missing or ambiguous certificate identity')
        with open(CONFIG_FILE) as stream:
            config = json.load(stream)
        with open(config['cache_file']) as stream:
            inventory = json.load(stream)
        vlan = select_vlan(names[0], inventory, config, time.time())
        # Numeric enum values match UniFi's required RADIUS attributes. The VLAN
        # ID itself is a string, per RFC 3580 section 3.31. No tunnel tag is used.
        return radiusd.RLM_MODULE_UPDATED, {'reply': (
            ('Tunnel-Type', '13'),
            ('Tunnel-Medium-Type', '6'),
            ('Tunnel-Private-Group-Id', str(vlan)),
        )}
    except Exception as exc:
        radiusd.radlog(radiusd.L_ERR, 'VLAN authorization denied: ' + str(exc))
        return radiusd.RLM_MODULE_REJECT
