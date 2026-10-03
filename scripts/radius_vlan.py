"""FreeRADIUS EAP-TLS certificate authorization policy. Never derive authorization from outer User-Name."""
import json
import time

import radiusd
from device_policy import CERTIFICATE_DIRECTORY, consume_certificate, select_vlan

CONFIG_FILE = '/etc/freeradius/3.0/vlan-policy.json'


def authorize(request):
    try:
        with open(CONFIG_FILE) as stream:
            config = json.load(stream)
        if config.get('certificate_inventory', False):
            # check-device-vlan sets this internal attribute exclusively from the
            # outer server session-state. Ignore all CN/outer identity attributes.
            names = [value for key, value in request.get('request', ()) if key == 'Tmp-String-0']
            if len(names) != 1:
                raise ValueError('missing or ambiguous server certificate session')
            identity = consume_certificate(names[0], CERTIFICATE_DIRECTORY)
        else:
            names = [value for key, value in request.get('request', ())
                     if key == 'TLS-Client-Cert-Common-Name']
            if len(names) != 1:
                raise ValueError('missing or ambiguous certificate identity')
            identity = names[0]
        with open(config['cache_file']) as stream:
            inventory = json.load(stream)
        vlan = select_vlan(identity, inventory, config, time.time())
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
