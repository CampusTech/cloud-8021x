"""FreeRADIUS EAP-TLS certificate authorization policy. Never derive authorization from outer User-Name."""
import json
import time

import radiusd
import radius_identity
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
        location = None
        if config.get('locations') or config.get('certificate_inventory', False):
            locations = [value for key, value in request.get('request', ()) if key == 'Tmp-String-1']
            if len(locations) != 1:
                raise ValueError('missing or ambiguous trusted RADIUS location')
            location = locations[0]
        vlan = select_vlan(identity, inventory, config, time.time(), location)
        # Numeric enum values match UniFi's required RADIUS attributes. The VLAN
        # ID itself is a string, per RFC 3580 section 3.31. No tunnel tag is used.
        reply = (
            ('Tunnel-Type', '13'),
            ('Tunnel-Medium-Type', '6'),
            ('Tunnel-Private-Group-Id', str(vlan)),
        )
        if config.get('certificate_inventory', False):
            # Only an accepted exact leaf fingerprint can mint a log binding.
            # A request Class or an outer username never supplies this identity.
            stations = [value for key, value in request.get('request', ())
                        if key == 'Calling-Station-Id']
            if len(stations) != 1:
                raise ValueError('missing or ambiguous calling station')
            device_id = inventory['certificates'][identity]['device_id']
            binding = radius_identity.issue(radius_identity.read_key(), device_id, identity,
                                            vlan, location, stations[0], time.time())
            reply += (('Class', binding),)
        return radiusd.RLM_MODULE_UPDATED, {'reply': reply}
    except Exception as exc:
        radiusd.radlog(radiusd.L_ERR, 'VLAN authorization denied: ' + str(exc))
        return radiusd.RLM_MODULE_REJECT
