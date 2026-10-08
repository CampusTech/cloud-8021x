"""Serialize certificate-mode RADIUS events without trusting claimed identities."""
from datetime import datetime, timezone
import hashlib
import json
import re
import sys


def attributes(request, name):
    return dict(request.get(name, ()))


def record(request, enrichment, accounting=False):
    incoming = attributes(request, 'request')
    control = attributes(request, 'config')
    # Identity fields come ONLY from verified enrichment, not earlier reply attrs.
    reply = dict(enrichment)
    event = control.get('Tmp-String-5', 'Access-Reject')
    if accounting:
        event = {'Start': 'Acct-Start', 'Stop': 'Acct-Stop', 'Interim-Update': 'Acct-Update',
                 '1': 'Acct-Start', '2': 'Acct-Stop', '3': 'Acct-Update'}.get(
                     incoming.get('Acct-Status-Type'), 'Acct-Unknown')
    result = {'timestamp': datetime.now(timezone.utc).isoformat(), 'event': event,
              'device_id': reply.get('Tmp-String-2', ''),
              'certificate_fingerprint': reply.get('Tmp-String-3', ''),
              'identity_verified': bool(reply.get('Tmp-String-2')),
              'serial': reply.get('Login-LAT-Service', ''),
              'raw_identity': incoming.get('User-Name', ''),
              'device_owner': reply.get('Reply-Message', ''),
              'device_name': reply.get('Filter-Id', ''),
              'device_model': reply.get('Login-LAT-Node', ''),
              'vlan_id': reply.get('Tunnel-Private-Group-Id', ''),
              'vlan_name': reply.get('Tmp-String-7', ''),
              'ssid': reply.get('Login-LAT-Port', ''),
              'site_name': reply.get('Connect-Info', ''),
              'ap_name': reply.get('Callback-Id', '')}
    for key, attr in {'src_ip': 'Packet-Src-IP-Address', 'nas_ip': 'NAS-IP-Address',
                      'nas_port': 'NAS-Port', 'calling_station': 'Calling-Station-Id',
                      'called_station': 'Called-Station-Id', 'session_id': 'Acct-Session-Id',
                      'multi_session_id': 'Acct-Multi-Session-Id',
                      'cert_cn': 'TLS-Client-Cert-Common-Name',
                      'cert_issuer': 'TLS-Client-Cert-Issuer',
                      'cert_expiration': 'TLS-Client-Cert-Expiration'}.items():
        result[key] = incoming.get(attr, '')
    result['src_ip'] = control.get('Tmp-String-6', result['src_ip'])
    if event == 'Access-Reject':
        result['reject_reason'] = incoming.get('Module-Failure-Message', control.get('Module-Failure-Message', ''))
    if accounting:
        result['username'] = incoming.get('User-Name', '')
        result['terminate_cause'] = incoming.get('Acct-Terminate-Cause', '')
        for key, attr in {'session_time': 'Acct-Session-Time', 'input_bytes': 'Acct-Input-Octets',
                          'output_bytes': 'Acct-Output-Octets'}.items():
            try:
                result[key] = max(0, int(incoming.get(attr, 0)))
            except (ValueError, TypeError):
                result[key] = 0
    return json.dumps(result, separators=(',', ':'), ensure_ascii=True)


def expiry_pairs(lines, issuer):
    """Stable per-device metric keys; old logs retain their serial-based identity."""
    for line in lines:
        try:
            item = json.loads(line)
            identity = item.get('device_id', item.get('serial', ''))
            expiration = item.get('cert_expiration', '')
            if (not isinstance(identity, str) or not identity
                    or issuer not in item.get('cert_issuer', '')
                    or not isinstance(expiration, str)
                    or not re.fullmatch(r'[0-9]{12}Z', expiration)):
                continue
            # No shell delimiters from device metadata enter the metrics script.
            yield hashlib.sha256(identity.encode()).hexdigest(), expiration[:-1]
        except (ValueError, TypeError, AttributeError):
            continue


if __name__ == '__main__':
    for identity, expiration in expiry_pairs(sys.stdin, sys.argv[1]):
        print(identity, expiration)
