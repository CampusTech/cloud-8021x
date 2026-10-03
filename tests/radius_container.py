"""Test fixture executed only inside the disposable Debian container."""
import hashlib
import json
from pathlib import Path
import socket
import ssl
import sys
import struct
import subprocess
import threading
import time

RADDB = Path('/etc/freeradius/3.0')
CACHE = RADDB / 'device-policy-cache.json'
CERTIFICATE_MODE = '--certificate-inventory' in sys.argv


def configure():
    source = Path('/tmp/startup.sh').read_text()
    parts = ['#!/bin/bash', 'set -euo pipefail', 'RADDB=/etc/freeradius/3.0',
             'HAS_JAMF_LOOKUP=false', 'HAS_FLEET_LOOKUP=false', 'HAS_UNIFI_LOOKUP=false',
             'HAS_MERAKI_LOOKUP=false', 'REWRITE_USERNAME=false', 'VLAN_POLICY_ENABLED=true',
             'TLS_SESSION_CACHE=true', 'TLS_SESSION_CACHE_LIFETIME=24', 'TLS_MAX_VERSION=1.2']
    start = source.index('# Shared identity/policy code')
    end = source.index('\n', source.index('\nchmod 644', start) + 1)
    parts.append(source[start:end])
    start = source.index('echo "=== Configuring EAP-TLS')
    parts.append(source[start:source.index('# 6. Configure RADIUS', start)])
    start = source.index('echo "=== Configuring JSON auth logging')
    parts.append(source[start:source.index('# 12. Configure status', start)])
    subprocess.run(['bash'], input='\n'.join(parts), text=True, check=True)
    # Accounting's SQL database is unrelated to EAP auth; this fixture has no DB.
    site = RADDB / 'sites-available/default'
    site.write_text(site.read_text().replace('        sql\n', '        noop\n'))
    # Force real resumption in the test fixture. The deployed config retains its
    # existing cache settings; without persist_dir Debian 12 does full reauths.
    eap = RADDB / 'mods-available/eap'
    if not CERTIFICATE_MODE:
        eap.write_text(eap.read_text().replace('name = "eap-tls"',
                                             'name = "eap-tls"\n            persist_dir = /tmp/tlscache'))
    else:
        assert 'enable = no' in eap.read_text(), 'Fingerprint mode must disable session resumption'
    subprocess.run(['bash'], input=r'''
set -euo pipefail
mkdir -p /tmp/tlscache
chown freerad:freerad /tmp/tlscache
cd /etc/freeradius/3.0/certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out okta-ca.pem -days 1 -subj /CN=TestCA 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr -subj /CN=radius.test 2>/dev/null
printf 'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:radius.test\n' > server.ext
openssl x509 -req -in server.csr -CA okta-ca.pem -CAkey ca.key -CAcreateserial -out server-cert.pem -days 1 -extfile server.ext 2>/dev/null
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048 -out dh.pem 2>/dev/null
for identity in personal-enrollment-id STAFFSERIAL unknown forged-staff; do
    subject="$identity"
    if [ "$identity" = forged-staff ]; then subject=STAFFSERIAL; fi
    openssl req -newkey rsa:2048 -nodes -keyout "$identity.key" -out "$identity.csr" -subj "/CN=$subject" 2>/dev/null
    printf 'extendedKeyUsage=clientAuth\n' > client.ext
    openssl x509 -req -in "$identity.csr" -CA okta-ca.pem -CAkey ca.key -CAcreateserial -out "$identity.pem" -days 1 -extfile client.ext 2>/dev/null
done
chown freerad:freerad *.pem server-key.pem
chmod 640 server-key.pem
''', text=True, check=True)
    result = subprocess.run(['freeradius', '-XC'], text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    print('PASS: rendered FreeRADIUS configuration validates', flush=True)


def inventory(groups=None, enrolled=True, age=0, certificate_age=0, ambiguous=False):
    data = {'version': 1, 'updated_at': time.time() - age, 'identities': {
        'personal-enrollment-id': {'device_id': '42', 'groups': groups if groups is not None else ['byod'], 'enrolled': enrolled},
        'STAFFSERIAL': {'device_id': '1', 'groups': ['staff'], 'enrolled': True}}}
    if CERTIFICATE_MODE:
        data['version'] = 2
        data['certificates'] = {}
        for identity, device in data['identities'].items():
            der = ssl.PEM_cert_to_DER_cert((RADDB / 'certs' / (identity + '.pem')).read_text())
            fingerprint = hashlib.sha256(der).hexdigest()
            data['certificates'][fingerprint] = None if ambiguous else dict(device, observed_at=time.time() - certificate_age)
    temporary = CACHE.with_suffix('.tmp')
    temporary.write_text(json.dumps(data))
    temporary.replace(CACHE)


def vlan_attributes(packet):
    attrs = []
    pos = 20
    while pos < len(packet):
        kind, size = packet[pos:pos+2]
        value = packet[pos+2:pos+size]
        if packet[0] == 3:
            assert kind != 26, 'Access-Reject must not expose MS-MPPE keys'
        if kind == 79 and packet[0] == 3:
            assert value[0] == 4, 'Access-Reject must carry EAP-Failure, not EAP-Success'
        if kind in (64, 65):
            attrs.append((kind, struct.unpack('!I', value)[0]))
        elif kind == 81:
            attrs.append((kind, value.decode()))
        pos += size
    return attrs


def authenticate(name, certificate='personal-enrollment-id', expected=(200,), after_accept=None):
    """UDP relay records actual server replies and updates inventory BEFORE reauth."""
    config = f'''network={{
    ssid="test"
    key_mgmt=WPA-EAP
    eap=TLS
    identity="STAFFSERIAL"
    ca_cert="{RADDB}/certs/okta-ca.pem"
    client_cert="{RADDB}/certs/{certificate}.pem"
    private_key="{RADDB}/certs/{certificate}.key"
    domain_suffix_match="radius.test"
    eapol_flags=0
}}
'''
    Path('/tmp/eap.conf').write_text(config)
    stop = threading.Event()
    replies, errors = [], []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
        relay.bind(('127.0.0.1', 18120))
        relay.settimeout(0.1)

        def forward():
            client = None
            try:
                while not stop.is_set():
                    try:
                        packet, address = relay.recvfrom(65535)
                    except socket.timeout:
                        continue
                    if address[1] == 1812:
                        if packet[0] in (2, 3):
                            replies.append((packet[0], vlan_attributes(packet)))
                            if packet[0] == 2 and after_accept:
                                after_accept()
                        relay.sendto(packet, client)
                    else:
                        client = address
                        relay.sendto(packet, ('127.0.0.1', 1812))
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=forward)
        worker.start()
        try:
            result = subprocess.run(['eapol_test', '-c', '/tmp/eap.conf', '-p', '18120',
                                     '-a', '127.0.0.1', '-s', 'testing123',
                                     '-r', str(len(expected)-1), '-t', '15'], capture_output=True, text=True, timeout=25)
        finally:
            stop.set()
            worker.join()
    Path('/tmp/eap-' + name + '.log').write_text(result.stdout + result.stderr)
    want = [(3, []) if vlan is None else (2, [(64, 13), (65, 6), (81, str(vlan))]) for vlan in expected]
    assert not errors, errors
    assert replies == want, (name, replies, want, result.stdout[-2000:])
    assert (result.returncode == 0) == (expected[-1] is not None), (name, result.returncode)
    if len(expected) > 1:
        if CERTIFICATE_MODE:
            assert 'resumed=1' not in result.stdout, 'Fingerprint mode unexpectedly resumed TLS'
        else:
            assert 'resumed=1' in result.stdout, 'Test did not exercise real TLS resumption'
    print('PASS:', name, replies, flush=True)


def main():
    configure()
    with open('/tmp/radius-debug.log', 'w') as log:
        server = subprocess.Popen(['freeradius', '-X'], stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                if 'Ready to process requests' in Path('/tmp/radius-debug.log').read_text():
                    break
                if server.poll() is not None:
                    raise AssertionError(Path('/tmp/radius-debug.log').read_text())
                time.sleep(0.05)
            else:
                raise AssertionError('RADIUS did not start')
            inventory()
            authenticate('byod-spoofed-username')
            authenticate('staff', certificate='STAFFSERIAL', expected=(100,))
            inventory()
            authenticate('reauth-changed-group' if CERTIFICATE_MODE else 'resume-changed-group', expected=(200, 100), after_accept=lambda: inventory(['staff']))
            inventory()
            authenticate('reauth-unenrolled' if CERTIFICATE_MODE else 'resume-unenrolled', expected=(200, None), after_accept=lambda: inventory(enrolled=False))
            inventory()
            authenticate('unknown', certificate='unknown', expected=(None,))
            if CERTIFICATE_MODE:
                inventory()
                authenticate('forged-staff-cn', certificate='forged-staff', expected=(None,))
                inventory(certificate_age=86401)
                authenticate('expired-certificate-observation', expected=(None,))
                inventory(ambiguous=True)
                authenticate('ambiguous-certificate', expected=(None,))
            inventory(age=3601)
            authenticate('expired-cache', expected=(None,))
            inventory(groups=[])
            authenticate('unmapped-group', expected=(None,))
            if CERTIFICATE_MODE:
                inventory()
                helper = RADDB / 'mods-config/python3/device_policy.py'
                moved = helper.with_suffix('.disabled')
                helper.rename(moved)
                try:
                    authenticate('missing-fingerprint-hook', expected=(None,))
                finally:
                    moved.rename(helper)
                assert not list(Path('/run/radius-certificate-bindings').iterdir()), 'Handshake files leaked'
            CACHE.write_text('{')
            authenticate('corrupt-cache', expected=(None,))
        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == '__main__':
    main()
