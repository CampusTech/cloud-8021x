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
ATTESTED_ACME = '--attested-acme' in sys.argv
SOURCE_DISCOVERY = '--source-discovery' in sys.argv
SOURCE_STATE = Path('/var/lib/radius-sources/state.json')
AUTH_LOG = Path('/var/log/freeradius/radius-auth.json')
ACCT_LOG = Path('/var/log/freeradius/radius-acct.json')
NO_VLAN = 'unassigned'  # Access-Accept with no tunnel attributes; None means reject.
DEVICES = {
    '42': {'serial': '', 'device_owner': 'byod"owner\n@example.com',
           'device_name': 'Personal "Mac"\nLaptop', 'device_model': 'MacBook Air'},
    '1': {'serial': 'STAFFSERIAL', 'device_owner': 'staff@example.com',
          'device_name': 'Staff Mac', 'device_model': 'MacBook Pro'},
}


def configure():
    source = Path('/tmp/startup.sh').read_text()
    parts = ['#!/bin/bash', 'set -euo pipefail', 'RADDB=/etc/freeradius/3.0',
             'HAS_JAMF_LOOKUP=false', 'HAS_FLEET_LOOKUP=true', 'HAS_UNIFI_LOOKUP=false',
             'HAS_MERAKI_LOOKUP=false', 'REWRITE_USERNAME=false', 'VLAN_POLICY_ENABLED=true',
             'REWRITE_USERNAME_SEPARATOR=" - "',
             'CERTIFICATE_INVENTORY=' + str(CERTIFICATE_MODE).lower(),
             'TLS_SESSION_CACHE=true', 'TLS_SESSION_CACHE_LIFETIME=24', 'TLS_MAX_VERSION=1.2']
    start = source.index('# Shared identity/policy code')
    end = source.index('\nCERT_DIR=', start)
    parts.append(source[start:end])
    start = source.index('echo "=== Configuring EAP-TLS')
    parts.append(source[start:source.index('# 6. Configure RADIUS', start)])
    # Install the real generated lookup module, without provisioning Fleet API
    # credentials, cache refresh jobs, or network access to a Fleet instance.
    start = source.rfind('if [ ', 0, source.index('echo "=== Configuring Python lookup module'))
    parts.append(source[start:source.index('# 11. Configure FreeRADIUS JSON auth logging', start)])
    start = source.index('echo "=== Configuring JSON auth logging')
    parts.append(source[start:source.index('# 12. Configure status', start)])
    if SOURCE_DISCOVERY:
        start = source.index('cat > "$RADDB/mods-available/radius_source_check"')
        end = source.index('\nSOURCECHECKEOF', start) + len('\nSOURCECHECKEOF')
        parts.append(source[start:end])
        parts.append('ln -sf "$RADDB/mods-available/radius_source_check" "$RADDB/mods-enabled/radius_source_check"')
    else:
        (RADDB / 'mods-enabled/radius_source_check').unlink(missing_ok=True)
    subprocess.run(['bash'], input='\n'.join(parts), text=True, check=True)
    for log in (AUTH_LOG, ACCT_LOG):
        log.write_text('')
    # Disposable public fixture key. Both auth and accounting use this key.
    key = Path('/run/radius-accounting-key')
    key.write_text('0123456789abcdef' * 4)
    subprocess.run(['chown', 'freerad:freerad', str(key)], check=True)
    key.chmod(0o600)
    # Distinct authenticated clients simulate offices behind distinct NAT IPs.
    # Rebuild only this disposable fixture's clients so --container is repeatable.
    (RADDB / 'clients.conf').write_text(
        'client localhost {\n ipaddr = 127.0.0.1\n secret = testing123\n shortname = localhost\n}\n')
    with (RADDB / 'clients.conf').open('a') as stream:
        for suffix, office in [(2, 'nyc'), (3, 'atl'), (4, 'unknown-office')]:
            stream.write(f'\nclient office{suffix} {{\n ipaddr = 127.0.0.{suffix}\n'
                         f' secret = testing123\n shortname = {office}\n}}\n')
    if SOURCE_DISCOVERY:
        with (RADDB / 'clients.conf').open('a') as stream:
            for name, address, office in [('discovered', '127.0.0.5', 'dynamic-office'),
                                           ('old-discovered', '127.0.0.6', 'dynamic-office'),
                                           ('cidr', '127.0.1.0/24', 'cidr-office')]:
                stream.write(f'\nclient {name} {{\n ipaddr = {address}\n'
                             f' secret = testing123\n shortname = {office}\n}}\n')
        clients = {office: {'cidrs': [f'127.0.0.{suffix}/32']}
                   for suffix, office in [(1, 'localhost'), (2, 'nyc'), (3, 'atl'), (4, 'unknown-office')]}
        clients['dynamic-office'] = {'cidrs': [], 'unifi_host_id': 'fixture-console'}
        clients['cidr-office'] = {'cidrs': ['127.0.1.0/24']}
        (RADDB / 'radius-sources.json').write_text(json.dumps({'project': 'test', 'clients': clients}))
        SOURCE_STATE.parent.mkdir(exist_ok=True)
        source_state()
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
    subprocess.run(['bash'], input=('CERTIFICATE_MODE=' + str(CERTIFICATE_MODE).lower() + '\n') + r'''
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
    if [ "$CERTIFICATE_MODE" = true ] && { [ "$identity" = personal-enrollment-id ] || [ "$identity" = STAFFSERIAL ]; }; then
        subject=cloud-8021x-inventory
    fi
    openssl req -newkey rsa:2048 -nodes -keyout "$identity.key" -out "$identity.csr" -subj "/CN=$subject" 2>/dev/null
    printf 'extendedKeyUsage=clientAuth\n' > client.ext
    openssl x509 -req -in "$identity.csr" -CA okta-ca.pem -CAkey ca.key -CAcreateserial -out "$identity.pem" -days 1 -extfile client.ext 2>/dev/null
done
chown freerad:freerad *.pem server-key.pem
chmod 640 server-key.pem
''', text=True, check=True)
    if ATTESTED_ACME:
        assert CERTIFICATE_MODE
        subprocess.run(['bash'], input=r'''
set -euo pipefail
cd /etc/freeradius/3.0/certs
openssl ecparam -name prime256v1 -genkey -noout -out attested-ca.key
openssl req -x509 -new -key attested-ca.key -out attested-acme-issuer.pem -days 1 -subj /CN=AttestedCA 2>/dev/null
cat attested-acme-issuer.pem >> okta-ca.pem
for identity in STAFFSERIAL forged-staff; do
    kind=06
    if [ "$identity" = forged-staff ]; then kind=08; fi
    openssl req -new -key "$identity.key" -out "$identity.csr" -subj /CN=STAFFSERIAL 2>/dev/null
    cat > attested.ext <<EOF
extendedKeyUsage=clientAuth
1.3.6.1.4.1.37476.9000.64.1=DER:30:10:02:01:$kind:04:09:77:69:66:69:2d:61:63:6d:65:04:00
subjectAltName=otherName:1.3.6.1.5.5.7.8.3;SEQUENCE:permanent
[permanent]
identifier=UTF8:STAFFSERIAL
EOF
    openssl x509 -req -in "$identity.csr" -CA attested-acme-issuer.pem -CAkey attested-ca.key -CAcreateserial -out "$identity.pem" -days 1 -extfile attested.ext 2>/dev/null
done
chmod 644 attested-acme-issuer.pem
''', text=True, check=True)
        policy_file = RADDB / 'vlan-policy.json'
        policy = json.loads(policy_file.read_text())
        policy['attested_acme'] = True
        policy_file.write_text(json.dumps(policy))
    result = subprocess.run(['freeradius', '-XC'], text=True, capture_output=True)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    print('PASS: rendered FreeRADIUS configuration validates', flush=True)


def source_state(age=0, identifier='fixture-console'):
    SOURCE_STATE.write_text(json.dumps({'updated_at': time.time() - age,
        'host_ids': {'dynamic-office': identifier},
        'sources': {'dynamic-office': ['127.0.0.5/32']}}))
    SOURCE_STATE.chmod(0o644)


def inventory(groups=None, enrolled=True, age=0, certificate_age=0, ambiguous=False):
    data = {'version': 1, 'updated_at': time.time() - age, 'identities': {
        'personal-enrollment-id': {'device_id': '42', 'groups': groups if groups is not None else ['byod'], 'enrolled': enrolled},
        'STAFFSERIAL': {'device_id': '1', 'groups': ['staff'], 'enrolled': True}}}
    if CERTIFICATE_MODE:
        data['version'] = 2
        data['devices'] = DEVICES
        data['certificates'] = {}
        if ATTESTED_ACME:
            data['hardware_serials'] = {'STAFFSERIAL': data['identities']['STAFFSERIAL']}
        for identity, device in data['identities'].items():
            if ATTESTED_ACME and identity == 'STAFFSERIAL':
                continue  # No fingerprint observation exists for the ACME device.
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


def packet_attributes(packet):
    """Keep octet-valued Class unchanged when relaying it into accounting."""
    attrs = {}
    pos = 20
    while pos < len(packet):
        kind, size = packet[pos:pos + 2]
        assert size >= 2 and pos + size <= len(packet), 'Malformed RADIUS attribute'
        attrs.setdefault(kind, []).append(packet[pos + 2:pos + size])
        pos += size
    return attrs


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def identity_log(record, device_id, certificate, vlan):
    """These assertions exercise emitted JSON, including quote/newline escaping."""
    der = ssl.PEM_cert_to_DER_cert((RADDB / 'certs' / (certificate + '.pem')).read_text())
    expected = dict(DEVICES[device_id], device_id=device_id,
                    certificate_fingerprint=hashlib.sha256(der).hexdigest(),
                    vlan_id='' if vlan == NO_VLAN else str(vlan),
                    identity_verified=True, raw_identity='STAFFSERIAL')
    for key, value in expected.items():
        assert record.get(key) == value, (key, record, value)


def unattributed_log(record):
    assert record.get('identity_verified') is False, record
    for key in ('device_id', 'serial', 'device_owner', 'device_name', 'device_model', 'vlan_name'):
        assert record.get(key) == '', (key, record)


def accounting(name, binding, status=1, source_ip='127.0.0.1', station=None,
               expected_device='42', expected_vlan=200, expect_drop=False):
    """Send real Accounting-Requests with unchanged or deliberately bad Class."""
    def attr(kind, value):
        if isinstance(value, str):
            value = value.encode()
        elif isinstance(value, int):
            value = struct.pack('!I', value)
        return bytes((kind, len(value) + 2)) + value

    offset = len(records(ACCT_LOG))
    attrs = b''.join([attr(1, 'STAFFSERIAL'), attr(4, socket.inet_aton('192.0.2.1')),
                      attr(31, station or binding['station']), attr(40, status),
                      attr(44, 'wire-' + name), attr(46, 30), attr(42, 1234), attr(43, 5678)])
    for value in binding.get('classes', []):
        attrs += attr(25, value)
    header = struct.pack('!BBH', 4, status, 20 + len(attrs))
    secret = b'testing123'
    authenticator = hashlib.md5(header + bytes(16) + attrs + secret).digest()
    request = header + authenticator + attrs
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.bind((source_ip, 0))
        client.settimeout(2 if expect_drop else 5)
        client.sendto(request, ('127.0.0.1', 1813))
        if expect_drop:
            try:
                response, _ = client.recvfrom(65535)
            except socket.timeout:
                assert records(ACCT_LOG)[offset:] == [], (name, 'Denied accounting must not be logged')
                print('PASS: accounting dropped', name, flush=True)
                return
            raise AssertionError((name, 'Denied accounting unexpectedly received a response', response))
        response, _ = client.recvfrom(65535)
    assert response[:2] == bytes((5, status)), (name, response)
    if expected_vlan == NO_VLAN:
        assert not vlan_attributes(response), (name, 'Opt-out accounting must not emit a VLAN')
    assert response[4:20] == hashlib.md5(response[:4] + authenticator + response[20:] + secret).digest()
    logged = records(ACCT_LOG)[offset:]
    assert len(logged) == 1, (name, logged)
    event = {1: 'Acct-Start', 2: 'Acct-Stop', 3: 'Acct-Update'}[status]
    assert logged[0]['event'] == event, (name, logged)
    assert logged[0]['src_ip'] == source_ip, (name, logged)
    if expected_device:
        certificate = 'personal-enrollment-id' if expected_device == '42' else 'STAFFSERIAL'
        identity_log(logged[0], expected_device, certificate, expected_vlan)
    else:
        unattributed_log(logged[0])
    print('PASS: accounting', name, event, flush=True)


def authenticate(name, certificate='personal-enrollment-id', expected=(200,), after_accept=None,
                 source_ip='127.0.0.1', nas_identifier=None):
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
    replies, errors, bindings = [], [], []
    log_offset = len(records(AUTH_LOG)) if CERTIFICATE_MODE else 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
        relay.bind((source_ip, 18120))
        relay.settimeout(0.1)

        def forward():
            client = None
            station = None
            try:
                while not stop.is_set():
                    try:
                        packet, address = relay.recvfrom(65535)
                    except socket.timeout:
                        continue
                    if address[1] == 1812:
                        if packet[0] in (2, 3):
                            replies.append((packet[0], vlan_attributes(packet)))
                            if packet[0] == 2:
                                bindings.append({'classes': packet_attributes(packet).get(25, []), 'station': station})
                            if packet[0] == 2 and after_accept:
                                after_accept()
                        relay.sendto(packet, client)
                    else:
                        client = address
                        stations = packet_attributes(packet).get(31, [])
                        if stations:
                            station = stations[0]
                        relay.sendto(packet, ('127.0.0.1', 1812))
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=forward)
        worker.start()
        try:
            result = subprocess.run(['eapol_test', '-c', '/tmp/eap.conf', '-p', '18120',
                                     '-a', source_ip, '-s', 'testing123',
                                     *(['-N32:s:' + nas_identifier] if nas_identifier else []),
                                     '-r', str(len(expected)-1), '-t', '15'], capture_output=True, text=True, timeout=25)
        finally:
            stop.set()
            worker.join()
    Path('/tmp/eap-' + name + '.log').write_text(result.stdout + result.stderr)
    want = [(3, []) if vlan is None else (2, [] if vlan == NO_VLAN else
            [(64, 13), (65, 6), (81, str(vlan))]) for vlan in expected]
    assert not errors, errors
    assert replies == want, (name, replies, want, result.stdout[-2000:])
    assert (result.returncode == 0) == (expected[-1] is not None), (name, result.returncode)
    if CERTIFICATE_MODE:
        logged = records(AUTH_LOG)[log_offset:]
        assert len(logged) == len(expected), (name, logged, expected)
        for record, vlan in zip(logged, expected):
            assert record['event'] == ('Access-Reject' if vlan is None else 'Access-Accept'), (name, record)
            assert record['src_ip'] == source_ip, (name, record)
            if vlan is not None:
                identity_log(record, '1' if certificate == 'STAFFSERIAL' else '42', certificate, vlan)
                assert record['cert_cn'] == ('STAFFSERIAL' if ATTESTED_ACME and certificate == 'STAFFSERIAL' else 'cloud-8021x-inventory'), (name, record)
            elif certificate in ('unknown', 'forged-staff'):
                unattributed_log(record)
        for binding in bindings:
            assert len(binding['classes']) == 1 and binding['classes'][0], (name, binding)
            assert binding['station'], 'EAP test must capture Calling-Station-Id for accounting binding'
    if len(expected) > 1:
        if CERTIFICATE_MODE:
            assert 'resumed=1' not in result.stdout, 'Fingerprint mode unexpectedly resumed TLS'
        else:
            assert 'resumed=1' in result.stdout, 'Test did not exercise real TLS resumption'
    print('PASS:', name, replies, flush=True)
    return bindings[-1] if bindings else None


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
            byod = authenticate('byod-spoofed-username')
            staff = authenticate('staff', certificate='STAFFSERIAL', expected=(100,))
            if CERTIFICATE_MODE:
                assert records(AUTH_LOG)[-2]['vlan_name'] == 'Guest "BYOD"'
                assert records(AUTH_LOG)[-1]['vlan_name'] == 'Secure'
                for status in (1, 3, 2):
                    accounting('byod-' + str(status), byod, status=status)
                    assert records(ACCT_LOG)[-1]['vlan_name'] == 'Guest "BYOD"'
                accounting('staff', staff, expected_device='1', expected_vlan=100)
                assert records(ACCT_LOG)[-1]['vlan_name'] == 'Secure'
                inventory(['staff'])
                accounting('byod-original-vlan-name', byod)
                assert records(ACCT_LOG)[-1]['vlan_name'] == 'Guest "BYOD"'
                accounting('missing-class', dict(byod, classes=[]), expected_device=None)
                token = byod['classes'][0]
                forged = token[:-8] + (b'A' if token[-8:-7] != b'A' else b'B') + token[-7:]
                accounting('forged-class', dict(byod, classes=[forged]), expected_device=None)
                accounting('cross-station-class', byod, station='de-ad-be-ef-00-01', expected_device=None)
                accounting('cross-office-class', byod, source_ip='127.0.0.2', expected_device=None)
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
            inventory()
            if SOURCE_DISCOVERY:
                source_state()
                dynamic = authenticate('fresh-discovered-source', source_ip='127.0.0.5')
                if CERTIFICATE_MODE:
                    accounting('fresh-discovered-source', dynamic, source_ip='127.0.0.5')
                authenticate('unobserved-source-spoofed-nas', source_ip='127.0.0.6',
                             nas_identifier='dynamic-office', expected=(None,))
                source_state(age=901)
                authenticate('stale-discovered-source', source_ip='127.0.0.5',
                             nas_identifier='localhost', expected=(None,))
                if CERTIFICATE_MODE:
                    accounting('stale-discovered-source', dynamic, source_ip='127.0.0.5', expect_drop=True)
                authenticate('static-cidr-with-stale-discovery', source_ip='127.0.1.27')
                source_state(identifier='other-console')
                authenticate('changed-console-id', source_ip='127.0.0.5', expected=(None,))
                source_state()
                authenticate('refreshed-discovered-source', source_ip='127.0.0.5')
            policy_file = RADDB / 'vlan-policy.json'
            policy = json.loads(policy_file.read_text())
            policy['locations'] = {'nyc': {'group_vlans': {'byod': 210}, 'vlan_names': {'210': 'NYC Guest'}},
                                   'atl': {'group_vlans': {'byod': 220}, 'vlan_names': {'220': 'ATL Guest'}}}
            policy_file.write_text(json.dumps(policy))
            if CERTIFICATE_MODE:
                sources = {'nyc': {'unifi_host_id': 'nyc-console'}, 'atl': {'meraki_network_id': 'N_ATL'}}
                (RADDB / 'vlan-name-sources.json').write_text(json.dumps(sources))
                controller_names = {'locations': {
                    'nyc': {'source': sources['nyc'], 'updated_at': time.time(), 'names': {'210': 'UniFi Guest "NYC"'}},
                    'atl': {'source': sources['atl'], 'updated_at': time.time(), 'names': {'220': 'Meraki Guest ATL'}}}}
                controller_cache = RADDB / 'vlan-name-cache.json'
                controller_cache.write_text(json.dumps(controller_names))
            nyc_session = authenticate('nyc-location', source_ip='127.0.0.2', expected=(210,))
            if CERTIFICATE_MODE:
                assert records(AUTH_LOG)[-1]['vlan_name'] == 'UniFi Guest "NYC"'
            authenticate('atl-location-spoofed-nas', source_ip='127.0.0.3', nas_identifier='nyc', expected=(220,))
            if CERTIFICATE_MODE:
                assert records(AUTH_LOG)[-1]['vlan_name'] == 'Meraki Guest ATL'
                controller_names['locations']['nyc']['names']['210'] = 'Renamed UniFi Guest'
                controller_cache.write_text(json.dumps(controller_names))
                accounting('nyc-controller-rename', nyc_session, source_ip='127.0.0.2', expected_vlan=210)
                assert records(ACCT_LOG)[-1]['vlan_name'] == 'Renamed UniFi Guest'
                controller_cache.write_text('invalid')
                accounting('nyc-controller-unavailable', nyc_session, source_ip='127.0.0.2', expected_vlan=210)
                assert records(ACCT_LOG)[-1]['vlan_name'] == 'NYC Guest'
                controller_cache.write_text(json.dumps(controller_names))
            authenticate('atl-location-reauth', source_ip='127.0.0.3', expected=(220, 220))
            authenticate('unknown-location', source_ip='127.0.0.4', nas_identifier='nyc', expected=(None,))

            def atl_policy(value):
                policy['locations']['atl'] = value
                policy_file.write_text(json.dumps(policy))

            atl_policy({'dynamic_vlans': False})
            inventory(groups=[])
            optout = authenticate('atl-optout-unmapped', source_ip='127.0.0.3', expected=(NO_VLAN,))
            if CERTIFICATE_MODE:
                for status in (1, 3, 2):
                    accounting('optout-' + str(status), optout, status=status,
                               source_ip='127.0.0.3', expected_vlan=NO_VLAN)
                    assert records(ACCT_LOG)[-1]['vlan_name'] == ''
                accounting('optout-cross-office', optout, source_ip='127.0.0.2', expected_device=None)
            inventory()
            authenticate('nyc-still-mapped', source_ip='127.0.0.2', expected=(210,))
            authenticate('optout-unknown-location', source_ip='127.0.0.4', expected=(None,))
            authenticate('optout-unknown-certificate', certificate='unknown', source_ip='127.0.0.3', expected=(None,))
            inventory(age=3601)
            authenticate('optout-expired-cache', source_ip='127.0.0.3', expected=(None,))
            if CERTIFICATE_MODE:
                inventory(certificate_age=86401)
                authenticate('optout-expired-certificate', source_ip='127.0.0.3', expected=(None,))
                inventory(ambiguous=True)
                authenticate('optout-ambiguous-certificate', source_ip='127.0.0.3', expected=(None,))
                inventory()
                authenticate('optout-forged-staff-cn', certificate='forged-staff', source_ip='127.0.0.3', expected=(None,))
            inventory()
            authenticate('optout-reauth-unenrolled', source_ip='127.0.0.3', expected=(NO_VLAN, None),
                         after_accept=lambda: inventory(enrolled=False))
            inventory()
            authenticate('optout-reauth-to-mapped', source_ip='127.0.0.3', expected=(NO_VLAN, 220),
                         after_accept=lambda: atl_policy({'group_vlans': {'byod': 220}}))
            authenticate('mapped-reauth-to-optout', source_ip='127.0.0.3', expected=(220, NO_VLAN),
                         after_accept=lambda: atl_policy({'dynamic_vlans': False}))

        finally:
            server.terminate()
            server.wait(timeout=10)


if __name__ == '__main__':
    main()
