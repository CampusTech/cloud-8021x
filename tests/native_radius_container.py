"""Development-only native fixture; never installed on a RADIUS server."""
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import pwd
import grp
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

ROOT = Path('/task6')
CERT = ROOT / 'certs'
RADDB = Path('/etc/freeradius/3.0')
CFG = Path('/etc/cloud-8021x/config.yaml')
AUTH = Path('/var/log/cloud8021x-auth')
SPOOL = Path('/var/spool/cloud8021x-accounting')
SECRET = b'fixture-secret-0123456789abcdef'
IP = subprocess.check_output(['hostname', '-I'], text=True).split()[0]
REPLAY_POLLS = 60

def run(*args, **kw):
    result=subprocess.run(args, text=True, capture_output=True, **kw)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed: {result.stdout[-1000:]} {result.stderr[-1000:]}')
    return result

def write(path, text, mode=0o644, owner=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    if owner:
        shutil.chown(path, user=owner)

def postgres_json(query, **variables):
    """Read the disposable fixture DB using quoted psql variables and verified TLS."""
    cfg=json.loads(CFG.read_text())
    dsn=Path(cfg['database']['migration_dsn']['file']).read_text().strip()
    dsn+=f" sslmode=verify-full sslrootcert='{cfg['database']['ca_file']}' connect_timeout=1"
    result=run('psql','-X','-A','-t','-v','ON_ERROR_STOP=1',
               *[arg for key,value in variables.items() for arg in ['-v',key+'='+json.dumps(value)]],
               '--dbname',dsn,input="SET statement_timeout='2s';\n"+query)
    # SET's command tag is the only non-JSON output.
    return json.loads(result.stdout.splitlines()[-1])

def intake_rows(records):
    sessions=sorted({record['session_id'] for record in records})
    return postgres_json("""SELECT coalesce(json_agg(row_to_json(r)),'[]') FROM (
        SELECT id,session_id,replay_id,extract(epoch FROM received_at)::bigint AS received_at,
               source_ip,client_id,location_id,status,packet_id,request_authenticator,
               processed_at IS NOT NULL AS processed,observation_id
        FROM ledger.intake WHERE session_id IN (SELECT jsonb_array_elements_text(:'sessions'::jsonb))
        ORDER BY id) r;""",sessions=sessions)

def pending_replay_ids():
    result=set()
    for path in SPOOL.glob('detail*'):
        assert path.is_file() and path.stat().st_size<=16*1024*1024,'unbounded native test spool'
        result.update(re.findall(rb'C8021X-Replay = "([a-f0-9]{64})"',path.read_bytes()))
    return {value.decode() for value in result}

def assert_replayed(records,rows,copies=1):
    assert records,'replay has no expected retained records'
    for expected in records:
        matching=[row for row in rows if row['replay_id']==expected['replay_id']]
        assert len(matching)==copies,('replay row count',expected['session_id'],len(matching),copies)
        for row in matching:
            assert all(row.get(key)==value for key,value in expected.items()),('replay changed original context',expected,row)
    assert not ({record['replay_id'] for record in records} & pending_replay_ids()),'replay pending work did not drain'

def wait_replayed(records,copies=1):
    for attempt in range(REPLAY_POLLS):
        rows=intake_rows(records)  # DB failure is a failure, never an elapsed-time success.
        try:assert_replayed(records,rows,copies)
        except AssertionError:
            if attempt==REPLAY_POLLS-1:raise
            time.sleep(.25)
        else:return rows

def retain_replay_expectations(session):
    """Inspect only test-owned native detail metadata; never installed in production."""
    records=[];saved=[]
    attributes={'session_id':'Acct-Session-Id','replay_id':'C8021X-Replay','received_at':'C8021X-Receipt',
                'source_ip':'C8021X-Source','client_id':'C8021X-Client','location_id':'C8021X-Location',
                'status':'Acct-Status-Type','packet_id':'C8021X-Packet-ID','request_authenticator':'C8021X-Authenticator'}
    for path in SPOOL.glob('detail*'):
        for chunk in path.read_text().split('\n\n'):
            if f'\tAcct-Session-Id = "{session}"\n' not in chunk+'\n':continue
            record={}
            for key,attribute in attributes.items():
                values=re.findall(r'^\t'+re.escape(attribute)+r' = (?:"([^"\\]*)"|([^\n"]+))$',chunk,re.M)
                assert len(values)==1,('invalid retained fixture metadata',attribute)
                record[key]=next(value for value in values[0] if value)
            record['received_at']=int(record['received_at'])
            assert re.fullmatch('[a-f0-9]{64}',record['replay_id'])
            records.append(record);saved.append(chunk+'\n\n')
    assert len(records)==3 and {r['status'] for r in records}=={'Start','Interim-Update','Stop'},'replay fixture did not retain all statuses'
    filename='replay-retained-'+session+'.detail'
    write(ROOT/filename,''.join(saved),0o600)
    write(ROOT/'replay-expectations.json',json.dumps({'records':records,'files':[filename]}),0o600)
    return records

def replay_test(duplicate=False):
    manifest=json.loads((ROOT/'replay-expectations.json').read_text())
    records=manifest['records']
    intake_rows(records)  # Fail immediately if the supposedly recovered DB is still down.
    radius=start_radius()
    try:
        rows=wait_replayed(records)
        if duplicate:
            expected_count=len({record['replay_id'] for record in records})
            assert len(records)==expected_count==3 and {record['status'] for record in records}=={'Start','Interim-Update','Stop'},'duplicate fixture requires three distinct status reports'
            run('runuser','-u','cloud8021x','--','/task6-native-fixture','process',str(CFG))
            before=intake_rows(records)
            assert all(row['processed'] and row['observation_id'] for row in before),'original replay did not reach shared ledger'
            for index,name in enumerate(manifest['files']):
                assert Path(name).name==name,'unsafe fixture replay filename'
                write(SPOOL/f'detail-repeat-{index}-{time.time_ns()}',(ROOT/name).read_text(),0o600,'freerad')
            wait_replayed(records,2)
            run('runuser','-u','cloud8021x','--','/task6-native-fixture','process',str(CFG))
            rows=intake_rows(records)
            ids=[]
            for record in records:
                copies=[row for row in rows if row['replay_id']==record['replay_id']]
                assert len(copies)==2 and all(row['processed'] for row in copies)
                assert len({row['observation_id'] for row in copies})==1 and copies[0]['observation_id'],'shared ledger did not deduplicate replay'
                ids.append(copies[0]['observation_id'])
            # These fixture statuses are distinct semantic reports. This is not
            # a uniqueness rule for native IDs on legitimate NAS retransmissions.
            assert len(set(ids))==expected_count,'distinct status reports collapsed into one observation'
            counts=postgres_json("""SELECT json_build_object(
                'observations',(SELECT count(*) FROM ledger.observations WHERE event_id IN (SELECT jsonb_array_elements_text(:'ids'::jsonb))),
                'outbox',(SELECT count(*) FROM ledger.work WHERE id IN (SELECT 'accounting:'||jsonb_array_elements_text(:'ids'::jsonb))));""",ids=ids)
            assert counts=={'observations':expected_count,'outbox':expected_count},('duplicate immutable event/outbox',counts)
        print('PASS exact retained replay receipt/source/identity, pending drain'+(' and shared-ledger duplicate/outbox checks' if duplicate else ''),flush=True)
    finally:radius.terminate();radius.wait(timeout=3)

def assert_packets_delivered(packets):
    """Every ACKed test packet needs an exact identifiable PostgreSQL intake row."""
    for attempt in range(REPLAY_POLLS):
        rows=intake_rows(packets)
        try:
            for packet in packets:
                matches=[row for row in rows if row['session_id']==packet['session_id'] and row['request_authenticator']==packet['request_authenticator']]
                assert len(matches)==1,('native intake missing ACKed packet',packet['session_id'])
                row=matches[0]
                assert all(row[key]==packet[key] for key in ['source_ip','client_id','location_id','status','packet_id'])
                assert packet['received_min']<=row['received_at']<=packet['received_max'],'native receipt was not original packet receipt'
                assert re.fullmatch('[a-f0-9]{64}',row['replay_id'])
            assert not ({row['replay_id'] for row in rows} & pending_replay_ids()),'ACKed packet pending work did not drain'
        except AssertionError:
            if attempt==REPLAY_POLLS-1:raise
            time.sleep(.25)
        else:
            print('PASS all ACKed test packets persisted with original context and drained work',flush=True)
            return

def prepare():
    ROOT.mkdir(exist_ok=True)
    CERT.mkdir(exist_ok=True)
    for group in ['cloud8021x', 'cloud8021x-events']:
        subprocess.run(['groupadd', '-f', group], check=True)
    try:
        pwd.getpwnam('cloud8021x')
    except KeyError:
        run('useradd', '-M', '-g', 'cloud8021x', '-s', '/usr/sbin/nologin', 'cloud8021x')
    run('usermod', '-a', '-G', 'cloud8021x-events', 'cloud8021x')
    run('usermod', '-a', '-G', 'cloud8021x-events', 'freerad')
    for path, user, group, mode in [('/run/radius-verified-leaves', 'freerad', 'freerad', 0o700),
                                    ('/run/radius-certificate-bindings', 'cloud8021x', 'cloud8021x', 0o700),
                                    (str(AUTH), 'freerad', 'cloud8021x-events', 0o2750),
                                    (str(SPOOL), 'freerad', 'freerad', 0o700),
                                    ('/var/lib/cloud-8021x', 'cloud8021x', 'cloud8021x', 0o700),
                                    ('/run/freeradius', 'freerad', 'freerad', 0o755)]:
        Path(path).mkdir(parents=True, exist_ok=True)
        shutil.chown(path, user=user, group=group)
        Path(path).chmod(mode)
    run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(CERT/'ca.key'),
        '-out', str(CERT/'ca.pem'), '-days', '2', '-subj', '/CN=DisposableNativeCA')
    for name, cn, purpose in [('server', 'localhost', 'serverAuth'), ('personal', 'cloud-8021x-inventory', 'clientAuth'),
                              ('unknown', 'cloud-8021x-inventory', 'clientAuth'), ('legacy', 'STAFFSERIAL', 'clientAuth')]:
        run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(CERT/(name+'.key')),
            '-out', str(CERT/(name+'.csr')), '-subj', '/CN='+cn)
        write(CERT/'ext', 'extendedKeyUsage='+purpose+'\n'+('subjectAltName=DNS:localhost\n' if name=='server' else ''))
        run('openssl', 'x509', '-req', '-in', str(CERT/(name+'.csr')), '-CA', str(CERT/'ca.pem'),
            '-CAkey', str(CERT/'ca.key'), '-CAcreateserial', '-out', str(CERT/(name+'.pem')), '-days', '1', '-extfile', str(CERT/'ext'))
    shutil.chown(CERT/'server.key', user='freerad')
    (CERT/'server.key').chmod(0o600)
    write(ROOT/'app/bearer', 'b'*64, 0o600, 'cloud8021x')
    write(ROOT/'app/class-key', 'A'*64, 0o600, 'cloud8021x')
    write(ROOT/'secrets/radius-secret', SECRET.decode(), 0o600)
    for kind, user, password in [('native', 'app_native', 'fixture-native'), ('runtime', 'app_runtime', 'fixture-runtime'), ('migration', 'postgres', 'fixture-migration')]:
        write(ROOT/(('app/' if kind=='runtime' else 'secrets/')+kind+'-dsn'), f'host=localhost port=55432 dbname=cloud8021x user={user} password={password}', 0o600, 'cloud8021x' if kind=='runtime' else None)
    config = {
        'schema_version': 1, 'hostname': 'native-fixture',
        'listeners': {'policy': {'address': '127.0.0.1:18121', 'token': {'file': str(ROOT/'app/bearer')}, 'max_concurrency': 2, 'timeout': '500ms'}},
        'database': {kind+'_dsn': {'file': str(ROOT/(('app/' if kind=='runtime' else 'secrets/')+kind+'-dsn'))} for kind in ['runtime', 'migration']},
        'policy': {'identity_mode': 'fingerprint', 'class_signing_key': {'file': str(ROOT/'app/class-key')},
                   'rules': [{'group_id': 'fixture:byod', 'location_id': 'nyc', 'vlan': 200}]},
        'network': {'providers': [{'id': 'fixture', 'kind': 'meraki', 'base_url': 'https://api.invalid', 'credential': {'file': '/task6/unused'}, 'scopes': ['site']}],
                    'locations': [{'id': 'nyc', 'provider_id': 'fixture', 'site_id': 'site', 'vlan_enabled': True}]},
        'radius_clients': [{'id': 'office', 'location_id': 'nyc', 'cidrs': [IP+'/32'], 'secret': {'file': str(ROOT/'secrets/radius-secret')}, 'medium': 'wifi', 'signaling_profile': 'meraki-numeric'}],
        'ca': {'root_files': [str(CERT/'ca.pem')], 'server_cert_file': str(CERT/'server.pem'), 'server_key_file': {'file': str(CERT/'server.key')}},
        'paths': {'auth_log_dir': str(AUTH), 'accounting_spool_dir': str(SPOOL)}}
    config['database'].update(native_writer_dsn={'file': str(ROOT/'secrets/native-dsn')}, ca_file=str(CERT/'ca.pem'), connect_timeout='1s', query_timeout='1s')
    write(CFG, json.dumps(config), 0o644)
    write('/etc/sudoers.d/cloud-8021x', run('/task6-native-fixture', 'sudoers-render', str(CFG)).stdout, 0o440)
    run('visudo', '-cf', '/etc/sudoers.d/cloud-8021x')
    for sub,owner in [('app','cloud8021x'),('secrets','root')]:
        (ROOT/sub).chmod(0o700)
        shutil.chown(ROOT/sub,user=owner)
    inventory()
    # Reset only this reserved disposable fixture's enabled native configuration.
    for directory in [RADDB/'mods-enabled', RADDB/'sites-enabled']:
        for item in directory.iterdir():
            item.unlink()
    run('/task6-native-fixture', 'render', str(CFG))
    print('PASS prepared actual Go-rendered native configuration', flush=True)

def inventory(enrolled=True, age=0, duplicate=False):
    now=time.time()
    fp=hashlib.sha256(ssl.PEM_cert_to_DER_cert((CERT/'personal.pem').read_text())).hexdigest()
    data={'version':2,'updated_at':now-age,'identities':{'STAFFSERIAL':{'device_id':'fixture:1','groups':['fixture:byod'],'enrolled':enrolled}},
          'hardware_serials':{},'devices':{'fixture:1':{'serial':'','device_owner':'owner@example.invalid','device_name':'Fixture','device_model':'Fixture'}},
          'certificates':{fp:None if duplicate else {'device_id':'fixture:1','groups':['fixture:byod'],'enrolled':enrolled,'observed_at':now}}}
    write('/var/lib/cloud-8021x/inventory.json', json.dumps(data), 0o600, 'cloud8021x')
    time.sleep(.15)

def negative_certificates():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import ExtendedKeyUsageOID
    import datetime
    ca=x509.load_pem_x509_certificate((CERT/'ca.pem').read_bytes())
    issuer=serialization.load_pem_private_key((CERT/'ca.key').read_bytes(),password=None)
    leaf=x509.load_pem_x509_certificate((CERT/'personal.pem').read_bytes())
    now=datetime.datetime.now(datetime.timezone.utc)
    expired=x509.CertificateBuilder().subject_name(leaf.subject).issuer_name(ca.subject).public_key(leaf.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=2)).not_valid_after(now-datetime.timedelta(days=1)).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False).sign(issuer,hashes.SHA256())
    (CERT/'expired.pem').write_bytes(expired.public_bytes(serialization.Encoding.PEM));shutil.copy(CERT/'personal.key',CERT/'expired.key')
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(CERT/'wrong-chain.key'),'-out',str(CERT/'wrong-chain.pem'),'-days','1','-subj','/CN=untrusted')

def attested_test():
    original=CFG.read_text();original_ca=(CERT/'ca.pem').read_text()
    run('openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',str(CERT/'attested-ca.key'))
    run('openssl','req','-x509','-new','-key',str(CERT/'attested-ca.key'),'-out',str(CERT/'attested-ca.pem'),'-days','1','-subj','/CN=AttestedFixtureCA')
    for name,kind in [('attested','06'),('attested-wrong','08')]:
        shutil.copy(CERT/'legacy.key',CERT/(name+'.key'))
        run('openssl','req','-new','-key',str(CERT/(name+'.key')),'-out',str(CERT/(name+'.csr')),'-subj','/CN=STAFFSERIAL')
        write(CERT/'attested.ext',f'extendedKeyUsage=clientAuth\n1.3.6.1.4.1.37476.9000.64.1=DER:30:10:02:01:{kind}:04:09:77:69:66:69:2d:61:63:6d:65:04:00\nsubjectAltName=otherName:1.3.6.1.5.5.7.8.3;SEQUENCE:permanent\n[permanent]\nidentifier=UTF8:STAFFSERIAL\n')
        run('openssl','x509','-req','-in',str(CERT/(name+'.csr')),'-CA',str(CERT/'attested-ca.pem'),'-CAkey',str(CERT/'attested-ca.key'),'-CAcreateserial','-out',str(CERT/(name+'.pem')),'-days','1','-extfile',str(CERT/'attested.ext'))
    write(CERT/'ca.pem',original_ca+(CERT/'attested-ca.pem').read_text())
    cfg=json.loads(original);cfg['policy']['attested_acme']={'enabled':True,'issuer_file':str(CERT/'attested-ca.pem'),'provisioner':'wifi-acme'}
    cfg['inventory']={'enabled':True,'provider':'fleet','fleet':{'base_url':'https://fixture.example.invalid','observer_token':{'file':'/task6/secrets/unused-observer'},'maintainer_token':{'file':'/task6/secrets/unused-maintainer'},'managed_certificates':True,'client_ca_file':str(CERT/'ca.pem')}}
    write(CFG,json.dumps(cfg))
    inventory();path=Path('/var/lib/cloud-8021x/inventory.json');data=json.loads(path.read_text());data['hardware_serials']['STAFFSERIAL']=data['identities']['STAFFSERIAL'];write(path,json.dumps(data),0o600,'cloud8021x')
    app=radius=None
    try:
        run('/task6-native-fixture','render',str(CFG));log=open(ROOT/'attested-policy.log','w');app=subprocess.Popen(['runuser','-u','cloud8021x','--','/task6-native-fixture','serve',str(CFG)],stdout=log,stderr=subprocess.STDOUT);time.sleep(.4)
        radius=start_radius()
        accepted=authenticate('attested-ACME',certificate='attested')
        assert_certificate_observation(accepted,'attested','ec')
        authenticate('attested-wrong-provisioner-type',certificate='attested-wrong',expected=None)
    finally:
        if radius and radius.poll() is None:radius.terminate();radius.wait(timeout=3)
        if app and app.poll() is None:app.terminate();app.wait(timeout=3)
        write(CFG,original);write(CERT/'ca.pem',original_ca);run('/task6-native-fixture','render',str(CFG));inventory()

def attributes(packet):
    out={};pos=20
    while pos<len(packet):
        kind,size=packet[pos:pos+2]
        assert size>=2 and pos+size<=len(packet)
        out.setdefault(kind,[]).append(packet[pos+2:pos+size]);pos+=size
    return out

def overloaded_policy():
    # Occupy the actual bounded Go HTTP handler with authenticated incomplete
    # bodies; no fake policy engine and no external API is involved.
    stop=threading.Event()
    def occupy(delay):
        time.sleep(delay)
        while not stop.is_set():
            with socket.create_connection(('127.0.0.1',18121),timeout=1) as connection:
                token=(ROOT/'app/bearer').read_text()
                connection.sendall(f'POST /authorize HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{'.encode())
                time.sleep(.3)
    workers=[threading.Thread(target=occupy,args=(i*.02,)) for i in range(8)]
    for worker in workers:worker.start()
    time.sleep(.2)
    try:authenticate('policy-overload',expected=None)
    finally:
        stop.set()
        for worker in workers:worker.join()
    time.sleep(.6)

def permissions_test():
    run('groupadd','-f','cloud8021x-spool-metadata')
    run('usermod','-G','cloud8021x-events,cloud8021x-spool-metadata','cloud8021x')
    run('usermod','-G','cloud8021x-events','freerad')
    shutil.chown(SPOOL,user='freerad',group='cloud8021x-spool-metadata');SPOOL.chmod(0o2750)
    for path in [CERT/'server.key',ROOT/'secrets/native-dsn',ROOT/'secrets/radius-secret',RADDB/'mods-enabled/sql',RADDB/'mods-enabled/rest']:
        assert subprocess.run(['runuser','-u','cloud8021x','--','test','-r',str(path)]).returncode!=0,('app can read backend secret',path)
    auth=next(AUTH.glob('*.detail'))
    run('runuser','-u','cloud8021x','--','test','-r',str(auth))
    assert subprocess.run(['runuser','-u','cloud8021x','--','test','-w',str(auth)]).returncode!=0
    marker=SPOOL/'detail-permission-check';write(marker,'synthetic',0o600,'freerad')
    try:
        run('runuser','-u','cloud8021x','--','stat',str(marker))
        assert subprocess.run(['runuser','-u','cloud8021x','--','test','-r',str(marker)]).returncode!=0
        assert subprocess.run(['runuser','-u','cloud8021x','--','test','-w',str(marker)]).returncode!=0
    finally:marker.unlink()
    assert subprocess.run(['runuser','-u','freerad','--','test','-x','/run/radius-certificate-bindings']).returncode!=0
    result=subprocess.run(['runuser','-u','freerad','--','sudo','-n','/usr/local/bin/cloud-8021x','--config',str(CFG),'radius','verify-leaf','/run/radius-verified-leaves/../forged','a'*32],capture_output=True,text=True)
    assert result.returncode!=0,'fixed helper accepted traversal'
    print('PASS dedicated app/event/spool metadata permissions and fixed helper traversal rejection',flush=True)

def sql_tls_test():
    original=CFG.read_text();dsn=ROOT/'secrets/native-dsn';original_dsn=dsn.read_text()
    negative_certificates()
    try:
        for kind in ['hostname','chain']:
            cfg=json.loads(original)
            write(dsn,original_dsn.replace('host=localhost','host=127.0.0.1') if kind=='hostname' else original_dsn,0o600)
            if kind=='chain':cfg['database']['ca_file']=str(CERT/'wrong-chain.pem')
            write(CFG,json.dumps(cfg));run('/task6-native-fixture','render',str(CFG))
            radius=start_radius()
            try:
                accounting('tls-'+kind);time.sleep(6)
                text=(ROOT/'radius-debug.log').read_text()
                assert ('does not match host name' in text if kind=='hostname' else 'certificate verify failed' in text),('TLS failure not observed',kind,text[-2500:])
                assert list(SPOOL.glob('*')),'unverified TLS advanced native replay'
            finally:radius.terminate();radius.wait(timeout=3)
            print('PASS native PostgreSQL rejects wrong '+kind+' and retains replay',flush=True)
    finally:write(CFG,original);write(dsn,original_dsn,0o600);run('/task6-native-fixture','render',str(CFG))

def authenticate(name, expected=200, certificate='personal', ports=(19,), remove_port=False, after_accept=None, legacy=False, check_context=False):
    received_min=int(time.time())
    offsets={p:p.stat().st_size for p in AUTH.glob('*.detail')}
    expected=list(expected) if isinstance(expected,tuple) else [expected]
    conf=f'network={{\n ssid="fixture"\n key_mgmt=WPA-EAP\n eap=TLS\n identity="spoofed"\n ca_cert="{CERT}/ca.pem"\n client_cert="{CERT}/{certificate}.pem"\n private_key="{CERT}/{certificate}.key"\n domain_suffix_match="localhost"\n eapol_flags=0\n}}\n'
    write(ROOT/'eap.conf',conf)
    stop=threading.Event();replies=[];errors=[];station=None
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as relay:
        relay.bind((IP,18120));relay.settimeout(.1)
        def forward():
            nonlocal station
            client=None
            try:
                while not stop.is_set():
                    try: packet,address=relay.recvfrom(65535)
                    except socket.timeout: continue
                    if address[1]==1812:
                        if packet[0] in (2,3):replies.append(packet)
                        if packet[0]==2 and after_accept:after_accept()
                        relay.sendto(packet,client)
                    else:
                        client=address
                        if remove_port:
                            fields=attributes(packet)
                            fields.pop(61,None)
                            fields[80]=[b'\0'*16]
                            raw=b''.join(bytes([k,len(v)+2])+v for k,values in fields.items() for v in values)
                            header=packet[:2]+struct.pack('!H',20+len(raw))+packet[4:20]
                            signature=hmac.new(SECRET,header+raw,hashlib.md5).digest()
                            fields[80]=[signature]
                            packet=header+b''.join(bytes([k,len(v)+2])+v for k,values in fields.items() for v in values)
                        station=attributes(packet).get(31,[b''])[0]
                        relay.sendto(packet,(IP,1812))
            except Exception as exc: errors.append(exc)
        worker=threading.Thread(target=forward);worker.start()
        try:
            result=subprocess.run(['eapol_test','-c',str(ROOT/'eap.conf'),'-a',IP,'-p','18120','-s',SECRET.decode(),'-r',str(len(expected)-1),'-t','8',
                                   *[arg for value in ports for arg in ['-N',f'61:d:{value}']]],capture_output=True,text=True,timeout=15)
        finally: stop.set();worker.join()
    write(ROOT/('eap-'+name+'.log'),result.stdout+result.stderr)
    assert not errors,errors
    assert len(replies)==len(expected),(name,[p[0] for p in replies],result.stdout[-1800:])
    for packet,want in zip(replies,expected):
        attrs=attributes(packet)
        if want is None:
            assert packet[0]==3 and 26 not in attrs,(name,packet[0],attrs)
            assert all(v[0]!=3 for v in attrs.get(79,[])), 'Reject included EAP Success'
        else:
            assert packet[0]==2,(name,packet[0],result.stdout[-1200:])
            if want==0:assert not any(k in attrs for k in [64,65,81]),(name,attrs)
            else:assert [struct.unpack('!I',attrs[k][0])[0] for k in [64,65]]==[13,6] and attrs[81]==[str(want).encode()],(name,attrs)
            if not legacy:assert len(attrs.get(25,[]))==1 and attrs[25][0].startswith(b'c8021x.1.'),attrs
    if len(expected)>1:
        assert ('resumed=1' in result.stdout)==legacy,(name,'resumption contract',result.stdout[-2000:])
    new_context=''
    for path in AUTH.glob('*.detail'):
        text=path.read_bytes()[offsets.get(path,0):].decode()
        new_context+=text
        for forbidden in ['TLS-Client-Cert-', 'TLS-Session-', 'EAP-MSK', 'EAP-EMSK', 'EAP-Session-Id', 'MS-MPPE-Send-Key', 'MS-MPPE-Recv-Key', 'User-Password', 'CHAP-Password', 'Tunnel-Password', 'EAP-Message', 'C8021X-Handoff', 'REST-HTTP-Header']:
            assert forbidden not in text,('new final auth log exposed suppressed field',name,forbidden)
    if check_context:
        outcome='Access-Reject' if expected[0] is None else 'Access-Accept'
        for field,value in [('Packet-Type',outcome),('C8021X-Client','"office"'),('C8021X-Location','"nyc"'),
                            ('C8021X-Source',json.dumps(IP)),('C8021X-Port-Count',str(len(ports))),('C8021X-Station-Count','1')]:
            assert f'\t{field} = {value}\n' in new_context,('missing shared final context',name,field)
        receipts=re.findall(r'\tC8021X-Receipt = (\d+)\n',new_context)
        assert len(receipts)==1 and received_min<=int(receipts[0])<=int(time.time()),('invalid shared receipt',name)
        # Keep the exact occurrence count independent of native list expansion.
        assert 0<new_context.count('\tC8021X-Port-Type = ')<=len(ports),('lost final port context',name)
    print('PASS EAP',name,flush=True)
    return {'classes':attrs.get(25,[]),'station':station,'auth_context':new_context}

def auth_outbox():
    return postgres_json("SELECT coalesce(json_agg(json_build_object('id',id,'payload',payload) ORDER BY id),'[]') FROM ledger.work WHERE kind='outbox' AND id LIKE 'auth:%';")

def ingest_auth():
    return json.loads(run('runuser','-u','cloud8021x','--','/task6-native-fixture','ingest',str(CFG)).stdout)

def observed_expiry():
    return json.loads(run('runuser','-u','cloud8021x','--','/task6-native-fixture','observe-expiry',str(CFG)).stdout)

def assert_certificate_observation(accepted,certificate,ca):
    """Native EAP fields must survive the real reader and runtime-role ledger."""
    context=accepted['auth_context']
    end=run('openssl','x509','-in',str(CERT/(certificate+'.pem')),'-noout','-enddate').stdout.strip().split('=',1)[1]
    expires=int(ssl.cert_time_to_seconds(end))
    native_expiry=time.strftime('%y%m%d%H%M%SZ',time.gmtime(expires))
    assert re.findall(r'^\tC8021X-Cert-Expiration = "([^"]*)"$',context,re.M)==[native_expiry],('native expiry propagation',certificate,context)
    issuer=re.findall(r'^\tC8021X-Cert-Issuer = "([^"]*)"$',context,re.M)
    trusted=json.loads(run('/task6-native-fixture','issuers',str(CFG)).stdout)
    assert len(issuer)==1 and trusted.get(issuer[0])==ca,('actual public issuer classification',certificate,issuer,trusted)
    fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert((CERT/(certificate+'.pem')).read_text())).hexdigest()
    before={row['id'] for row in auth_outbox()}
    assert ingest_auth()>0,'native final-auth stream did not ingest'
    rows=auth_outbox()
    matching=[row['payload'] for row in rows if row['id'] not in before and row['payload']['event']=='Access-Accept' and row['payload']['certificate_fingerprint']==fingerprint]
    assert len(matching)==1,('accepted fingerprint observation missing or duplicated',certificate,matching)
    payload=matching[0]
    assert payload['device_id']=='fixture:1' and payload['vlan_id']=='200',('expiry changed verified attribution',payload)
    assert payload['certificate_observation']=={'expires_at':expires,'ca_instance':ca},('persisted native expiry differs',payload)
    for row in rows:
        serialized=json.dumps(row['payload'])
        assert all(value not in serialized for value in ['TLS-Client-Cert-','TLS-Session-',issuer[0],native_expiry,'C8021X-Cert-','c8021x.1.']),('raw native metadata leaked into auth outbox',row['id'])
    observation=observed_expiry()
    assert observation=={'available':True,'count':1},('actual persisted seen-client expiry',observation)
    print('PASS native dedicated expiry/issuer fields, verified '+certificate+' fingerprint, sanitized persisted observation and runtime-role expiry count',flush=True)

def missing_expiry_test():
    """A retained native accepted record lacking R97 fields remains unavailable."""
    app=radius=None
    try:
        inventory()
        stream=open(ROOT/'expiry-missing-policy.log','w')
        app=subprocess.Popen(['runuser','-u','cloud8021x','--','/task6-native-fixture','serve',str(CFG)],stdout=stream,stderr=subprocess.STDOUT)
        time.sleep(.4);radius=start_radius()
        accepted=authenticate('expiry-missing-control')
        assert_certificate_observation(accepted,'personal','wifi')
        # Retain the genuine accepted record and verified Class; remove only the
        # new optional monitoring fields to model an old final-auth stream.
        context=re.sub(r'^\tC8021X-Cert-(?:Expiration|Issuer) = .*\n','',accepted['auth_context'],flags=re.M)
        assert context and 'C8021X-Cert-' not in context
        before={row['id'] for row in auth_outbox()}
        path=AUTH/('auth-'+os.urandom(16).hex()+'-'+str(int(time.time()))+'.detail')
        write(path,context,0o640,'freerad');shutil.chown(path,group='cloud8021x-events')
        assert ingest_auth()==1,'retained missing-field record not ingested exactly once'
        new=[row['payload'] for row in auth_outbox() if row['id'] not in before]
        assert len(new)==1 and new[0]['event']=='Access-Accept' and new[0]['device_id']=='fixture:1' and new[0]['certificate_fingerprint'],new
        assert 'certificate_observation' not in new[0],'missing native fields invented expiry'
        assert observed_expiry()=={'available':False},'missing coverage invented zero'
        print('PASS genuine retained accepted record without expiry preserves attribution and marks monitoring unavailable',flush=True)
    finally:
        if radius and radius.poll() is None:radius.terminate();radius.wait(timeout=3)
        if app and app.poll() is None:app.terminate();app.wait(timeout=3)

def accounting(name, binding=None, status=1, extra=(), expect_ack=True, omit=()):
    received_min=int(time.time())
    binding=binding or {'classes':[],'station':b'aa-bb-cc-dd-ee-ff'}
    attrs=[(40,struct.pack('!I',status)),(44,name.encode()),(4,socket.inet_aton('192.0.2.1')),(31,binding['station']),
           (46,struct.pack('!I',60)),(42,struct.pack('!I',4294967295)),(43,struct.pack('!I',4294967295)),
           (52,struct.pack('!I',4294967295)),(53,struct.pack('!I',4294967295)),*[(25,v) for v in binding['classes']],*extra]
    raw=b''.join(bytes([kind,len(value)+2])+value for kind,value in attrs if kind not in omit)
    head=struct.pack('!BBH',4,int(time.time()*1000)%256,20+len(raw))
    packet=head+hashlib.md5(head+b'\0'*16+raw+SECRET).digest()+raw
    with socket.socket(socket.AF_INET6 if ':' in IP else socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.bind((IP,0));client.settimeout(1)
        client.sendto(packet,(IP,1813))
        try: reply=client.recv(65535)
        except socket.timeout:reply=None
    assert bool(reply)==expect_ack,(name,'ACK',bool(reply))
    if reply: assert reply[0]==5
    print('PASS accounting',name,'ACK' if reply else 'suppressed',flush=True)
    return {'session_id':name,'status':None if 40 in omit else {1:'Start',2:'Stop',3:'Interim-Update'}.get(status,str(status)),
            'request_authenticator':'0x'+packet[4:20].hex(),'packet_id':str(packet[1]),
            'source_ip':IP,'client_id':'office','location_id':'nyc','received_min':received_min,'received_max':int(time.time())}

def start_radius():
    result=subprocess.run(['freeradius','-XC'],capture_output=True,text=True)
    write(ROOT/'config-check.log',result.stdout+result.stderr)
    assert result.returncode==0,result.stdout[-6000:]+result.stderr
    stream=open(ROOT/'radius-debug.log','w')
    environment={k:v for k,v in os.environ.items() if k!='HOME' and not k.startswith('PG')}
    server=subprocess.Popen(['freeradius','-X'],stdout=stream,stderr=subprocess.STDOUT,env=environment)
    for _ in range(100):
        text=(ROOT/'radius-debug.log').read_text()
        if 'Ready to process requests' in text:return server
        if server.poll() is not None:raise AssertionError(text[-6000:])
        time.sleep(.05)
    raise AssertionError('native server did not start')

def termination_test():
    """Actual native detail/replay SQL, ledger normalization and business projection."""
    suffix='-'+os.urandom(8).hex()
    cases=[('known',[(49,struct.pack('!I',1))],'User-Request',1,'User-Request'),
           ('legacy',[],None,0,'N/A'),
           ('duplicate',[(49,struct.pack('!I',1)),(49,struct.pack('!I',2))],'User-Request',2,'N/A'),
           ('unknown',[(49,struct.pack('!I',9999))],'9999',1,'N/A'),
           ('dot1x',[(49,struct.pack('!I',20))],'Reauthentication-Failure',1,'Reauthentication-Failure')]
    radius=start_radius()
    try:
        packets=[accounting('terminate-'+name+suffix,status=2,extra=extra) for name,extra,_,_,_ in cases]
        assert_packets_delivered(packets)
        run('runuser','-u','cloud8021x','--','/task6-native-fixture','process',str(CFG))
        proof=[]
        for name,_,raw,count,want in cases:
            rows=postgres_json("""SELECT json_agg(row_to_json(r)) FROM (
              SELECT i.terminate_cause,i.terminate_cause_count,o.event,w.payload
              FROM ledger.intake i JOIN ledger.observations o ON i.observation_id=o.event_id
              JOIN ledger.work w ON w.id='accounting:'||o.event_id
              WHERE i.session_id=(:'session'::jsonb #>> '{}')) r;""",session='terminate-'+name+suffix)
            assert len(rows)==1,rows
            row=rows[0]
            assert row['terminate_cause']==raw and row['terminate_cause_count']==count,row
            assert row['event']['terminate_cause']==want and row['payload']==row['event'],row
            projected=json.loads(run('/task6-native-fixture','project',str(CFG),input=json.dumps(row['payload'])).stdout)
            assert projected['Fields']['terminate_cause']==want,projected
            assert projected['Fields']['event']=='Acct-Stop' and projected['Fields']['input_bytes']==18446744073709551615,projected
            proof.append({'case':name,'raw':raw,'count':count,'projection':want,'event_id':row['event']['event_id']})
        write(ROOT/'termination-proof.json',json.dumps(proof,indent=2)+'\n')
        print('PASS native Stop detail/replay SQL -> PostgreSQL -> immutable neutral event -> business terminate_cause (known/absent/duplicate/unknown/802.1X)',flush=True)
    finally:
        radius.terminate();radius.wait(timeout=3)

def main():
    if sys.argv[1]=='termination':termination_test();return
    if sys.argv[1]=='ipv6':
        global IP
        original=CFG.read_text();old_ip=IP;cfg=json.loads(original)
        cfg['radius_clients'][0]['cidrs'].append('::1/128')
        try:
            write(CFG,json.dumps(cfg));run('/task6-native-fixture','render',str(CFG));radius=start_radius()
            try:
                IP='::1';accounting('ipv6-transport',extra=[(95,socket.inet_pton(socket.AF_INET6,'2001:db8::9'))],omit=(4,));time.sleep(6)
            finally:radius.terminate();radius.wait(timeout=3)
        finally:IP=old_ip;write(CFG,original);run('/task6-native-fixture','render',str(CFG))
        return
    if sys.argv[1]=='sqltls':sql_tls_test();return
    if sys.argv[1]=='permissions':permissions_test();return
    if sys.argv[1]=='prepare':prepare();return
    if sys.argv[1]=='attested':attested_test();return
    if sys.argv[1]=='expiry-missing':missing_expiry_test();return
    if sys.argv[1] in ['replay','replay-duplicate']:
        replay_test(duplicate=sys.argv[1]=='replay-duplicate');return
    if sys.argv[1]=='legacy':
        original=CFG.read_text();cfg=json.loads(original);cfg['policy']['identity_mode']='legacy-serial';cfg['paths']['downgrade_guard_file']='/var/lib/cloud-8021x/fixture-legacy-guard'
        write(CFG,json.dumps(cfg));run('/task6-native-fixture','render',str(CFG))
        cache=ROOT/'tls-cache';cache.mkdir(exist_ok=True);cache.chmod(0o700);shutil.chown(cache,user='freerad')
        path=RADDB/'mods-enabled/eap';path.write_text(path.read_text().replace('name = "cloud8021x"',f'name = "cloud8021x"\n persist_dir = {cache}'))
        app_log=open(ROOT/'legacy-policy.log','w');app=subprocess.Popen(['runuser','-u','cloud8021x','--','/task6-native-fixture','serve',str(CFG)],stdout=app_log,stderr=subprocess.STDOUT);time.sleep(.4)
        radius=start_radius()
        try:
            before={row['id'] for row in auth_outbox()}
            inventory();authenticate('legacy-current-policy',expected=(200,None),certificate='legacy',after_accept=lambda:inventory(enrolled=False),legacy=True)
            assert ingest_auth()>0,'legacy final-auth stream did not ingest'
            legacy_rows=[row['payload'] for row in auth_outbox() if row['id'] not in before and row['payload']['event']=='Access-Accept']
            assert len(legacy_rows)==1 and not legacy_rows[0]['device_id'] and not legacy_rows[0]['certificate_fingerprint'] and 'certificate_observation' not in legacy_rows[0],('legacy invented verified certificate observation',legacy_rows)
            assert observed_expiry()=={'available':False},'legacy unbound coverage invented expiry count'
            print('PASS legacy native auth retains missing/unavailable expiry coverage',flush=True)
        finally:
            radius.terminate();radius.wait(timeout=3);app.terminate();app.wait(timeout=3);write(CFG,original);run('/task6-native-fixture','render',str(CFG));inventory()
        return
    full=sys.argv[1]=='full'
    zero=sys.argv[1]=='zero'
    originals={}
    if full:
        for name in ['accounting_detail','auth_detail']:
            path=RADDB/'mods-enabled'/name
            originals[path]=path.read_text()
            path.write_text(re.sub(r'filename = .*','filename = /dev/full',originals[path]))
    if zero:
        path=RADDB/'mods-enabled/sql';originals[path]=path.read_text()
        query="INSERT INTO ledger.intake(received_at,source_ip,client_id,location_id,host,replay_id) SELECT now(),'192.0.2.1','office','nyc','fixture','zero' WHERE false"
        path.write_text(re.sub(r'query = ".*"','query = "'+query+'"',originals[path]))
    app_log=open(ROOT/'policy.log','w')
    app=subprocess.Popen(['runuser','-u','cloud8021x','--','/task6-native-fixture','serve',str(CFG)],stdout=app_log,stderr=subprocess.STDOUT)
    time.sleep(.4)
    assert app.poll() is None,(ROOT/'policy.log').read_text()
    if sys.argv[1]=='sources':
        path=RADDB/'clients.conf';original=path.read_text()
        identity=re.search(r'client:c8021x_config}" != "([a-f0-9]+)"',(RADDB/'sites-enabled/default').read_text()).group(1)
        proof=Path('/var/lib/cloud-8021x-source-proof');proof.mkdir(exist_ok=True);proof.chmod(0o755)
        client=hashlib.sha256(b'office').hexdigest()
        def publish(observed, generation=None, config=identity, source=IP):
            generation=generation or hashlib.sha256(os.urandom(32)).hexdigest()
            marker=proof/generation/config/client/source;marker.parent.mkdir(parents=True)
            marker.touch();marker.chmod(0o444);os.utime(marker,(observed,observed))
            for directory in [marker.parent,marker.parent.parent,marker.parent.parent.parent]:directory.chmod(0o555)
            write(proof/'next',generation);os.replace(proof/'next',proof/'current')
            return marker
        text=original.replace('c8021x_source_kind = static',f'c8021x_source_kind = dynamic\n c8021x_max_age = 2\n c8021x_config = {identity}\n c8021x_client_hash = {client}')
        path.write_text(text)
        marker=publish(int(time.time()))
        radius=start_radius()
        start=Path(f'/proc/{radius.pid}/stat').read_text().split()[21]
        def unchanged():
            assert radius.poll() is None and Path(f'/proc/{radius.pid}/stat').read_text().split()[21]==start,'proof refresh restarted native service'
        def denied(name):
            accounting('source-'+name,expect_ack=False);unchanged()
        try:
            accounting('source-fresh');unchanged()
            time.sleep(2);denied('expired')
            marker=publish(int(time.time()));accounting('source-root-refresh');unchanged()
            publish(int(time.time())+60);denied('future')
            publish(int(time.time()),config='0'*64);denied('wrong-config')
            publish(int(time.time()),source='8.8.8.8');denied('wrong-source')
            marker=publish(int(time.time()));marker.chmod(0o666);denied('writable-marker')
            marker=publish(int(time.time()));marker.chmod(0o644);marker.write_text('forged');denied('nonempty-marker')
            marker=publish(int(time.time()));marker.parent.chmod(0o755);os.link(marker,marker.parent/'hardlink');denied('hardlinked-marker')
            marker=publish(int(time.time()));marker.parent.chmod(0o755);marker.unlink();marker.symlink_to('/dev/null');denied('symlink-marker')
            marker=publish(int(time.time()));shutil.chown(marker,user='freerad');denied('forged-owner')
            marker=publish(int(time.time()));marker.parent.chmod(0o777);denied('writable-directory')
            marker=publish(int(time.time()));marker.parent.chmod(0o755);marker.unlink();denied('missing-marker')
            write(proof/'current','../'+'0'*61);denied('malformed-pointer')
            write(proof/'current','0'*64+'\n');denied('oversized-pointer')
            (proof/'current').unlink();(proof/'current').symlink_to('/dev/null');denied('symlink-pointer')
            (proof/'current').unlink();denied('missing-pointer')
            # Auth also fails closed before EAP success; longer age avoids the test handshake crossing a second boundary.
            radius.terminate();radius.wait(timeout=3)
            path.write_text(text.replace('c8021x_max_age = 2','c8021x_max_age = 60'))
            publish(int(time.time()));radius=start_radius();authenticate('source-fresh')
            publish(int(time.time())-61);authenticate('source-expired',expected=None)
            radius.terminate();radius.wait(timeout=3)
            path.write_text(original);radius=start_radius();authenticate('source-static-independent');accounting('source-static-independent')
        finally:
            if radius.poll() is None:radius.terminate();radius.wait(timeout=3)
            path.write_text(original);app.terminate();app.wait(timeout=3)
        print('PASS native protected proof fresh/expired/root-refresh with unchanged PID/start time, unsafe proofs, EAP guard, static fallback',flush=True)
        return
    radius=start_radius()
    try:
        if sys.argv[1]=='ports':
            authenticate('65-duplicate-ports',expected=0,ports=(19,)*65,check_context=True)
            # Leave room within the 200-attribute packet bound for fragmented EAP.
            authenticate('128-duplicate-ports',expected=0,ports=(19,)*128,check_context=True)
            authenticate('shared-reject-context',expected=None,certificate='unknown',check_context=True)
            return
        if zero:
            accounting('zero-affected-rows')
            time.sleep(6)
            assert list(SPOOL.glob('*')), 'zero-row SQL advanced replay'
            print('PASS zero affected SQL rows retain pending replay',flush=True)
            return
        if full:
            authenticate('observational-log-failure')
            accounting('disk-full',expect_ack=False)
            print('PASS patched /dev/full accounting ACK suppression; auth remains observational',flush=True)
            return
        if sys.argv[1]=='outage':
            binding=authenticate('database-outage')
            session='outage-'+os.urandom(8).hex()
            for status in [1,3,2]:accounting(session,binding,status=status)
            time.sleep(6)
            retain_replay_expectations(session)
            print('PASS database outage retains native replay files after NAS ACK',flush=True)
            return
        byod=authenticate('wireless')
        assert_certificate_observation(byod,'personal','wifi')
        negative_certificates()
        authenticate('wrong-chain',expected=None,certificate='wrong-chain')
        authenticate('expired-leaf',expected=None,certificate='expired')
        authenticate('wired',expected=0,ports=(15,))
        authenticate('duplicate-port',expected=0,ports=(19,15))
        authenticate('missing-port',expected=0,remove_port=True)
        authenticate('unknown-port',expected=0,ports=(999,))
        authenticate('unknown-certificate',expected=None,certificate='unknown')
        inventory(duplicate=True);authenticate('ambiguous-fingerprint',expected=None);inventory()
        inventory(age=3601);authenticate('expired-inventory',expected=None);inventory()
        authenticate('fingerprint-full-reauth-current-policy',expected=(200,None),after_accept=lambda:inventory(enrolled=False));inventory()
        inventory(enrolled=False);authenticate('unenrolled',expected=None);inventory()
        overloaded_policy()
        suffix='-'+os.urandom(8).hex()
        packets=[accounting('normal-session'+suffix,byod,status=status) for status in [1,3,2]]
        packets.append(accounting("quote'\\雪"+suffix,byod,extra=[(44,b'duplicate-session'),(25,b'forged')]))
        packets.append(accounting('unknown-status'+suffix,status=77))
        packets.append(accounting('missing-status'+suffix,omit=(40,)))
        packets.append(accounting('missing-counters'+suffix,status=3,omit=(42,43,46)))
        packets.append(accounting('duplicate-counter'+suffix,status=3,extra=[(42,struct.pack('!I',1))]))
        packets.append(accounting('ipv6-nas'+suffix,extra=[(95,socket.inet_pton(socket.AF_INET6,'2001:db8::9'))],omit=(4,)))
        app.terminate();app.wait(timeout=3)
        authenticate('policy-outage',expected=None)
        packets.append(accounting('policy-outage-accounting'+suffix))
        assert_packets_delivered(packets)
        for path in AUTH.glob('*.detail'):
            text=path.read_text()
            for forbidden in ['EAP-MSK', 'EAP-EMSK', 'EAP-Session-Id', 'MS-MPPE-Send-Key', 'MS-MPPE-Recv-Key', 'User-Password', 'CHAP-Password', 'Tunnel-Password', 'EAP-Message', 'C8021X-Handoff', 'REST-HTTP-Header']:
                assert forbidden not in text,('secret on disk',forbidden)
        print('PASS policy outage remains independent from native accounting',flush=True)
    finally:
        radius.terminate();radius.wait(timeout=3)
        if app.poll() is None:app.terminate();app.wait(timeout=3)
        for path,text in originals.items():path.write_text(text)

if __name__=='__main__':main()
