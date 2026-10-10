#!/usr/bin/env python3
"""One root-approved network-none guest, actual unchanged shipped step-ca SDK."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import socket
import time

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tests'))
from native_package_inputs import verify_bundle

OUT=Path('/private/tmp/cloud8021x-task11-kms-interop-r108-91a6')
BUNDLE=Path('/private/tmp/cloud8021x-task10-final-bundle-arm64')
BASE='sha256:196dfccbfa1af58025d2d0309c330413995c9592d8cc7f2b33bdb712665741cd'
MANIFEST='32ee7a3f741b557ae12d0e3fb7eb160d28fc485fe0d91402bd610fc7ed886054'
CA_SHA='c00ca165bee90e07a927ced5518150fada754486ba064d5a430f4a1ba7ef1450'
NAME='task11-kms-interop-91a6'
OWNER='task11-kms-interop'
created=False
COMMANDS={
    'cloud-active':['/input/cloud-fixture','--fixture-root','/work/active/cloud','--phase','active'],
    'metadata-active':['/input/cloud-fixture','--fixture-root','/work/active/metadata','--phase','active','--metadata'],
    'cloud-passive':['/input/cloud-fixture','--fixture-root','/work/passive/cloud','--phase','passive'],
    'metadata-passive':['/input/cloud-fixture','--fixture-root','/work/passive/metadata','--phase','passive','--metadata'],
    'step-ca-ec':['/usr/bin/step-ca','/work/ec/ca.json'],
    'step-ca-rsa':['/usr/bin/step-ca','/work/rsa/ca.json'],
    'step-ca-passive':['/usr/bin/step-ca','/work/ec/ca.json'],
}


def command(*args,log=None,timeout=45,check=True):
    p=subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    if len(p.stdout.encode())>8*1024**2:raise RuntimeError('bounded output exceeded')
    if log:(OUT/(log+'.log')).write_text(p.stdout)
    if check and p.returncode:raise RuntimeError(f'{args[0]} exit{p.returncode}: {p.stdout[-4000:]}')
    return p


def docker(*args,**kwargs):return command('docker',*args,**kwargs)
def execute(*args,**kwargs):return docker('exec',NAME,*args,**kwargs)
def read(path):return execute('cat',path).stdout


def background(name,args):
    if COMMANDS.get(name)!=args:raise RuntimeError('unowned process command')
    # PID/start ticks are captured before exec; exec preserves both. Fixed fixture literals only.
    script='echo $$ > /work/'+name+'.pid; cat /proc/$$/stat > /work/'+name+'.start-stat; exec '+' '.join(args)+' > /work/'+name+'.log 2>&1'
    docker('exec','-d',NAME,'sh','-c',script)


def process_stat(content,pid):
    try:
        fields=content.rpartition(')')[2].split()
        if content.split()[0]!=pid or len(fields)<20:raise ValueError('bad stat')
        return fields[0],fields[19]
    except (ValueError,IndexError):raise RuntimeError('invalid owned process stat') from None


def process_state(pid):
    # A fixed shell builtin test distinguishes missing /proc from exec/container failure.
    content=execute('sh','-c','if [ -e "/proc/$1/stat" ]; then cat "/proc/$1/stat"; else printf "retired\\n"; fi','sh',pid).stdout
    return None if content=='retired\n' else process_stat(content,pid)


def listener_released(name):
    host,port=('127.0.0.1',8443) if name.startswith('step-ca-') else (('169.254.169.254',80) if name.startswith('metadata-') else ('10.203.11.10',443))
    target=socket.inet_aton(host)[::-1].hex().upper()+f':{port:04X}'
    lines=read('/proc/net/tcp').splitlines()
    if not lines:raise RuntimeError('listener evidence missing')
    return not any(len(parts)>=4 and parts[1]==target and parts[3]=='0A' for parts in (line.split() for line in lines[1:]))


def stop(name):
    if name not in COMMANDS:raise RuntimeError('unowned process name')
    state=json.loads(docker('inspect',NAME).stdout)[0]
    if state['Config']['Labels'].get('cloud8021x.owner')!=OWNER or not state['State']['Running']:
        raise RuntimeError('stop refuses unowned/inactive fixture')
    proof={'name':name,'retired':False,'listener_released':False}
    try:
        pid=read('/work/'+name+'.pid').strip()
        if not pid.isdigit() or int(pid)<=1:raise RuntimeError('invalid owned process PID')
        _,start_ticks=process_stat(read('/work/'+name+'.start-stat'),pid)
        proof.update(pid=int(pid),start_ticks=start_ticks)
        current=process_state(pid)
        if current is not None:
            if current[1]!=start_ticks:raise RuntimeError('owned PID reused; refuses signal')
            if current[0]!='Z':
                if read('/proc/'+pid+'/cmdline')!='\x00'.join(COMMANDS[name])+'\x00':
                    raise RuntimeError('owned process argv changed; refuses signal')
                probe=execute('kill','-0',pid,check=False)
                proof['external_kill_probe']={'exit':probe.returncode,'output':probe.stdout}
                result=execute('sh','-c','kill -TERM "$1"','sh',pid,check=False)
                proof['builtin_term']={'exit':result.returncode,'output':result.stdout}
                if result.returncode:raise RuntimeError('owned builtin TERM failed')
        deadline=time.monotonic()+5
        while True:
            current=process_state(pid)
            if current is not None and current[1]!=start_ticks:raise RuntimeError('owned PID reused during retirement')
            proof['retired']=current is None or current[0]=='Z'
            proof['listener_released']=listener_released(name)
            if proof['retired'] and proof['listener_released']:return
            if time.monotonic()>=deadline:raise RuntimeError('owned process/listener failed bounded retirement')
            time.sleep(.1)
    finally:
        (OUT/('stop-'+name+'.json')).write_text(json.dumps(proof,indent=2)+'\n')


def main():
    global created
    manifest,archives,checksum=verify_bundle(BUNDLE,'arm64')
    assert checksum==MANIFEST and len(archives)==62
    assert docker('container','inspect',NAME,check=False).returncode!=0,'reserved name exists; refuses reuse'
    sources=[ROOT/'tests/fixtures/cloud/main.go',*sorted((ROOT/'tests/runtime/task11-kms-interop').rglob('*.go')),ROOT/'tests/runtime/task11-kms-interop/run.py']
    inputs={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources+[OUT/'cloud-fixture',OUT/'probe',OUT/'netsetup',OUT/'seed-data/identity.json']}
    (OUT/'inputs-sha256.json').write_text(json.dumps(inputs,indent=2))
    labels=['--label','cloud8021x.owner='+OWNER,'--label','cloud8021x.task=11','--label','cloud8021x.disposable=true','--label','cloud8021x.bundle.sha256='+MANIFEST,'--label','cloud8021x.step-ca.sha256='+CA_SHA]
    docker('create','--name',NAME,'--pull','never','--network','none','--cap-add','NET_ADMIN','--cpus','1','--memory','1024m','--pids-limit','128','--log-opt','max-size=4m','--log-opt','max-file=1',*labels,
        '--add-host','cloudkms.googleapis.com:10.203.11.10','--add-host','unlisted.googleapis.com:10.203.11.10','--add-host','metadata.google.internal:169.254.169.254',
        '-e','GOMAXPROCS=1','-v',str(BUNDLE)+':/bundle:ro','-v',str(OUT)+':/input:ro',BASE,'sleep','infinity')
    created=True;docker('start',NAME)
    state=json.loads(docker('inspect',NAME).stdout)[0]
    assert state['Image']==BASE and state['HostConfig']['NetworkMode']=='none' and not state['HostConfig'].get('PortBindings')
    assert state['HostConfig']['NanoCpus']==1000000000 and state['HostConfig']['Memory']==1024**3 and state['HostConfig']['PidsLimit']==128
    assert [cap.removeprefix('CAP_') for cap in state['HostConfig']['CapAdd']]==['NET_ADMIN']
    assert all(not mount['RW'] and mount['Destination'] in ['/input','/bundle'] for mount in state['Mounts'])
    assert all(not value.startswith(('GCE_METADATA_HOST=','GOOGLE_APPLICATION_CREDENTIALS=','CLOUDSDK_','SSL_CERT_FILE=','HTTPS_PROXY=','HTTP_PROXY=')) for value in state['Config']['Env'])
    proof={'image':state['Image'],'limits':{k:state['HostConfig'][k] for k in ['NanoCpus','Memory','PidsLimit','CapAdd','NetworkMode','PortBindings']},'mounts':state['Mounts'],'labels':state['Config']['Labels']}
    (OUT/'isolation-proof.json').write_text(json.dumps(proof,indent=2))
    execute('dpkg','--install','/bundle/'+archives['step-ca'],log='step-ca-install')
    assert execute('sha256sum','/usr/bin/step-ca').stdout.split()[0]==CA_SHA
    execute('/usr/bin/step-ca','version',log='step-ca-version')
    execute('sh','-c','mkdir -m700 /work; cp -a /input/seed-data/. /work/; printf "synthetic-only-v1\\n" > /etc/cloud8021x-task11-fixture')
    execute('/input/netsetup',log='loopback-addresses')
    interfaces=execute('ls','/sys/class/net').stdout.split();assert interfaces==['lo'],interfaces
    routes=read('/proc/net/route');assert len(routes.strip().splitlines())==1,routes
    (OUT/'routes.txt').write_text(routes)
    status=read('/proc/1/status')
    (OUT/'process-status.txt').write_text(status)
    capabilities=int(next(line.split()[1] for line in status.splitlines() if line.startswith('CapEff:')),16)
    assert capabilities & (1<<12),'actual NET_ADMIN capability bit missing'
    namespace=execute('readlink','/proc/1/ns/net','/proc/self/ns/net').stdout.splitlines()
    assert len(namespace)==2 and namespace[0]==namespace[1]
    (OUT/'network-namespace.txt').write_text('\n'.join(namespace)+'\n')
    (OUT/'mountinfo.txt').write_text(read('/proc/1/mountinfo'))
    execute('sh','-c','cat /work/transport-root.pem >> /etc/ssl/certs/ca-certificates.crt')
    background('cloud-active',['/input/cloud-fixture','--fixture-root','/work/active/cloud','--phase','active'])
    background('metadata-active',['/input/cloud-fixture','--fixture-root','/work/active/metadata','--phase','active','--metadata'])
    time.sleep(.4)
    for kind in ['ec','rsa']:
        background('step-ca-'+kind,['/usr/bin/step-ca','/work/'+kind+'/ca.json'])
        try:
            print(execute('/input/probe','issue','/work',kind,log='issue-'+kind,timeout=40).stdout,end='',flush=True)
        except Exception:
            (OUT/('step-ca-'+kind+'-red.log')).write_text(read('/work/step-ca-'+kind+'.log'))
            raise
        finally:stop('step-ca-'+kind)
    print(execute('/input/probe','denials','/work',log='denials').stdout,end='',flush=True)
    stop('cloud-active');stop('metadata-active')
    background('cloud-passive',['/input/cloud-fixture','--fixture-root','/work/passive/cloud','--phase','passive'])
    background('metadata-passive',['/input/cloud-fixture','--fixture-root','/work/passive/metadata','--phase','passive','--metadata'])
    time.sleep(.4)
    background('step-ca-passive',['/usr/bin/step-ca','/work/ec/ca.json'])
    result=execute('/input/probe','issue','/work','ec',log='passive-issuance-refused',timeout=40,check=False)
    assert result.returncode!=0,'passive KMS authority issued certificate'
    stop('step-ca-passive')
    active=json.loads('[]')
    for path in ['/work/active/cloud/journal.jsonl','/work/passive/cloud/journal.jsonl','/work/active/metadata/journal.jsonl','/work/passive/metadata/journal.jsonl']:
        content=read(path);assert len(content.encode())<32*1024**2
        rows=[json.loads(line) for line in content.splitlines()]
        assert all('body_sha256' in row and len(row['body_sha256'])==64 for row in rows)
        if path.endswith('/active/cloud/journal.jsonl'):active=rows
        if path.endswith('/passive/cloud/journal.jsonl'):
            assert any(row['target'].endswith('/GetPublicKey') and row['status']==0 for row in rows)
            assert any(row['target'].endswith('/AsymmetricSign') and row['status']==7 for row in rows)
            assert not any(row['target'].endswith('/AsymmetricSign') and row['status']==0 for row in rows),'passive signing succeeded'
    assert sum(row['target'].endswith('/GetPublicKey') and row['status']==0 for row in active)>=2
    assert sum(row['target'].endswith('/AsymmetricSign') and row['status']==0 for row in active)>=4
    assert any(row['target'].endswith('/Decrypt') and row['status']==7 for row in active)
    # Continuity compares only hashes of reserved private inputs; never their bytes.
    identities=json.loads((OUT/'seed-data/identity.json').read_text())
    for kind in ['ec','rsa']:
        assert execute('sha256sum','/work/private/'+kind+'.pem').stdout.split()[0]==identities[kind]['private_key_sha256']
        assert execute('sha256sum','/work/'+kind+'/root.pem').stdout.split()[0]==identities[kind]['root_certificate_sha256']
        assert execute('sha256sum','/work/'+kind+'/intermediate.pem').stdout.split()[0]==identities[kind]['intermediate_certificate_sha256']
    return 'PASS actual unchanged step-ca Google KMS TLS/ADC/public/sign wire + EC/RSA issuance/chain/signature + passive/unknown request denials'


def cleanup():
    if not created:return
    state=json.loads(docker('inspect',NAME).stdout)[0]
    if state['Config']['Labels'].get('cloud8021x.owner')!=OWNER:raise RuntimeError('cleanup refuses unowned KMS fixture')
    errors=[]
    try:
        docker('logs',NAME,log='container')
        docker('cp',NAME+':/work',str(OUT/'guest-artifacts'))
    except Exception as error:errors.append('capture: '+str(error))
    try:docker('rm','-f',NAME)
    except Exception as error:errors.append('removal: '+str(error))
    if errors:raise RuntimeError('KMS fixture cleanup failed: '+'; '.join(errors))


if __name__=='__main__':
    try:completion=main()
    finally:cleanup()
    print(completion,flush=True)
