"""Host-only native gate runner for an explicitly prepared disposable fixture."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
VERSION='3.2.10+dfsg-2~bookworm+campus3'

def run_native(container,mode):
    if not container:
        raise SystemExit('--native requires --container pointing to a prepared labeled disposable fixture')
    def docker(*args,**kwargs):
        return subprocess.run(['docker',*args],check=True,**kwargs)
    state=json.loads(docker('inspect',container,capture_output=True,text=True).stdout)[0]
    if state['Config'].get('Labels',{}).get('cloud8021x.test') not in ['pr39','task6'] or state['HostConfig'].get('PortBindings'):
        raise SystemExit('native fixtures require a cloud8021x.test label and no published host ports')
    architecture=docker('exec',container,'dpkg','--print-architecture',capture_output=True,text=True).stdout.strip()
    if architecture not in ['arm64','amd64']:
        raise SystemExit('unsupported native fixture architecture')
    for package in ['freeradius','libfreeradius3','freeradius-common','freeradius-config','freeradius-rest','freeradius-postgresql','freeradius-utils']:
        installed=docker('exec',container,'dpkg-query','-W','-f=${Status} ${Version}',package,capture_output=True,text=True).stdout
        if installed!='install ok installed '+VERSION:
            raise SystemExit('fixture must contain the completely configured matching security-fixed package family')
    with tempfile.TemporaryDirectory(prefix='cloud8021x-native-') as temporary:
        env={**os.environ,'GOOS':'linux','GOARCH':architecture,'GOTOOLCHAIN':'go1.27.1'}
        for package,name,destination in [('./tests/native_fixture','fixture','/task6-native-fixture'),('./cmd/cloud-8021x','daemon','/usr/local/bin/cloud-8021x')]:
            binary=str(Path(temporary)/name)
            subprocess.run(['go','build','-o',binary,package],cwd=ROOT,env=env,check=True)
            docker('cp',binary,container+':'+destination)
    docker('cp',str(ROOT/'tests/native_radius_container.py'),container+':/task6-native.py')
    docker('exec',container,'/task6-native-fixture','render','/etc/cloud-8021x/config.yaml')
    docker('exec',container,'python3','/task6-native.py',mode)
