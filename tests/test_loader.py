"""Actual thin-loader shell execution in a private no-network Debian13 container."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(os.environ.get('C8021X_LOADER_FIXTURE') == '1', 'set C8021X_LOADER_FIXTURE=1 for owned no-network container')
class LoaderExecution(unittest.TestCase):
    def test_success_and_fail_closed_boundaries(self):
        with tempfile.TemporaryDirectory(prefix='cloud8021x-loader-') as directory:
            fixture = Path(directory)
            app = b'#!/bin/bash\nprintf "%s\\n" "$*" >> /executed\n'
            payloads = {'cloud-8021x': app, 'manifest.json': b'{}\n', 'config.yaml': b'schema_version: 1\n',
                        'postgres-ca.pem': b'public synthetic CA\n', 'provenance.json': b'{}\n'}
            for name, value in payloads.items():
                (fixture / name).write_bytes(value)
            values = {'parallel':True, 'project_number': '123456789012', 'instance_name': 'green-test-primary', 'artifacts': [
                {'name': name, 'sha256': hashlib.sha256(value).hexdigest(),
                 'url': 'https://storage.googleapis.com/fixture/sha256/' + hashlib.sha256(value).hexdigest() + '/' + name + '?generation=1'}
                for name, value in payloads.items()]}
            (fixture / 'main.tf.json').write_text(json.dumps({'locals': {'loader': values}}))
            rendered = subprocess.run(['terraform', '-chdir=' + directory, 'console'], text=True, capture_output=True,
                                      input='jsonencode(templatefile(' + json.dumps(str(ROOT / 'scripts/startup.sh')) + ', local.loader))', check=True)
            (fixture / 'loader.sh').write_text(json.loads(json.loads(rendered.stdout)))
            # A legacy template selector must never invoke the retired bare
            # bootstrap command, which now only displays the green workflow.
            values['parallel'] = False
            (fixture / 'main.tf.json').write_text(json.dumps({'locals': {'loader': values}}))
            retired = subprocess.run(['terraform', '-chdir=' + directory, 'console'], text=True, capture_output=True,
                                     input='jsonencode(templatefile(' + json.dumps(str(ROOT / 'scripts/startup.sh')) + ', local.loader))', check=True)
            (fixture / 'retired-selector.sh').write_text(json.loads(json.loads(retired.stdout)))
            (fixture / 'curl').write_text('''#!/bin/bash
set -eu
url=${!#}
case "$url" in
 */project/numeric-project-id) echo 123456789012; exit;;
 */instance/name) cat /instance; exit;;
 */default/token) echo '{"access_token":"synthetic.fixture-token","expires_in":3600}'; exit;;
esac
out=''
while [ "$#" -gt 0 ]; do
 if [ "$1" = --output ]; then out=$2; shift; fi
 shift
done
name=${url##*/}; name=${name%%\\?*}
cp "/payload/$name" "$out"
''')
            container = 'cloud8021x-infra-loader-' + uuid.uuid4().hex[:10]
            def docker(*args, ok=True):
                result = subprocess.run(['docker', *args], text=True, capture_output=True)
                if ok:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result
            docker('run', '-d', '--name', container, '--network=none', '--label', 'cloud8021x.slice=infrastructure',
                   '--label', 'cloud8021x.disposable=true', '-v', directory + ':/fixture:ro', 'debian:trixie-slim', 'sleep', 'infinity')
            try:
                docker('exec', container, 'bash', '-c', 'cp /fixture/curl /usr/bin/curl; chmod 755 /usr/bin/curl')
                scenarios = [('success', '', True), ('retired selector', '', True), ('app checksum', 'echo tampered >> /payload/cloud-8021x', False),
                             ('manifest checksum', 'echo tampered >> /payload/manifest.json', False),
                             ('wrong instance', 'echo radius-primary > /instance', False),
                             ('symlink parent', 'ln -s /tmp /var/cache/cloud-8021x', False),
                             ('writable parent', 'mkdir -m 0777 /var/cache/cloud-8021x', False),
                             ('missing manifest', 'rm /payload/manifest.json', False)]
                for name, change, success in scenarios:
                    with self.subTest(name=name):
                        docker('exec', container, 'bash', '-c', 'rm -rf /var/cache/cloud-8021x /payload /executed; mkdir /payload; cp /fixture/cloud-8021x /fixture/*.json /fixture/*.yaml /fixture/*.pem /payload/; echo green-test-primary > /instance; ' + change)
                        loader = '/fixture/retired-selector.sh' if name == 'retired selector' else '/fixture/loader.sh'
                        result = docker('exec', container, 'bash', loader, ok=False)
                        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                        execution = docker('exec', container, 'bash', '-c', 'cat /executed 2>/dev/null || true').stdout
                        self.assertEqual(bool(execution), success)
                        self.assertNotIn('synthetic.fixture-token', result.stdout + result.stderr)
                        if success:
                            self.assertIn('bootstrap prepare --incoming', execution)
                            self.assertEqual(docker('exec', container, 'stat', '-c', '%u:%g:%a', '/var/cache/cloud-8021x/artifacts/manifest.json').stdout.strip(), '0:0:600')
            finally:
                docker('rm', '-f', container)

if __name__ == '__main__':
    unittest.main()
