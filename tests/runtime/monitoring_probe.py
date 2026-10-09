"""Owned installed-Agent check acceptance. No external listener or telemetry."""
import http.server, ssl, threading, json, pathlib, shutil, subprocess, time, os, yaml, sys
for path,content in json.loads(pathlib.Path('/fixture/native-monitoring.json').read_text()).items():
 p=pathlib.Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content)
pathlib.Path('/etc/datadog-agent/datadog.yaml').write_text('hostname: green-fixture-primary\napi_key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nsite: us5.datadoghq.com\nlog_to_console: true\n')
pathlib.Path('/etc/datadog-agent/auth_token').write_text('a'*64)
os.chmod('/etc/datadog-agent/auth_token',0o600)
pathlib.Path('/etc/datadog-agent/ipc_cert.pem').write_bytes(pathlib.Path('/fixture/tls.crt').read_bytes()+pathlib.Path('/fixture/tls.key').read_bytes())
os.chmod('/etc/datadog-agent/ipc_cert.pem',0o600)
p=pathlib.Path('/etc/cloud-8021x');p.mkdir(parents=True,exist_ok=True);shutil.copy('/fixture/tls-ca.crt',p/'client-cas.pem')
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.path=='/health': raw=b'{"status":"ok"}'
  else:
   raw=('''# HELP step_ca_uptime_seconds uptime
# TYPE step_ca_uptime_seconds gauge
step_ca_uptime_seconds 100
# HELP step_ca_x509_signed_total signed
# TYPE step_ca_x509_signed_total counter
step_ca_x509_signed_total{provisioner="%s",success="true"} %d
# HELP step_ca_kms_errors errors
# TYPE step_ca_kms_errors counter
step_ca_kms_errors %d
'''%(("wifi-acme" if self.server.server_port==9090 else "wifi-scep"),int(time.monotonic()),int(time.monotonic()))).encode()
  self.send_response(200);self.send_header('Content-Type','text/plain; version=0.0.4');self.end_headers();self.wfile.write(raw)
 def log_message(self,*args):pass
class Server(http.server.HTTPServer):
 def handle_error(self,request,address):
  if not isinstance(sys.exception(),(ConnectionResetError,BrokenPipeError)): super().handle_error(request,address)
for port in [9090,9091,8443,8444]:
 server=Server(('127.0.0.1',port),Handler)
 if port>8000 and port<9000:
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); cert='rsa-tls' if port==8444 else 'tls'; ctx.load_cert_chain('/fixture/'+cert+'.crt','/fixture/'+cert+'.key');server.socket=ctx.wrap_socket(server.socket,server_side=True)
 threading.Thread(target=server.serve_forever,daemon=True).start()
children=[]
for name,count in [('freeradius',1),('step-ca',2)]:
 shutil.copy('/bin/sleep','/tmp/'+name)
 for _ in range(count):children.append(subprocess.Popen(['/tmp/'+name,'120']))
try:
 for check in ['openmetrics','http_check','process']:
  p=subprocess.run(['/opt/datadog-agent/bin/agent/agent','check',check,'--json','--check-rate'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
  pathlib.Path('/output/'+check+'.log').write_bytes(p.stdout)
  print(check,p.returncode,flush=True)
  if p.returncode:print(p.stdout.decode()[-4000:],flush=True);raise SystemExit(1)
  text=p.stdout.decode(); rows=json.loads(text[text.index('[\n'):])
  assert len(rows)==2, (check,'both configured instances must execute')
  for row in rows:
   assert row['runner']['TotalErrors']==0, row['runner']
   metrics=row['aggregator']['metrics']; checks=row['aggregator']['service_checks']
   assert all(m['host']=='green-fixture-primary' for m in metrics)
   assert all(c['host_name']=='green-fixture-primary' for c in checks)
  if check=='openmetrics':
   for ca in ['ec','rsa']:
    metrics=[m for r in rows for m in r['aggregator']['metrics'] if 'ca_instance:'+ca in m['tags']]
    for name in ['smallstep.x509.signed.count','smallstep.kms.errors.count']:
     assert any(m['metric']==name and m['type']=='count' and 'service:smallstep-ca' in m['tags'] for m in metrics),(ca,name)
    assert any('provisioner:'+('wifi-acme' if ca=='ec' else 'wifi-scep') in m['tags'] and 'success:true' in m['tags'] for m in metrics)
  elif check=='http_check':
   for instance in ['stepca_health','stepca_rsa_health']:
    assert any(c['check']=='http.can_connect' and c['status']==0 and 'instance:'+instance in c['tags'] for r in rows for c in r['aggregator']['service_checks'])
  else:
   for name in ['freeradius','step-ca']:
    assert any(c['check']=='process.up' and c['status']==0 and 'process:'+name in c['tags'] for r in rows for c in r['aggregator']['service_checks'])
   assert any(m['metric']=='system.processes.run_time.max' and m['type']=='gauge' and 'process_name:freeradius' in m['tags'] for r in rows for m in r['aggregator']['metrics'])

 # Trust and DNS failures must be visible through the exact generated Agent check.
 health_path=pathlib.Path('/etc/datadog-agent/conf.d/http_check.d/cloud-8021x.yaml')
 original=health_path.read_text()
 for scenario in ['wrong-ca','wrong-name']:
  if scenario=='wrong-ca': shutil.copy('/fixture/wrong-ca.crt','/etc/cloud-8021x/client-cas.pem')
  else:
   shutil.copy('/fixture/tls-ca.crt','/etc/cloud-8021x/client-cas.pem')
   config=yaml.safe_load(original)
   for instance in config['instances']: instance['headers']['Host']='wrong.fixture.test'
   health_path.write_text(yaml.safe_dump(config))
  result=subprocess.run(['/opt/datadog-agent/bin/agent/agent','check','http_check','--json'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
  pathlib.Path('/output/http_check-'+scenario+'.log').write_bytes(result.stdout)
  assert result.returncode==0, result.stdout.decode()[-4000:]
  text=result.stdout.decode(); rows=json.loads(text[text.index('[\n'):])
  assert len(rows)==2
  for row in rows:
   checks=[c for c in row['aggregator']['service_checks'] if c['check']=='http.can_connect']
   assert checks and all(c['status']==2 for c in checks), (scenario,checks)
   expected='CERTIFICATE_VERIFY_FAILED' if scenario=='wrong-ca' else "hostname 'wrong.fixture.test' doesn't match"
   assert all(expected in c['message'] for c in checks), (scenario,checks)
  print('http_check '+scenario+' refused both CA endpoints',flush=True)
 health_path.write_text(original)
 shutil.copy('/fixture/tls-ca.crt','/etc/cloud-8021x/client-cas.pem')

finally:
 for child in children:child.terminate();child.wait()
