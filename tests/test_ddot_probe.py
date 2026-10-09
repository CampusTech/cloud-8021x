#!/usr/bin/env python3
"""Source-only DDOT probe regressions; no Agent, Docker, or network execution.

Extract functions through AST because the fixture scripts intentionally execute
services at top level. DDOT_TEST_MUTATION restores old failure behavior in memory
for regression sensitivity checks; it never modifies the fixture source files.
"""
import ast
import contextlib
import io
import json
import pathlib
import os
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
def helpers(filename):
    source=(ROOT/'tests'/filename).read_text()
    if os.environ.get('DDOT_TEST_MUTATION')=='lost-output':
        source=source.replace("    (evidence / (name + '.stdout')).write_bytes(result.stdout)","    result.check_returncode()\n    (evidence / (name + '.stdout')).write_bytes(result.stdout)")
    if os.environ.get('DDOT_TEST_MUTATION')=='token-only':
        source=source.replace("    deadline = time.monotonic() + seconds\n    report =","    if token.exists() and process.poll() is None: return\n    deadline = time.monotonic() + seconds\n    report =")
    tree=ast.parse(source)
    ns=dict(pathlib=pathlib,json=json,subprocess=subprocess,time=time,ssl=ssl,urllib=__import__('urllib'),sys=sys)
    exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.Import,ast.ImportFrom))],type_ignores=[]),filename,'exec'),ns)
    return ns

class ProbeTests(unittest.TestCase):
    def test_failed_host_check_evidence_precedes_raise(self):
        for file in ['ddot_probe.py','ddot_queue.py']:
            with self.subTest(file=file),tempfile.TemporaryDirectory() as tmp:
                capture=helpers(file)['capture_command']
                command=[sys.executable,'-c',"import sys;print('synthetic cpu stdout');print('synthetic IPC failure',file=sys.stderr);sys.exit(255)"]
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    capture(command,pathlib.Path(tmp),'host-check-cpu',timeout=2)
                self.assertEqual(raised.exception.returncode,255)
                self.assertEqual((pathlib.Path(tmp)/'host-check-cpu.stdout').read_text(),'synthetic cpu stdout\n')
                self.assertEqual((pathlib.Path(tmp)/'host-check-cpu.stderr').read_text(),'synthetic IPC failure\n')
                self.assertEqual(json.loads((pathlib.Path(tmp)/'host-check-cpu.result.json').read_text())['returncode'],255)
    def test_timeout_preserves_output(self):
        for file in ['ddot_probe.py','ddot_queue.py']:
            with self.subTest(file=file),tempfile.TemporaryDirectory() as tmp:
                capture=helpers(file)['capture_command']
                with self.assertRaises(subprocess.TimeoutExpired):
                    capture([sys.executable,'-u','-c',"import time;print('before stall');time.sleep(5)"],pathlib.Path(tmp),'timeout',timeout=.2)
                self.assertEqual((pathlib.Path(tmp)/'timeout.stdout').read_text(),'before stall\n')
                self.assertTrue(json.loads((pathlib.Path(tmp)/'timeout.result.json').read_text())['timed_out'])
    def test_token_before_cert_is_not_readiness(self):
        ns=helpers('ddot_probe.py')
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);token=root/'token';cert=root/'cert';token.write_text('synthetic-token')
            process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)'])
            calls=[]
            def api(t,c,timeout):
                calls.append(1)
                if len(calls)==1:
                    self.assertFalse(c.exists());c.write_text('synthetic-cert')
                    raise FileNotFoundError('certificate not yet published')
                if len(calls)==2:raise ConnectionRefusedError('API not yet listening')
                if len(calls)==3:return {'Healthy':['healthcheck'],'Unhealthy':['initializing']}
                return {'Healthy':['healthcheck'],'Unhealthy':None}
            try:
                ns['wait_core_api'](process,token,cert,root,seconds=1,probe=api)
                self.assertEqual(len(calls),4)
                result=json.loads((root/'core-readiness.json').read_text())
                self.assertEqual(result['outcome'],'ready')
                self.assertEqual(result['attempts'][2]['health']['Unhealthy'],['initializing'])
                self.assertEqual([x.get('error') for x in result['attempts'][:2]],['FileNotFoundError','ConnectionRefusedError'])
                self.assertNotIn('synthetic-token',json.dumps(result))
            finally:process.terminate();process.wait(timeout=2)
    def test_readiness_timeout_and_exit_have_evidence(self):
        ns=helpers('ddot_probe.py')
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);process=subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)'])
            def failed(*args,**kwargs):raise ConnectionRefusedError('not ready')
            try:
                start=time.monotonic()
                with self.assertRaises(AssertionError):ns['wait_core_api'](process,root/'token',root/'cert',root,seconds=.15,probe=failed)
                self.assertLess(time.monotonic()-start,1)
                self.assertEqual(json.loads((root/'core-readiness.json').read_text())['outcome'],'timeout')
            finally:process.terminate();process.wait(timeout=2)
            with self.assertRaises(AssertionError):ns['wait_core_api'](process,root/'token',root/'cert',root,seconds=2,probe=failed)
            self.assertEqual(json.loads((root/'core-readiness.json').read_text())['outcome'],'exited')
    def test_api_uses_real_contract_verified_tls_and_bearer(self):
        ns=helpers('ddot_probe.py')
        with tempfile.TemporaryDirectory() as tmp:
            token=pathlib.Path(tmp)/'token';token.write_text('synthetic-token');cert=pathlib.Path(tmp)/'cert'
            response=io.BytesIO(b'{"Healthy":["healthcheck"],"Unhealthy":null}')
            response.status=200
            with patch.object(ssl,'create_default_context',return_value='verified-context') as tls,patch.object(urllib.request,'urlopen',return_value=contextlib.closing(response)) as opened:
                self.assertEqual(ns['core_api_status'](token,cert,timeout=.5)['Healthy'],['healthcheck'])
                tls.assert_called_once_with(cafile=str(cert))
                request=opened.call_args.args[0]
                self.assertEqual(request.full_url,'https://127.0.0.1:5001/agent/status/health')
                self.assertEqual(request.get_header('Authorization'),'Bearer synthetic-token')
                self.assertEqual(opened.call_args.kwargs,{'context':'verified-context','timeout':.5})

    def test_unchanged_host_checks_and_preflight_cleanup_wiring(self):
        tree=ast.parse((ROOT/'tests/ddot_probe.py').read_text())
        checks=next(n for n in ast.walk(tree) if isinstance(n,ast.For) and isinstance(n.target,ast.Name) and n.target.id=='check')
        self.assertEqual(ast.literal_eval(checks.iter),['cpu','disk','io','load','memory','network','uptime'])
        calls=[n for n in ast.walk(checks) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='capture_command']
        self.assertEqual(len(calls),1)
        self.assertIn('--check-rate',ast.unparse(calls[0]));self.assertIn('--json',ast.unparse(calls[0]))
        self.assertIn("get('metrics')",ast.unparse(checks))
        guarded=next(n for n in tree.body if isinstance(n,ast.Try) and checks in n.body)
        self.assertIn('wait_core_api',ast.unparse(guarded.body[0]))
        self.assertIn('core.kill()',ast.unparse(guarded.finalbody))
        queue=(ROOT/'tests/ddot_queue.py').read_text()
        self.assertIn("evidence, 'probe', timeout=900",queue)
        self.assertIn('subprocess.TimeoutExpired',queue)

if __name__ == "__main__":
    unittest.main()
