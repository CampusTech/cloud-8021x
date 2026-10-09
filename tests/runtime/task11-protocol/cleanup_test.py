"""Exercise the runner's real finally block; no copied cleanup implementation."""
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SOURCE=Path(__file__).with_name('run.py')
spec=importlib.util.spec_from_file_location('protocol_runner',SOURCE)
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def invoke_cleanup():
    module=ast.parse(SOURCE.read_text())
    guard=next(node for node in reversed(module.body) if isinstance(node,ast.If))
    block=next(node for node in guard.body if isinstance(node,ast.Try))
    code=ast.Module(body=block.finalbody,type_ignores=[])
    exec(compile(ast.fix_missing_locations(code),str(SOURCE),'exec'),runner.__dict__)


class CleanupFailures(unittest.TestCase):
    def setUp(self):
        runner.NAME='native'
        runner.created=[('network','net'),('container','native'),('container','pg')]
        self.calls=[]
        self.fail=None
        self.unowned=set()

    def docker(self,*args,**kwargs):
        self.calls.append(args)
        if 'inspect' in args:
            owner='another-owner' if args[-1] in self.unowned else runner.OWNER
            return json.dumps([{'Config':{'Labels':{'cloud8021x.owner':owner}},'Labels':{'cloud8021x.owner':owner}}])
        if args[0]=='logs' and self.fail=='logs':raise RuntimeError('injected log failure')
        if args[0]=='exec':
            if self.fail=='probe':raise RuntimeError('injected probe failure')
            return 'yes'
        if args[0]=='cp' and self.fail=='copy':raise RuntimeError('injected copy failure')
        if args[:2]==('rm','-f') and args[-1]=='native' and self.fail=='remove':raise RuntimeError('injected remove failure')
        if args[:2]==('network','rm') and self.fail=='network-remove':raise RuntimeError('injected network remove failure')
        return ''

    def removal_calls(self):
        return [args for args in self.calls if args[0]=='rm' or args[:2]==('network','rm')]

    def test_evidence_failure_cannot_skip_any_owned_removal_or_report_success(self):
        for failure in ['logs','probe','copy']:
            with self.subTest(failure=failure):
                self.calls=[];self.fail=failure
                with mock.patch.object(runner,'docker',side_effect=self.docker),contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(RuntimeError):invoke_cleanup()
                self.assertEqual(self.removal_calls(),[('rm','-f','pg'),('rm','-f','native'),('network','rm','net')])

    def test_removal_failure_propagates_and_remaining_resources_are_attempted(self):
        for failure in ['remove','network-remove']:
            with self.subTest(failure=failure):
                self.calls=[];self.fail=failure
                with mock.patch.object(runner,'docker',side_effect=self.docker),contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(RuntimeError):invoke_cleanup()
                self.assertEqual(self.removal_calls(),[('rm','-f','pg'),('rm','-f','native'),('network','rm','net')])

    def test_unowned_resource_is_untouched_and_other_owned_resources_continue(self):
        self.unowned={'native'}
        with mock.patch.object(runner,'docker',side_effect=self.docker),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):invoke_cleanup()
        self.assertEqual(self.removal_calls(),[('rm','-f','pg'),('network','rm','net')])
        self.assertNotIn(('logs','native'),self.calls)

    def test_missing_ownership_evidence_refuses_removal_and_fails(self):
        def missing(*args,**kwargs):
            if args[:2]==('container','inspect') and args[-1]=='native':raise RuntimeError('inspect failed')
            return self.docker(*args,**kwargs)
        with mock.patch.object(runner,'docker',side_effect=missing),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):invoke_cleanup()
        self.assertEqual(self.removal_calls(),[('rm','-f','pg'),('network','rm','net')])

    def test_successful_capture_and_removal(self):
        with mock.patch.object(runner,'docker',side_effect=self.docker):invoke_cleanup()
        self.assertEqual(self.removal_calls(),[('rm','-f','pg'),('rm','-f','native'),('network','rm','net')])


def actual_stopped():
    """One cached stopped container; independently rescue only this exact label."""
    name='task11-protocol-cleanup-91a6'
    output=Path(os.environ['TASK11_CLEANUP_EVIDENCE'])
    output.mkdir(exist_ok=True)
    def docker(*args,check=True):
        return subprocess.run(['docker',*args],text=True,capture_output=True,check=check)
    if docker('container','inspect',name,check=False).returncode==0:
        raise RuntimeError('reserved regression name already exists; refuses reuse')
    try:
        docker('create','--name',name,'--pull','never','--network','none','--cpus','1','--memory','128m','--pids-limit','32',
               '--label','cloud8021x.owner='+runner.OWNER,'--label','cloud8021x.task=11','--label','cloud8021x.disposable=true',runner.BASE,'/bin/true')
        docker('start',name);docker('wait',name)
        state=json.loads(docker('container','inspect',name).stdout)[0]
        assert not state['State']['Running'] and state['State']['ExitCode']==0
        assert state['HostConfig']['NetworkMode']=='none' and not state['HostConfig'].get('PortBindings')
        assert state['HostConfig']['NanoCpus']==1000000000 and state['HostConfig']['Memory']==128*1024**2
        (output/'stopped-isolation.json').write_text(json.dumps({'name':name,'image':state['Image'],'state':state['State'],
            'cpu':state['HostConfig']['NanoCpus'],'memory':state['HostConfig']['Memory'],'network':state['HostConfig']['NetworkMode'],
            'ports':state['HostConfig'].get('PortBindings'),'labels':state['Config']['Labels']},indent=2))
        result=subprocess.run([sys.executable,str(Path(__file__)),'--cleanup-driver',name,str(output)],text=True,capture_output=True,
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
        (output/'driver.log').write_text(result.stdout+result.stderr)
        absent=docker('container','inspect',name,check=False).returncode!=0
        proof={'driver_exit':result.returncode,'owned_container_removed':absent}
        (output/'outcome.json').write_text(json.dumps(proof,indent=2))
        print(json.dumps(proof),flush=True)
        assert absent,'runner stranded the actual stopped owned container'
        assert result.returncode!=0,'evidence failure was reported as cleanup success'
    finally:
        state=docker('container','inspect',name,check=False)
        if state.returncode==0:
            identity=json.loads(state.stdout)[0]
            if identity['Config']['Labels'].get('cloud8021x.owner')!=runner.OWNER:raise RuntimeError('rescue refuses unowned container')
            docker('rm','-f',name)
            (output/'independent-rescue.txt').write_text('Original cleanup stranded container; regression harness removed only its exact owned container after recording RED.\n')


if __name__=='__main__':
    if '--cleanup-driver' in sys.argv:
        runner.NAME=sys.argv[2];runner.OUT=Path(sys.argv[3]);runner.created=[('container',runner.NAME)]
        invoke_cleanup()
    elif '--actual-stopped' in sys.argv:
        actual_stopped()
    else:
        unittest.main()
