"""Invoke the authenticated upstream generators without loading unrelated tasks.

This is the same schema_codegen/_compress_no_bazel pipeline as upstream's
build task. No schema values or generated Go behavior are changed here.
"""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types

for name in ['tasks', 'tasks.schema', 'tasks.libs', 'tasks.libs.types']:
    module = types.ModuleType(name)
    module.__path__ = [str(Path(name.replace('.', '/')).resolve())]
    sys.modules[name] = module

from tasks.schema.merge_schema import resolve_schema
from tasks.schema.codegen_init_settings import run_codegen, run_constants_codegen, run_core_constant_codegen
from tasks.schema.produce_byproduct import produce_byproduct

schema = Path('pkg/config/schema')
setup = 'pkg/config/setup'
core = resolve_schema(str(schema / 'yaml/core_schema.yaml'))
probe = resolve_schema(str(schema / 'yaml/system-probe_schema.yaml'))
run_codegen(core, setup)
run_codegen(probe, setup, sysprobe=True)
run_core_constant_codegen(core, setup)
run_constants_codegen(core, probe, setup + '/constants')
(schema / 'compressed').mkdir(exist_ok=True)
for name in ['core_schema', 'system-probe_schema']:
    descriptor, path = tempfile.mkstemp(suffix='.yaml')
    os.close(descriptor)
    try:
        produce_byproduct('embedded', str(schema / 'yaml' / (name + '.yaml')), path)
        subprocess.run(['zstd', '--force', '--no-check', '-5', path, '-o', str(schema / 'compressed' / (name + '.yaml.zstd'))], check=True)
    finally:
        os.unlink(path)
